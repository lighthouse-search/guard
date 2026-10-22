#!/usr/bin/env python3
"""Repo-wide dependency refresh and security audit for the Auto update workflow.

Subcommands
  discover            list every Cargo/npm manifest in the repo
  update              run `cargo update` / `npm update` across all of them
  audit               emit JSON advisory findings per manifest
  report BEFORE AFTER render a markdown summary and set workflow outputs

The point of `report` is to catch the failure mode a plain `cargo update` /
`npm update` cannot fix on its own: an advisory whose patched release is NOT a
breaking change, yet is held back by an exact version pin in the manifest. That
is invisible to the lockfile-changed check -- the lockfile never moves -- so it
is surfaced explicitly instead.
"""
import argparse, json, os, re, subprocess, sys, pathlib

SKIP = {"node_modules", "target", "_static", ".next", "out", ".git", "dist"}
ROOT = pathlib.Path(os.environ.get("GITHUB_WORKSPACE", ".")).resolve()


def walk(filename):
    for p in sorted(ROOT.rglob(filename)):
        if any(part in SKIP for part in p.relative_to(ROOT).parts):
            continue
        yield p


def discover():
    return {
        "cargo": [str(p.parent.relative_to(ROOT)) for p in walk("Cargo.toml")],
        "npm": [str(p.parent.relative_to(ROOT)) for p in walk("package.json")],
    }


def run(cmd, cwd, timeout=900):
    try:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return 1, "", str(e)



# RustSec advisories carry a CVSS v3.1 *vector string* (`cvss = "CVSS:3.1/AV:N/..."`)
# and, for non-vulnerabilities, an `informational` kind. There is no `severity`
# field, so it has to be derived. Scored offline per the CVSS v3.1 spec; verified
# against the published scores for RUSTSEC-2024-0336 (7.5), 2026-0285 (5.3),
# 2023-0053 (7.5) and 2020-0071 (6.2).
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(x):
    """CVSS v3.1 Appendix A roundup: integer arithmetic, avoids float drift."""
    i = int(round(x * 100000))
    return i / 100000.0 if i % 10000 == 0 else (i // 10000 + 1) / 10.0


def cvss31_base_score(vector):
    m = dict(part.split(":", 1) for part in str(vector).split("/") if ":" in part)
    try:
        av, ac, ui = _AV[m["AV"]], _AC[m["AC"]], _UI[m["UI"]]
        changed = m["S"] == "C"
        pr = (_PR_C if changed else _PR_U)[m["PR"]]
        c, i_, a = _CIA[m["C"]], _CIA[m["I"]], _CIA[m["A"]]
    except KeyError:
        return None
    iss = 1 - ((1 - c) * (1 - i_) * (1 - a))
    impact = (7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15) if changed else 6.42 * iss
    if impact <= 0:
        return 0.0
    expl = 8.22 * av * ac * pr * ui
    return _roundup(min((impact + expl) * (1.08 if changed else 1.0), 10))


def severity_from_advisory(adv):
    """CVSS band, or the informational kind for advisories that are not CVEs."""
    score = cvss31_base_score(adv.get("cvss")) if adv.get("cvss") else None
    if score is not None:
        if score == 0:   return "none", score
        if score < 4.0:  return "low", score
        if score < 7.0:  return "moderate", score
        if score < 9.0:  return "high", score
        return "critical", score
    info = adv.get("informational")
    # unmaintained / unsound / notice are advisories, but not rated vulnerabilities.
    return (str(info) if info else "unknown"), None


def cargo_constrained_by(d, name, version):
    """Which dependents hold `name` at `version` — i.e. why the refresh can't move it."""
    code, out, _ = run(["cargo", "tree", "--invert", f"{name}@{version}",
                        "--depth", "1", "--prefix", "none"], ROOT / d, timeout=180)
    if code != 0:
        return []
    out_lines = out.split("\n")[1:]
    seen, uniq = set(), []
    for line in out_lines:
        tok = line.strip().split(" ")
        if not tok or not tok[0] or tok[0] == name:
            continue
        label = " ".join(tok[:2])
        if label not in seen:
            seen.add(label); uniq.append(label)
    return uniq[:4]


# ---------------------------------------------------------------- update

def cmd_update(args):
    m = discover()
    for d in m["cargo"]:
        code, out, err = run(["cargo", "update"], ROOT / d)
        n = len(re.findall(r"^\s+(?:Updating|Adding|Removing) ", out + err, re.M))
        print(f"cargo  {d}: {'ok' if code == 0 else 'FAILED'} ({n} packages changed)")
        if code != 0:
            print(f"  {err.strip()[:400]}")
    # A `file:` dependency must be refreshed before the package that consumes it.
    for d in sorted(m["npm"], key=lambda p: -len(p)):
        code, out, err = run(["npm", "update", "--package-lock-only"], ROOT / d)
        print(f"npm    {d}: {'ok' if code == 0 else 'FAILED'}")
        if code != 0:
            print(f"  {err.strip()[:400]}")
    return 0


# ---------------------------------------------------------------- audit

def exact_pins(pkg_json):
    """Dependencies pinned to an exact version, which blocks `npm update`."""
    try:
        d = json.loads(pkg_json.read_text())
    except Exception:
        return {}
    pins = {}
    for sec in ("dependencies", "devDependencies", "optionalDependencies"):
        for k, v in (d.get(sec) or {}).items():
            if isinstance(v, str) and v[:1].isdigit():
                pins[k] = v
    return pins


def audit_npm(d):
    code, out, err = run(["npm", "audit", "--package-lock-only", "--json"], ROOT / d)
    if not out.strip():
        return {"error": (err or "no output").strip()[:200], "findings": []}
    try:
        data = json.loads(out)
    except Exception as e:
        return {"error": f"unparseable audit json: {e}", "findings": []}
    pins = exact_pins(ROOT / d / "package.json")
    findings = []
    for name, v in (data.get("vulnerabilities") or {}).items():
        fa = v.get("fixAvailable")
        fix_target = fa.get("name") if isinstance(fa, dict) else None
        # The pin that would hold a fix back is on the package npm wants to
        # bump, which for a transitive advisory is the parent, not `name`.
        pin = pins.get(name) or (pins.get(fix_target) if fix_target else None)
        if fa is False:
            cls, fix = "no_fix", None
        elif isinstance(fa, dict) and fa.get("isSemVerMajor"):
            cls, fix = "major_needed", f"{fa.get('name')}@{fa.get('version')}"
        elif isinstance(fa, dict):
            # Non-breaking fix exists. If an exact pin sits on the package that
            # needs bumping, that pin is what stopped `npm update` taking it.
            cls = "pin_blocked" if pin else "constrained"
            fix = f"{fa.get('name')}@{fa.get('version')}"
        else:
            cls, fix = ("pin_blocked" if pin else "constrained"), "available"
        titles = sorted({x.get("title") for x in (v.get("via") or [])
                         if isinstance(x, dict) and x.get("title")})
        findings.append({
            "package": name, "severity": v.get("severity"), "class": cls,
            "fix": fix, "titles": titles[:3], "blocking_pin": pin,
        })
    return {"error": None, "findings": findings}


def audit_cargo(d):
    code, out, err = run(["cargo", "audit", "--json"], ROOT / d)
    if not out.strip():
        return {"error": (err or "cargo-audit unavailable").strip()[:200], "findings": []}
    try:
        data = json.loads(out)
    except Exception as e:
        return {"error": f"unparseable audit json: {e}", "findings": []}
    try:
        toml = (ROOT / d / "Cargo.toml").read_text()
    except Exception:
        toml = ""
    findings, parents_cache = [], {}
    for item in ((data.get("vulnerabilities") or {}).get("list") or []):
        adv, pkg = item.get("advisory") or {}, item.get("package") or {}
        patched = (item.get("versions") or {}).get("patched") or []
        name, ver = pkg.get("name", "?"), pkg.get("version", "?")
        severity, score = severity_from_advisory(adv)

        pinned = re.search(rf'^\s*{re.escape(name)}\s*=\s*"=\s*([^"]+)"', toml, re.M)
        same_major = any(p.lstrip("^>=~ ").split(".")[0] == ver.split(".")[0] for p in patched)

        constrained_by = []
        if not patched:
            cls = "no_fix"
        elif pinned:
            cls = "pin_blocked"
        elif same_major:
            # A patched release exists in the same major, yet `cargo update` has
            # already run and left this version in place — so a dependency
            # requirement is holding it back. Name it rather than claiming the fix
            # is simply "available but not taken".
            key = (name, ver)
            if key not in parents_cache:
                parents_cache[key] = cargo_constrained_by(d, name, ver)
            constrained_by = parents_cache[key]
            cls = "constrained"
        else:
            cls = "major_needed"

        findings.append({
            "package": name, "version": ver, "severity": severity, "score": score,
            "class": cls, "fix": ", ".join(patched) or None,
            "titles": [adv.get("title", "")][:1],
            "blocking_pin": pinned.group(1) if pinned else None,
            "id": adv.get("id"), "constrained_by": constrained_by,
        })
    return {"error": None, "findings": findings}


def cmd_audit(args):
    m = discover()
    res = {"cargo": {}, "npm": {}}
    for d in m["cargo"]:
        res["cargo"][d] = audit_cargo(d)
    for d in m["npm"]:
        res["npm"][d] = audit_npm(d)
    out = json.dumps(res, indent=2)
    if args.out:
        pathlib.Path(args.out).write_text(out)
    else:
        print(out)
    return 0


# ---------------------------------------------------------------- report

def _label(f):
    """`crate 1.2.3` (RUSTSEC-xxxx, high 7.5) — enough to act on and to tell
    two findings for the same crate apart."""
    ver = f" `{f['version']}`" if f.get("version") else ""
    bits = [b for b in (f.get("id"), f.get("severity")) if b]
    if f.get("score") is not None:
        bits[-1] = f"{f['severity']} {f['score']}"
    return f"`{f['package']}`{ver}" + (f" ({', '.join(bits)})" if bits else "")


SEV = ["critical", "high", "moderate", "medium", "low", "unknown", None]


def tally(blob):
    c = {s: 0 for s in SEV if s}
    for eco in blob.values():
        for r in eco.values():
            for f in r.get("findings", []):
                s = (f.get("severity") or "unknown").lower()
                c[s if s in c else "unknown"] += 1
    return c


def count_for(r):
    return len(r.get("findings", []))


def cmd_report(args):
    before = json.loads(pathlib.Path(args.before).read_text())
    after = json.loads(pathlib.Path(args.after).read_text())
    tb, ta = tally(before), tally(after)

    lines = ["## Dependency security audit", ""]
    lines.append("| Severity | Before | After |")
    lines.append("|---|---:|---:|")
    for s in ("critical", "high", "moderate", "low", "unknown"):
        if tb.get(s) or ta.get(s):
            lines.append(f"| {s} | {tb.get(s,0)} | {ta.get(s,0)} |")
    lines += ["", "| Manifest | Before | After |", "|---|---:|---:|"]
    for eco in ("cargo", "npm"):
        for d, r in sorted(after.get(eco, {}).items()):
            b = count_for(before.get(eco, {}).get(d, {}))
            a = count_for(r)
            if b or a:
                lines.append(f"| `{d or '.'}` ({eco}) | {b} | {a} |")

    blocked, constrained, major, nofix, errors = [], [], [], [], []
    buckets = {"pin_blocked": blocked, "constrained": constrained, "major_needed": major}
    for eco in ("cargo", "npm"):
        for d, r in sorted(after.get(eco, {}).items()):
            if r.get("error"):
                errors.append(f"`{d or '.'}` ({eco}): {r['error']}")
            for f in r.get("findings", []):
                buckets.get(f["class"], nofix).append((d, eco, f))

    if blocked:
        lines += ["", "### ⚠️ Non-breaking security fixes being held back", "",
                  "These have a patched release that is **not** a breaking change, yet the "
                  "update did not take it — an exact version pin is blocking it. "
                  "Relax the pin (e.g. `\"1.2.3\"` -> `\"^1.2.3\"`) so future runs pick it up.", ""]
        for d, eco, f in blocked:
            pin = f" (pinned at `{f['blocking_pin']}`)" if f.get("blocking_pin") else ""
            lines.append(f"- {_label(f)} in `{d or '.'}`{pin} — fix: `{f['fix']}`")
            for t in f.get("titles", [])[:2]:
                if t:
                    lines.append(f"  - {t}")
    if constrained:
        lines += ["", "### Held back by a dependency requirement", "",
                  "A patched release exists, but the refresh already ran and could not move to "
                  "it: a dependency pins the version shown. These are not fixable by updating — "
                  "they need the named dependent to release a bump, or that dependent replaced.", ""]
        for d, eco, f in constrained:
            why = f" — held by {', '.join(f'`{x}`' for x in f['constrained_by'])}" if f.get("constrained_by") else ""
            lines.append(f"- {_label(f)} in `{d or '.'}` -> needs `{f['fix']}`{why}")
    if major:
        lines += ["", "### Needs a major-version bump (human decision)", ""]
        for d, eco, f in major:
            lines.append(f"- {_label(f)} in `{d or '.'}` — fix: `{f['fix']}`")
    if nofix:
        lines += ["", "### No upstream fix available (informational)", ""]
        for d, eco, f in nofix:
            lines.append(f"- {_label(f)} in `{d or '.'}`")
    if errors:
        lines += ["", "### Audit could not run", ""] + [f"- {e}" for e in errors]

    md = "\n".join(lines) + "\n"
    if args.summary:
        pathlib.Path(args.summary).write_text(md)
    print(md)

    if args.github_output:
        with open(args.github_output, "a") as fh:
            fh.write(f"blocked_count={len(blocked)}\n")
            fh.write(f"constrained_count={len(constrained)}\n")
            fh.write(f"vuln_total_before={sum(tb.values())}\n")
            fh.write(f"vuln_total_after={sum(ta.values())}\n")
    return 0


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("discover")
    sub.add_parser("update")
    a = sub.add_parser("audit"); a.add_argument("--out")
    r = sub.add_parser("report")
    r.add_argument("before"); r.add_argument("after")
    r.add_argument("--summary"); r.add_argument("--github-output")
    args = ap.parse_args()
    if args.cmd == "discover":
        print(json.dumps(discover(), indent=2)); return 0
    return {"update": cmd_update, "audit": cmd_audit, "report": cmd_report}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
