# WireGuard: policy-enforced access to non-HTTPS protocols

Status: **Phases 0–5 implemented** (minus tunnel identity, noted below).
Phases 6 and 7 are still plan.

## Goal

Guard can currently authenticate and proxy HTTPS. This plan extends it to arbitrary
protocols over a Guard-managed WireGuard server, with the same policy engine deciding
what each device may reach, and support for chaining through downstream WireGuard
instances (client → Guard/VPS → home site → Home Assistant).

## Where we are today

Shipped in `510a560`, undocumented, and with no authorization of any kind:

| Piece | File |
| --- | --- |
| Interface lifecycle, key persistence, `wg syncconf` reload, peer apply, IP allocation | `server/src/wireguard.rs` |
| `POST /guard/api/wireguard/register`, RFC 9421 device-signed, one key per device | `server/src/endpoints/wireguard.rs` |
| `devices.wireguard_public_key`, `devices.wireguard_ip` | `server/src/device.rs`, `server/src/tables.rs` |
| Desktop keygen, registration, `wg-quick` up/down (macOS only) | `desktop-client/src-tauri/src/wireguard.rs` |

The crypto and identity half is sound. The gaps:

1. **No policy is ever evaluated.** `wireguard_register` checks the device signature and
   hands out a tunnel. `policy_authentication` is never called.
2. **No dataplane enforcement.** Server-side `AllowedIPs = <peer>/32` is cryptokey
   routing — it filters the *source* a peer may claim, not the destinations it may
   reach. There is no packet filter anywhere in the repo.
3. **No revocation.** No peer-removal path; peers are restored from the DB on every boot.
4. **No chaining primitives.** `build_conf` emits only `/32` client peers — no site peers
   with multi-CIDR `AllowedIPs`, no `Endpoint`, no keepalive, no routing.

## Model

Everything reachable over the tunnel is a **resource**: a name, a destination Guard
dials, and a set of `applied_policies`. Two kinds, distinguished by how Guard works out
which resource a connection is for:

- **`[hostname.*]` — demuxed by Host header.** Already fully specified today. Reachable
  publicly *and* over the tunnel, via the existing `http_handler` pipeline, with no new
  config. These are the things you'd open in a browser.
- **`[wireguard.endpoint.*]` — demuxed by service IP + port.** Everything that isn't
  Host-addressed: SSH, SMB, IPP, Postgres, HTTPS APIs you can't set a Host on. Guard
  allocates a service IP per endpoint from a dedicated subnet, listens on it, and
  splices bytes to the destination.

Both resolve to *name → destination Guard dials → policies*. One policy evaluation, one
proxy core, two demux strategies.

### Why terminate at Guard rather than route

Guard dials the backend itself, so the destination never needs resolving to a CIDR, no
`ip_forward`, no masquerade, no FORWARD chain — packets to the backend **originate from
Guard**, which is ordinary outbound routing. Consequences:

- **Client `AllowedIPs` is static**: `peer_subnet` + service subnet, forever. Policy
  changes never require client reconfiguration.
- The client **cannot address backends directly** — only the service IPs Guard exposes.
- One policy implementation in Rust, not policy in Rust *and* in a generated ruleset.
- No root firewall manipulation; doesn't pin Guard to Linux.

Cost: Guard is on the data path, and backends see Guard as the source rather than the
device (access control already ran, but backend audit logs lose per-device attribution).

### What this model cannot do

Deferred to the routed tier (Phase 7), explicitly out of scope before then:

- **Subnet grants** — "this device may reach all of `10.0.1.0/24`". Can't allocate a
  service IP per possible destination.
- **Payload-embedded addresses** — classic FTP, SIP, some RPC. Needs a per-protocol ALG.
- **ICMP** — ping, path-MTU discovery.
- **Printer-initiated / scan-to-folder** — the proxy is client-initiated only. Pull-based
  scanning (eSCL over IPP) is fine.
- **Multicast discovery** — mDNS, WS-Discovery, NetBIOS browsing. Note this is *not*
  fixed by the routed tier either: multicast is link-local by design and won't cross the
  tunnel in either model. Phase 6 addresses it separately via unicast DNS-SD.

---

## Phase 0 — Repair the existing foundation — DONE

Prerequisite for everything else; no new features.

- **Resolve the conf-ownership conflict.** `ensure_interface` rewrites
  `/etc/wireguard/<iface>.conf` from the DB on boot, while `apply_peer` calls
  `wg-quick save`, which writes the *running* config back. They fight, and `save` will
  strip any hooks added later. Make the DB authoritative: drop `wg-quick save`, always
  regenerate the conf from the DB, and apply live with `wg set` / `wg syncconf`.
- **Add peer removal.** `wireguard::remove_peer(interface, public_key)` →
  `wg set <iface> peer <key> remove`, plus `device_clear_wireguard(device_id)` in
  `device.rs`. Nothing can be revoked without this.
- **Stop panicking in the request path.** `endpoints/wireguard.rs:108`, `:132`, `:144`
  use `.expect()` on DB calls, and `endpoints/reverse_proxy_authentication.rs:38` does the
  same on hostname resolution; a transient error panics the task instead of returning 500.
  Convert to `error_message(...)`.
- **Document it.** A `[wireguard]` section in the README and an
  `example/wireguard-config.toml`. Currently no example config mentions WireGuard.

**Done when:** a peer can be added and removed live, the conf survives a restart
unchanged, and no DB error can panic the endpoint.

## Phase 1 — Policy on the tunnel — DONE

- **Evaluate policy at registration.** In `wireguard_register`, after device
  authentication: `device.user_id` → load user → build the same `serde_json::Value` the
  HTTP pipeline passes to `policy_authentication` → evaluate against
  `[wireguard].applied_policies` (falling back to `[device_authentication]`). Deny → no
  peer, no tunnel.
- **Source tunnel IP → device.** `device_get_by_wireguard_ip(ip)` in `device.rs`, mirroring
  `device_get_by_wireguard_public_key`. This is the identity primitive the rest of the
  plan depends on.
- **Re-evaluation loop.** A periodic task (default 60s) re-runs policy for every
  registered peer and removes those that no longer pass. Without this, revocation only
  takes effect on re-registration, which a connected peer never does.

**Security — the single most important invariant in this plan:** a source address in
`peer_subnet` is only trustworthy if the packet *actually arrived on the WireGuard
interface*. Guard binds `0.0.0.0` (`main.rs:344`), so identity must never be inferred
from the source IP alone. Bind a **separate listener to the tunnel address** and treat
only connections accepted there as tunnel-authenticated; additionally assert the accepted
connection's local address is the tunnel address. Enable `rp_filter` on the host and
document it. Getting this wrong turns a source-IP spoof into full impersonation.

**Done when:** a device failing policy cannot register, and revoking a user's access
removes their peer within the re-evaluation interval.

## Phase 2 — Hostnames reachable over the tunnel — DONE, except tunnel identity

No new proxy code; this is wiring the existing pipeline to tunnel identity.

### Determining arrival

Everything in this phase depends on knowing whether a request came in over the tunnel,
and that is **not** available for free. Guard binds `0.0.0.0:guard_port`
(`main.rs:344`), so a second listener on `10.8.0.1:guard_port` cannot also bind —
`0.0.0.0` already covers it (`EADDRINUSE`). Two structural options:

**The local-address option was spiked and does not work.** `axum-server` 0.8 calls
`make_service(socket_addr)` with only the *peer* address (`server.rs:298`); the accepted
`TcpStream` is never handed to the service, so a custom `Connected` impl cannot see which
local address a connection landed on. That forecloses the no-config structural option.

**What is implemented instead:** `wireguard::arrival_from(source)` classifies a request by
whether its source address falls inside `peer_subnet`, defaulting to `Public` on any
malformed or missing config so a mistake fails closed. IPv4-mapped IPv6 sources
(`::ffff:10.8.0.2`, which a dual-stack listener reports) are unwrapped, so a real peer is
not misclassified as public.

This is weaker than a structural check and its integrity rests on two things, both
documented in the function and the README:

- For TCP, blind spoofing cannot reach the handler — an attacker forging a source inside
  `peer_subnet` never sees the SYN-ACK, since it routes into the tunnel. Completing a
  handshake requires being on-path.
- `rp_filter` must be on, so the kernel drops a forged `peer_subnet` source arriving on a
  public interface. `warn_if_rp_filter_disabled()` checks `/proc/sys/net/ipv4/conf/all/rp_filter`
  at startup and logs an error when it is `0`.

**Still worth doing:** the structural version, via a `[server].bind` key that binds the
public listener to explicit addresses so a second listener can own the tunnel address and
arrival is decided by which socket accepted. That is the right end state; the derivation
above is what the current dependency allows.

**`rp_filter` is required regardless**, as defence in depth: it makes the kernel drop a
packet claiming a `peer_subnet` source that arrives on the public interface, before Guard
sees it. Document it as a host requirement and warn at startup when it is off — but it
must never be the only barrier, which is what the structural check above provides.

### Work

- **NOT DONE — tunnel-aware auth in `http_handler`.** On tunnel arrival, resolve the
  device from the source address and use it as the authenticated identity, bypassing the
  cookie flow. `device_get_by_wireguard_ip` exists and is ready; the remaining work is
  inside `user_authentication_pipeline`, which currently always expects a cookie-derived
  user *and* an authentication method, so a device-derived identity needs a path through
  it. Hostnames are already reachable over the tunnel without this — tunnel users simply
  still see the login page. This is convenience; `wireguard_only` is the security half and
  is done.
- **`wireguard_only = true` on `[hostname.*]`.** Checked in `http_handler` immediately
  after `get_current_valid_hostname`, before authentication. Return **404, not 403** — a
  403 confirms to an internet scanner that the hostname is a real Guard-protected service.
- **`wireguard = false`** to exclude a hostname from the tunnel entirely.
- **Static client `AllowedIPs`** — see below.

### Two holes `wireguard_only` does not cover

- **The reverse-proxy flow.** `reverse_proxy_authentication` receives `remote_addr` =
  the reverse proxy, and takes the hostname from a forwarded header, so arrival is always
  the proxy's connection. `wireguard_only` on a hostname served through the nginx
  subrequest flow would look protective and do nothing. **Reject the combination at config
  load** rather than trusting a forwarded client IP, which is only as good as the nginx
  deployment.
- **Metadata leaks existence.** `metadata_get_authentication_methods` is public and
  resolves any hostname by name, leaving a tunnel-only entry enumerable along with its
  auth methods. It must 404 for `wireguard_only` hostnames on public arrival.

### Static `AllowedIPs`

`success_response` currently does `wg.allowed_ips.or(wg.peer_subnet)`. It becomes computed
and identical for every device — `peer_subnet` + `service_subnet` — with the existing
`allowed_ips` key retained only as an explicit operator override (e.g. `0.0.0.0/0` for a
full tunnel). Every client config is then:

```ini
[Interface]
PrivateKey = <device's own key, never leaves the device>
Address    = 10.8.0.2/32                 # per-device
DNS        = 10.8.0.1                    # Guard's tunnel resolver (Phase 3)

[Peer]
PublicKey  = <Guard's key>
Endpoint   = vpn.example.com:51820
AllowedIPs = 10.8.0.0/24, 10.9.0.0/24    # identical for every device, forever
PersistentKeepalive = 25
```

Only `PrivateKey` and `Address` differ per device. Granting or revoking access changes
nothing in this file: a device's reachable set is decided by Guard at connection time, not
by its routing table. The desktop client's `parse_dns_list` already accepts a bare IP, so
the `DNS` line needs no client change.

**Peer-to-peer stays off.** `10.8.0.0/24` in `AllowedIPs` only means the client *sends*
that range into the tunnel. Reaching another peer would require `ip_forward` on the Guard
host, which this design never enables. Clients can reach Guard's tunnel address and the
service IPs, and nothing else — including each other.

**Done when:** a `[hostname.*]` entry is reachable over the tunnel with no login page,
`wireguard_only` entries are unreachable and unenumerable publicly, and every device
receives byte-identical `AllowedIPs`.

## Phase 3 — Tunnel resolver — DONE

Without this, auto-included hostnames resolve publicly and take the HTTPS path anyway.

- Unicast DNS server (`hickory-server`) bound to the tunnel address, port 53.
- Exposure is blocked three ways: specific-address bind, refusal to start on a publicly
  routable `server_address`, and a source check against `peer_subnet` before any lookup.
- Serves A records for every active `[hostname.*]` → Guard's tunnel address, and later
  every `[wireguard.endpoint.*]` → its service IP.
- Forwards everything else upstream, or refuses, per config.
- Populate the existing (currently unserved) `ConfigWireguard.dns` field with the tunnel
  address so clients pick it up, plus a search domain for Phase 6.
- Rebuild the zone on config reload and when endpoints change.

**Certificates:** clients hitting `gitlab.example.com` over the tunnel terminate TLS at
Guard, which must present a cert valid for that name. Same problem Guard already has in
its public role (`server/src/misc/tls.rs`), but confirm it holds for tunnel-only
hostnames that may never have had a public cert issued.

**Done when:** a tunnel client resolves and reaches a `[hostname.*]` by its real name.

## Phase 4 — Service IPs and the generic TCP proxy — DONE

The protocol-agnostic tier. A byte splice never parses the protocol, so SMB, SSH,
Postgres and IPP all work through the same code.

- **Config:**
  ```toml
  [wireguard]
  service_subnet = "10.9.0.0/24"     # Guard allocates from this; never handed to peers

  [wireguard.endpoint.nas_ssh]
  active = true
  destination = "10.0.1.20:22"       # what Guard dials, same spirit as proxy_to
  dns_name = "nas.internal"          # optional; what the resolver answers
  applied_policies = ["staff_only"]
  ```
- **Allocation.** Guard assigns the service IP itself — stable across restarts (persist
  the mapping), never user-specified. Reuse/generalise `wireguard::allocate_ip`.
- **Listener: one per endpoint, bound to its own `(service_ip, port)`.** Not a wildcard
  bind with demux — a listener on `0.0.0.0:22` for an SSH endpoint would collide with the
  host's own sshd. Binding `10.9.0.5:22` specifically has no such conflict, and demux
  becomes implicit in which listener accepted the connection. Service IPs need no
  forwarding, because Guard itself answers on them.
- **Per-connection flow:** source address → device → user → policy → dial `destination`
  → `tokio::io::copy_bidirectional`. Log every accepted and refused connection; this is
  the audit trail that replaces backend per-device attribution.
- **Limits.** Per-device and global connection caps, dial timeout, idle timeout. Guard is
  now on the data path and an unbounded splice pool is a denial-of-service surface.

**Done when:** `ssh nas.internal` and mounting an SMB share both work over the tunnel for
a permitted device and are refused for a non-permitted one.

## Phase 5 — Site peers and chaining — DONE

- Extend `build_conf` with a site peer type: multi-CIDR `AllowedIPs`, optional `Endpoint`,
  `PersistentKeepalive`.
  ```toml
  [wireguard.site.home]
  public_key = "..."
  subnets = ["10.0.1.0/24"]
  persistent_keepalive = 25          # it dials out; it's behind NAT
  ```
- `allocate_ip` assumes every peer is a `/32` host inside `peer_subnet`. Rather than
  teach it about site subnets, `validate_site_config` rejects any overlap between a site
  and `peer_subnet` at startup, which makes a collision impossible by construction.
- Guard reaching `10.0.1.20` is then plain outbound routing over `wg0` — no forwarding, no
  NAT, because the connection originates from Guard.
- **Health gating.** Parse `wg show <iface> latest-handshakes`; mark a site down if it
  hasn't handshaked within ~3× keepalive, and fail its endpoints closed rather than
  hanging on a dial timeout.

**Deferred from the earlier discussion:** multi-site "nearest" routing. `AllowedIPs` must
be unique across peers on an interface, so the kernel cannot choose between two sites —
selection has to happen in the resolver (distinct subnet per site, resolver picks) or via
per-device DNAT. When it lands, start with **static affinity + health gating**: an ordered
site preference per device/user. GeoIP from the peer's real endpoint is a later
refinement; measured latency is not worth it, since Guard can observe VPS↔site RTT but not
client↔site, which is the number that matters on a chained path.

**Done:** a Home Assistant instance behind a home WireGuard peer is reachable from a
tunnel client. A downed site is detected and logged each re-evaluation pass; using that
to fail a *request* fast (rather than waiting on a connect timeout) needs the
`proxy_to` → site mapping, which arrives naturally with the Phase 4 endpoint model.

## Phase 6 — DNS-SD

Makes printers and similar appear in native dialogs without multicast.

- `service_type = "_ipps._tcp"` on an endpoint publishes PTR/SRV/TXT records through the
  Phase 3 resolver.
- Push the search domain via the client's DNS config so DNS-SD browsing finds them.
- **AirPrint needs specific TXT records** (`rp`, `pdl`, `URF`) or iOS/macOS won't offer the
  printer — copy them from the real printer's announcement rather than synthesizing.
- Covers macOS/CUPS. Windows is weak on DNS-SD; those clients add the printer by address
  until a real mDNS responder lands (deferred — needs `224.0.0.251/32` in `AllowedIPs` and
  is fiddly for the coverage it adds).

**Done when:** a shared printer appears in the macOS print dialog over the tunnel and
prints, with policy enforced per device.

## Phase 7 — Routed tier (deferred, only if needed)

For subnet grants, ICMP and network browsing. Only this phase needs a packet filter.

- `net.ipv4.ip_forward=1`, wg0→wg0 forwarding permitted only through a Guard-generated
  ruleset.
- One `table inet guard` with a verdict map `tunnel IP → allowed destination set`,
  regenerated atomically with `nft -f` on policy change.
- Masquerade at the VPS so sites need no return route — tradeoff: sites see all traffic as
  coming from Guard, so per-device policy *must* be enforced at the VPS, and a compromised
  VPS is the whole blast radius.
- For devices with a subnet grant, `AllowedIPs` becomes policy-dependent again and is
  pushed on reconnect (`desktop-client/src-tauri/src/wireguard.rs:129` already
  re-registers before `wg-quick up`, so this propagates on connect but not mid-session).
- Put the enforcement behind a `Dataplane` trait so an in-process boringtun implementation
  can replace nftables later — shelling out to `wg`/`wg-quick` as root already sits awkwardly
  with the README's "run anywhere" goal, and nftables deepens that.

---

## Cross-cutting

**New dependencies:** `hickory-server` (DNS). The TCP proxy needs only `tokio`, already
present. Phase 7 shells out to `nft`.

**Portability.** `wireguard.rs` is already Unix-only (`std::os::unix::fs::PermissionsExt`)
and shells out to `wg`/`wg-quick` as root. The desktop client's privileged path is macOS-only
(`osascript`). This plan does not worsen that, and the userspace-proxy choice deliberately
avoids making it worse, but the gap against "run anywhere" should be acknowledged in the
README rather than left implicit.

**Config reload.** Resolver zones, service IP allocations and policy results all derive
from `CONFIG_VALUE`. Each phase must define what happens on reload; the re-evaluation loop
from Phase 1 is the natural place to hang this.

**Testing.** Unit-test allocation, CIDR parsing and policy derivation directly. Integration
needs two netns-separated WireGuard instances to exercise the chain; worth building in
Phase 1 since every later phase depends on it.

## Open questions

1. Should `[hostname.*]` entries be tunnel-reachable by default, or opt-in? Default-on is
   more useful; default-off is safer for anything whose `proxy_to` resolves publicly.
   Leaning default-on **only** when the destination is private, with explicit opt-in otherwise.
2. Does per-path policy need to differ (public with MFA vs. tunnel with device identity),
   or is `wireguard_only` enough for v1? Leaning the latter.
3. ~~Does the resolver forward unmatched queries upstream, or refuse?~~ **Resolved: both.**
   Refusing alone is not viable — `wg-quick`'s `DNS=` replaces the client's resolver, so a
   refuse-only resolver leaves peers with no working DNS at all. Guard forwards when
   `dns_upstream` is set, refuses when it is not, and only advertises itself to clients in
   the former case, so the unusable combination never reaches a device.
