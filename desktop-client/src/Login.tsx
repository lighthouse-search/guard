import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faArrowRight, faSpinner } from "@fortawesome/free-solid-svg-icons";
import "./Login.css";

export type Session = {
  email: string;
  host: string;
  deviceId: string | null;
};

type GuardInstance = { host: string; email_domain: string };
type DeviceAuthStart = { state: string; url: string };
type Phase = "email" | "discovering" | "awaiting" | "error";

export default function Login({
  onAuthenticated,
}: {
  onAuthenticated: (session: Session) => void;
}) {
  const [email, setEmail] = useState("");
  const [phase, setPhase] = useState<Phase>("email");
  const [error, setError] = useState("");
  const [instance, setInstance] = useState<GuardInstance | null>(null);
  // Manual mode: the user types the Guard address directly instead of having it
  // discovered from their email domain.
  const [manual, setManual] = useState(false);
  // Optional separate API address for dev, where the frontend (the page host)
  // and API run on different addresses. Empty means "same as the address above".
  const [manualApi, setManualApi] = useState("");

  // Held in refs so the (once-registered) callback listener reads fresh values.
  const expectedState = useRef<string | null>(null);
  const emailRef = useRef("");
  const hostRef = useRef(""); // API host — used for enroll + as the session host.
  const pageHostRef = useRef(""); // host the auth page is opened on.

  // The auth web page deep-links back as `guard://…?state=…&setup_token=…`,
  // which the Rust side forwards as an `auth-callback` event. We exchange the
  // one-time setup token for an enrollment (posting our own public key).
  useEffect(() => {
    const unlisten = listen<string>("auth-callback", (event) => {
      try {
        const url = new URL(event.payload);
        const state = url.searchParams.get("state");
        if (!expectedState.current || state !== expectedState.current) {
          return; // not the request we started (or already handled)
        }
        // Handle each state exactly once: the setup token is single-use, so a
        // duplicate callback would fail with "invalid/expired token" and clobber
        // the successful result.
        expectedState.current = null;
        const setupToken = url.searchParams.get("setup_token");
        if (!setupToken) {
          setError("Authorization callback was missing its setup token.");
          setPhase("error");
          return;
        }
        invoke<string>("enroll_device", { host: hostRef.current, setupToken })
          .then((deviceId) => {
            onAuthenticated({
              email: emailRef.current,
              host: hostRef.current,
              deviceId,
            });
          })
          .catch((err) => {
            setError(typeof err === "string" ? err : "Enrollment failed.");
            setPhase("error");
          });
      } catch {
        // ignore malformed callback URLs
      }
    });
    return () => {
      unlisten.then((f) => f());
    };
  }, [onAuthenticated]);

  const busy = phase === "discovering" || phase === "awaiting";

  // Strip scheme/path so a pasted URL becomes a bare host (guard.example.com).
  function normalizeHost(input: string) {
    return input
      .trim()
      .replace(/^https?:\/\//i, "")
      .replace(/\/.*$/, "");
  }

  async function beginAuth(target: string, isManual: boolean) {
    setError("");
    setPhase("discovering");
    try {
      let pageHost: string;
      let apiHost: string;
      if (isManual) {
        // The user typed the Guard address directly — no DNS discovery.
        pageHost = normalizeHost(target);
        // In dev the API may live on a different host than the page.
        apiHost = manualApi.trim() ? normalizeHost(manualApi) : pageHost;
        emailRef.current = "";
        setInstance({ host: apiHost, email_domain: apiHost });
      } else {
        emailRef.current = target;
        const found = await invoke<GuardInstance>("discover_guard_instance", {
          email: target,
        });
        setInstance(found);
        // A discovered instance serves both the page and the API.
        pageHost = found.host;
        apiHost = found.host;
      }
      hostRef.current = apiHost;
      pageHostRef.current = pageHost;

      const start = await invoke<DeviceAuthStart>(
        "start_device_authentication",
        { pageHost, apiHost },
      );
      expectedState.current = start.state;
      setPhase("awaiting");
    } catch (err) {
      setError(typeof err === "string" ? err : "Something went wrong.");
      setPhase("error");
    }
  }

  function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    const target = email.trim();
    if (!target || busy) return;
    beginAuth(target, manual);
  }

  function toggleManual() {
    setManual((m) => !m);
    setEmail("");
    setManualApi("");
    setError("");
  }

  function reset() {
    expectedState.current = null;
    setInstance(null);
    setPhase("email");
    setError("");
  }

  return (
    <main className="popover login">
      {/* <div className="login-logo" aria-hidden="true">
        <FontAwesomeIcon icon={faShieldHalved} />
      </div> */}
      <h1 className="login-title">Sign in to Guard</h1>

      {phase === "awaiting" ? (
        <>
          <p className="login-sub">
            Continue in your browser to finish signing in, then return here.
          </p>
          {instance && <p className="login-host mono">{instance.host}</p>}
          <div className="login-waiting">
            <FontAwesomeIcon icon={faSpinner} spin /> Waiting for authorization…
          </div>
          <div className="login-actions">
            <button
              className="link-button"
              onClick={() =>
                hostRef.current &&
                beginAuth(manual ? pageHostRef.current : emailRef.current, manual)
              }
            >
              Reopen browser
            </button>
            <button className="link-button" onClick={reset}>
              {manual ? "Use a different address" : "Use a different email"}
            </button>
          </div>
        </>
      ) : (
        <>
          <p className="login-sub">
            {manual
              ? "Enter your organization's Guard address."
              : "Enter your work email and we'll find your organization's Guard instance."}
          </p>
          <form className="login-form" onSubmit={onSubmit}>
            <input
              className="login-input"
              type={manual ? "text" : "email"}
              inputMode={manual ? "url" : "email"}
              autoFocus
              autoCapitalize="off"
              autoCorrect="off"
              placeholder={manual ? "guard.company.com" : "you@company.com"}
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              disabled={phase === "discovering"}
            />
            <button
              className="login-submit"
              type="submit"
              disabled={!email.trim() || phase === "discovering"}
            >
              {phase === "discovering" ? (
                <FontAwesomeIcon icon={faSpinner} spin />
              ) : (
                <FontAwesomeIcon icon={faArrowRight} />
              )}
            </button>
          </form>
          {manual && (
            <input
              className="login-input login-input--api"
              type="text"
              inputMode="url"
              autoCapitalize="off"
              autoCorrect="off"
              placeholder="API address (optional)"
              value={manualApi}
              onChange={(e) => setManualApi(e.target.value)}
              disabled={phase === "discovering"}
            />
          )}
          <button type="button" className="login-hint" onClick={toggleManual}>
            {manual ? "Use email instead" : "Enter Guard address"}
          </button>
          {phase === "error" && <p className="login-error">{error}</p>}
        </>
      )}

      {/* <footer className="footer login-footer">
        <span className="footer-hint">Guard</span>
      </footer> */}
    </main>
  );
}
