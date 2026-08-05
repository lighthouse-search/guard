import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import {
  faShieldHalved,
  faArrowRight,
  faSpinner,
} from "@fortawesome/free-solid-svg-icons";
import "./Login.css";

export type Session = {
  email: string;
  host: string;
  token: string | null;
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

  // Held in refs so the (once-registered) callback listener reads fresh values.
  const expectedState = useRef<string | null>(null);
  const emailRef = useRef("");
  const hostRef = useRef("");

  // The auth web page deep-links back as `guard://…?state=…&token=…`, which
  // the Rust side forwards to us as an `auth-callback` event.
  useEffect(() => {
    const unlisten = listen<string>("auth-callback", (event) => {
      try {
        const url = new URL(event.payload);
        const state = url.searchParams.get("state");
        if (!expectedState.current || state !== expectedState.current) {
          return; // not the request we started
        }
        onAuthenticated({
          email: emailRef.current,
          host: hostRef.current,
          token: url.searchParams.get("token"),
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

  async function beginAuth(target: string) {
    setError("");
    setPhase("discovering");
    emailRef.current = target;
    try {
      const found = await invoke<GuardInstance>("discover_guard_instance", {
        email: target,
      });
      setInstance(found);
      hostRef.current = found.host;

      const start = await invoke<DeviceAuthStart>(
        "start_device_authentication",
        { host: found.host },
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
    beginAuth(target);
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
              onClick={() => hostRef.current && beginAuth(emailRef.current)}
            >
              Reopen browser
            </button>
            <button className="link-button" onClick={reset}>
              Use a different email
            </button>
          </div>
        </>
      ) : (
        <>
          <p className="login-sub">
            Enter your work email and we'll find your organization's Guard
            instance.
          </p>
          <form className="login-form" onSubmit={onSubmit}>
            <input
              className="login-input"
              type="email"
              inputMode="email"
              autoFocus
              placeholder="you@company.com"
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
          {phase === "error" && <p className="login-error">{error}</p>}
        </>
      )}

      {/* <footer className="footer login-footer">
        <span className="footer-hint">Guard</span>
      </footer> */}
    </main>
  );
}
