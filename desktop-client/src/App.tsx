import { useState } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faCircle, faCheck, faGear } from "@fortawesome/free-solid-svg-icons";
import Login, { Session } from "./Login";
import "./App.css";

type Status = "disconnected" | "connecting" | "connected";

// Placeholder tunnel data — wire this up to the WireGuard backend later.
const TUNNEL = {
  name: "Company Limited",
  endpoint: "guard.example.com",
  address: "10.8.0.4/32",
  ping: 27
};

function App() {
  const [session, setSession] = useState<Session | null>(null);
  const [status, setStatus] = useState<Status>("disconnected");

  const isBusy = status === "connecting";
  const isConnected = status === "connected";

  if (!session) {
    return <Login onAuthenticated={setSession} />;
  }

  const greetingName = session.email.split("@")[0] || "there";

  function toggle() {
    if (isBusy) return;
    if (isConnected) {
      setStatus("disconnected");
      return;
    }
    // Simulated connect handshake — replace with `invoke("connect", …)`.
    setStatus("connecting");
    setTimeout(() => setStatus("connected"), 900);
  }

  const statusLabel =
    status === "connected"
      ? "Connected"
      : status === "connecting"
        ? "Connecting…"
        : "Disconnected";

  return (
    <main className="popover">
      <header className="header">
        <div className="brand">
          {/* <span className="brand-mark" aria-hidden="true" /> */}
          <span className="brand-name">Hey, {greetingName}!</span>
        </div>

        <div className="flex">
          <span className={`pill pill--${status}`}>{statusLabel}</span>
          <button className="icon-button" aria-label="Settings">
            <FontAwesomeIcon icon={faGear} />
          </button>
        </div>
      </header>

      <section className={`shield shield--${status}`}>
        <div className="shield-icon" aria-hidden="true">
          {isConnected ? (
            <span className="check-badge">
              <FontAwesomeIcon icon={faCircle} className="check-badge-disc" />
              <FontAwesomeIcon icon={faCheck} className="check-badge-tick" />
            </span>
          ) : (
            <FontAwesomeIcon icon={faCircle} />
          )}
        </div>
        <p className="shield-title">
          {isConnected ? "Connected" : "Not connected"}
        </p>
        <p className="shield-sub">
          {isConnected
            ? "Everything looks good!"
            : "Internal applications may be unavailable."}
        </p>
      </section>

      <button
        className={`toggle ${isConnected ? "toggle--on" : ""}`}
        onClick={toggle}
        disabled={isBusy}
      >
        {isConnected ? "Disconnect" : isBusy ? "Connecting…" : "Connect"}
      </button>

      <section className="tunnel">
        <div className="tunnel-row">
          <span className="tunnel-key">Tunnel</span>
          <span className="tunnel-val">{TUNNEL.name}</span>
        </div>
        <div className="tunnel-row">
          <span className="tunnel-key">Endpoint</span>
          <span className="tunnel-val">{TUNNEL.endpoint}</span>
        </div>
        <div className="tunnel-row">
          <span className="tunnel-key">Address</span>
          <span className="tunnel-val">{TUNNEL.address}</span>
        </div>
        <div className="tunnel-row">
          <span className="tunnel-key">Ping</span>
          <span className="tunnel-val">{TUNNEL.ping} ms</span>
        </div>
      </section>

      <footer className="footer">
        <span className="footer-hint">Guard</span>
      </footer>
    </main>
  );
}

export default App;
