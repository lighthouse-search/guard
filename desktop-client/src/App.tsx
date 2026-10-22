import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import {
  faCircle,
  faCheck,
  faGear,
  faChevronLeft,
} from "@fortawesome/free-solid-svg-icons";
import Login, { Session } from "./Login";
import "./App.css";

type Status = "disconnected" | "connecting" | "connected" | "disconnecting";
type View = "dashboard" | "settings";

// Tunnel parameters Guard returns from WireGuard registration.
type Registration = {
  address: string | null;
  server_public_key: string | null;
  server_address: string | null;
  endpoint: string | null;
  allowed_ips: string | null;
  dns: string | null;
  persistent_keepalive: number | null;
};

function App() {
  const [session, setSession] = useState<Session | null>(null);
  const [status, setStatus] = useState<Status>("disconnected");
  const [view, setView] = useState<View>("dashboard");
  const [registration, setRegistration] = useState<Registration | null>(null);
  const [ping, setPing] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  const isBusy = status === "connecting" || status === "disconnecting";
  const isConnected = status === "connected";

  // Fetch tunnel parameters up front (idempotent registration) so the dashboard
  // shows accurate endpoint/address before the user connects.
  const host = session?.host;
  const deviceId = session?.deviceId ?? null;
  useEffect(() => {
    if (!host || !deviceId) return;
    let active = true;
    invoke<Registration>("register_wireguard", { host, deviceId })
      .then((reg) => { if (active) setRegistration(reg); })
      .catch(() => { /* leave info blank; surfaced on connect if it really fails */ });
    return () => { active = false; };
  }, [host, deviceId]);

  // While connected, poll the in-tunnel gateway for a live ping.
  const gateway = registration?.server_address ?? null;
  useEffect(() => {
    if (status !== "connected") return;
    let active = true;
    async function poll() {
      try {
        const s = await invoke<{ connected: boolean; ping_ms: number | null }>(
          "wireguard_status",
          { gateway },
        );
        if (active) setPing(s.ping_ms);
      } catch {
        if (active) setPing(null);
      }
    }
    poll();
    const id = setInterval(poll, 5000);
    return () => { active = false; clearInterval(id); };
  }, [status, gateway]);

  if (!session) {
    return <Login onAuthenticated={setSession} />;
  }

  const greetingName = session.email.split("@")[0] || "there";

  async function logout() {
    // Forget the device key so the next sign-in enrolls fresh.
    try {
      await invoke("logout");
    } catch {
      // Best effort — sign out locally regardless.
    }
    // Best effort: drop the tunnel before forgetting the session.
    try {
      await invoke("wireguard_disconnect");
    } catch {
      // ignore
    }
    setStatus("disconnected");
    setRegistration(null);
    setPing(null);
    setError(null);
    setView("dashboard");
    setSession(null);
  }

  if (view === "settings") {
    return (
      <main className="popover">
        <header className="header">
          <div className="brand">
            <button
              className="icon-button"
              aria-label="Back"
              onClick={() => setView("dashboard")}
            >
              <FontAwesomeIcon icon={faChevronLeft} />
            </button>
            <span className="brand-name">Settings</span>
          </div>
        </header>

        <section className="tunnel">
          <div className="tunnel-row">
            <span className="tunnel-key">Account</span>
            <span className="tunnel-val">{session.email || "—"}</span>
          </div>
          <div className="tunnel-row">
            <span className="tunnel-key">Instance</span>
            <span className="tunnel-val mono">{session.host}</span>
          </div>
          <div className="tunnel-row">
            <span className="tunnel-key">Device</span>
            <span className="tunnel-val mono">{session.deviceId ?? "—"}</span>
          </div>
        </section>

        <button className="toggle toggle--on" onClick={logout}>
          Log out
        </button>

        <footer className="footer">
          <span className="footer-hint">Guard</span>
        </footer>
      </main>
    );
  }

  async function toggle() {
    if (isBusy) return;
    setError(null);

    if (isConnected) {
      setStatus("disconnecting");
      try {
        await invoke("wireguard_disconnect");
        setStatus("disconnected");
        setPing(null);
      } catch (e) {
        // Still up — surface why it wouldn't come down.
        setError(String(e));
        setStatus("connected");
      }
      return;
    }

    if (!session!.deviceId) {
      setError("This device isn't enrolled yet — sign in again.");
      return;
    }
    setStatus("connecting");
    try {
      const reg = await invoke<Registration>("wireguard_connect", {
        host: session!.host,
        deviceId: session!.deviceId,
      });
      setRegistration(reg);
      setStatus("connected");
    } catch (e) {
      setError(String(e));
      setStatus("disconnected");
    }
  }

  const statusLabel =
    status === "connected"
      ? "Connected"
      : status === "connecting"
        ? "Connecting…"
        : status === "disconnecting"
          ? "Disconnecting…"
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
          <button
            className="icon-button"
            aria-label="Settings"
            onClick={() => setView("settings")}
          >
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
          {error
            ? error
            : isConnected
              ? "Everything looks good!"
              : "Internal applications may be unavailable."}
        </p>
      </section>

      <button
        className={`toggle ${isConnected ? "toggle--on" : ""}`}
        onClick={toggle}
        disabled={isBusy}
      >
        {status === "connected"
          ? "Disconnect"
          : status === "connecting"
            ? "Connecting…"
            : status === "disconnecting"
              ? "Disconnecting…"
              : "Connect"}
      </button>

      <section className="tunnel">
        <div className="tunnel-row">
          <span className="tunnel-key">Tunnel</span>
          <span className="tunnel-val mono">{session.host}</span>
        </div>
        <div className="tunnel-row">
          <span className="tunnel-key">Endpoint</span>
          <span className="tunnel-val">{registration?.endpoint ?? "—"}</span>
        </div>
        <div className="tunnel-row">
          <span className="tunnel-key">Address</span>
          <span className="tunnel-val mono">
            {registration?.address ? `${registration.address}/32` : "—"}
          </span>
        </div>
        <div className="tunnel-row">
          <span className="tunnel-key">Ping</span>
          <span className="tunnel-val">
            {isConnected && ping !== null ? `${ping} ms` : "—"}
          </span>
        </div>
      </section>

      <footer className="footer">
        <span className="footer-hint">Guard</span>
      </footer>
    </main>
  );
}

export default App;
