//! Loopback callback server.
//!
//! An alternative to the `guard://` deep link. macOS only registers a custom
//! URL scheme for a *bundled* app, so deep links don't fire under `tauri dev`.
//! Instead the auth web page can redirect to a tiny HTTP server we run on
//! 127.0.0.1 — bound to loopback only, so it isn't reachable off-machine. Both
//! paths emit the same `auth-callback` event, so the frontend treats them
//! identically. The deep link remains available as an option.

use tauri::{AppHandle, Emitter};

/// Managed state holding the port the callback server bound to.
pub struct CallbackServer {
    pub port: u16,
}

const DONE_HTML: &str = "<!doctype html><html><head><meta charset=\"utf-8\">\
<title>Guard</title></head><body style=\"font-family:-apple-system,system-ui,\
sans-serif;background:#1e1e20;color:#f5f5f7;display:flex;align-items:center;\
justify-content:center;height:100vh;margin:0\"><div style=\"text-align:center\">\
<h2>You're all set</h2><p>You can return to the Guard app and close this tab.</p>\
</div></body></html>";

/// Start the loopback callback server on an ephemeral port. Returns the port.
/// Requests to `/callback…` are forwarded to the frontend as an `auth-callback`
/// event (same payload shape as the deep link) and answered with a done page.
pub fn start(app: AppHandle) -> Result<u16, String> {
    let server = tiny_http::Server::http("127.0.0.1:0")
        .map_err(|e| format!("Could not start callback server: {e}"))?;
    let port = server
        .server_addr()
        .to_ip()
        .map(|addr| addr.port())
        .ok_or_else(|| "Callback server has no port".to_string())?;

    std::thread::spawn(move || {
        for request in server.incoming_requests() {
            let raw = request.url().to_string();
            if raw.starts_with("/callback") {
                // Reconstruct a full URL so the frontend can parse the query
                // (mirrors the `guard://auth-callback?…` deep-link payload).
                let full = format!("http://127.0.0.1:{port}{raw}");
                let _ = app.emit("auth-callback", full);

                let header = tiny_http::Header::from_bytes(
                    &b"Content-Type"[..],
                    &b"text/html; charset=utf-8"[..],
                )
                .expect("valid content-type header");
                let response =
                    tiny_http::Response::from_string(DONE_HTML).with_header(header);
                let _ = request.respond(response);
            } else {
                let _ = request.respond(tiny_http::Response::empty(404));
            }
        }
    });

    Ok(port)
}
