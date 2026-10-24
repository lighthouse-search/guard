//! WireGuard interface + peer management.
//!
//! Guard owns the whole WireGuard server lifecycle on its host:
//!
//!   * On startup ([`ensure_interface`]) it generates and persists the server
//!     private key (once), writes the interface config, brings the interface up,
//!     derives its own public key, and restores every peer it knows about from
//!     the database — so the operator configures nothing by hand.
//!   * At runtime ([`apply_peer`]) it adds peers *live* with `wg set` (no tunnel
//!     downtime) and persists them with `wg-quick save`.
//!
//! Everything shells out to `wg` / `wg-quick`, so Guard must run on the
//! WireGuard host with permission to manage the interface (root / CAP_NET_ADMIN).

use std::collections::HashSet;
use std::io::Write;
use std::net::Ipv4Addr;
use std::process::Stdio;

use once_cell::sync::OnceCell;
use tokio::process::Command;

use crate::device::device_list_wireguard_peers;
use crate::structs::ConfigWireguard;
use crate::CONFIG_VALUE;

/// The server's WireGuard public key, derived once at startup from the key Guard
/// manages and returned to clients during registration.
static SERVER_PUBLIC_KEY: OnceCell<String> = OnceCell::new();

const DEFAULT_LISTEN_PORT: u16 = 51820;

/// The [wireguard] config, or an error if the feature isn't configured.
pub fn config() -> Result<ConfigWireguard, String> {
    CONFIG_VALUE
        .wireguard
        .clone()
        .ok_or_else(|| "WireGuard is not configured (missing [wireguard]).".to_string())
}

/// The server public key returned to clients. Prefers the key Guard derived from
/// the interface it manages; falls back to a configured override.
pub fn server_public_key() -> Option<String> {
    SERVER_PUBLIC_KEY
        .get()
        .cloned()
        .or_else(|| CONFIG_VALUE.wireguard.clone().and_then(|wg| wg.server_public_key))
}

fn interface_name(wg: &ConfigWireguard) -> Result<String, String> {
    wg.interface.clone().ok_or_else(|| "[wireguard].interface is not configured.".to_string())
}

fn key_path(wg: &ConfigWireguard, interface: &str) -> String {
    wg.key_path.clone().unwrap_or_else(|| format!("/etc/wireguard/{}.key", interface))
}

fn conf_path(interface: &str) -> String {
    format!("/etc/wireguard/{}.conf", interface)
}

/// Bring the WireGuard interface up (creating it, its key, and its config on
/// first run) and restore all known peers. Idempotent: safe to call on every
/// startup, whether or not the interface is already up.
pub async fn ensure_interface() -> Result<(), String> {
    // Guard drives WireGuard through `wg`/`wg-quick` and stores its key with a
    // Unix file mode. Neither applies elsewhere, so say so once and clearly
    // rather than failing later on a missing binary or an unsettable
    // permission.
    if cfg!(unix) == false {
        return Err("WireGuard is only supported on Unix hosts: Guard manages the interface with \
                    'wg'/'wg-quick' and protects its key with a Unix file mode."
            .to_string());
    }

    let wg = config()?;
    let interface = interface_name(&wg)?;

    let peer_subnet = wg.peer_subnet.clone().ok_or_else(|| "[wireguard].peer_subnet is not configured.".to_string())?;
    let server_address = wg.server_address.clone().ok_or_else(|| "[wireguard].server_address is not configured.".to_string())?;

    // Persisted server key — generated once, reused thereafter so the server
    // public key stays stable across restarts.
    let private_key = load_or_create_server_key(&wg, &interface)?;
    let public_key = wg_pubkey(&private_key)?;

    // Build the full interface config from the stored key + every peer we know
    // about, so the running interface matches Guard's database.
    let peers = device_list_wireguard_peers().await.map_err(|error| format!("Failed to list WireGuard peers: {}", error))?;
    let listen_port = wg.listen_port.unwrap_or(DEFAULT_LISTEN_PORT);
    let prefix = subnet_prefix(&peer_subnet)?;
    let conf = build_conf(&private_key, &server_address, prefix, listen_port, &peers);

    let conf_path = conf_path(&interface);
    write_private_file(&conf_path, &conf)?;

    if interface_is_up(&interface).await {
        // Already up — apply the regenerated config without downtime.
        sync_conf(&interface, &conf_path).await?;
    } else {
        run("wg-quick", &["up", &interface]).await?;
    }

    let _ = SERVER_PUBLIC_KEY.set(public_key);
    log::info!("WireGuard interface '{}' is up with {} peer(s).", interface, peers.len());
    Ok(())
}

/// Add (or update) a peer on the live interface and persist it to the config
/// file. `allowed_ip` is the peer's assigned tunnel address (a /32 route).
pub async fn apply_peer(interface: &str, public_key: &str, allowed_ip: &str) -> Result<(), String> {
    // Apply live — no tunnel restart, existing peers stay connected.
    run("wg", &["set", interface, "peer", public_key, "allowed-ips", &format!("{}/32", allowed_ip)]).await?;
    // Persist the running config so the peer survives a restart.
    run("wg-quick", &["save", interface]).await?;
    Ok(())
}

/// Build a wg-quick interface config from the server key + peers.
fn build_conf(private_key: &str, server_address: &str, prefix: u32, listen_port: u16, peers: &[(String, String)]) -> String {
    let mut conf = String::from("[Interface]\n");
    conf.push_str(&format!("PrivateKey = {}\n", private_key));
    conf.push_str(&format!("Address = {}/{}\n", server_address, prefix));
    conf.push_str(&format!("ListenPort = {}\n", listen_port));
    for (public_key, ip) in peers {
        conf.push_str("\n[Peer]\n");
        conf.push_str(&format!("PublicKey = {}\n", public_key));
        conf.push_str(&format!("AllowedIPs = {}/32\n", ip));
    }
    conf
}

/// Apply a changed config to a running interface without downtime:
/// `wg syncconf <iface> <(wg-quick strip <iface>)>`, done without a shell.
async fn sync_conf(interface: &str, conf_path: &str) -> Result<(), String> {
    let stripped = Command::new("wg-quick")
        .args(["strip", conf_path])
        .output()
        .await
        .map_err(|error| format!("Failed to run 'wg-quick strip': {}", error))?;
    if stripped.status.success() == false {
        return Err(format!("'wg-quick strip' failed: {}", String::from_utf8_lossy(&stripped.stderr).trim()));
    }

    // wg syncconf needs a file path, not stdin — stage the stripped config.
    let stripped_path = format!("{}.stripped", conf_path);
    write_private_file(&stripped_path, &String::from_utf8_lossy(&stripped.stdout))?;
    let result = run("wg", &["syncconf", interface, &stripped_path]).await;
    let _ = std::fs::remove_file(&stripped_path);
    result
}

/// Read the persisted server private key, generating and storing it on first run.
fn load_or_create_server_key(wg: &ConfigWireguard, interface: &str) -> Result<String, String> {
    let path = key_path(wg, interface);
    match std::fs::read_to_string(&path) {
        Ok(key) if key.trim().is_empty() == false => Ok(key.trim().to_string()),
        _ => {
            let key = wg_genkey()?;
            write_private_file(&path, &format!("{}\n", key))?;
            Ok(key)
        }
    }
}

/// Write a file 0600, creating parent dirs. Used for anything holding key material.
fn write_private_file(path: &str, contents: &str) -> Result<(), String> {
    if let Some(parent) = std::path::Path::new(path).parent() {
        std::fs::create_dir_all(parent).map_err(|error| format!("Could not create '{}': {}", parent.display(), error))?;
    }
    std::fs::write(path, contents).map_err(|error| format!("Could not write '{}': {}", path, error))?;
    restrict_to_owner(path)
}

/// Restrict a file to its owner.
#[cfg(unix)]
fn restrict_to_owner(path: &str) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("Could not set permissions on '{}': {}", path, error))
}

/// Non-Unix has no mode to set — `PermissionsExt` does not exist there and the
/// Windows equivalent is an ACL edit. Refuse rather than leave key material at
/// whatever the inherited ACL happens to be. `ensure_interface` should have
/// stopped before reaching here, so this is a backstop; the `cfg` is what lets
/// the crate compile for the Windows release build.
#[cfg(not(unix))]
fn restrict_to_owner(path: &str) -> Result<(), String> {
    Err(format!(
        "Refusing to write '{}': Guard cannot restrict file permissions on this platform, and this \
         file holds WireGuard key material.",
        path
    ))
}

/// Is the interface currently up? `wg show <iface>` succeeds only when it exists.
async fn interface_is_up(interface: &str) -> bool {
    Command::new("wg")
        .args(["show", interface])
        .output()
        .await
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// `wg genkey` — a new base64 private key.
fn wg_genkey() -> Result<String, String> {
    let output = std::process::Command::new("wg")
        .arg("genkey")
        .output()
        .map_err(|error| format!("Could not run 'wg genkey' (is WireGuard installed?): {}", error))?;
    if output.status.success() == false {
        return Err(format!("'wg genkey' failed: {}", String::from_utf8_lossy(&output.stderr).trim()));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// `wg pubkey` — derive the public key from a private key fed on stdin.
fn wg_pubkey(private_key: &str) -> Result<String, String> {
    let mut child = std::process::Command::new("wg")
        .arg("pubkey")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("Could not run 'wg pubkey': {}", error))?;

    let mut stdin = child.stdin.take().ok_or_else(|| "Failed to open 'wg pubkey' stdin.".to_string())?;
    stdin.write_all(private_key.as_bytes()).map_err(|error| format!("Failed to write to 'wg pubkey': {}", error))?;
    drop(stdin);

    let output = child.wait_with_output().map_err(|error| format!("Failed to read 'wg pubkey' output: {}", error))?;
    if output.status.success() == false {
        return Err(format!("'wg pubkey' failed: {}", String::from_utf8_lossy(&output.stderr).trim()));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Run a `wg`/`wg-quick` command, mapping a non-zero exit to an error.
async fn run(program: &str, args: &[&str]) -> Result<(), String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .await
        .map_err(|error| format!("Failed to run '{}' (is WireGuard installed and is Guard permitted to run it?): {}", program, error))?;
    if output.status.success() == false {
        return Err(format!("'{} {}' failed: {}", program, args.join(" "), String::from_utf8_lossy(&output.stderr).trim()));
    }
    Ok(())
}

/// The prefix length ("/24") of a CIDR, used for the interface Address.
fn subnet_prefix(cidr: &str) -> Result<u32, String> {
    let (_, prefix) = parse_cidr(cidr)?;
    Ok(prefix)
}

/// Parse an IPv4 CIDR ("a.b.c.d/n") into (address bits, prefix length).
fn parse_cidr(cidr: &str) -> Result<(u32, u32), String> {
    let (addr, prefix) = cidr
        .split_once('/')
        .ok_or_else(|| format!("peer_subnet '{}' is not CIDR notation.", cidr))?;
    let ip: Ipv4Addr = addr
        .parse()
        .map_err(|_| format!("peer_subnet '{}' has an invalid address.", cidr))?;
    let prefix: u32 = prefix
        .parse()
        .map_err(|_| format!("peer_subnet '{}' has an invalid prefix.", cidr))?;
    if prefix > 32 {
        return Err(format!("peer_subnet '{}' prefix is out of range.", cidr));
    }
    Ok((u32::from(ip), prefix))
}

/// Allocate the next free host address in `peer_subnet`, skipping the network
/// and broadcast addresses, the server's own tunnel address, and anything
/// already handed out to another device.
pub fn allocate_ip(peer_subnet: &str, server_address: Option<&str>, used: &[String]) -> Result<String, String> {
    let (base, prefix) = parse_cidr(peer_subnet)?;
    // Shifting a u32 by 32 is UB in Rust, so handle the /0 case explicitly.
    let mask: u32 = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    let network = base & mask;
    let broadcast = network | !mask;

    let server: Option<u32> = match server_address {
        Some(addr) => Some(u32::from(
            addr.parse::<Ipv4Addr>()
                .map_err(|_| format!("server_address '{}' is invalid.", addr))?,
        )),
        None => None,
    };
    let used_ints: HashSet<u32> = used
        .iter()
        .filter_map(|ip| ip.parse::<Ipv4Addr>().ok())
        .map(u32::from)
        .collect();

    // Usable host addresses are (network, broadcast) exclusive.
    let mut candidate = network.wrapping_add(1);
    while candidate < broadcast {
        if Some(candidate) != server && used_ints.contains(&candidate) == false {
            return Ok(Ipv4Addr::from(candidate).to_string());
        }
        candidate += 1;
    }
    Err(format!("No free addresses left in peer_subnet '{}'.", peer_subnet))
}
