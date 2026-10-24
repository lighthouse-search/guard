//! WireGuard interface + peer management.
//!
//! Guard owns the whole WireGuard server lifecycle on its host:
//!
//!   * On startup ([`ensure_interface`]) it generates and persists the server
//!     private key (once), writes the interface config, brings the interface up,
//!     derives its own public key, and restores every peer it knows about from
//!     the database — so the operator configures nothing by hand.
//!   * At runtime ([`reconcile`]) it makes the live interface match the database
//!     exactly — adding peers that are missing and removing peers that are no
//!     longer authorised — live with `wg set`, so there is no tunnel downtime.
//!
//! The database is the single source of truth for peers. The on-disk config is
//! always regenerated from it, never read back: `wg-quick save` is deliberately
//! not used, because it writes the *running* config over the file and would both
//! fight the regeneration and strip anything Guard renders into it.
//!
//! Everything shells out to `wg` / `wg-quick`, so Guard must run on the
//! WireGuard host with permission to manage the interface (root / CAP_NET_ADMIN).

use std::collections::HashSet;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::process::Stdio;

use once_cell::sync::OnceCell;
use tokio::process::Command;

use crate::device::{device_clear_wireguard, device_list_wireguard_peers, device_list_wireguard_registered};
use crate::policy::{policy_authentication, resolve_policies};
use crate::structs::{ConfigWireguard, ConfigWireguardSite, GuardDevices};
use crate::users::user_get;
use crate::CONFIG_VALUE;

/// The server's WireGuard public key, derived once at startup from the key Guard
/// manages and returned to clients during registration.
static SERVER_PUBLIC_KEY: OnceCell<String> = OnceCell::new();

const DEFAULT_LISTEN_PORT: u16 = 51820;

/// How often every registered peer is re-checked against policy, when
/// `[wireguard].reevaluation_interval_secs` is unset.
const DEFAULT_REEVALUATION_INTERVAL_SECS: u64 = 60;

/// Keepalive for a site peer with no fixed `endpoint`. Such a site is behind
/// NAT and dials out, so something has to hold the mapping open.
const DEFAULT_SITE_KEEPALIVE_SECS: u32 = 25;

/// A site is considered down after this many missed keepalive intervals.
const SITE_HANDSHAKE_GRACE_INTERVALS: u64 = 3;

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

/// A downstream WireGuard instance Guard chains through, resolved from config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SitePeer {
    pub name: String,
    pub public_key: String,
    /// Networks behind this site. Become the peer's `AllowedIPs`, which is what
    /// gives Guard a route into them.
    pub subnets: Vec<String>,
    pub endpoint: Option<String>,
    pub persistent_keepalive: Option<u32>,
}

impl SitePeer {
    /// Keepalive to write. A site with no fixed endpoint dialled out to reach
    /// Guard and is almost certainly behind NAT, so it needs one whether or not
    /// the operator thought to set it.
    fn keepalive(&self) -> Option<u32> {
        match (self.persistent_keepalive, &self.endpoint) {
            (Some(explicit), _) => Some(explicit),
            (None, None) => Some(DEFAULT_SITE_KEEPALIVE_SECS),
            (None, Some(_)) => None,
        }
    }
}

/// Active, well-formed site peers from `[wireguard.site.*]`.
///
/// Malformed entries are skipped with a warning rather than failing: startup
/// validation already rejects them, so reaching here means config changed
/// underneath us, and dropping one site should not take the others down.
pub fn sites() -> Vec<SitePeer> {
    let configured = match CONFIG_VALUE.wireguard.clone().and_then(|wg| wg.site) {
        Some(sites) => sites,
        None => return Vec::new(),
    };

    let mut sites: Vec<SitePeer> = configured
        .into_iter()
        .filter(|(_, site)| site.active)
        .filter_map(|(name, site)| match resolve_site(&name, &site) {
            Ok(site) => Some(site),
            Err(error) => {
                log::warn!("Ignoring [wireguard.site.{}]: {}", name, error);
                None
            }
        })
        .collect();

    // Config comes from a HashMap, so fix an order — otherwise the generated
    // conf churns between restarts for no reason.
    sites.sort_by(|a, b| a.name.cmp(&b.name));
    sites
}

fn resolve_site(name: &str, site: &ConfigWireguardSite) -> Result<SitePeer, String> {
    let public_key = site
        .public_key
        .clone()
        .filter(|key| key.trim().is_empty() == false)
        .ok_or_else(|| "public_key is required.".to_string())?;
    validate_wireguard_key(&public_key)?;

    let subnets = site.subnets.clone().unwrap_or_default();
    if subnets.is_empty() {
        return Err("subnets is required — without it the site has nothing behind it to route to.".to_string());
    }
    for subnet in &subnets {
        parse_cidr(subnet).map_err(|error| format!("subnet '{}' is invalid: {}", subnet, error))?;
    }

    Ok(SitePeer {
        name: name.to_string(),
        public_key: public_key.trim().to_string(),
        subnets,
        endpoint: site.endpoint.clone().filter(|value| value.trim().is_empty() == false),
        persistent_keepalive: site.persistent_keepalive,
    })
}

/// A WireGuard key is base64 over exactly 32 bytes. Rejecting anything else
/// keeps junk from ever reaching `wg`.
fn validate_wireguard_key(key: &str) -> Result<(), String> {
    use base64::{engine::general_purpose, Engine as _};
    match general_purpose::STANDARD.decode(key.trim()) {
        Ok(bytes) if bytes.len() == 32 => Ok(()),
        _ => Err(format!("'{}' is not a valid WireGuard key (base64, 32 bytes).", key)),
    }
}

/// The policy ids a device's user must satisfy to hold a WireGuard registration.
/// `[wireguard].applied_policies` when set, otherwise the device-authentication
/// policies, so an operator who has already scoped who may enrol a device does
/// not have to restate it.
fn applied_policies(wg: &ConfigWireguard) -> Vec<String> {
    wg.applied_policies
        .clone()
        .or_else(|| CONFIG_VALUE.device_authentication.clone().and_then(|device| device.applied_policies))
        .unwrap_or_default()
}

/// Does this device's user currently satisfy the WireGuard policies?
///
/// Evaluated at registration and again by the revocation loop, so losing access
/// tears an existing tunnel down rather than waiting for the device to
/// reconnect. Deny-by-default throughout: an unresolvable user, a missing
/// policy list, or an error all mean "no tunnel". A tunnel reaches past the
/// HTTPS layer, so it must never be granted because configuration was missing.
pub async fn device_passes_policy(device: &GuardDevices) -> Result<bool, String> {
    let wg = config()?;
    let policy_ids = applied_policies(&wg);
    if policy_ids.is_empty() {
        log::warn!(
            "Denying WireGuard for device '{}': no policies are configured. Set [wireguard].applied_policies \
             (or [device_authentication].applied_policies) to say who may hold a tunnel.",
            device.id
        );
        return Ok(false);
    }

    let user = match user_get(Some(device.user_id.clone()), None).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            log::info!("Denying WireGuard for device '{}': its user no longer exists.", device.id);
            return Ok(false);
        }
        Err(error) => return Err(format!("Could not load the user for device '{}': {}", device.id, error)),
    };

    // Same shape the HTTP pipeline hands the policy engine, so one policy means
    // the same thing whether it is evaluated for a browser request or a tunnel.
    let user_as_value = serde_json::json!({
        "id": user.id,
        "email": user.email
    });

    let policies = resolve_policies(policy_ids, true).await;
    Ok(policy_authentication(policies, user_as_value, device.wireguard_ip.clone().unwrap_or_default()).await)
}

/// The resolver address handed to clients.
///
/// An explicit `[wireguard].dns` always wins. Otherwise Guard advertises itself
/// only when its resolver is both running AND able to forward — because
/// wg-quick's `DNS=` replaces the client's resolver outright, pointing peers at
/// a resolver that refuses everything it does not own would leave them unable
/// to resolve anything else. Better to advertise nothing and let them keep
/// working DNS than to hand out one that breaks the device.
pub fn client_dns(wg: &ConfigWireguard) -> Option<String> {
    if let Some(dns) = wg.dns.clone() {
        return Some(dns);
    }

    let resolver_running = wg.dns_server.unwrap_or(true);
    let can_forward = wg.dns_upstream.as_ref().map(|list| list.is_empty() == false).unwrap_or(false);
    if resolver_running && can_forward {
        return wg.server_address.clone();
    }

    None
}

/// What a client routes into the tunnel (its peer `AllowedIPs`).
///
/// Deliberately the same for every device: `peer_subnet` + `service_subnet`.
/// A device's reachable set is decided by Guard when it answers a connection,
/// not by the device's routing table, so granting or revoking access never
/// requires pushing new client config. The client cannot address backends
/// directly at all — only Guard's tunnel address and the service addresses
/// Guard itself answers on.
///
/// `[wireguard].allowed_ips` remains as an explicit operator override, for
/// cases like a full tunnel ("0.0.0.0/0") where egress should also be captured.
pub fn client_allowed_ips(wg: &ConfigWireguard) -> Option<String> {
    if let Some(override_value) = wg.allowed_ips.clone() {
        return Some(override_value);
    }

    let ranges: Vec<String> = [wg.peer_subnet.clone(), wg.service_subnet.clone()]
        .into_iter()
        .flatten()
        .collect();
    if ranges.is_empty() {
        return None;
    }
    Some(ranges.join(", "))
}

/// Whether a request reached Guard over the WireGuard tunnel or from anywhere
/// else. Controls `wireguard_only` hostnames, so it is a security decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arrival {
    Public,
    Wireguard,
}

/// Classify a request by its source address.
///
/// INTEGRITY — read before relying on this. Guard binds `0.0.0.0`, and
/// axum-server 0.8 hands the service only the peer address (it calls
/// `make_service(socket_addr)` and never exposes the accepted `TcpStream`), so
/// Guard cannot tell which local address a connection landed on and cannot run
/// a second listener bound to the tunnel address on the same port. Arrival is
/// therefore derived from the source address being inside `peer_subnet`.
///
/// What makes that sound, and what it depends on:
///
///   * For TCP, blind spoofing cannot reach here: an attacker forging a source
///     inside `peer_subnet` never sees the SYN-ACK, because it is routed into
///     the tunnel. Completing a handshake requires being on-path.
///   * `rp_filter` must be enabled on the host, so the kernel drops a packet
///     claiming a `peer_subnet` source that arrives on a public interface
///     before Guard ever sees it. [`warn_if_rp_filter_disabled`] checks this at
///     startup; it is a hard requirement, not a nicety.
///   * Nothing else may route `peer_subnet` to this host. A second path into
///     that range (another VPN, a misconfigured route) defeats the check.
///
/// The structural alternative — a dedicated listener bound to the tunnel
/// address, with arrival decided by which socket accepted — needs the public
/// listener bound to explicit addresses rather than `0.0.0.0`, since the two
/// would otherwise collide on the same port. That is the right end state and is
/// tracked in docs/wireguard.md.
pub fn arrival_from(source: IpAddr) -> Arrival {
    let within = config()
        .ok()
        .and_then(|wg| wg.peer_subnet)
        .map(|subnet| ip_in_cidr(source, &subnet))
        .unwrap_or(false);

    // Default to Public: a misconfiguration must not hand out tunnel trust.
    match within {
        true => Arrival::Wireguard,
        false => Arrival::Public,
    }
}

/// Is `ip` inside the IPv4 CIDR `cidr`? IPv6 sources are never considered to be
/// in a (v4) peer subnet.
pub(crate) fn ip_in_cidr(ip: IpAddr, cidr: &str) -> bool {
    let ip = match ip {
        IpAddr::V4(ip) => u32::from(ip),
        // An IPv4-mapped IPv6 source ("::ffff:10.8.0.2") is the same host; a
        // dual-stack listener reports sources in this form, so unwrap it rather
        // than misclassifying a tunnel peer as public.
        IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
            Some(ip) => u32::from(ip),
            None => return false,
        },
    };
    let (base, prefix) = match parse_cidr(cidr) {
        Ok(parsed) => parsed,
        Err(_) => return false,
    };
    let mask: u32 = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    (ip & mask) == (base & mask)
}

/// Is this address in a range the internet cannot route to it?
///
/// Used to refuse to expose tunnel-side services on a public address. Covers
/// RFC1918, CGNAT (RFC6598), link-local and loopback — the ranges a WireGuard
/// tunnel address legitimately comes from.
pub fn is_private_ipv4(ip: Ipv4Addr) -> bool {
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        // 100.64.0.0/10, which plenty of tunnels use.
        || (ip.octets()[0] == 100 && (64..128).contains(&ip.octets()[1]))
}

/// Warn loudly when Linux reverse-path filtering is off, since [`arrival_from`]
/// depends on it to reject spoofed tunnel sources. Not an error: Guard still
/// runs, but an operator using `wireguard_only` needs to know.
pub fn warn_if_rp_filter_disabled() {
    if cfg!(target_os = "linux") == false {
        return;
    }

    // rp_filter is per-interface; "all" is the one that gates the rest.
    let value = std::fs::read_to_string("/proc/sys/net/ipv4/conf/all/rp_filter")
        .ok()
        .map(|value| value.trim().to_string());

    match value.as_deref() {
        Some("1") | Some("2") => {}
        Some("0") => log::error!(
            "net.ipv4.conf.all.rp_filter is 0. Guard decides whether a request arrived over WireGuard \
             from its source address, and without reverse-path filtering the kernel will accept packets \
             that forge a source inside the peer subnet. Set it to 1 before relying on wireguard_only."
        ),
        _ => log::warn!("Could not read net.ipv4.conf.all.rp_filter; ensure reverse-path filtering is enabled."),
    }
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
    let wg = config()?;
    let interface = interface_name(&wg)?;

    // Validated here so startup fails loudly rather than at the first write.
    wg.peer_subnet.clone().ok_or_else(|| "[wireguard].peer_subnet is not configured.".to_string())?;
    wg.server_address.clone().ok_or_else(|| "[wireguard].server_address is not configured.".to_string())?;

    // Persisted server key — generated once, reused thereafter so the server
    // public key stays stable across restarts.
    let private_key = load_or_create_server_key(&wg, &interface)?;
    let public_key = wg_pubkey(&private_key)?;

    // Build the full interface config from the stored key + every peer we know
    // about, so the running interface matches Guard's database.
    let peers = device_list_wireguard_peers().await.map_err(|error| format!("Failed to list WireGuard peers: {}", error))?;
    write_conf(&wg, &interface, &peers)?;
    let conf_path = conf_path(&interface);

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

/// Add (or update) a peer on the live interface. `allowed_ip` is the peer's
/// assigned tunnel address (a /32 route). Does not touch the config file —
/// callers persist to the database and then call [`reconcile`].
pub async fn apply_peer(interface: &str, public_key: &str, allowed_ip: &str) -> Result<(), String> {
    // Apply live — no tunnel restart, existing peers stay connected.
    run("wg", &["set", interface, "peer", public_key, "allowed-ips", &format!("{}/32", allowed_ip)]).await
}

/// Add (or update) a site peer on the live interface: whole subnets rather
/// than a single tunnel address, optionally with a fixed endpoint and a
/// keepalive to hold a NAT mapping open.
pub async fn apply_site_peer(interface: &str, site: &SitePeer) -> Result<(), String> {
    let allowed_ips = site.subnets.join(",");
    let mut args: Vec<String> = vec![
        "set".to_string(),
        interface.to_string(),
        "peer".to_string(),
        site.public_key.clone(),
        "allowed-ips".to_string(),
        allowed_ips,
    ];
    if let Some(endpoint) = &site.endpoint {
        args.push("endpoint".to_string());
        args.push(endpoint.clone());
    }
    if let Some(keepalive) = site.keepalive() {
        args.push("persistent-keepalive".to_string());
        args.push(keepalive.to_string());
    }

    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    run("wg", &args).await
}

/// Remove a peer from the live interface. Idempotent at the `wg` level: removing
/// a peer that isn't present succeeds.
pub async fn remove_peer(interface: &str, public_key: &str) -> Result<(), String> {
    run("wg", &["set", interface, "peer", public_key, "remove"]).await
}

/// The public keys currently configured on the live interface.
async fn live_peers(interface: &str) -> Result<HashSet<String>, String> {
    let output = Command::new("wg")
        .args(["show", interface, "peers"])
        .output()
        .await
        .map_err(|error| format!("Failed to run 'wg show {} peers': {}", interface, error))?;
    if output.status.success() == false {
        return Err(format!("'wg show {} peers' failed: {}", interface, String::from_utf8_lossy(&output.stderr).trim()));
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| line.trim().to_string())
        .filter(|line| line.is_empty() == false)
        .collect())
}

/// Make the live interface match the database exactly, then rewrite the config
/// file from the database so the state survives a restart.
///
/// This is the only way peers should be changed at runtime. It is idempotent and
/// self-healing: a peer the database no longer knows about is removed from the
/// interface even if it was added out of band, and a peer that failed to apply
/// earlier is re-applied on the next call. Both registration (after persisting)
/// and the revocation loop go through here.
pub async fn reconcile() -> Result<(), String> {
    let wg = config()?;
    let interface = interface_name(&wg)?;

    let desired = device_list_wireguard_peers().await.map_err(|error| format!("Failed to list WireGuard peers: {}", error))?;
    // Sites come from config rather than the database, but they are every bit
    // as "desired" — leaving them out here would have reconcile tear down the
    // very peers that give Guard its routes.
    let sites = sites();

    // Remove anything live that is no longer authorised, before adding new
    // peers — so a revoked key cannot stay up because a later add failed.
    let mut desired_keys: HashSet<String> = desired.iter().map(|(public_key, _)| public_key.clone()).collect();
    desired_keys.extend(sites.iter().map(|site| site.public_key.clone()));
    for public_key in live_peers(&interface).await? {
        if desired_keys.contains(&public_key) == false {
            log::info!("Removing WireGuard peer no longer present in the database or config.");
            remove_peer(&interface, &public_key).await?;
        }
    }

    for (public_key, ip) in &desired {
        apply_peer(&interface, public_key, ip).await?;
    }
    for site in &sites {
        apply_site_peer(&interface, site).await?;
    }

    write_conf(&wg, &interface, &desired)?;
    Ok(())
}

/// Regenerate the interface config file from the database's view of the peers.
/// The file is always written from scratch; it is never read back.
fn write_conf(wg: &ConfigWireguard, interface: &str, peers: &[(String, String)]) -> Result<(), String> {
    let peer_subnet = wg.peer_subnet.clone().ok_or_else(|| "[wireguard].peer_subnet is not configured.".to_string())?;
    let server_address = wg.server_address.clone().ok_or_else(|| "[wireguard].server_address is not configured.".to_string())?;
    let private_key = load_or_create_server_key(wg, interface)?;
    let listen_port = wg.listen_port.unwrap_or(DEFAULT_LISTEN_PORT);
    let prefix = subnet_prefix(&peer_subnet)?;

    let conf = build_conf(&private_key, &server_address, prefix, listen_port, peers, &sites());
    write_private_file(&conf_path(interface), &conf)
}

/// Build a wg-quick interface config from the server key + peers.
fn build_conf(
    private_key: &str,
    server_address: &str,
    prefix: u32,
    listen_port: u16,
    peers: &[(String, String)],
    sites: &[SitePeer],
) -> String {
    let mut conf = String::from("[Interface]\n");
    conf.push_str(&format!("PrivateKey = {}\n", private_key));
    conf.push_str(&format!("Address = {}/{}\n", server_address, prefix));
    conf.push_str(&format!("ListenPort = {}\n", listen_port));

    // Device peers: one tunnel address each.
    for (public_key, ip) in peers {
        conf.push_str("\n[Peer]\n");
        conf.push_str(&format!("PublicKey = {}\n", public_key));
        conf.push_str(&format!("AllowedIPs = {}/32\n", ip));
    }

    // Site peers: whole networks behind them. The AllowedIPs here is what
    // gives Guard a route into those networks, so a proxy_to pointing at one
    // resolves and connects.
    for site in sites {
        conf.push_str(&format!("\n# site: {}\n", site.name));
        conf.push_str("[Peer]\n");
        conf.push_str(&format!("PublicKey = {}\n", site.public_key));
        conf.push_str(&format!("AllowedIPs = {}\n", site.subnets.join(", ")));
        if let Some(endpoint) = &site.endpoint {
            conf.push_str(&format!("Endpoint = {}\n", endpoint));
        }
        if let Some(keepalive) = site.keepalive() {
            conf.push_str(&format!("PersistentKeepalive = {}\n", keepalive));
        }
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
    use std::os::unix::fs::PermissionsExt;

    if let Some(parent) = std::path::Path::new(path).parent() {
        std::fs::create_dir_all(parent).map_err(|error| format!("Could not create '{}': {}", parent.display(), error))?;
    }
    std::fs::write(path, contents).map_err(|error| format!("Could not write '{}': {}", path, error))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("Could not set permissions on '{}': {}", path, error))?;
    Ok(())
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


/// Re-check every registered peer against policy and tear down the ones that no
/// longer pass, then bring the live interface in line.
///
/// Registration-time checks alone are not revocation: a connected peer never
/// re-registers, so without this a user who loses access keeps their tunnel
/// indefinitely. Returns how many registrations were revoked.
pub async fn revoke_unauthorised() -> Result<usize, String> {
    let devices = device_list_wireguard_registered()
        .await
        .map_err(|error| format!("Failed to list registered WireGuard devices: {}", error))?;

    let mut revoked = 0;
    for device in devices {
        match device_passes_policy(&device).await {
            Ok(true) => {}
            Ok(false) => {
                log::info!("Revoking WireGuard access for device '{}': no longer permitted by policy.", device.id);
                if let Err(error) = device_clear_wireguard(&device.id).await {
                    log::error!("Failed to clear the WireGuard registration for device '{}': {}", device.id, error);
                    continue;
                }
                revoked += 1;
            }
            // An evaluation ERROR is not a denial. A database blip or an
            // unreachable dependency must never be allowed to tear down every
            // live tunnel at once; leave the peer in place and retry next pass.
            // Only a definitive "no" revokes.
            Err(error) => {
                log::error!("Could not re-evaluate WireGuard policy for device '{}', leaving it in place: {}", device.id, error);
            }
        }
    }

    if revoked > 0 {
        reconcile().await?;
    }
    Ok(revoked)
}

/// Run [`revoke_unauthorised`] on a fixed interval for the life of the process.
pub fn spawn_revocation_loop() {
    let interval_secs = CONFIG_VALUE
        .wireguard
        .clone()
        .and_then(|wg| wg.reevaluation_interval_secs)
        .unwrap_or(DEFAULT_REEVALUATION_INTERVAL_SECS)
        .max(1);

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
        // The first tick fires immediately; skip straight to the interval so
        // startup isn't doing policy work while the interface is still coming up.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            match revoke_unauthorised().await {
                Ok(0) => {}
                Ok(revoked) => log::info!("WireGuard revocation pass removed {} peer(s).", revoked),
                Err(error) => log::error!("WireGuard revocation pass failed: {}", error),
            }
            report_unhealthy_sites().await;
        }
    });

    log::info!("WireGuard policy re-evaluation running every {}s.", interval_secs);
}


/// Reject configurations whose `wireguard_only` hostnames cannot actually be
/// enforced, rather than letting them look protective and do nothing.
///
/// `reverse_proxy_authentication` answers subrequests from a reverse proxy, so
/// the connection Guard sees is always the proxy's — the arrival of the *client*
/// is not observable there, and `wireguard_only` would silently pass. A config
/// that reads as "no public surface" while serving the hostname publicly is
/// worse than one that refuses to start, so this is fatal.
pub fn validate_hostname_config() -> Result<(), String> {
    let reverse_proxy_enabled = CONFIG_VALUE
        .features
        .as_ref()
        .and_then(|features| features.reverse_proxy_authentication)
        .unwrap_or(false);
    if reverse_proxy_enabled == false {
        return Ok(());
    }

    let offenders: Vec<String> = CONFIG_VALUE
        .hostname
        .clone()
        .unwrap_or_default()
        .values()
        .filter(|hostname| hostname.wireguard_only.unwrap_or(false))
        .map(|hostname| hostname.host.clone())
        .collect();

    if offenders.is_empty() {
        return Ok(());
    }

    Err(format!(
        "wireguard_only cannot be enforced while features.reverse_proxy_authentication is enabled: in that \
         flow Guard sees the reverse proxy's connection, never the client's, so the restriction would pass \
         silently and the service would stay publicly reachable. Affected hostname(s): {}. Either remove \
         wireguard_only from them or serve them through Guard's own proxy (features.proxy).",
        offenders.join(", ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wg(peer_subnet: Option<&str>, service_subnet: Option<&str>, allowed_ips: Option<&str>) -> ConfigWireguard {
        ConfigWireguard {
            peer_subnet: peer_subnet.map(str::to_string),
            service_subnet: service_subnet.map(str::to_string),
            allowed_ips: allowed_ips.map(str::to_string),
            ..Default::default()
        }
    }

    #[test]
    fn allocates_the_first_free_host_address() {
        let ip = allocate_ip("10.8.0.0/24", Some("10.8.0.1"), &[]).unwrap();
        // .0 is the network and .1 is the server, so the first peer is .2.
        assert_eq!(ip, "10.8.0.2");
    }

    #[test]
    fn allocation_skips_addresses_already_handed_out() {
        let used = vec!["10.8.0.2".to_string(), "10.8.0.3".to_string()];
        let ip = allocate_ip("10.8.0.0/24", Some("10.8.0.1"), &used).unwrap();
        assert_eq!(ip, "10.8.0.4");
    }

    #[test]
    fn allocation_never_reuses_the_server_address() {
        // The server sits mid-range here, so the allocator has to step over it.
        let ip = allocate_ip("10.8.0.0/30", Some("10.8.0.1"), &[]).unwrap();
        assert_eq!(ip, "10.8.0.2");
    }

    #[test]
    fn allocation_fails_when_the_subnet_is_exhausted() {
        // /30 leaves .1 and .2 usable; the server takes one, `used` takes the other.
        let used = vec!["10.8.0.2".to_string()];
        assert!(allocate_ip("10.8.0.0/30", Some("10.8.0.1"), &used).is_err());
    }

    #[test]
    fn cidr_membership_matches_only_inside_the_range() {
        assert!(ip_in_cidr("10.8.0.2".parse().unwrap(), "10.8.0.0/24"));
        assert!(ip_in_cidr("10.8.0.255".parse().unwrap(), "10.8.0.0/24"));
        assert!(ip_in_cidr("10.8.1.1".parse().unwrap(), "10.8.0.0/24") == false);
        assert!(ip_in_cidr("203.0.113.9".parse().unwrap(), "10.8.0.0/24") == false);
    }

    #[test]
    fn ipv4_mapped_ipv6_sources_are_matched() {
        // A dual-stack listener reports a v4 peer as "::ffff:10.8.0.2"; treating
        // that as public would misclassify a real tunnel peer.
        assert!(ip_in_cidr("::ffff:10.8.0.2".parse().unwrap(), "10.8.0.0/24"));
        assert!(ip_in_cidr("::1".parse().unwrap(), "10.8.0.0/24") == false);
    }

    #[test]
    fn private_ranges_are_recognised() {
        assert!(is_private_ipv4("10.8.0.1".parse().unwrap()));
        assert!(is_private_ipv4("192.168.1.1".parse().unwrap()));
        assert!(is_private_ipv4("172.16.0.1".parse().unwrap()));
        assert!(is_private_ipv4("100.64.0.1".parse().unwrap()));
        assert!(is_private_ipv4("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn public_addresses_are_not_private() {
        // Binding tunnel services to one of these would expose them.
        assert!(is_private_ipv4("8.8.8.8".parse().unwrap()) == false);
        assert!(is_private_ipv4("203.0.113.5".parse().unwrap()) == false);
        assert!(is_private_ipv4("172.32.0.1".parse().unwrap()) == false);
        assert!(is_private_ipv4("100.128.0.1".parse().unwrap()) == false);
    }

    #[test]
    fn malformed_cidr_never_grants_membership() {
        // Arrival defaults to Public on bad config rather than granting trust.
        assert!(ip_in_cidr("10.8.0.2".parse().unwrap(), "not-a-cidr") == false);
        assert!(ip_in_cidr("10.8.0.2".parse().unwrap(), "10.8.0.0/99") == false);
    }

    #[test]
    fn client_dns_prefers_an_explicit_setting() {
        let mut config = wg(Some("10.8.0.0/24"), None, None);
        config.server_address = Some("10.8.0.1".to_string());
        config.dns = Some("1.1.1.1".to_string());
        assert_eq!(client_dns(&config), Some("1.1.1.1".to_string()));
    }

    #[test]
    fn client_dns_advertises_guard_when_the_resolver_can_forward() {
        let mut config = wg(Some("10.8.0.0/24"), None, None);
        config.server_address = Some("10.8.0.1".to_string());
        config.dns_upstream = Some(vec!["1.1.1.1".to_string()]);
        assert_eq!(client_dns(&config), Some("10.8.0.1".to_string()));
    }

    #[test]
    fn client_dns_is_withheld_when_the_resolver_cannot_forward() {
        // Advertising a resolver that refuses everything it does not own would
        // leave the peer unable to resolve anything else at all.
        let mut config = wg(Some("10.8.0.0/24"), None, None);
        config.server_address = Some("10.8.0.1".to_string());
        assert_eq!(client_dns(&config), None);
    }

    #[test]
    fn client_dns_is_withheld_when_the_resolver_is_disabled() {
        let mut config = wg(Some("10.8.0.0/24"), None, None);
        config.server_address = Some("10.8.0.1".to_string());
        config.dns_upstream = Some(vec!["1.1.1.1".to_string()]);
        config.dns_server = Some(false);
        assert_eq!(client_dns(&config), None);
    }

    #[test]
    fn client_allowed_ips_is_peer_plus_service_subnet() {
        let allowed = client_allowed_ips(&wg(Some("10.8.0.0/24"), Some("10.9.0.0/24"), None));
        assert_eq!(allowed, Some("10.8.0.0/24, 10.9.0.0/24".to_string()));
    }

    #[test]
    fn client_allowed_ips_honours_an_explicit_override() {
        let allowed = client_allowed_ips(&wg(Some("10.8.0.0/24"), Some("10.9.0.0/24"), Some("0.0.0.0/0")));
        assert_eq!(allowed, Some("0.0.0.0/0".to_string()));
    }

    #[test]
    fn client_allowed_ips_omits_an_unconfigured_service_subnet() {
        let allowed = client_allowed_ips(&wg(Some("10.8.0.0/24"), None, None));
        assert_eq!(allowed, Some("10.8.0.0/24".to_string()));
    }

    fn site(name: &str, subnets: &[&str], endpoint: Option<&str>, keepalive: Option<u32>) -> SitePeer {
        SitePeer {
            name: name.to_string(),
            public_key: format!("{}-key", name),
            subnets: subnets.iter().map(|s| s.to_string()).collect(),
            endpoint: endpoint.map(str::to_string),
            persistent_keepalive: keepalive,
        }
    }

    #[test]
    fn a_site_without_an_endpoint_gets_a_default_keepalive() {
        // It dialled out to reach Guard, so it is behind NAT and something has
        // to hold the mapping open.
        assert_eq!(site("home", &["10.0.1.0/24"], None, None).keepalive(), Some(DEFAULT_SITE_KEEPALIVE_SECS));
    }

    #[test]
    fn a_site_with_a_fixed_endpoint_gets_no_implicit_keepalive() {
        assert_eq!(site("dc", &["10.0.2.0/24"], Some("dc.example.com:51820"), None).keepalive(), None);
    }

    #[test]
    fn an_explicit_keepalive_always_wins() {
        assert_eq!(site("dc", &["10.0.2.0/24"], Some("dc.example.com:51820"), Some(10)).keepalive(), Some(10));
        assert_eq!(site("home", &["10.0.1.0/24"], None, Some(5)).keepalive(), Some(5));
    }

    #[test]
    fn conf_emits_site_peers_with_their_subnets() {
        let sites = vec![
            site("home", &["10.0.1.0/24", "10.0.2.0/24"], None, None),
            site("dc", &["10.0.3.0/24"], Some("dc.example.com:51820"), Some(15)),
        ];
        let conf = build_conf("server-key", "10.8.0.1", 24, 51820, &[], &sites);

        assert!(conf.contains("AllowedIPs = 10.0.1.0/24, 10.0.2.0/24"), "{}", conf);
        assert!(conf.contains("PublicKey = home-key"), "{}", conf);
        assert!(conf.contains("PersistentKeepalive = 25"), "{}", conf);
        assert!(conf.contains("Endpoint = dc.example.com:51820"), "{}", conf);
        assert!(conf.contains("PersistentKeepalive = 15"), "{}", conf);
    }

    #[test]
    fn overlapping_cidrs_are_detected() {
        assert!(cidrs_overlap("10.0.1.0/24", "10.0.1.0/24"));
        // One contained in the other, in both directions.
        assert!(cidrs_overlap("10.0.0.0/16", "10.0.1.0/24"));
        assert!(cidrs_overlap("10.0.1.0/24", "10.0.0.0/16"));
        assert!(cidrs_overlap("0.0.0.0/0", "10.0.1.0/24"));
    }

    #[test]
    fn disjoint_cidrs_do_not_overlap() {
        assert!(cidrs_overlap("10.0.1.0/24", "10.0.2.0/24") == false);
        assert!(cidrs_overlap("10.8.0.0/24", "10.0.1.0/24") == false);
        assert!(cidrs_overlap("192.168.1.0/24", "10.0.0.0/8") == false);
    }

    #[test]
    fn a_site_needs_a_valid_key_and_at_least_one_subnet() {
        let valid_key = {
            use base64::{engine::general_purpose, Engine as _};
            general_purpose::STANDARD.encode([7u8; 32])
        };

        let missing_subnets = ConfigWireguardSite {
            active: true,
            public_key: Some(valid_key.clone()),
            subnets: None,
            ..Default::default()
        };
        assert!(resolve_site("home", &missing_subnets).is_err());

        let bad_key = ConfigWireguardSite {
            active: true,
            public_key: Some("not-a-key".to_string()),
            subnets: Some(vec!["10.0.1.0/24".to_string()]),
            ..Default::default()
        };
        assert!(resolve_site("home", &bad_key).is_err());

        let good = ConfigWireguardSite {
            active: true,
            public_key: Some(valid_key),
            subnets: Some(vec!["10.0.1.0/24".to_string()]),
            ..Default::default()
        };
        assert!(resolve_site("home", &good).is_ok());
    }

    #[test]
    fn a_site_subnet_that_is_not_a_cidr_is_rejected() {
        use base64::{engine::general_purpose, Engine as _};
        let site = ConfigWireguardSite {
            active: true,
            public_key: Some(general_purpose::STANDARD.encode([7u8; 32])),
            subnets: Some(vec!["10.0.1.5".to_string()]),
            ..Default::default()
        };
        assert!(resolve_site("home", &site).is_err());
    }

    #[test]
    fn conf_lists_every_peer_as_a_slash_32() {
        let peers = vec![
            ("key-one".to_string(), "10.8.0.2".to_string()),
            ("key-two".to_string(), "10.8.0.3".to_string()),
        ];
        let conf = build_conf("server-key", "10.8.0.1", 24, 51820, &peers, &[]);
        assert!(conf.contains("Address = 10.8.0.1/24"));
        assert!(conf.contains("ListenPort = 51820"));
        assert!(conf.contains("PublicKey = key-one"));
        assert!(conf.contains("AllowedIPs = 10.8.0.2/32"));
        assert!(conf.contains("AllowedIPs = 10.8.0.3/32"));
    }
}


/// Whether each configured site has handshaked recently enough to be considered
/// up, keyed by site name.
///
/// A site peer behind NAT keeps the tunnel alive with periodic handshakes, so a
/// stale timestamp is the earliest signal that the far end is gone. Knowing
/// this lets Guard fail fast instead of hanging on a TCP connect into a network
/// that is not currently reachable.
pub async fn site_health() -> Result<Vec<(String, bool)>, String> {
    let wg = config()?;
    let interface = interface_name(&wg)?;
    let handshakes = latest_handshakes(&interface).await?;
    let now = crate::global::get_epoch();

    Ok(sites()
        .into_iter()
        .map(|site| {
            let grace = i64::from(site.keepalive().unwrap_or(DEFAULT_SITE_KEEPALIVE_SECS))
                * SITE_HANDSHAKE_GRACE_INTERVALS as i64;
            let healthy = match handshakes.get(&site.public_key) {
                // `wg` reports 0 for a peer that has never completed a
                // handshake, which is "never up", not "up a long time ago".
                Some(0) | None => false,
                Some(last) => now.saturating_sub(*last) <= grace,
            };
            (site.name, healthy)
        })
        .collect())
}

/// `wg show <iface> latest-handshakes` — public key to unix timestamp.
async fn latest_handshakes(interface: &str) -> Result<std::collections::HashMap<String, i64>, String> {
    let output = Command::new("wg")
        .args(["show", interface, "latest-handshakes"])
        .output()
        .await
        .map_err(|error| format!("Failed to run 'wg show {} latest-handshakes': {}", interface, error))?;
    if output.status.success() == false {
        return Err(format!(
            "'wg show {} latest-handshakes' failed: {}",
            interface,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let key = parts.next()?;
            let timestamp = parts.next()?.parse::<i64>().ok()?;
            Some((key.to_string(), timestamp))
        })
        .collect())
}

/// Reject site configurations WireGuard itself could not honour, or that would
/// silently break address allocation.
///
/// `AllowedIPs` must be unique across the peers of an interface — WireGuard
/// routes by longest-prefix match, so the same range cannot belong to two
/// peers. An overlap with `peer_subnet` is worse still: it would collide with
/// the addresses Guard hands out to devices.
pub fn validate_site_config() -> Result<(), String> {
    let wg = match CONFIG_VALUE.wireguard.clone() {
        Some(wg) => wg,
        None => return Ok(()),
    };

    let configured = match wg.site.clone() {
        Some(sites) => sites,
        None => return Ok(()),
    };

    let mut problems: Vec<String> = Vec::new();
    let mut resolved: Vec<SitePeer> = Vec::new();

    let mut names: Vec<String> = configured.keys().cloned().collect();
    names.sort();
    for name in names {
        let site = &configured[&name];
        if site.active == false {
            continue;
        }
        match resolve_site(&name, site) {
            Ok(site) => resolved.push(site),
            Err(error) => problems.push(format!("  [wireguard.site.{}]: {}", name, error)),
        }
    }

    // A site must not claim the range devices are allocated from.
    if let Some(peer_subnet) = wg.peer_subnet.clone() {
        for site in &resolved {
            for subnet in &site.subnets {
                if cidrs_overlap(subnet, &peer_subnet) {
                    problems.push(format!(
                        "  [wireguard.site.{}] subnet '{}' overlaps [wireguard].peer_subnet '{}'; device \
                         addresses are allocated from that range",
                        site.name, subnet, peer_subnet
                    ));
                }
            }
        }
    }

    // Nor may two sites claim the same range.
    for (index, site) in resolved.iter().enumerate() {
        for other in resolved.iter().skip(index + 1) {
            for subnet in &site.subnets {
                for other_subnet in &other.subnets {
                    if cidrs_overlap(subnet, other_subnet) {
                        problems.push(format!(
                            "  [wireguard.site.{}] subnet '{}' overlaps [wireguard.site.{}] subnet '{}'; \
                             WireGuard cannot route the same range to two peers",
                            site.name, subnet, other.name, other_subnet
                        ));
                    }
                }
            }
        }
    }

    if problems.is_empty() {
        return Ok(());
    }
    problems.sort();
    problems.dedup();
    Err(format!("The WireGuard site configuration is not usable:\n{}", problems.join("\n")))
}

/// Do two IPv4 CIDRs share any address? True when either contains the other's
/// network address, which for CIDRs is equivalent to overlapping.
fn cidrs_overlap(left: &str, right: &str) -> bool {
    let (left_base, left_prefix) = match parse_cidr(left) {
        Ok(parsed) => parsed,
        Err(_) => return false,
    };
    let (right_base, right_prefix) = match parse_cidr(right) {
        Ok(parsed) => parsed,
        Err(_) => return false,
    };

    // Compare on the shorter (less specific) prefix: if the networks match
    // there, one range contains the other.
    let prefix = left_prefix.min(right_prefix);
    let mask: u32 = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    (left_base & mask) == (right_base & mask)
}


/// Log sites that have stopped handshaking.
///
/// Without this a downed site is invisible until something tries to reach
/// through it and hangs on a connect timeout, which looks like an application
/// fault rather than a tunnel that is gone.
async fn report_unhealthy_sites() {
    let health = match site_health().await {
        Ok(health) => health,
        // Only reachable when `wg` itself is unavailable, which the interface
        // startup path already reports.
        Err(error) => {
            log::debug!("Could not read WireGuard site health: {}", error);
            return;
        }
    };

    for (name, healthy) in health {
        if healthy == false {
            log::warn!(
                "WireGuard site '{}' has not handshaked recently; anything behind it is unreachable.",
                name
            );
        }
    }
}
