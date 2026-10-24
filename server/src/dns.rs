//! Tunnel DNS resolver.
//!
//! Clients receive `[wireguard].dns` as their resolver, which points at Guard's
//! own tunnel address. Guard answers authoritatively for the names it knows —
//! every active `[hostname.*]` resolves to Guard's tunnel address, so a request
//! for `ha.example.com` from a peer lands on Guard's HTTPS pipeline over the
//! tunnel rather than going out to public DNS.
//!
//! Everything else is forwarded upstream. That is not optional: `wg-quick`'s
//! `DNS=` replaces the client's resolver outright, so a resolver that refused
//! unknown names would break all other name resolution on the device. When no
//! upstream is configured Guard refuses instead of guessing, and says so at
//! startup.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::{Resolver, TokioResolver};
use hickory_server::proto::op::{Header, HeaderCounts, Metadata, OpCode, ResponseCode};
use hickory_server::proto::rr::rdata::A;
use hickory_server::proto::rr::{Name, RData, Record, RecordType};
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponseBuilder;
use hickory_server::Server;

use crate::hostname::get_active_hostnames;
use crate::structs::ConfigWireguard;

/// TTL on the records Guard serves. Deliberately short: the zone is rebuilt
/// from config and a stale answer sends a client to the wrong place.
const RECORD_TTL_SECS: u32 = 30;

/// Standard DNS port. Guard binds this on its tunnel address only.
const DEFAULT_DNS_PORT: u16 = 53;

type Zone = HashMap<Name, Ipv4Addr>;

/// Answers for Guard's own names, forwarding everything else upstream.
struct GuardResolver {
    zone: Arc<Zone>,
    upstream: Option<Arc<TokioResolver>>,
    /// CIDR a query's source must fall inside to be answered at all. Belt to
    /// the bind's braces: binding the tunnel address should already mean only
    /// peers can reach us, but a second route into that range on the host (a
    /// container network, another VPN) would otherwise be enough to use Guard
    /// as a resolver. `None` disables the check.
    allowed_source: Option<String>,
}

#[async_trait::async_trait]
impl RequestHandler for GuardResolver {
    async fn handle_request<R: ResponseHandler, T: hickory_server::net::runtime::Time>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        // Guard serves queries only. Updates and anything else are not ours.
        if request.metadata.op_code != OpCode::Query {
            return self.respond_error(request, &mut response_handle, ResponseCode::NotImp).await;
        }

        // Refuse anything that did not come from the tunnel before doing any
        // work, so Guard cannot be used as a resolver by whatever else can
        // reach this address.
        if let Some(allowed) = &self.allowed_source {
            if crate::wireguard::ip_in_cidr(request.src().ip(), allowed) == false {
                log::debug!("Refusing DNS query from non-peer source {}.", request.src());
                return self.respond_error(request, &mut response_handle, ResponseCode::Refused).await;
            }
        }

        let info = match request.request_info() {
            Ok(info) => info,
            // Malformed, or more than one question (which no real client sends).
            Err(_) => return self.respond_error(request, &mut response_handle, ResponseCode::FormErr).await,
        };

        let name = normalise(info.query.name().into());
        let record_type = info.query.query_type();

        if let Some(address) = self.zone.get(&name) {
            return self.respond_local(request, &mut response_handle, &name, record_type, *address).await;
        }

        match &self.upstream {
            Some(resolver) => self.respond_forwarded(request, &mut response_handle, resolver, &name, record_type).await,
            // Not an open resolver, and nothing to forward to.
            None => self.respond_error(request, &mut response_handle, ResponseCode::Refused).await,
        }
    }
}

impl GuardResolver {
    /// Answer for a name Guard owns.
    async fn respond_local<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: &mut R,
        name: &Name,
        record_type: RecordType,
        address: Ipv4Addr,
    ) -> ResponseInfo {
        // Guard has no IPv6 tunnel address, so an AAAA query for a name we own
        // must be an empty NOERROR, never NXDOMAIN — the name does exist, and
        // NXDOMAIN would make clients stop trying the A record entirely.
        let answers: Vec<Record> = match record_type {
            RecordType::A => vec![Record::from_rdata(
                name.clone(),
                RECORD_TTL_SECS,
                RData::A(A(address)),
            )],
            _ => Vec::new(),
        };

        let builder = MessageResponseBuilder::from_message_request(request);
        let mut metadata = Metadata::response_from_request(&request.metadata);
        metadata.authoritative = true;
        metadata.response_code = ResponseCode::NoError;

        let message = builder.build(metadata, answers.iter(), [], [], []);
        self.send(response_handle, message, request).await
    }

    /// Pass a name Guard does not own to the configured upstream.
    async fn respond_forwarded<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: &mut R,
        resolver: &TokioResolver,
        name: &Name,
        record_type: RecordType,
    ) -> ResponseInfo {
        let lookup = resolver.lookup(name.clone(), record_type).await;

        let (answers, response_code): (Vec<Record>, ResponseCode) = match lookup {
            Ok(lookup) => (lookup.answers().to_vec(), ResponseCode::NoError),
            Err(error) => {
                // An upstream miss is a normal answer, not a Guard failure, so
                // keep it at debug: a busy tunnel resolves constantly.
                log::debug!("Upstream lookup for '{}' failed: {}", name, error);
                (Vec::new(), ResponseCode::NXDomain)
            }
        };

        let builder = MessageResponseBuilder::from_message_request(request);
        let mut metadata = Metadata::response_from_request(&request.metadata);
        // Forwarded answers are not ours to vouch for.
        metadata.authoritative = false;
        metadata.recursion_available = true;
        metadata.response_code = response_code;

        let message = builder.build(metadata, answers.iter(), [], [], []);
        self.send(response_handle, message, request).await
    }

    async fn respond_error<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: &mut R,
        code: ResponseCode,
    ) -> ResponseInfo {
        let builder = MessageResponseBuilder::from_message_request(request);
        let message = builder.error_msg(&request.metadata, code);
        match response_handle.send_response(message).await {
            Ok(info) => info,
            Err(error) => {
                log::warn!("Failed to send DNS error response: {}", error);
                fallback_response_info(request)
            }
        }
    }

    async fn send<'a, R: ResponseHandler>(
        &self,
        response_handle: &mut R,
        message: hickory_server::zone_handler::MessageResponse<
            '_,
            'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
        >,
        request: &Request,
    ) -> ResponseInfo {
        match response_handle.send_response(message).await {
            Ok(info) => info,
            Err(error) => {
                log::warn!("Failed to send DNS response: {}", error);
                fallback_response_info(request)
            }
        }
    }
}

/// A ResponseInfo to return when the response could not be sent at all. The
/// value is only used for logging and metrics by the caller.
fn fallback_response_info(request: &Request) -> ResponseInfo {
    let mut metadata = Metadata::response_from_request(&request.metadata);
    metadata.response_code = ResponseCode::ServFail;
    ResponseInfo::from(Header { metadata, counts: HeaderCounts::default() })
}

/// Lowercase, fully-qualified form, so lookups are case-insensitive (DNS is)
/// and "example.com" and "example.com." are the same key.
fn normalise(mut name: Name) -> Name {
    name.set_fqdn(true);
    name.to_lowercase()
}

/// Build the zone: every active hostname that is not excluded from the tunnel,
/// pointing at Guard's own tunnel address.
///
/// A `[hostname.*]` host may carry a port ("example.com:8443") because Guard
/// allows the same name on different ports; DNS has no concept of a port, so
/// the port is stripped and both entries collapse to one record.
pub async fn build_zone(server_address: Ipv4Addr) -> Zone {
    let mut zone = zone_from_hostnames(get_active_hostnames().await, server_address);

    // Services answer on their own address, not Guard's, because that address
    // is how the proxy knows which service a connection is for.
    for service in crate::wireguard::services().unwrap_or_default() {
        let dns_name = match service.dns_name {
            Some(dns_name) => dns_name,
            None => continue,
        };
        match dns_name.parse::<Name>() {
            Ok(name) => {
                zone.insert(normalise(name), service.service_address);
            }
            Err(error) => log::warn!(
                "Service '{}' has an invalid dns_name '{}' and will not resolve: {}",
                service.name, dns_name, error
            ),
        }
    }

    zone
}

/// The pure half of [`build_zone`], so the mapping rules can be tested without
/// standing up a config.
fn zone_from_hostnames(hostnames: Vec<crate::structs::GuardedHostname>, server_address: Ipv4Addr) -> Zone {
    let mut zone: Zone = HashMap::new();

    for hostname in hostnames {
        if hostname.wireguard.unwrap_or(true) == false {
            continue;
        }

        let host = hostname.host.split(':').next().unwrap_or_default().to_string();
        match host.parse::<Name>() {
            Ok(name) => {
                zone.insert(normalise(name), server_address);
            }
            Err(error) => log::warn!(
                "Hostname '{}' is not a valid DNS name and will not resolve over the tunnel: {}",
                hostname.host,
                error
            ),
        }
    }

    zone
}

/// Start the tunnel resolver, if it is configured and can bind.
///
/// Bound to the tunnel address only — never `0.0.0.0` — so Guard does not
/// become a resolver reachable from the public internet.
pub async fn spawn(wg: &ConfigWireguard) -> Result<(), String> {
    if wg.dns_server.unwrap_or(true) == false {
        log::info!("Tunnel DNS resolver is disabled ([wireguard].dns_server = false).");
        return Ok(());
    }

    let server_address: Ipv4Addr = wg
        .server_address
        .clone()
        .ok_or_else(|| "[wireguard].server_address is required to run the tunnel resolver.".to_string())?
        .parse()
        .map_err(|_| "[wireguard].server_address is not a valid IPv4 address.".to_string())?;

    // Refuse to expose the resolver on an address the internet can route to.
    // `server_address` is the tunnel gateway and should always be private;
    // getting it wrong (or confusing it with `endpoint`) would otherwise turn
    // Guard into an open forwarding resolver — a DNS amplification source.
    if crate::wireguard::is_private_ipv4(server_address) == false {
        return Err(format!(
            "Refusing to start the tunnel resolver: [wireguard].server_address ('{}') is a publicly \
             routable address. It must be the tunnel-side gateway (e.g. 10.8.0.1); binding a public \
             address here would expose Guard as an open resolver.",
            server_address
        ));
    }

    let upstream = build_upstream(wg)?;
    if upstream.is_none() {
        log::warn!(
            "No [wireguard].dns_upstream is configured, so the tunnel resolver will REFUSE every name \\
             Guard does not own. Because wg-quick's DNS= replaces the client's resolver outright, peers \\
             will be unable to resolve anything else while connected. Set dns_upstream unless that is \\
             deliberate."
        );
    }

    let zone = build_zone(server_address).await;
    log::info!("Tunnel resolver serving {} name(s).", zone.len());

    let bind = SocketAddr::new(IpAddr::V4(server_address), wg.dns_port.unwrap_or(DEFAULT_DNS_PORT));
    let bound = serve(bind, zone, upstream, wg.peer_subnet.clone()).await?;
    log::info!("Tunnel resolver listening on {} (UDP/TCP).", bound);
    Ok(())
}

/// Bind and start the resolver, returning the address it actually bound. Split
/// out from [`spawn`] so the server can be exercised over a real socket in
/// tests without standing up a config or an interface.
async fn serve(
    bind: SocketAddr,
    zone: Zone,
    upstream: Option<Arc<TokioResolver>>,
    allowed_source: Option<String>,
) -> Result<SocketAddr, String> {
    let handler = GuardResolver { zone: Arc::new(zone), upstream, allowed_source };
    let mut server = Server::new(handler);

    let udp = tokio::net::UdpSocket::bind(bind)
        .await
        .map_err(|error| format!("Could not bind the tunnel resolver to {} (UDP): {}", bind, error))?;
    // Port 0 means "pick one"; everything after must use what was actually bound.
    let bound = udp
        .local_addr()
        .map_err(|error| format!("Could not read the resolver's bound address: {}", error))?;
    let tcp = tokio::net::TcpListener::bind(bound)
        .await
        .map_err(|error| format!("Could not bind the tunnel resolver to {} (TCP): {}", bound, error))?;

    server.register_socket(udp);
    // 5s idle timeout, 64KiB response buffer — a DNS response over TCP cannot
    // exceed 64KiB anyway (the length prefix is 16-bit).
    server.register_listener(tcp, Duration::from_secs(5), u16::MAX as usize);

    tokio::spawn(async move {
        if let Err(error) = server.block_until_done().await {
            log::error!("Tunnel resolver stopped: {}", error);
        }
    });

    Ok(bound)
}

/// The upstream resolver unresolved names are forwarded to, if configured.
fn build_upstream(wg: &ConfigWireguard) -> Result<Option<Arc<TokioResolver>>, String> {
    let upstreams = match wg.dns_upstream.clone() {
        Some(upstreams) if upstreams.is_empty() == false => upstreams,
        _ => return Ok(None),
    };

    let mut name_servers = Vec::new();
    for upstream in &upstreams {
        let ip: IpAddr = upstream
            .parse()
            .map_err(|_| format!("[wireguard].dns_upstream entry '{}' is not an IP address.", upstream))?;
        name_servers.push(NameServerConfig::udp_and_tcp(ip));
    }

    let config = ResolverConfig::from_name_servers(name_servers);
    let resolver = Resolver::builder_with_config(config, TokioRuntimeProvider::default())
        .build()
        .map_err(|error| format!("Could not build the upstream resolver: {}", error))?;

    Ok(Some(Arc::new(resolver)))
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::structs::GuardedHostname;

    fn hostname(host: &str, active: bool, wireguard: Option<bool>) -> GuardedHostname {
        GuardedHostname {
            active,
            host: host.to_string(),
            proxy_to: None,
            authentication_methods: Vec::new(),
            multistep_authentication_methods: false,
            applied_policies: Vec::new(),
            alias: None,
            public_description: None,
            logo: None,
            image: None,
            motd_banner: None,
            background_colour: None,
            domain_placeholder: None,
            username_placeholder: None,
            style: None,
            wireguard_only: None,
            wireguard,
        }
    }

    fn gateway() -> Ipv4Addr {
        "10.8.0.1".parse().unwrap()
    }

    fn lookup(zone: &Zone, name: &str) -> Option<Ipv4Addr> {
        zone.get(&normalise(name.parse().unwrap())).copied()
    }

    #[test]
    fn hostnames_resolve_to_the_tunnel_gateway() {
        let zone = zone_from_hostnames(vec![hostname("ha.example.com", true, None)], gateway());
        assert_eq!(lookup(&zone, "ha.example.com"), Some(gateway()));
    }

    #[test]
    fn lookup_is_case_insensitive_and_trailing_dot_agnostic() {
        // DNS is case-insensitive, and clients send both "name" and "name.".
        let zone = zone_from_hostnames(vec![hostname("HA.Example.COM", true, None)], gateway());
        assert_eq!(lookup(&zone, "ha.example.com"), Some(gateway()));
        assert_eq!(lookup(&zone, "ha.example.com."), Some(gateway()));
        assert_eq!(lookup(&zone, "HA.EXAMPLE.COM"), Some(gateway()));
    }

    #[test]
    fn a_port_in_the_host_is_stripped() {
        // Guard allows the same name on different ports; DNS has no ports, so
        // both collapse to one record rather than producing an invalid name.
        let zone = zone_from_hostnames(
            vec![hostname("example.com:8443", true, None), hostname("example.com:9000", true, None)],
            gateway(),
        );
        assert_eq!(zone.len(), 1);
        assert_eq!(lookup(&zone, "example.com"), Some(gateway()));
    }

    #[test]
    fn hostnames_excluded_from_the_tunnel_are_not_served() {
        let zone = zone_from_hostnames(vec![hostname("status.example.com", true, Some(false))], gateway());
        assert!(zone.is_empty());
    }

    #[test]
    fn wireguard_only_hostnames_are_served() {
        // The whole point of a tunnel-only hostname is that it resolves here.
        let mut entry = hostname("ha.example.com", true, None);
        entry.wireguard_only = Some(true);
        let zone = zone_from_hostnames(vec![entry], gateway());
        assert_eq!(lookup(&zone, "ha.example.com"), Some(gateway()));
    }

    /// Start a resolver on an ephemeral loopback port and return a client
    /// pointed at it, so the real UDP path is exercised.
    async fn running_resolver(zone: Zone) -> (SocketAddr, TokioResolver) {
        running_resolver_with_source(zone, None).await
    }

    async fn running_resolver_with_source(zone: Zone, allowed_source: Option<String>) -> (SocketAddr, TokioResolver) {
        let bound = serve("127.0.0.1:0".parse().unwrap(), zone, None, allowed_source).await.unwrap();

        let mut name_server = NameServerConfig::udp_and_tcp(bound.ip());
        // The port lives per-connection (UDP and TCP are separate entries).
        for connection in &mut name_server.connections {
            connection.port = bound.port();
        }
        let config = ResolverConfig::from_name_servers(vec![name_server]);
        let client = Resolver::builder_with_config(config, TokioRuntimeProvider::default()).build().unwrap();

        (bound, client)
    }

    #[tokio::test]
    async fn serves_an_a_record_for_a_known_name_over_the_wire() {
        let zone = zone_from_hostnames(vec![hostname("ha.example.com", true, None)], gateway());
        let (_bound, client) = running_resolver(zone).await;

        let response = client.ipv4_lookup("ha.example.com.").await.unwrap();
        let addresses: Vec<Ipv4Addr> = response
            .answers()
            .iter()
            .filter_map(|record| match &record.data {
                RData::A(a) => Some(a.0),
                _ => None,
            })
            .collect();
        assert_eq!(addresses, vec![gateway()]);
    }

    #[tokio::test]
    async fn aaaa_for_a_known_name_is_empty_noerror_not_nxdomain() {
        // NXDOMAIN here would tell the client the name does not exist at all,
        // and many stacks then stop trying the A record.
        let zone = zone_from_hostnames(vec![hostname("ha.example.com", true, None)], gateway());
        let (_bound, client) = running_resolver(zone).await;

        let response = client.lookup("ha.example.com.", RecordType::AAAA).await;
        match response {
            Ok(lookup) => assert!(lookup.answers().is_empty()),
            // hickory surfaces an empty NOERROR as NoRecordsFound; what matters
            // is that it is not NXDOMAIN.
            Err(error) => {
                let text = error.to_string();
                assert!(text.contains("no record") || text.contains("No records"), "unexpected: {}", text);
            }
        }
    }

    #[tokio::test]
    async fn an_unknown_name_is_refused_when_no_upstream_is_configured() {
        // Guard must not act as an open resolver.
        let zone = zone_from_hostnames(vec![hostname("ha.example.com", true, None)], gateway());
        let (_bound, client) = running_resolver(zone).await;

        let error = client.lookup("example.org.", RecordType::A).await.unwrap_err();
        assert!(error.to_string().to_lowercase().contains("refused"), "unexpected: {}", error);
    }

    #[tokio::test]
    async fn a_query_from_outside_the_peer_subnet_is_refused() {
        // Even for a name Guard owns: if the source is not a tunnel peer, Guard
        // must not answer at all.
        let zone = zone_from_hostnames(vec![hostname("ha.example.com", true, None)], gateway());
        let (_bound, client) = running_resolver_with_source(zone, Some("10.8.0.0/24".to_string())).await;

        let error = client.ipv4_lookup("ha.example.com.").await.unwrap_err();
        assert!(error.to_string().to_lowercase().contains("refused"), "unexpected: {}", error);
    }

    #[tokio::test]
    async fn a_query_from_inside_the_peer_subnet_is_answered() {
        // The loopback source the test client uses is inside this range, so the
        // same query that was refused above is answered here.
        let zone = zone_from_hostnames(vec![hostname("ha.example.com", true, None)], gateway());
        let (_bound, client) = running_resolver_with_source(zone, Some("127.0.0.0/8".to_string())).await;

        let response = client.ipv4_lookup("ha.example.com.").await.unwrap();
        assert!(response.answers().is_empty() == false);
    }

    #[test]
    fn an_invalid_dns_name_is_skipped_rather_than_panicking() {
        let zone = zone_from_hostnames(
            vec![hostname("not a hostname!", true, None), hostname("ok.example.com", true, None)],
            gateway(),
        );
        assert_eq!(zone.len(), 1);
        assert_eq!(lookup(&zone, "ok.example.com"), Some(gateway()));
    }
}
