//! Protocol-agnostic TCP proxy for tunnel services.
//!
//! Hostnames are demuxed by their Host header and go through Guard's HTTP
//! pipeline. Everything else — SSH, SMB, printing, databases — has no such
//! hint: the destination *is* the address. So each `[wireguard.service.*]` gets
//! an address of its own from `service_subnet`, and Guard listens there.
//!
//! Which service a connection is for is therefore implicit in which listener
//! accepted it, and no demultiplexing is needed. Binding the specific service
//! address also avoids colliding with the host's own daemons — a listener on
//! `0.0.0.0:22` would fight sshd, `10.9.0.5:22` does not.
//!
//! Per connection: the source tunnel address identifies the device, policy is
//! evaluated for its user, and on success the bytes are spliced to the
//! destination. The payload is never parsed, which is exactly why this works
//! for any single-connection TCP protocol.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};

use crate::device::device_get_by_wireguard_ip;
use crate::structs::GuardDevices;
use crate::wireguard::{self, ServicePeer};

/// How long to wait for the destination to accept a connection. Past this the
/// backend is treated as down; the client gets a closed connection rather than
/// hanging indefinitely.
const DIAL_TIMEOUT_SECS: u64 = 10;

const DEFAULT_MAX_CONNECTIONS: usize = 512;
const DEFAULT_MAX_CONNECTIONS_PER_DEVICE: usize = 64;

/// Live connection accounting, shared by every listener.
///
/// Guard is on the data path here, so an unbounded splice pool is a denial of
/// service surface: one device opening connections in a loop would otherwise
/// exhaust file descriptors and memory for everyone.
struct Limits {
    total: AtomicUsize,
    max_total: usize,
    max_per_device: usize,
    per_device: tokio::sync::Mutex<std::collections::HashMap<String, usize>>,
}

impl Limits {
    fn new(max_total: usize, max_per_device: usize) -> Self {
        Self {
            total: AtomicUsize::new(0),
            max_total,
            max_per_device,
            per_device: tokio::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Reserve a slot, or report why it cannot be given.
    async fn acquire(self: &Arc<Self>, device_id: &str) -> Option<ConnectionSlot> {
        let mut per_device = self.per_device.lock().await;

        if self.total.load(Ordering::SeqCst) >= self.max_total {
            return None;
        }
        let device_count = per_device.entry(device_id.to_string()).or_insert(0);
        if *device_count >= self.max_per_device {
            return None;
        }

        *device_count += 1;
        self.total.fetch_add(1, Ordering::SeqCst);

        Some(ConnectionSlot {
            limits: Arc::clone(self),
            device_id: device_id.to_string(),
        })
    }
}

/// Releases its slot when dropped, so a panic or early return cannot leak one.
struct ConnectionSlot {
    limits: Arc<Limits>,
    device_id: String,
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.limits.total.fetch_sub(1, Ordering::SeqCst);
        let limits = Arc::clone(&self.limits);
        let device_id = self.device_id.clone();
        tokio::spawn(async move {
            let mut per_device = limits.per_device.lock().await;
            if let Some(count) = per_device.get_mut(&device_id) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    per_device.remove(&device_id);
                }
            }
        });
    }
}

/// Start a listener for every configured service.
///
/// A service that cannot bind is logged and skipped rather than taking the
/// others down: one typo should not cost every service on the tunnel.
pub async fn spawn() -> Result<(), String> {
    let services = wireguard::services()?;
    if services.is_empty() {
        return Ok(());
    }

    let wg = wireguard::config()?;
    let limits = Arc::new(Limits::new(
        wg.max_connections.unwrap_or(DEFAULT_MAX_CONNECTIONS),
        wg.max_connections_per_device.unwrap_or(DEFAULT_MAX_CONNECTIONS_PER_DEVICE),
    ));
    let peer_subnet = wg.peer_subnet.clone();

    let mut started = 0;
    for service in services {
        let bind = SocketAddr::new(IpAddr::V4(service.service_address), service.port);
        let listener = match TcpListener::bind(bind).await {
            Ok(listener) => listener,
            Err(error) => {
                log::error!(
                    "Service '{}' is unavailable: could not bind {}: {}. Is the WireGuard interface up \
                     with that address assigned?",
                    service.name, bind, error
                );
                continue;
            }
        };

        log::info!("Service '{}' listening on {} -> {}", service.name, bind, service.destination);
        tokio::spawn(accept_loop(listener, service, Arc::clone(&limits), peer_subnet.clone()));
        started += 1;
    }

    log::info!("{} tunnel service listener(s) running.", started);
    Ok(())
}

async fn accept_loop(listener: TcpListener, service: ServicePeer, limits: Arc<Limits>, peer_subnet: Option<String>) {
    loop {
        let (client, source) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                log::warn!("Service '{}' failed to accept a connection: {}", service.name, error);
                continue;
            }
        };

        let service = service.clone();
        let limits = Arc::clone(&limits);
        let peer_subnet = peer_subnet.clone();
        tokio::spawn(async move {
            handle(client, source, service, limits, peer_subnet).await;
        });
    }
}

async fn handle(
    client: TcpStream,
    source: SocketAddr,
    service: ServicePeer,
    limits: Arc<Limits>,
    peer_subnet: Option<String>,
) {
    // The source address must be a tunnel peer. The listener is bound to a
    // service address that only the tunnel routes to, but checking the source
    // too means a second route into that range on the host is not enough to
    // reach a service.
    if let Some(subnet) = &peer_subnet {
        if wireguard::ip_in_cidr(source.ip(), subnet) == false {
            log::warn!("Service '{}': refused {} — not a tunnel peer.", service.name, source);
            return;
        }
    }

    let device = match authorised_device(&service, source).await {
        Some(device) => device,
        // authorised_device logs the specific reason.
        None => return,
    };

    let slot = match limits.acquire(&device.id).await {
        Some(slot) => slot,
        None => {
            log::warn!(
                "Service '{}': refused device '{}' — connection limit reached.",
                service.name, device.id
            );
            return;
        }
    };

    let destination = match tokio::time::timeout(
        Duration::from_secs(DIAL_TIMEOUT_SECS),
        TcpStream::connect(&service.destination),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            log::warn!("Service '{}': could not reach {}: {}", service.name, service.destination, error);
            return;
        }
        Err(_) => {
            log::warn!(
                "Service '{}': timed out dialling {} after {}s.",
                service.name, service.destination, DIAL_TIMEOUT_SECS
            );
            return;
        }
    };

    // Guard is the source address the backend sees, so this log is the only
    // per-device record of who reached what.
    log::info!(
        "Service '{}': device '{}' connected to {}.",
        service.name, device.id, service.destination
    );

    splice(client, destination, &service, &device).await;
    drop(slot);
}

/// Resolve the connecting device from its tunnel address and check it against
/// the service's policies. Deny-by-default at every step.
async fn authorised_device(service: &ServicePeer, source: SocketAddr) -> Option<GuardDevices> {
    // Stored tunnel addresses are IPv4; a dual-stack listener would otherwise
    // report "::ffff:10.8.0.2" here and never match.
    let lookup = wireguard::canonical_ip(source.ip()).to_string();
    let device = match device_get_by_wireguard_ip(&lookup).await {
        Ok(Some(device)) => device,
        Ok(None) => {
            log::warn!("Service '{}': refused {} — no device holds that tunnel address.", service.name, source);
            return None;
        }
        Err(error) => {
            log::error!("Service '{}': could not look up {}: {}", service.name, source, error);
            return None;
        }
    };

    match wireguard::device_passes_service_policy(&device, &service.applied_policies).await {
        Ok(true) => Some(device),
        Ok(false) => {
            log::warn!(
                "Service '{}': refused device '{}' — not permitted by policy.",
                service.name, device.id
            );
            None
        }
        Err(error) => {
            log::error!(
                "Service '{}': could not evaluate policy for device '{}': {}",
                service.name, device.id, error
            );
            None
        }
    }
}

/// Copy bytes in both directions until either side closes. The payload is
/// never inspected, which is what makes this protocol-agnostic.
async fn splice(mut client: TcpStream, mut destination: TcpStream, service: &ServicePeer, device: &GuardDevices) {
    match tokio::io::copy_bidirectional(&mut client, &mut destination).await {
        Ok((to_destination, to_client)) => log::debug!(
            "Service '{}': device '{}' finished ({} bytes up, {} bytes down).",
            service.name, device.id, to_destination, to_client
        ),
        // A reset mid-stream is normal when a client disconnects abruptly.
        Err(error) => log::debug!(
            "Service '{}': device '{}' connection ended: {}",
            service.name, device.id, error
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn service(name: &str, destination: &str) -> ServicePeer {
        ServicePeer {
            name: name.to_string(),
            service_address: "10.9.0.1".parse().unwrap(),
            port: 22,
            destination: destination.to_string(),
            dns_name: None,
            applied_policies: vec!["staff_only".to_string()],
        }
    }

    fn device(id: &str) -> GuardDevices {
        GuardDevices {
            id: id.to_string(),
            user_id: "user-1".to_string(),
            authentication_method: "email".to_string(),
            collateral: None,
            public_key: String::new(),
            created: None,
            wireguard_public_key: None,
            wireguard_ip: Some("10.8.0.2".to_string()),
        }
    }

    #[tokio::test]
    async fn a_device_is_capped_at_its_own_limit() {
        let limits = Arc::new(Limits::new(100, 2));

        let first = limits.acquire("device-a").await;
        let second = limits.acquire("device-a").await;
        let third = limits.acquire("device-a").await;

        assert!(first.is_some());
        assert!(second.is_some());
        assert!(third.is_none(), "a device must not exceed its per-device cap");
    }

    #[tokio::test]
    async fn one_device_hitting_its_cap_does_not_block_another() {
        let limits = Arc::new(Limits::new(100, 1));

        let _first = limits.acquire("device-a").await.unwrap();
        assert!(limits.acquire("device-a").await.is_none());
        assert!(limits.acquire("device-b").await.is_some(), "a noisy device must not starve others");
    }

    #[tokio::test]
    async fn the_global_cap_applies_across_devices() {
        let limits = Arc::new(Limits::new(2, 100));

        let _first = limits.acquire("device-a").await.unwrap();
        let _second = limits.acquire("device-b").await.unwrap();
        assert!(limits.acquire("device-c").await.is_none());
    }

    #[tokio::test]
    async fn dropping_a_slot_returns_capacity() {
        let limits = Arc::new(Limits::new(1, 1));

        let slot = limits.acquire("device-a").await;
        assert!(slot.is_some());
        assert!(limits.acquire("device-a").await.is_none());

        drop(slot);
        // The per-device counter is released on a spawned task, so give it a
        // moment to land before asserting capacity is back.
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        assert!(limits.acquire("device-a").await.is_some(), "capacity must return once a connection ends");
    }

    #[tokio::test]
    async fn bytes_are_spliced_in_both_directions_untouched() {
        // An echo backend standing in for SSH/SMB/whatever: the proxy must not
        // care what the payload is.
        let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = backend.accept().await.unwrap();
            let mut buffer = [0u8; 1024];
            let read = stream.read(&mut buffer).await.unwrap();
            // Echo it back with a marker, proving both directions carry bytes.
            stream.write_all(&buffer[..read]).await.unwrap();
            stream.write_all(b"-from-backend").await.unwrap();
            stream.flush().await.unwrap();
        });

        // Stand in for the client side of an accepted connection.
        let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let front_addr = front.local_addr().unwrap();
        let service = service("test", &backend_addr.to_string());

        tokio::spawn(async move {
            let (client, _) = front.accept().await.unwrap();
            let destination = TcpStream::connect(service.destination.clone()).await.unwrap();
            splice(client, destination, &service, &device("device-a")).await;
        });

        let mut client = TcpStream::connect(front_addr).await.unwrap();
        // Deliberately not valid UTF-8 or any known protocol.
        client.write_all(&[0x00, 0xff, 0x10, b'h', b'i']).await.unwrap();
        client.flush().await.unwrap();

        let mut received = Vec::new();
        client.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, [&[0x00, 0xff, 0x10, b'h', b'i'][..], b"-from-backend"].concat());
    }
}
