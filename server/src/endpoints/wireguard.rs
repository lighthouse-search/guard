use axum::body::Bytes;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};

use base64::{engine::general_purpose, Engine as _};
use once_cell::sync::Lazy;
use serde_json::json;
use tokio::sync::Mutex;

use crate::device::{device_clear_wireguard, device_get, device_get_by_wireguard_public_key, device_http_signature_authentication, device_list_wireguard_ips, device_set_wireguard};
use crate::http_signature::RequestContext;
use crate::structs::ConfigWireguard;
use crate::wireguard;
use crate::error_message;

// Serialises the allocate → apply → persist section so two concurrent
// registrations can't hand out the same tunnel address or both pass the
// one-key-per-device check before either writes.
static REGISTER_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

#[derive(serde::Deserialize)]
struct WireguardRegisterBody {
    public_key: Option<String>,
}

fn header_str(headers: &HeaderMap, name: &str) -> Option<String> {
    headers.get(name).and_then(|value| value.to_str().ok()).map(|value| value.to_string())
}

// Register a device's WireGuard public key.
//
// The device authenticates by signing THIS request with its Guard ed25519 device
// key (RFC 9421); the WireGuard public key rides in the signed body, so it can't
// be swapped in transit. On success Guard allocates a tunnel address, applies the
// peer to the live interface, and returns the details the client needs to build
// its tunnel. A device may register exactly one WireGuard key, and a key may
// belong to only one device.
pub async fn wireguard_register(method: Method, uri: Uri, headers: HeaderMap, body: Bytes) -> Response {
    // WireGuard must be configured for this endpoint to do anything. Internal
    // WireGuard details (interface names, the `wg` command, peer keys, subnets)
    // must never reach the client — log them and return a generic message.
    let wg = match wireguard::config() {
        Ok(cfg) => cfg,
        Err(error) => {
            log::info!("WireGuard registration attempted but not configured: {}", error);
            return error_message(11001, StatusCode::NOT_FOUND, "WireGuard registration failed.".to_string());
        }
    };

    // --- Authenticate the device via its RFC 9421 signature over this request ---
    let signature_input = match header_str(&headers, "signature-input") {
        Some(value) => value,
        None => return error_message(11002, StatusCode::BAD_REQUEST, "Missing 'Signature-Input' header.".to_string()),
    };
    let signature = match header_str(&headers, "signature") {
        Some(value) => value,
        None => return error_message(11002, StatusCode::BAD_REQUEST, "Missing 'Signature' header.".to_string()),
    };
    let content_digest = header_str(&headers, "content-digest");
    // @authority is the Host the client signed (the host it dialed).
    let authority = match header_str(&headers, "host") {
        Some(value) => value,
        None => return error_message(11002, StatusCode::BAD_REQUEST, "Missing 'Host' header.".to_string()),
    };
    let method_str = method.as_str().to_string();
    let path = uri.path().to_string();
    let query = uri.query().map(|value| value.to_string());

    let ctx = RequestContext {
        method: &method_str,
        authority: &authority,
        path: &path,
        query: query.as_deref(),
        content_digest: content_digest.as_deref(),
        // Passing the body means the signed Content-Digest is recomputed and
        // checked here, binding the public key below to the signature.
        body: Some(&body),
    };

    let device = match device_http_signature_authentication(&signature_input, &signature, Some(&ctx), Some(300)).await {
        Ok(device) => device,
        Err(response) => return response,
    };

    // --- Parse + validate the WireGuard public key from the (signed) body ---
    let parsed: WireguardRegisterBody = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(_) => return error_message(11003, StatusCode::BAD_REQUEST, "Body must be JSON { public_key }.".to_string()),
    };
    let public_key = match parsed.public_key {
        Some(key) if key.trim().is_empty() == false => key.trim().to_string(),
        _ => return error_message(11004, StatusCode::BAD_REQUEST, "body.public_key is null or whitespace.".to_string()),
    };
    // A WireGuard public key is a base64-encoded 32-byte value. Reject anything
    // else so we never feed junk to `wg`.
    match general_purpose::STANDARD.decode(&public_key) {
        Ok(bytes) if bytes.len() == 32 => {}
        _ => return error_message(11005, StatusCode::BAD_REQUEST, "body.public_key is not a valid WireGuard (base64, 32-byte) key.".to_string()),
    }

    // Everything below (check policy → allocate → persist → apply) runs under the
    // lock so it's atomic against concurrent registrations.
    let _guard = REGISTER_LOCK.lock().await;

    // Re-read the device under the lock so the one-key-per-device check reflects
    // any registration that just committed.
    let device = match device_get(device.id.clone()).await {
        Ok(Some(device)) => device,
        Ok(None) => return error_message(11002, StatusCode::UNAUTHORIZED, "Device no longer exists.".to_string()),
        Err(error) => {
            log::error!("Could not re-read device during WireGuard registration: {}", error);
            return error_message(11011, StatusCode::INTERNAL_SERVER_ERROR, "WireGuard registration failed.".to_string());
        }
    };

    // --- The device's user must satisfy the WireGuard policies ---
    //
    // A valid device signature proves *which* device is asking, not that it is
    // allowed a tunnel. Without this check any enrolled device reaches every
    // service on the tunnel, which is the whole point of the feature.
    match wireguard::device_passes_policy(&device).await {
        Ok(true) => {}
        Ok(false) => {
            log::info!("WireGuard registration denied by policy for device '{}'.", device.id);
            return error_message(11012, StatusCode::FORBIDDEN, "Not authorised for WireGuard access.".to_string());
        }
        Err(error) => {
            log::error!("Could not evaluate WireGuard policy for device '{}': {}", device.id, error);
            return error_message(11012, StatusCode::INTERNAL_SERVER_ERROR, "WireGuard registration failed.".to_string());
        }
    }

    // --- One WireGuard key per device ---
    if let Some(existing) = device.wireguard_public_key.clone() {
        if existing == public_key {
            // Idempotent: same device re-registering the same key.
            return success_response(&wg, device.wireguard_ip.as_deref().unwrap_or_default());
        }
        return error_message(11006, StatusCode::CONFLICT, "This device already has a WireGuard key registered.".to_string());
    }

    // --- The key must not already belong to another device ---
    match device_get_by_wireguard_public_key(&public_key).await {
        Ok(Some(other)) if other.id != device.id => {
            return error_message(11007, StatusCode::CONFLICT, "This WireGuard key is already registered to another device.".to_string());
        }
        Ok(_) => {}
        Err(error) => {
            log::error!("Could not query device by WireGuard key: {}", error);
            return error_message(11011, StatusCode::INTERNAL_SERVER_ERROR, "WireGuard registration failed.".to_string());
        }
    }

    // --- Allocate a tunnel address ---
    let peer_subnet = match wg.peer_subnet.clone() {
        Some(subnet) => subnet,
        None => {
            log::error!("[wireguard].peer_subnet is not configured.");
            return error_message(11008, StatusCode::INTERNAL_SERVER_ERROR, "WireGuard registration failed.".to_string());
        }
    };

    let used = match device_list_wireguard_ips().await {
        Ok(used) => used,
        Err(error) => {
            log::error!("Could not list allocated WireGuard addresses: {}", error);
            return error_message(11011, StatusCode::INTERNAL_SERVER_ERROR, "WireGuard registration failed.".to_string());
        }
    };
    let allocated_ip = match wireguard::allocate_ip(&peer_subnet, wg.server_address.as_deref(), &used) {
        Ok(ip) => ip,
        Err(error) => {
            log::error!("Could not allocate a WireGuard address: {}", error);
            return error_message(11009, StatusCode::INTERNAL_SERVER_ERROR, "WireGuard registration failed.".to_string());
        }
    };

    // --- Persist, then bring the live interface in line with the database ---
    //
    // Database first: it is the source of truth, and `reconcile` derives the
    // live peer set from it. The reverse order could leave a live peer with no
    // database row — an access grant nothing knows how to revoke — whereas a row
    // whose peer failed to apply is simply re-applied on the next reconcile.
    if let Err(error) = device_set_wireguard(&device.id, &public_key, &allocated_ip).await {
        log::error!("Could not persist WireGuard registration: {}", error);
        return error_message(11011, StatusCode::INTERNAL_SERVER_ERROR, "WireGuard registration failed.".to_string());
    }

    if let Err(error) = wireguard::reconcile().await {
        log::error!("Could not apply WireGuard peer, rolling the registration back: {}", error);
        // Roll back so the device can retry cleanly rather than holding an
        // address that was never applied.
        if let Err(rollback) = device_clear_wireguard(&device.id).await {
            log::error!("Failed to roll back the WireGuard registration for device '{}': {}", device.id, rollback);
        }
        return error_message(11010, StatusCode::INTERNAL_SERVER_ERROR, "WireGuard registration failed.".to_string());
    }

    success_response(&wg, &allocated_ip)
}

fn success_response(wg: &ConfigWireguard, address: &str) -> Response {
    (
        StatusCode::OK,
        serde_json::to_string(&json!({
            "ok": true,
            "address": address,
            "server_public_key": wireguard::server_public_key(),
            "server_address": wg.server_address,
            "endpoint": wg.endpoint,
            "allowed_ips": wireguard::client_allowed_ips(wg),
            "dns": wireguard::client_dns(wg),
            "persistent_keepalive": wg.persistent_keepalive
        })).unwrap(),
    ).into_response()
}
