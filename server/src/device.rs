use axum::response::Response;
use serde_json::Value;

use diesel::sql_query;
use diesel::prelude::*;
use diesel::sql_types::*;

use crate::global::{generate_uuid, get_epoch};
use crate::hostname::prepend_hostname_to_cookie;
use crate::responses::*;
use crate::structs::*;
use crate::http_signature::{self, RequestContext};
use crate::signed_token;
use std::error::Error;

use crate::SQL_TABLES;

/// A device static-auth cookie carries a serialized RFC 9421 signature (with an
/// empty covered-components list) so a browser navigation can prove device
/// identity without setting `Signature` headers. The cookie value is the
/// base64url of this JSON (see `parse_static_auth_cookie`).
#[derive(serde::Deserialize)]
pub struct StaticAuthCookie {
    pub signature_input: String,
    pub signature: String,
}

/// Decode a guard_static_auth cookie value (base64url of the credential JSON).
pub fn parse_static_auth_cookie(value: &str) -> Result<StaticAuthCookie, String> {
    use base64::{engine::general_purpose, Engine as _};
    let json = general_purpose::URL_SAFE_NO_PAD
        .decode(value.trim())
        .map_err(|error| format!("guard_static_auth cookie is not valid base64url: {}", error))?;
    serde_json::from_slice(&json)
        .map_err(|error| format!("guard_static_auth cookie is not valid JSON: {}", error))
}

// Some authenticatiom methods, such as email require action (such as sending a magiclink) before the user can present credentials to authenticate. This is where that logic is kept.

pub async fn device_get(id: String) -> Result<Option<GuardDevices>, Box<dyn Error>> {
    let mut db = crate::DB_POOL.get().expect("Failed to get a connection from the pool.");
    let sql: ConfigSqlTables = (&*SQL_TABLES).clone();

    let query = format!("SELECT id, user_id, authentication_method, collateral, public_key, created, wireguard_public_key, wireguard_ip FROM {} WHERE id=?", sql.device.unwrap());

    let result: Vec<GuardDevices> = sql_query(query)
    .bind::<Text, _>(id)
    .load::<GuardDevices>(&mut db)
    .expect("Something went wrong querying the DB.");

    if result.len() == 0 {
        // Device not found.
        return Ok(None);
    }

    let device = result[0].clone();

    Ok(Some(device))
}

// Look up a device by its registered WireGuard public key. Used to enforce that
// a given WireGuard key belongs to exactly one device (a second device claiming
// the same key is rejected).
pub async fn device_get_by_wireguard_public_key(wireguard_public_key: &str) -> Result<Option<GuardDevices>, Box<dyn Error>> {
    let mut db = crate::DB_POOL.get().expect("Failed to get a connection from the pool.");
    let sql: ConfigSqlTables = (&*SQL_TABLES).clone();

    let query = format!("SELECT id, user_id, authentication_method, collateral, public_key, created, wireguard_public_key, wireguard_ip FROM {} WHERE wireguard_public_key=?", sql.device.unwrap());

    let result: Vec<GuardDevices> = sql_query(query)
    .bind::<Text, _>(wireguard_public_key.to_string())
    .load::<GuardDevices>(&mut db)
    .expect("Something went wrong querying the DB.");

    Ok(result.into_iter().next())
}

// Every tunnel address currently allocated to a device, so the allocator can
// pick the next free one in the configured peer subnet.
pub async fn device_list_wireguard_ips() -> Result<Vec<String>, Box<dyn Error>> {
    let mut db = crate::DB_POOL.get().expect("Failed to get a connection from the pool.");
    let sql: ConfigSqlTables = (&*SQL_TABLES).clone();

    let query = format!("SELECT id, user_id, authentication_method, collateral, public_key, created, wireguard_public_key, wireguard_ip FROM {} WHERE wireguard_ip IS NOT NULL", sql.device.unwrap());

    let result: Vec<GuardDevices> = sql_query(query)
    .load::<GuardDevices>(&mut db)
    .expect("Something went wrong querying the DB.");

    Ok(result.into_iter().filter_map(|device| device.wireguard_ip).collect())
}

// Every registered WireGuard peer (public key + tunnel address), so Guard can
// rebuild the interface config and restore peers on startup.
pub async fn device_list_wireguard_peers() -> Result<Vec<(String, String)>, Box<dyn Error>> {
    let mut db = crate::DB_POOL.get().expect("Failed to get a connection from the pool.");
    let sql: ConfigSqlTables = (&*SQL_TABLES).clone();

    let query = format!("SELECT id, user_id, authentication_method, collateral, public_key, created, wireguard_public_key, wireguard_ip FROM {} WHERE wireguard_public_key IS NOT NULL AND wireguard_ip IS NOT NULL", sql.device.unwrap());

    let result: Vec<GuardDevices> = sql_query(query)
    .load::<GuardDevices>(&mut db)
    .expect("Something went wrong querying the DB.");

    Ok(result
        .into_iter()
        .filter_map(|device| match (device.wireguard_public_key, device.wireguard_ip) {
            (Some(public_key), Some(ip)) => Some((public_key, ip)),
            _ => None,
        })
        .collect())
}

// Bind a WireGuard public key + allocated tunnel address to a device.
pub async fn device_set_wireguard(device_id: &str, wireguard_public_key: &str, wireguard_ip: &str) -> Result<(), Box<dyn Error>> {
    let mut db = crate::DB_POOL.get().expect("Failed to get a connection from the pool.");
    let sql: ConfigSqlTables = (&*SQL_TABLES).clone();

    let query = format!("UPDATE {} SET wireguard_public_key=?, wireguard_ip=? WHERE id=?", sql.device.unwrap());
    sql_query(query)
    .bind::<Text, _>(wireguard_public_key.to_string())
    .bind::<Text, _>(wireguard_ip.to_string())
    .bind::<Text, _>(device_id.to_string())
    .execute(&mut db)
    .expect("Something went wrong querying the DB.");

    Ok(())
}

pub async fn device_create(user_id: String, authentication_method_id: String, collateral: Option<String>, public_key: String) -> Result<String, Box<dyn Error>> {
    let mut db = crate::DB_POOL.get().expect("Failed to get a connection from the pool.");
    let device_id = generate_uuid();

    let sql: ConfigSqlTables = (&*SQL_TABLES).clone();
    let query = format!("INSERT INTO {} (id, user_id, authentication_method, collateral, public_key, created) VALUES (?, ?, ?, ?, ?, ?)", sql.device.unwrap());
    sql_query(query)
    .bind::<Text, _>(device_id.clone())
    .bind::<Text, _>(user_id.clone())
    .bind::<Text, _>(authentication_method_id.clone())
    .bind::<Text, _>(collateral.unwrap_or("".to_string()))
    .bind::<Text, _>(public_key.clone())
    .bind::<BigInt, _>(get_epoch())
    .execute(&mut db)
    .expect("Something went wrong querying the DB.");

    Ok(device_id)
}

pub fn device_guard_static_auth_from_cookies(jar: &indexmap::IndexMap<String, String>) -> Option<String> {
    let mut _signed_data: String = String::new();

    let cookie_name = prepend_hostname_to_cookie("guard_static_auth");
    if jar.get(&cookie_name.clone()).is_none() == false {
        _signed_data = jar.get(&cookie_name.clone()).expect("Failed to parse signed_data.").to_string();
        log::debug!("Signed_data cookie: {:?}", _signed_data);
    } else {
        log::debug!("Signed_data cookie: None");
        return None;
    }

    return Some(_signed_data);
}

// Verify an ed25519 signed *data* token (currently the OAuth authorization
// `code`). The signed payload identifies the device via `device_id`; we load
// that device's public key and verify the token was signed by it. Returns the
// device alongside the verified payload.
pub async fn device_signed_authentication(signed_token: String) -> Result<(GuardDevices, Option<Value>), Response> {
    let unverified_payload = signed_token::parse_unverified(&signed_token).map_err(|error| {
        log::info!("Failed to parse signed token payload: {}", error);
        error_message(3001, axum::http::StatusCode::UNAUTHORIZED, "Invalid signed token.".to_string())
    })?;

    let device_id = unverified_payload
        .get("device_id")
        .and_then(|value| value.as_str())
        .ok_or_else(|| {
            log::info!("Signed token payload is missing device_id.");
            error_message(3002, axum::http::StatusCode::UNAUTHORIZED, "Signed token is missing device_id.".to_string())
        })?
        .to_string();

    let device = device_get(device_id).await.expect("Failed to query for device.").ok_or_else(|| {
        log::info!("Signed token references an unknown device.");
        error_message(3003, axum::http::StatusCode::UNAUTHORIZED, "Invalid signed token.".to_string())
    })?;

    let payload = signed_token::verify(&signed_token, &device.public_key).map_err(|error| {
        log::info!("Signed token verification failed: {}", error);
        error_message(3004, axum::http::StatusCode::UNAUTHORIZED, "Invalid signed token.".to_string())
    })?;

    return Ok((device, Some(payload)));
}

// Verify an RFC 9421 HTTP Message Signature and return the authenticated
// device. `ctx` supplies the live request components when the signature covers
// them (per-request programmatic clients); it is `None` for the empty-component
// cookie credential used by browser navigations. The device is identified by
// the signature's `keyid` parameter.
pub async fn device_http_signature_authentication(
    signature_input: &str,
    signature: &str,
    ctx: Option<&RequestContext<'_>>,
    max_age_secs: Option<i64>,
) -> Result<GuardDevices, Response> {
    let parsed = http_signature::parse(signature_input, signature).map_err(|error| {
        log::info!("Failed to parse HTTP signature: {}", error);
        error_message(3001, axum::http::StatusCode::UNAUTHORIZED, "Invalid request signature.".to_string())
    })?;

    let device = device_get(parsed.keyid.clone()).await.expect("Failed to query for device.").ok_or_else(|| {
        log::info!("HTTP signature references an unknown device (keyid={}).", parsed.keyid);
        error_message(3002, axum::http::StatusCode::UNAUTHORIZED, "Invalid request signature.".to_string())
    })?;

    http_signature::verify_parsed(&parsed, &device.public_key, ctx, max_age_secs).map_err(|error| {
        log::info!("HTTP signature verification failed: {}", error);
        error_message(3003, axum::http::StatusCode::UNAUTHORIZED, "Invalid request signature.".to_string())
    })?;

    return Ok(device);
}