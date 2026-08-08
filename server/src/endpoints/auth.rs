use axum::extract::ConnectInfo;
use axum::response::{Response, IntoResponse};
use serde_json::{json, Value};
use std::net::SocketAddr;
use crate::auth_method_handling::handling_email_magiclink;
use crate::auth_method_request::request_email;
use crate::device::device_create;
use crate::global::is_valid_authentication_method;
use crate::hostname::{device_authentication_hostname, get_hostname, is_valid_authentication_method_for_hostname};
use crate::responses::fatal_error;
use crate::{EssentialAuthenticateRequestData, GuardUser, Magiclink, MagiclinkHandlingData, MagiclinkRequestData, MethodRequestBody, RequestMagiclink};
use crate::error_message;
use crate::structs::*;

#[derive(serde::Deserialize)]
pub struct HostQuery {
    host: Option<String>,
}

// The request/authenticate logic lives in `run_auth_request` / `run_authenticate`
// exactly once. The endpoints below differ ONLY in how they resolve the auth
// context (`GuardedHostname`): a client-supplied [hostname.*], or the general
// [device_authentication] context. Keeping a single pipeline ensures security
// logic (auth-method validation, policies, magiclink verification) can't be
// applied to one flow and forgotten on the other.

// ---- Auth-method request (send magiclink / begin auth) ----

async fn run_auth_request(hostname: GuardedHostname, remote_addr: SocketAddr, body: MethodRequestBody) -> Response {
    let authentication_method_result = is_valid_authentication_method(body.authentication_method.clone()).await;
    if authentication_method_result.is_none() != false {
        return error_message(6003, axum::http::StatusCode::BAD_REQUEST, "body.authentication_method is not a valid authentication method.".to_string());
    }
    let authentication_method = authentication_method_result.unwrap();

    let valid_authentication_method_for_hostname = is_valid_authentication_method_for_hostname(hostname.clone(), authentication_method.clone()).await;
    if valid_authentication_method_for_hostname.is_ok() != true {
        return error_message(6004, axum::http::StatusCode::BAD_REQUEST, "Invalid authentication method for hostname.".to_string());
    }

    if authentication_method.method_type == "email" {
        let request_data: MagiclinkRequestData = serde_json::from_value(body.request_data.clone()).unwrap();

        if request_data.email.is_none() {
            return error_message(6005, axum::http::StatusCode::BAD_REQUEST, "body.request_data.email is null or whitespace.".to_string());
        }
        let requested_email = request_data.email.clone().expect("Missing body.request_data.email");

        let request_magiclink_response: RequestMagiclink = request_email(requested_email.clone(), authentication_method, request_data.clone(), remote_addr, hostname).await.expect("Failed to send magiclink.");
        if request_magiclink_response.error_to_respond_to_client_with.is_none() == false {
            return request_magiclink_response.error_to_respond_to_client_with.unwrap();
        }
    } else {
        log::info!("authentication_method.method_type is invalid. Something went wrong in startup config validation.");
        return fatal_error();
    }

    (
        axum::http::StatusCode::OK,
        serde_json::to_string(&json!({
            "ok": true
        })).unwrap(),
    ).into_response()
}

pub async fn auth_method_request(params: axum::extract::Query<HostQuery>, ConnectInfo(remote_addr): ConnectInfo<SocketAddr>, _headers: axum::http::HeaderMap, axum::Json(body): axum::Json<MethodRequestBody>) -> Response {
    if params.host.is_none() == true {
        return error_message(6001, axum::http::StatusCode::BAD_REQUEST, "params.host is null or whitespace.".to_string());
    }
    let hostname_result = get_hostname(params.host.clone().unwrap()).await;
    if hostname_result.is_err() == true {
        return error_message(6002, axum::http::StatusCode::BAD_REQUEST, "params.host is invalid.".to_string());
    }

    run_auth_request(hostname_result.unwrap(), remote_addr, body).await
}

// Device authentication: no client-supplied host; the context comes from
// [device_authentication]. Same pipeline as above.
pub async fn auth_device_request(ConnectInfo(remote_addr): ConnectInfo<SocketAddr>, _headers: axum::http::HeaderMap, axum::Json(body): axum::Json<MethodRequestBody>) -> Response {
    let hostname = match device_authentication_hostname() {
        Ok(hostname) => hostname,
        Err(error) => return error_message(6002, axum::http::StatusCode::BAD_REQUEST, error),
    };

    run_auth_request(hostname, remote_addr, body).await
}

// ---- Authenticate (verify magiclink) ----

// Shared security core for both authenticate flows: validates the auth method,
// enforces the hostname/policy check, and verifies the magiclink. Returns the
// authenticated user id + method. The *terminal action* differs per caller
// (enroll a browser-supplied key now, vs issue a device setup token), but every
// security check lives here so neither flow can skip one.
async fn authenticate_user(hostname: GuardedHostname, remote_addr: SocketAddr, body: &MethodRequestBody) -> Result<(String, AuthMethod), Response> {
    let authentication_method = match is_valid_authentication_method(body.authentication_method.clone()).await {
        Some(method) => method,
        None => return Err(error_message(7002, axum::http::StatusCode::BAD_REQUEST, "body.authentication_method is not a valid authentication method.".to_string())),
    };

    let valid_authentication_method_for_hostname = is_valid_authentication_method_for_hostname(hostname.clone(), authentication_method.clone()).await;
    if valid_authentication_method_for_hostname.is_ok() != true {
        return Err(error_message(7003, axum::http::StatusCode::BAD_REQUEST, "Invalid authentication method for hostname.".to_string()));
    }

    // This is the user data the external authentication method is returning. For example, when an unauthenticated client attempts to prove themself via oauth, whatever data returned in the user-info oauth endpoint is returned here. This data is very random, for example, it may not contain an email.
    let mut _attempted_external_user: Option<Value> = None;
    let mut _attempted_authentication_method: Option<String> = None;
    if authentication_method.method_type == "email" {
        let request_data: MagiclinkHandlingData = serde_json::from_value(body.request_data.clone()).unwrap();
        let handling_magiclink = handling_email_magiclink(request_data.clone(), authentication_method.clone(), remote_addr).await.expect("Failed to verify magiclink.");
        if handling_magiclink.error_to_respond_to_client_with.is_none() == false {
            return Err(handling_magiclink.error_to_respond_to_client_with.unwrap());
        }

        let magiclink: Magiclink = handling_magiclink.magiclink.unwrap();

        let user: GuardUser = handling_magiclink.user.unwrap();
        let user_value: Value = serde_json::to_value(user).expect("Failed to convert user to json value");
        _attempted_external_user = Some(user_value);
        _attempted_authentication_method = Some(magiclink.authentication_method);
    } else {
        log::info!("authentication_method.method_type is invalid. Something went wrong in startup config validation.");
        return Err(fatal_error());
    }

    if _attempted_external_user.is_none() == true {
        log::info!("Authentication method did not return user info.");
        return Err(fatal_error());
    }

    if _attempted_authentication_method.is_none() == true || _attempted_authentication_method.clone().unwrap() != authentication_method.method_type.clone() {
        log::info!("Authentication method mismatch. Client specified '{}', when the trusted authentication method returned '{}'", authentication_method.method_type.clone(), _attempted_authentication_method.clone().unwrap());
        return Err(fatal_error());
    }

    let attempted_external_user_unwrapped = _attempted_external_user.unwrap();
    let user_id: String = attempted_external_user_unwrapped.get("id").unwrap().as_str().expect("Missing attempted_external_user.id").to_string();

    Ok((user_id, authentication_method))
}

// Browser-as-device: the login page generated the keypair and sends its public
// key here, so the device is enrolled immediately.
pub async fn authenticate(params: axum::extract::Query<HostQuery>, ConnectInfo(remote_addr): ConnectInfo<SocketAddr>, _headers: axum::http::HeaderMap, axum::Json(body): axum::Json<MethodRequestBody>) -> Response {
    if params.host.is_none() == true {
        return error_message(7001, axum::http::StatusCode::BAD_REQUEST, "params.host is null or whitespace.".to_string());
    }
    let hostname_check = get_hostname(params.host.clone().unwrap()).await;
    if hostname_check.is_err() == true {
        return error_message(7001, axum::http::StatusCode::BAD_REQUEST, "params.host is invalid.".to_string());
    }
    let hostname = hostname_check.unwrap();

    let (user_id, authentication_method) = match authenticate_user(hostname.clone(), remote_addr, &body).await {
        Ok(result) => result,
        Err(response) => return response,
    };

    let essential_authenticate_request_data: EssentialAuthenticateRequestData = serde_json::from_value(body.request_data.clone()).unwrap();
    let public_key = essential_authenticate_request_data.public_key;

    // TODO: Collateral should be removed. Oauth isn't handled this way anymore.
    let device_id = device_create(
        user_id,
        authentication_method.clone().id.unwrap(),
        Some("".to_string()),
        public_key
    ).await.expect("Failed to create device");

    let public_authmethod: AuthMethodPublic = authentication_method.into();
    let hostname_pub: GuardedHostnamePub = hostname.into();

    (
        axum::http::StatusCode::OK,
        serde_json::to_string(&json!({
            "ok": true,
            "device_id": device_id,
            "authentication_method": public_authmethod,
            "hostname": hostname_pub
        })).unwrap(),
    ).into_response()
}

// Desktop-as-device: no client-supplied host, and we deliberately do NOT accept
// a public key here. A public key preset in a phishing URL must not be able to
// enroll an attacker's device under the victim. Instead we issue a one-time,
// short-lived setup token bound to the authenticated user; the desktop app posts
// its own public key with that token to `auth_device_enroll`.
pub async fn auth_device_authenticate(ConnectInfo(remote_addr): ConnectInfo<SocketAddr>, _headers: axum::http::HeaderMap, axum::Json(body): axum::Json<MethodRequestBody>) -> Response {
    let hostname = match device_authentication_hostname() {
        Ok(hostname) => hostname,
        Err(error) => return error_message(7001, axum::http::StatusCode::BAD_REQUEST, error),
    };

    let (user_id, authentication_method) = match authenticate_user(hostname, remote_addr, &body).await {
        Ok(result) => result,
        Err(response) => return response,
    };

    let setup_token = crate::setup_token::issue(user_id, authentication_method.id.clone().unwrap());

    (
        axum::http::StatusCode::OK,
        serde_json::to_string(&json!({
            "ok": true,
            "setup_token": setup_token
        })).unwrap(),
    ).into_response()
}

#[derive(serde::Deserialize)]
pub struct DeviceEnrollBody {
    setup_token: Option<String>,
    public_key: Option<String>,
}

// Enroll a device using a setup token from `auth_device_authenticate`. The
// public key is supplied here by the desktop app over its own connection (never
// via the browser URL), so an attacker cannot preset it.
pub async fn auth_device_enroll(axum::Json(body): axum::Json<DeviceEnrollBody>) -> Response {
    let setup_token = match body.setup_token {
        Some(token) if token.is_empty() == false => token,
        _ => return error_message(7201, axum::http::StatusCode::BAD_REQUEST, "body.setup_token is null or whitespace.".to_string()),
    };
    let public_key = match body.public_key {
        Some(key) if key.is_empty() == false => key,
        _ => return error_message(7202, axum::http::StatusCode::BAD_REQUEST, "body.public_key is null or whitespace.".to_string()),
    };

    let (user_id, authentication_method_id) = match crate::setup_token::consume(&setup_token) {
        Some(pair) => pair,
        None => return error_message(7203, axum::http::StatusCode::UNAUTHORIZED, "Invalid or expired setup token.".to_string()),
    };

    let device_id = device_create(
        user_id,
        authentication_method_id,
        Some("".to_string()),
        public_key
    ).await.expect("Failed to create device");

    (
        axum::http::StatusCode::OK,
        serde_json::to_string(&json!({
            "ok": true,
            "device_id": device_id
        })).unwrap(),
    ).into_response()
}
