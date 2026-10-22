use axum::extract::Query;
use axum::response::{Response, IntoResponse};

use serde_json::json;
use std::net::SocketAddr;

use crate::hostname::{device_authentication_hostname, hostname_auth_exit_flow, is_valid_authentication_method_for_hostname};
use crate::policy::{get_hostname_policies, policy_authentication};
use crate::structs::AuthMethod;
use crate::{error_message, global::get_authentication_method, globals::environment_variables, protocols::oauth::{client::{oauth_code_exchange_for_access_key, oauth_userinfo}, pipeline::oauth_get_data_from_oauth_login_url}};

#[derive(serde::Deserialize)]
pub struct QueryDetails {
    authentication_method: Option<String>,
    code: Option<String>,
    host: Option<String>,
}

// Shared core: validate the authentication method is a real oauth method and
// exchange the authorization `code` for the identity provider's access token.
// Both the browser (host-scoped) and desktop-device exchange endpoints go
// through here, so the "is this a valid oauth method / did the exchange succeed"
// checks can't diverge between the two flows. Returns (auth_method, access_token).
async fn oauth_exchange(authentication_method: Option<String>, code: Option<String>) -> Result<(AuthMethod, String), Response> {
    let authentication_method = match authentication_method {
        Some(value) => value,
        None => return Err(error_message(10001, axum::http::StatusCode::BAD_REQUEST, "params.authentication_method is null.".to_string())),
    };
    let code = match code {
        Some(value) => value,
        None => return Err(error_message(10002, axum::http::StatusCode::BAD_REQUEST, "params.code is null.".to_string())),
    };

    let auth_method = match get_authentication_method(authentication_method.clone(), true).await {
        Some(method) => method,
        None => return Err(error_message(10003, axum::http::StatusCode::BAD_REQUEST, format!("'{}' is not a valid authentication method", authentication_method))),
    };
    if auth_method.method_type != "oauth" {
        return Err(error_message(10004, axum::http::StatusCode::BAD_REQUEST, format!("authentication method '{}' is not oauth", authentication_method)));
    }

    let oauth_client_secret_env = auth_method.oauth_client_secret_env.clone().unwrap();
    let client_secret: String = environment_variables::get(oauth_client_secret_env.clone()).expect(&format!("environment variable '{}' is missing.", oauth_client_secret_env));

    let data_from_login_url = oauth_get_data_from_oauth_login_url(auth_method.login_page.clone().expect("Missing login_page"));
    let result = oauth_code_exchange_for_access_key(
        auth_method.oauth_client_token_endpoint.clone().expect("Missing auth_method.oauth_client_token_endpoint"),
        auth_method.oauth_client_id.clone().expect("Missing auth_method.oauth_client_id"),
        client_secret,
        code,
        data_from_login_url.scope.unwrap(),
        data_from_login_url.redirect_uri.unwrap()
    ).await.expect("Failed to get oauth code exchange, something went wrong during the request");

    if result.is_none() == true {
        log::info!("External authentication failed. Most likely because the client is unauthorized, or there's an issue with the application oauth information provided for this authentication-method in the config (Are your OAuth URLs, client-id, client-secret, redirect_uri and scope all valid?)");
        return Err(error_message(10005, axum::http::StatusCode::BAD_REQUEST, "Unauthorized, external authentication failed.".to_string()));
    }

    // access_token is guaranteed Some here — oauth_code_exchange_for_access_key
    // returns None (handled above) when the provider omitted it.
    let access_token = result.unwrap().access_token.expect("access_token missing after non-None exchange");
    Ok((auth_method, access_token))
}

// Browser login: the browser keeps the identity provider's access token as its
// credential (validated live per request by oauth_pipeline), so this returns the
// access token for the client to store.
pub async fn oauth_exchange_code(params: Query<QueryDetails>, axum::extract::ConnectInfo(_remote_addr): axum::extract::ConnectInfo<SocketAddr>, _headers: axum::http::HeaderMap) -> Response {
    let (auth_method, access_token) = match oauth_exchange(params.authentication_method.clone(), params.code.clone()).await {
        Ok(result) => result,
        Err(response) => return response,
    };

    if params.host.is_none() == true {
        return error_message(10006, axum::http::StatusCode::BAD_REQUEST, "params.hostname is null or whitespace.".to_string());
    }

    let hostname_result = hostname_auth_exit_flow(params.host.clone().unwrap(), auth_method).await;
    if hostname_result.is_none() == true {
        return error_message(10007, axum::http::StatusCode::BAD_REQUEST, "Invalid params.host".to_string());
    }

    (
        axum::http::StatusCode::OK,
        serde_json::to_string(&json!({
            "ok": true,
            "access_token": access_token,
            "hostname": hostname_result.unwrap()
        })).unwrap(),
    ).into_response()
}

// Device authentication (opened by the desktop app): completed entirely in the
// browser. We resolve the external user (same lookup the reverse-proxy oauth
// pipeline uses), then issue a one-time setup token bound to that user —
// mirroring the email device flow (auth_device_authenticate). The browser hands
// that setup token to the desktop over the loopback callback; the desktop
// enrolls its own ed25519 key with it (auth_device_enroll) and never touches
// oauth. The provider access token is used only to look the user up, then
// discarded.
pub async fn oauth_device_exchange_code(params: Query<QueryDetails>, axum::extract::ConnectInfo(remote_addr): axum::extract::ConnectInfo<SocketAddr>, _headers: axum::http::HeaderMap) -> Response {
    let (auth_method, access_token) = match oauth_exchange(params.authentication_method.clone(), params.code.clone()).await {
        Ok(result) => result,
        Err(response) => return response,
    };

    // Device authentication has no client-supplied host; validate the method
    // against the general [device_authentication] context.
    let hostname = match device_authentication_hostname() {
        Ok(hostname) => hostname,
        Err(error) => return error_message(10006, axum::http::StatusCode::BAD_REQUEST, error),
    };
    if is_valid_authentication_method_for_hostname(hostname.clone(), auth_method.clone()).await.is_ok() != true {
        return error_message(10007, axum::http::StatusCode::BAD_REQUEST, "Invalid authentication method for device authentication.".to_string());
    }

    // Resolve the external user the same way the reverse-proxy oauth pipeline
    // does, so the device is bound to the same identity.
    let user_info = match oauth_userinfo(auth_method.oauth_client_user_info.clone().expect("Missing oauth_client_user_info"), access_token).await {
        Ok(user_info) => user_info,
        Err(error) => {
            log::info!("Failed to get oauth userinfo for device authentication: {}", error);
            return error_message(10008, axum::http::StatusCode::UNAUTHORIZED, "Unauthorized, external authentication failed.".to_string());
        }
    };
    let user_id = match user_info.get("id").and_then(|id| id.as_str()) {
        Some(id) => id.to_string(),
        None => {
            log::info!("oauth userinfo did not contain an 'id' field.");
            return error_message(10009, axum::http::StatusCode::BAD_REQUEST, "External authentication did not return a user id.".to_string());
        }
    };

    // Authorise the resolved identity against [device_authentication].applied_policies
    // BEFORE issuing a setup token. is_valid_authentication_method_for_hostname above
    // only checks the method is permitted — it never reads applied_policies — so
    // without this a device could be enrolled for any identity the provider will
    // authenticate. This mirrors user_authentication_pipeline (the reverse proxy) and
    // user_get_otherwise_create (the email device flow): policy_authentication is
    // deny-by-default, so an empty policy list refuses, exactly as it does there.
    //
    // The provider's whole user object is the subject, so policies can match on any
    // claim it returns (email, hd, organisation, ...), the same data the reverse-proxy
    // oauth pipeline evaluates.
    if policy_authentication(get_hostname_policies(hostname, true).await, user_info.clone(), remote_addr.to_string()).await == false {
        log::info!("Device authentication refused by policy for authentication method '{}'.", auth_method.id.clone().unwrap_or_default());
        return error_message(10010, axum::http::StatusCode::UNAUTHORIZED, "Unauthorized due to policy".to_string());
    }

    let setup_token = crate::setup_token::issue(user_id, auth_method.id.clone().unwrap());

    (
        axum::http::StatusCode::OK,
        serde_json::to_string(&json!({
            "ok": true,
            "setup_token": setup_token
        })).unwrap(),
    ).into_response()
}