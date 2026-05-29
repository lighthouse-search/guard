use axum::extract::{ConnectInfo, Query};
use axum::response::{Response, IntoResponse};

use serde_json::{json, Value};
use std::net::SocketAddr;

use crate::hostname::hostname_auth_exit_flow;
use crate::{error_message, global::get_authentication_method, globals::environment_variables, protocols::oauth::{client::oauth_code_exchange_for_access_key, pipeline::oauth_get_data_from_oauth_login_url}};

#[derive(serde::Deserialize)]
pub struct QueryDetails {
    authentication_method: Option<String>,
    code: Option<String>,
    host: Option<String>,
}
pub async fn oauth_exchange_code(params: Query<QueryDetails>, axum::extract::ConnectInfo(remote_addr): axum::extract::ConnectInfo<SocketAddr>, _headers: axum::http::HeaderMap) -> Response {
    if params.authentication_method.is_none() == true {
        return error_message(10001, axum::http::StatusCode::BAD_REQUEST, "params.authentication_method is null.".to_string());
    }
    if params.code.is_none() == true {
        return error_message(10002, axum::http::StatusCode::BAD_REQUEST, "params.code is null.".to_string());
    }

    let authentication_method_string_unwrapped = params.authentication_method.clone().unwrap();
    
    let auth_method_wrapped = get_authentication_method(authentication_method_string_unwrapped.clone(), true).await;
    if auth_method_wrapped.is_none() == true {
        return error_message(10003, axum::http::StatusCode::BAD_REQUEST, format!("'{}' is not a valid authentication method", authentication_method_string_unwrapped));
    }
    let auth_method = auth_method_wrapped.unwrap();
    if auth_method.method_type != "oauth" {
        return error_message(10004, axum::http::StatusCode::BAD_REQUEST, format!("authentication method '{}' is not oauth", authentication_method_string_unwrapped));
    }

    let oauth_client_secret_env = auth_method.oauth_client_secret_env.clone().unwrap();
    let client_secret: String = environment_variables::get(oauth_client_secret_env.clone()).expect(&format!("environment variable '{}' is missing.", oauth_client_secret_env));

    let data_from_login_url = oauth_get_data_from_oauth_login_url(auth_method.login_page.clone().expect("Missing login_page"));
    let result = oauth_code_exchange_for_access_key(
        auth_method.oauth_client_token_endpoint.clone().expect("Missing auth_method.oauth_client_token_endpoint"),
        auth_method.oauth_client_id.clone().expect("Missing auth_method.oauth_client_id"),
        client_secret,
        params.code.clone().unwrap(),
        data_from_login_url.scope.unwrap(),
        data_from_login_url.redirect_uri.unwrap()
    ).await.expect("Failed to get oauth code exchange, something went wrong during the request");
    
    if result.is_none() == true {
        log::info!("External authentication failed. Most likely because the client is unauthorized, or there's an issue with the application oauth information provided for this authentication-method in the config (Are your OAuth URLs, client-id, client-secret, redirect_uri and scope all valid?)");
        return error_message(10005, axum::http::StatusCode::BAD_REQUEST, "Unauthorized, external authentication failed.".to_string());
    }

    let oauth_code_exchange = result.unwrap();

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
            "access_token": oauth_code_exchange.access_token,
            "hostname": hostname_result.unwrap()
        })).unwrap(),
    ).into_response()
}