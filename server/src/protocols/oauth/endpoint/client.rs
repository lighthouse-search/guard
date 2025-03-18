use serde_json::{json, Value};
use std::net::SocketAddr;

use rocket::{http::Status, response::status::{self, Custom}, get};

use diesel::sql_query;
use diesel::prelude::*;
use diesel::sql_types::*;

use crate::{global::{get_hostname, is_valid_authentication_method_for_hostname}, hostname::hostname_auth_exit_flow, structs::*};

use crate::{error_message, global::get_authentication_method, globals::environment_variables, protocols::oauth::{client::oauth_code_exchange_for_access_key, pipeline::oauth_get_data_from_oauth_login_url}, Headers};

#[get("/exchange-code?<authentication_method>&<code>&<host>")]
pub async fn oauth_exchange_code(mut authentication_method: Option<String>, code: Option<String>, host: Option<String>, remote_addr: SocketAddr, headers: &Headers) -> Result<Custom<Value>, Status> {
    if (authentication_method.is_none() == true) {
        return Ok(status::Custom(Status::BadRequest, error_message("params.authentication_method is null.")));
    }
    if (code.is_none() == true) {
        return Ok(status::Custom(Status::BadRequest, error_message("params.code is null.")));
    }

    let authentication_method_string_unwrapped = authentication_method.unwrap();
    
    let mut auth_method_wrapped = get_authentication_method(authentication_method_string_unwrapped.clone(), true).await;
    if (auth_method_wrapped.is_none() == true) {
        return Ok(status::Custom(Status::BadRequest, error_message(&format!("'{}' is not a valid authentication method", authentication_method_string_unwrapped))));
    }
    let auth_method = auth_method_wrapped.unwrap();
    if (auth_method.method_type != "oauth") {
        return Ok(status::Custom(Status::BadRequest, error_message(&format!("authentication method '{}' is not oauth", authentication_method_string_unwrapped))));
    }

    let oauth_client_secret_env = auth_method.oauth_client_secret_env.clone().unwrap();
    let client_secret: String = environment_variables::get(oauth_client_secret_env.clone()).expect(&format!("environment variable '{}' is missing.", oauth_client_secret_env));

    let data_from_login_url = oauth_get_data_from_oauth_login_url(auth_method.login_page.clone());
    let result = oauth_code_exchange_for_access_key(
        auth_method.oauth_client_token_endpoint.clone().unwrap(),
        auth_method.oauth_client_id.clone().unwrap(),
        client_secret,
        code.unwrap(),
        data_from_login_url.scope.unwrap(),
        data_from_login_url.redirect_uri.unwrap()
    ).await.expect("Failed to get oauth code exchange, something went wrong during the request");
    
    if (result.is_none() == true) {
        println!("External authentication failed. Most likely because the client is unauthorized, or there's an issue with the application oauth information provided for this authentication-method in the config (Are your OAuth URLs, client-id, client-secret, redirect_uri and scope all valid?)");
        return Ok(status::Custom(Status::Unauthorized, error_message("Unauthorized, external authentication failed.")));
    }

    let oauth_code_exchange = result.unwrap();

    if (host.is_none() == true) {
        return Ok(status::Custom(Status::BadRequest, error_message("params.hostname is null or whitespace.")));
    }
    
    let hostname_result = hostname_auth_exit_flow(host.unwrap(), auth_method).await;
    if (hostname_result.is_none() == true) {
        return Ok(status::Custom(Status::BadRequest, error_message("Invalid params.host")));
    }

    Ok(status::Custom(Status::Ok, json!({
        "ok": true,
        "access_token": oauth_code_exchange.access_token,
        "hostname": hostname_result.unwrap()
    })))
}