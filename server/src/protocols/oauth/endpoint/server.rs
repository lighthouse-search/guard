use serde_json::{json, Value};
use std::net::SocketAddr;

use rocket::{http::Status, response::status::{self, Custom}, get};

use diesel::sql_query;
use diesel::prelude::*;
use diesel::sql_types::*;

use crate::{hostname::hostname_auth_exit_flow, structs::*};
use crate::protocols::oauth::{client::oauth_code_exchange_for_access_key, pipeline::oauth_get_data_from_oauth_login_url};
use crate::{error_message, Headers};
use crate::global::is_null_or_whitespace;
use crate::device::device_signed_authentication;
use crate::protocols::oauth::server::bearer_token::create_access_and_refresh_tokens;
use rocket::form::Form;
use rocket::FromForm;
use rocket::post;
use serde::Deserialize;

#[derive(FromForm, Deserialize, Debug, Clone)]
struct AuthRequest {
    grant_type: Option<String>,
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
}

#[post("/token", data = "<auth_request>")]
pub async fn oauth_server_token(auth_request: Form<AuthRequest>, remote_addr: SocketAddr, headers: &Headers) -> Result<Custom<Value>, Status> {
    let grant_type = auth_request.grant_type.clone();
    let code = auth_request.code.clone();
    let redirect_uri = auth_request.redirect_uri.clone();

    // TODO: client_id and client_secret aren't validated.
    // TODO: There's no application gating.
    let client_id = auth_request.client_id.clone();
    let client_secret = auth_request.client_secret.clone();

    if (is_null_or_whitespace(client_id.clone())) {
        return Ok(status::Custom(Status::BadRequest, error_message("params.client_id is null or whitespace.")));
    }
    if (is_null_or_whitespace(redirect_uri.clone())) {
        return Ok(status::Custom(Status::BadRequest, error_message("params.redirect_uri is null or whitespace.")));
    }
    if (is_null_or_whitespace(code.clone())) {
        return Ok(status::Custom(Status::BadRequest, error_message("params.code is null or whitespace.")));
    }

    let (device, additional_data) = device_signed_authentication(code.unwrap()).await.expect("Authentication failed.");

    let mut errors: Vec<String> = Vec::new();

    let code_data: Oauth_server_token_code = serde_json::from_value(additional_data.unwrap()).expect("Failed to parse OAuth code metadata.");
    if (code_data.client_id.is_none()) {
        errors.push(String::from("params.code.client_id is null or whitespace."));
    }
    if (code_data.scope.is_none()) {
        errors.push(String::from("params.code.scope is null or whitespace."));
    }
    if (code_data.redirect_uri.is_none()) {
        errors.push(String::from("params.code.redirect_uri is null or whitespace."));
    }
    if (code_data.grant_type.is_none()) {
        errors.push(String::from("params.code.grant_type is null or whitespace."));
    }
    if (code_data.nonce.is_none()) {
        errors.push(String::from("params.code.nonce is null or whitespace."));
    }

    if (errors.len() > 0) {
        return Ok(status::Custom(Status::BadRequest, json!(
            {
                "error": true,
                "message": errors
            }
        )));
    }

    let client_id_unwrapped = client_id.clone().unwrap();
    let nonce_unwrapped = code_data.nonce.clone().unwrap();
    let scope_unwrapped: Vec<String> = code_data.scope.clone().unwrap().split(" ").map(|s| s.to_string()).collect();

    // Verify code is signed for client_id and redirect_uri.
    if (code_data.client_id.unwrap() != client_id_unwrapped) {
        errors.push(String::from("params.code is not signed for params.client_id"));
    }

    if (code_data.redirect_uri.unwrap() != redirect_uri.unwrap()) {
        errors.push(String::from("params.code is not signed for params.redirect_uri"));
    }

    let valid_scopes: Vec<String> = vec![String::from("user_information_read"), String::from("email_read"), String::from("authentication_method_read")];
    let scopes: Vec<String> = code_data.scope.unwrap().split(' ').map(|s| s.to_string()).collect();
    for scope in scopes {
        if (valid_scopes.contains(&scope) == false) {
            // Invalid scope.
            errors.push(format!("\"{}\" is an invalid scope.", scope));
        }
    }

    if (errors.len() > 0) {
        return Ok(status::Custom(Status::BadRequest, json!(
            {
                "error": true,
                "message": errors
            }
        )));
    }
    // -------------- Verify code is signed for client_id and redirect_uri.

    let access_and_refresh_tokens = create_access_and_refresh_tokens(&device.user_id, &client_id_unwrapped.clone(), &nonce_unwrapped.clone(), scope_unwrapped.clone()).await;

    // TODO: Verify params.code expiry time.
    // TODO: Verify scope, redirect url and grant type against application metadata.
    // TODO: Delete existing tokens after new authentication.
    // TODO: Verify user isn't suspended.
    
    // {
    //     device_id: credentials_object_v.deviceid,
    //     client_id: oauth.client_id,
    //     scope: search_params.get("scope"),
    //     redirect_uri: search_params.get("redirect_uri"),
    //     grant_type: search_params.get("grant_type")
    // }

    Ok(status::Custom(Status::Ok, json!(
        {
            "token_type": "Bearer",
            "expires_in": 3600,
            "access_token": access_and_refresh_tokens.access_token.hash,
            "refresh_token": access_and_refresh_tokens.refresh_token.hash,
        }
    )))
}