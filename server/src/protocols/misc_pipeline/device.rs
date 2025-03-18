use serde::{Serialize, Deserialize};
use serde_json::{Value, json};

use rocket::response::status;
use rocket::http::{Status, CookieJar, Cookie};

use diesel::sql_query;
use diesel::prelude::*;
use diesel::sql_types::*;

use crate::global::{generate_random_id, get_hostname, get_authentication_method, is_valid_authentication_method_for_hostname};
use crate::responses::*;
use crate::structs::*;
use crate::tables::*;
use crate::policy::*;

use crate::device::{device_signed_authentication, device_get, device_guard_static_auth_from_cookies};
use crate::users::user_get;
use crate::hostname::prepend_hostname_to_cookie;

use std::error::Error;
use std::fmt::format;
use std::net::SocketAddr;

use hades_auth::*;

use crate::{CONFIG_VALUE, SQL_TABLES};

pub async fn device_pipeline_server_oauth(required_scopes: Vec<&str>, hostname: Guarded_Hostname, jar: &CookieJar<'_>, remote_addr: SocketAddr, headers: &Headers) -> Result<(bool, Option<Guard_user>, Option<Guard_devices>, Option<AuthMethod>), String> {
    // Check the Authroization header starts with ("Bearer "), consistent with OAuth standard.
    if (headers.headers_map.get("Authorization").expect("Missing Authorization header.").clone().starts_with("Bearer ") == false) {
        return Err(String::from("Authorization header does not start with 'Bearer '.").into());
    }
    let authorization_header = headers.headers_map.get("Authorization").expect("Missing Authorization header.").trim_start_matches("Bearer ");

    // Verify bearer_token (access token) is valid (generally and for this scope).
    let verify_token = crate::protocols::oauth::server::bearer_token::verify(authorization_header, required_scopes)
    .await
    .expect("Failed to verify token");
    
    // Cool, the token is valid for this scope.
    // The user may have given permissions to a token, but we need to ensure the administrator is allowing tokens from oauth applications to be used on a hostname.
    // The admin may have used "oauth" to handle OAuth applications generally.
    let oauth_general_authentication_method = get_authentication_method(String::from("oauth"), true).await; 
    
    // The admin may have used "oauth_[client_id]" to handle a specific OAuth application.
    let oauth_application_specific_id = format!("oauth_{}", verify_token.application_clientid);
    let oauth_application_authentication_method = get_authentication_method(oauth_application_specific_id.clone(), true).await;
    
    // Check if either authentication method is available.
    if (oauth_general_authentication_method.is_none() == true && oauth_application_authentication_method.is_none() == true) {
        return Err(format!("neither {} nor {} authentication methods exist.", "oauth", oauth_application_specific_id.clone()).into());
    }
    // >1 authentication method for this OAuth application is available. If the application specific authentication method is available, we'll use that.
    let using_authentication_method = if (oauth_application_authentication_method.is_none() == false) { oauth_application_authentication_method.unwrap() } else { oauth_general_authentication_method.unwrap() };

    // FUTURE: Should return error to client, saying authentication method is invalid for this hostname.
    is_valid_authentication_method_for_hostname(hostname.clone(), using_authentication_method.clone()).await.expect("Failed to validate authentication method for hostname");

    let (user_result) = user_get(Some(verify_token.user_id.clone()), None).await.expect("Failed to get user");
    let user: Guard_user = user_result.expect("User tied to token does not exist.");

    return Ok((true, Some(user), None, Some(using_authentication_method)));
}

pub async fn device_pipeline_static_auth(required_scopes: Vec<&str>, hostname: Guarded_Hostname, jar: &CookieJar<'_>, remote_addr: SocketAddr, headers: &Headers) -> Result<(bool, Option<Guard_user>, Option<Guard_devices>, Option<AuthMethod>), String> {
    // Guard device authentication. Uses Hades-Auth and is used with email authentication. Much more secure than bearer tokens as everything is signed.
    let signed_data = device_guard_static_auth_from_cookies(jar);
    if (signed_data.is_none() == true) {
        println!("missing {}", prepend_hostname_to_cookie("guard_static_auth"));
        return Err(format!("missing {}", prepend_hostname_to_cookie("guard_static_auth")));
    }

    let device_authentication = device_signed_authentication(signed_data.unwrap()).await;
    if (device_authentication.is_err() == true) {
        return Err(String::from("device signed authentication failed."));
    }
    let (device, additional_data) = device_authentication.unwrap();

    let device_authentication_method = get_authentication_method(device.authentication_method.clone(), true).await.expect("Invalid or missing authentication method.");
    
    // FUTURE: Should return error to client, saying authentication method is invalid for this hostname.
    is_valid_authentication_method_for_hostname(hostname.clone(), device_authentication_method.clone()).await.expect("Failed to validate authentication method for hostname");

    let (user_result) = user_get(Some(device.user_id.clone()), None).await.expect("Failed to get user");

    let user: Guard_user = user_result.expect("User tied to device does not exist.");

    return Ok((true, Some(user), Some(device), Some(device_authentication_method)));
}