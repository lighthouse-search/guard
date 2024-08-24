use rocket::response::status::Custom;
use rocket::{http::Status, response::status, serde::json::Json, post};
use serde_json::{json, Value};
use std::net::SocketAddr;
use crate::auth_method_handling::handling_email_magiclink;
use crate::auth_method_request::request_email;
use crate::device::device_create;
use crate::global::is_valid_authentication_method;
use crate::hostname::hostname_auth_exit_flow;
use crate::users::attempted_external_user_handling;
use crate::{Essential_authenticate_request_data, Guard_user, Magiclink, Magiclink_handling_data, Magiclink_request_data, Method_request_body, Request_magiclink};
use crate::{error_message, global::{get_hostname, is_null_or_whitespace, is_valid_authentication_method_for_hostname}, Headers};
use crate::structs::*;

use diesel::sql_query;
use diesel::prelude::*;
use diesel::sql_types::*;

#[post("/request?<host>", format = "application/json", data = "<body>")]
pub async fn auth_method_request(mut host: Option<String>, mut body: Json<Method_request_body>, remote_addr: SocketAddr, headers: &Headers) -> Result<Custom<Value>, Status> {
    let mut db = crate::DB_POOL.get().expect("Failed to get a connection from the pool.");

    if (host.is_none() == true) {
        return Ok(status::Custom(Status::BadRequest, error_message("params.host is null or whitespace.")));
    }
    let hostname_result = get_hostname(host.unwrap()).await;
    if (hostname_result.is_err() == true) {
        return Ok(status::Custom(Status::BadRequest, error_message("params.host is invalid.")));
    }
    let hostname = hostname_result.unwrap();

    let authentication_method_result = is_valid_authentication_method(body.authentication_method.clone()).await;
    if (authentication_method_result.is_none() != false) {
        return Ok(status::Custom(Status::BadRequest, error_message("body.authentication_method is not a valid authentication method.")));
    }

    let authentication_method = authentication_method_result.unwrap();
    
    let is_valid_hostname_for_authmethod_result = is_valid_authentication_method_for_hostname(hostname.clone(), authentication_method.clone()).await.expect("Invalid authentication method for hostname.");;
    // if (is_valid_hostname_for_authmethod_result.is_ok() != true) {
    //     return Ok(status::Custom(Status::BadRequest, error_message("Invalid authentication method for hostname.".into())));
    // }

    if (authentication_method.method_type == "email") {
        let request_data: Magiclink_request_data = serde_json::from_value(body.request_data.clone()).unwrap();
        
        if (request_data.email.is_none()) {
            // Return error.
            return Ok(status::Custom(Status::BadRequest, error_message("body.request_data.email is null or whitespace.")));
        }
        let mut requested_email = request_data.email.clone().expect("Missing body.request_data.email");

        let (request_magiclink_response): (Request_magiclink) = request_email(requested_email.clone(), authentication_method, request_data.clone(), remote_addr, hostname).await.expect("Failed to send magiclink.");
        if (request_magiclink_response.error_to_respond_to_client_with.is_none() == false) {
            return Ok(request_magiclink_response.error_to_respond_to_client_with.unwrap());
        }
    } else {
        println!("authentication_method.method_type is invalid. Something went wrong in startup config validation.");
        return Err(Status::InternalServerError);
    }

    Ok(status::Custom(Status::Ok, json!({
        "ok": true
    })))
}

#[post("/authenticate?<host>", format = "application/json", data = "<body>")]
pub async fn authenticate(mut host: Option<String>, mut body: Json<Method_request_body>, remote_addr: SocketAddr, headers: &Headers) -> Result<Custom<Value>, Status> {
    let mut db = crate::DB_POOL.get().expect("Failed to get a connection from the pool.");

    // TODO: this should return 404 instead of error.
    let hostname_check = get_hostname(host.unwrap()).await;
    if (hostname_check.is_err() == true) {
        return Ok(status::Custom(Status::BadRequest, error_message("params.host is invalid.".into())));
    }
    let hostname = hostname_check.unwrap();

    let authentication_method_result = is_valid_authentication_method(body.authentication_method.clone()).await;
    if (authentication_method_result.is_none() != false) {
        return Ok(status::Custom(Status::BadRequest, error_message("body.authentication_method is not a valid authentication method.".into())));
    }
    let authentication_method = authentication_method_result.unwrap();

    let is_valid_hostname_for_authmethod_result = is_valid_authentication_method_for_hostname(hostname.clone(), authentication_method.clone()).await.expect("Invalid authentication method for hostname.");
    // if (is_valid_hostname_for_authmethod_result.is_ok() != true) {
    //     return Ok(status::Custom(Status::BadRequest, error_message("Invalid authentication method for hostname.".into())));
    // }

    // This is the user data the external authentication method is returning. For example, when an unauthenticated client attempts to prove themself via oauth, whatever data returned in the user-info oauth endpoint is returned here. This data is very random, for example, it may not contain an email.

    // TODO: I don't know why these variables are called "attempted_[..]" when it's the user data returned from a trusted authentication method. This makes it sound as if the client is providing this data. These variables need to be updated.
    let mut attempted_external_user: Option<Value> = None;
    let mut attempted_authentication_method: Option<String> = None;
    if (authentication_method.method_type == "email") {
        let request_data: Magiclink_handling_data = serde_json::from_value(body.request_data.clone()).unwrap();
        let (handling_magiclink) = handling_email_magiclink(request_data.clone(), authentication_method.clone(), remote_addr).await.expect("Failed to verify magiclink.");
        if (handling_magiclink.error_to_respond_to_client_with.is_none() == false) {
            return Ok(handling_magiclink.error_to_respond_to_client_with.unwrap());
        }

        let magiclink: Magiclink = handling_magiclink.magiclink.unwrap();

        let user: Guard_user = handling_magiclink.user.unwrap();
        let user_value: Value = serde_json::to_value(user).expect("Failed to convert user to json value");
        attempted_external_user = Some(user_value);
        attempted_authentication_method = Some(magiclink.authentication_method);
    } else {
        println!("authentication_method.method_type is invalid. Something went wrong in startup config validation.");
        return Err(Status::InternalServerError);
    }

    if (attempted_external_user.is_none() == true) {
        // Authentication method did not return user info. This should have been handled in protocol specific functions, like 'handling_email_magiclink'.
        println!("Authentication method did not return user info.");
        return Err(Status::InternalServerError);
    }

    if (attempted_authentication_method.is_none() == true || attempted_authentication_method.clone().unwrap() != authentication_method.method_type.clone()) {
        println!("Authentication method mismatch. Client specified '{}', when the trusted authentication method returned '{}'", authentication_method.method_type.clone(), attempted_authentication_method.clone().unwrap());
        return Err(Status::InternalServerError);
    }

    println!("attempted_external_user: {:?}", attempted_external_user.clone());

    let essential_authenticate_request_data: Essential_authenticate_request_data = serde_json::from_value(body.request_data.clone()).unwrap();
    let public_key = essential_authenticate_request_data.public_key;

    let attempted_external_user_unwrapped = attempted_external_user.unwrap();
    let user_id: String = attempted_external_user_unwrapped.get("id").unwrap().as_str().expect("Missing attempted_external_user.id").to_string();
    
    // TODO: Collateral should be removed. Oauth isn't handled this way anymore.
    let (device_id) = device_create(
        user_id,
        authentication_method.clone().id.unwrap(),
        Some("".to_string()),
        public_key
    ).await.expect("Failed to create device");

    let public_authmethod: AuthMethod_Public = authentication_method.clone().into();
    
    let hostname_result = hostname_auth_exit_flow(hostname.host, authentication_method).await;
    if (hostname_result.is_none() == true) {
        return Ok(status::Custom(Status::BadRequest, error_message("Invalid params.host")));
    }

    Ok(status::Custom(Status::Ok, json!({
        "ok": true,
        "device_id": device_id,
        "authentication_method": public_authmethod,
        "hostname": hostname_result
    })))
}