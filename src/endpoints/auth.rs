use rocket::response::status::Custom;
use rocket::{http::Status, response::status, serde::json::Json};
use rocket_db_pools::{Database, Connection};
use rocket_db_pools::diesel::{MysqlPool, prelude::*};
use serde_json::{json, Value};
use std::net::SocketAddr;
use crate::auth_method_handling::handling_email_magiclink;
use crate::auth_method_request::request_email;
use crate::device::device_create;
use crate::global::is_valid_authentication_method;
use crate::users::attempted_external_user_handling;
use crate::{Essential_authenticate_request_data, Guard_user, Magiclink, Magiclink_handling_data, Magiclink_request_data, Method_request_body, Request_magiclink};
use crate::{error_message, global::{get_hostname, is_null_or_whitespace, is_valid_authentication_method_for_hostname}, Db, Headers};
use crate::structs::*;

#[post("/request?<host>", format = "application/json", data = "<body>")]
pub async fn auth_method_request(mut db: Connection<Db>, mut host: Option<String>, mut body: Json<Method_request_body>, remote_addr: SocketAddr, headers: &Headers) -> Result<Custom<Value>, Status> {
    if (host.is_none() == true) {
        return Ok(status::Custom(Status::BadRequest, error_message("params.hostname is null or whitespace.")));
    }
    let hostname = get_hostname(host.unwrap()).await.expect("Invalid or missing hostname.");

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
        let mut requested_email = request_data.email.clone().expect("Missing body.request_data.email");
        if (is_null_or_whitespace(requested_email.clone())) {
            // Return error.
            return Ok(status::Custom(Status::BadRequest, error_message("body.request_data.email is null or whitespace.")));
        }

        let (request_magiclink_response, request_magiclink_response_db): (Request_magiclink, Connection<Db>) = request_email(db, requested_email.clone(), authentication_method, request_data.clone(), remote_addr, hostname).await.expect("Failed to send magiclink.");
        if (request_magiclink_response.error_to_respond_to_client_with.is_none() == false) {
            return Ok(request_magiclink_response.error_to_respond_to_client_with.unwrap());
        }
        db = request_magiclink_response_db;
    } else {
        println!("authentication_method.method_type is invalid. Something went wrong in startup config validation.");
        return Err(Status::InternalServerError);
    }

    Ok(status::Custom(Status::Ok, json!({
        "ok": true
    })))
}

#[post("/authenticate?<host>", format = "application/json", data = "<body>")]
pub async fn authenticate(mut db: Connection<Db>, mut host: Option<String>, mut body: Json<Method_request_body>, remote_addr: SocketAddr, headers: &Headers) -> Result<Custom<Value>, Status> {
    let hostname = get_hostname(host.unwrap()).await.expect("Invalid or missing hostname.");

    let authentication_method_result = is_valid_authentication_method(body.authentication_method.clone()).await;
    if (authentication_method_result.is_none() != false) {
        return Ok(status::Custom(Status::BadRequest, error_message("body.authentication_method is not a valid authentication method.".into())));
    }
    let authentication_method = authentication_method_result.unwrap();

    let is_valid_hostname_for_authmethod_result = is_valid_authentication_method_for_hostname(hostname.clone(), authentication_method.clone()).await.expect("Invalid authentication method for hostname.");
    // if (is_valid_hostname_for_authmethod_result.is_ok() != true) {
    //     return Ok(status::Custom(Status::BadRequest, error_message("Invalid authentication method for hostname.".into())));
    // }

    // This is the user data someone is attempting to sign-in with. For example, when an unauthenticated client attempts to prove themself via oauth, whatever data returned in the user-info oauth endpoint is returned here. This data is very random, for example, it may not contain an email.
    let mut attempted_external_user: Option<Value> = None;

    if (authentication_method.method_type == "email") {
        let request_data: Magiclink_handling_data = serde_json::from_value(body.request_data.clone()).unwrap();
        let (handling_magiclink, magiclink_handling_db) = handling_email_magiclink(db, request_data.clone(), authentication_method.clone(), remote_addr).await.expect("Failed to verify magiclink.");
        if (handling_magiclink.error_to_respond_to_client_with.is_none() == false) {
            return Ok(handling_magiclink.error_to_respond_to_client_with.unwrap());
        }
        db = magiclink_handling_db;

        let magiclink: Magiclink = handling_magiclink.magiclink.unwrap();
        let user: Guard_user = handling_magiclink.user.unwrap();
        let user_value: Value = serde_json::to_value(user).expect("Failed to convert user to json value");
        attempted_external_user = Some(user_value);
    } else {
        println!("authentication_method.method_type is invalid. Something went wrong in startup config validation.");
        return Err(Status::InternalServerError);
    }

    if (attempted_external_user.is_none() == true) {
        // Authentication method did not return user info. This should have been handled in protocol specific functions, like 'handling_email_magiclink'.
        println!("Authentication method did not return user info.");
        return Err(Status::InternalServerError);
    }

    let (user_id, external_user_handling_db) = attempted_external_user_handling(db, attempted_external_user.unwrap(), authentication_method.clone()).await.expect("Failed to complete external user handling");
    db = external_user_handling_db;

    let essential_authenticate_request_data: Essential_authenticate_request_data = serde_json::from_value(body.request_data.clone()).unwrap();
    let public_key = essential_authenticate_request_data.public_key;

    // TODO: Collateral needs to be here, such as a userid or MS bearer token, so when that person loses access they immediately get kicked.

    let (device_id, device_db) = device_create(
        db,
        user_id.unwrap(),
        authentication_method.clone().id.unwrap(),
        Some("".to_string()),
        public_key
    ).await.expect("Failed to create device");

    db = device_db;

    let public_authmethod: AuthMethod_Public = authentication_method.into();

    Ok(status::Custom(Status::Ok, json!({
        "ok": true,
        "device_id": device_id,
        "authentication_method": public_authmethod
    })))
}