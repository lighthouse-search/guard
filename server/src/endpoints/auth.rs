use rocket::response::status::Custom;
use rocket::{http::Status, response::status, serde::json::Json, post};
use serde_json::{json, Value};
use std::net::SocketAddr;
use crate::auth_method_handling::handling_email_magiclink;
use crate::auth_method_request::request_email;
use crate::device::device_create;
use crate::global::is_valid_authentication_method;
use crate::hostname::{get_hostname, hostname_auth_exit_flow, is_valid_authentication_method_for_hostname};
use crate::{EssentialAuthenticateRequestData, GuardUser, Magiclink, MagiclinkHandlingData, MagiclinkRequestData, MethodRequestBody, RequestMagiclink};
use crate::{error_message, Headers};
use crate::structs::*;

#[post("/request?<host>", format = "application/json", data = "<body>")]
pub async fn auth_method_request(host: Option<String>, body: Json<MethodRequestBody>, remote_addr: SocketAddr, _headers: &Headers) -> Result<Custom<Value>, Status> {
    let _db = crate::DB_POOL.get().expect("Failed to get a connection from the pool.");

    if host.is_none() == true {
        return Ok(status::Custom(Status::BadRequest, error_message("params.host is null or whitespace.").into()));
    }
    let hostname_result = get_hostname(host.unwrap()).await;
    if hostname_result.is_err() == true {
        return Ok(status::Custom(Status::BadRequest, error_message("params.host is invalid.").into()));
    }
    let hostname = hostname_result.unwrap();

    let authentication_method_result = is_valid_authentication_method(body.authentication_method.clone()).await;
    if authentication_method_result.is_none() != false {
        return Ok(status::Custom(Status::BadRequest, error_message("body.authentication_method is not a valid authentication method.").into()));
    }

    let authentication_method = authentication_method_result.unwrap();
    
    let valid_authentication_method_for_hostname = is_valid_authentication_method_for_hostname(hostname.clone(), authentication_method.clone()).await;
    if valid_authentication_method_for_hostname.is_ok() != true {
        return Ok(status::Custom(Status::BadRequest, error_message("Invalid authentication method for hostname.").into()));
    }

    if authentication_method.method_type == "email" {
        let request_data: MagiclinkRequestData = serde_json::from_value(body.request_data.clone()).unwrap();
        
        if request_data.email.is_none() {
            // Return error.
            return Ok(status::Custom(Status::BadRequest, error_message("body.request_data.email is null or whitespace.").into()));
        }
        let requested_email = request_data.email.clone().expect("Missing body.request_data.email");

        let request_magiclink_response: RequestMagiclink = request_email(requested_email.clone(), authentication_method, request_data.clone(), remote_addr, hostname).await.expect("Failed to send magiclink.");
        if request_magiclink_response.error_to_respond_to_client_with.is_none() == false {
            return Ok(request_magiclink_response.error_to_respond_to_client_with.unwrap());
        }
    } else {
        log::info!("authentication_method.method_type is invalid. Something went wrong in startup config validation.");
        return Err(Status::InternalServerError);
    }

    Ok(status::Custom(Status::Ok, json!({
        "ok": true
    })))
}

#[post("/authenticate?<host>", format = "application/json", data = "<body>")]
pub async fn authenticate(host: Option<String>, body: Json<MethodRequestBody>, remote_addr: SocketAddr, _headers: &Headers) -> Result<Custom<Value>, Status> {
    let _db = crate::DB_POOL.get().expect("Failed to get a connection from the pool.");

    // TODO: this should return 404 instead of error.
    let hostname_check = get_hostname(host.unwrap()).await;
    if hostname_check.is_err() == true {
        return Ok(status::Custom(Status::BadRequest, error_message("params.host is invalid.".into()).into()));
    }
    let hostname = hostname_check.unwrap();

    let authentication_method_result = is_valid_authentication_method(body.authentication_method.clone()).await;
    if authentication_method_result.is_none() != false {
        return Ok(status::Custom(Status::BadRequest, error_message("body.authentication_method is not a valid authentication method.".into()).into()));
    }
    let authentication_method = authentication_method_result.unwrap();

    let valid_authentication_method_for_hostname = is_valid_authentication_method_for_hostname(hostname.clone(), authentication_method.clone()).await;
    if valid_authentication_method_for_hostname.is_ok() != true {
        return Ok(status::Custom(Status::BadRequest, error_message("Invalid authentication method for hostname.").into()));
    }

    // This is the user data the external authentication method is returning. For example, when an unauthenticated client attempts to prove themself via oauth, whatever data returned in the user-info oauth endpoint is returned here. This data is very random, for example, it may not contain an email.

    // TODO: I don't know why these variables are called "attempted_[..]" when it's the user data returned from a trusted authentication method. This makes it sound as if the client is providing this data. These variables need to be updated.
    let mut _attempted_external_user: Option<Value> = None;
    let mut _attempted_authentication_method: Option<String> = None;
    if authentication_method.method_type == "email" {
        let request_data: MagiclinkHandlingData = serde_json::from_value(body.request_data.clone()).unwrap();
        let handling_magiclink = handling_email_magiclink(request_data.clone(), authentication_method.clone(), remote_addr).await.expect("Failed to verify magiclink.");
        if handling_magiclink.error_to_respond_to_client_with.is_none() == false {
            return Ok(handling_magiclink.error_to_respond_to_client_with.unwrap());
        }

        let magiclink: Magiclink = handling_magiclink.magiclink.unwrap();

        let user: GuardUser = handling_magiclink.user.unwrap();
        let user_value: Value = serde_json::to_value(user).expect("Failed to convert user to json value");
        _attempted_external_user = Some(user_value);
        _attempted_authentication_method = Some(magiclink.authentication_method);
    } else {
        log::info!("authentication_method.method_type is invalid. Something went wrong in startup config validation.");
        return Err(Status::InternalServerError);
    }

    if _attempted_external_user.is_none() == true {
        // Authentication method did not return user info. This should have been handled in protocol specific functions, like 'handling_email_magiclink'.
        log::info!("Authentication method did not return user info.");
        return Err(Status::InternalServerError);
    }

    if _attempted_authentication_method.is_none() == true || _attempted_authentication_method.clone().unwrap() != authentication_method.method_type.clone() {
        log::info!("Authentication method mismatch. Client specified '{}', when the trusted authentication method returned '{}'", authentication_method.method_type.clone(), _attempted_authentication_method.clone().unwrap());
        return Err(Status::InternalServerError);
    }

    log::info!("attempted_external_user: {:?}", _attempted_external_user.clone());

    let essential_authenticate_request_data: EssentialAuthenticateRequestData = serde_json::from_value(body.request_data.clone()).unwrap();
    let public_key = essential_authenticate_request_data.public_key;

    let attempted_external_user_unwrapped = _attempted_external_user.unwrap();
    let user_id: String = attempted_external_user_unwrapped.get("id").unwrap().as_str().expect("Missing attempted_external_user.id").to_string();
    
    // TODO: Collateral should be removed. Oauth isn't handled this way anymore.
    let device_id = device_create(
        user_id,
        authentication_method.clone().id.unwrap(),
        Some("".to_string()),
        public_key
    ).await.expect("Failed to create device");

    let public_authmethod: AuthMethodPublic = authentication_method.clone().into();
    
    let hostname_result = hostname_auth_exit_flow(hostname.host, authentication_method).await;
    if hostname_result.is_none() == true {
        return Ok(status::Custom(Status::BadRequest, error_message("Invalid params.host").into()));
    }

    Ok(status::Custom(Status::Ok, json!({
        "ok": true,
        "device_id": device_id,
        "authentication_method": public_authmethod,
        "hostname": hostname_result
    })))
}