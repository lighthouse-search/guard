use serde::{Serialize, Deserialize};
use serde_json::{Value, json};

use diesel::sql_query;
use diesel::prelude::*;
use diesel::sql_types::*;

use rocket::http::{Status, CookieJar, Cookie};

use crate::global::{generate_random_id, get_hostname, get_authentication_method, is_valid_authentication_method_for_hostname};
use crate::protocols::misc_pipeline::device::device_pipeline;
use crate::protocols::oauth::oauth_pipeline::oauth_pipeline;
use crate::responses::*;
use crate::structs::*;

use std::error::Error;
use std::net::SocketAddr;

pub async fn protocol_decision_to_pipeline(hostname: Guarded_Hostname, jar: &CookieJar<'_>, remote_addr: SocketAddr, headers: &Headers) -> Result<(bool, Option<Value>, Option<Guard_devices>, Option<Value>), Box<dyn Error>> {
    let (auth_metadata_result, error_to_respond_to_client_with) = get_auth_metadata_from_cookies(jar, remote_addr.clone(), hostname.clone(), headers.clone()).await;
    if (auth_metadata_result.is_none() == true || error_to_respond_to_client_with.is_none() == false) {
        // get_auth_metadata_from_cookies failed, either missing auth_metadata_result (which is an extremely odd error) or error_to_respond_to_client_with was returned.
        println!("get_auth_metadata_from_cookies failed, either missing auth_metadata_result (which is an extremely odd error) or error_to_respond_to_client_with was returned.");
        return Ok((false, None, None, error_to_respond_to_client_with));
    }

    let auth_metadata: Guard_authentication_metadata = auth_metadata_result.unwrap();
    let authentication_method = auth_metadata.authentication_method.unwrap();

    if (authentication_method.method_type == "oauth") {
        // OAuth.

        let (success, user) = oauth_pipeline(hostname, authentication_method, jar, remote_addr, headers).await.expect("Something went wrong during OAuth user info");

        if (success == false) {
            println!("oauth_pipeline failed");
            return Ok((false, None, None, None));
        }

        return Ok((true, user, None, None));
    } else if (authentication_method.method_type == "email") {
        // Guard device authentication. Uses Hades-Auth and is used with email authentication. Much more secure than bearer tokens as everything is signed.

        let (success, user, device) = device_pipeline(hostname, jar, remote_addr, headers).await.expect("Device pipeline failed");

        let user_value: Value = serde_json::to_value(user).expect("Failed ot convert user to value");

        println!("email_user_value: {}", user_value);

        return Ok((success, Some(user_value), device, None));
    } else {
        return Err(format!("Unhandled authentication_method.method_type type '{}'", authentication_method.method_type).into());
    }
}

pub async fn get_auth_metadata_from_cookies(jar: &CookieJar<'_>, remote_addr: SocketAddr, hostname: Guarded_Hostname, headers: &Headers) -> (Option<Guard_authentication_metadata>, Option<Value>) {
    let mut auth_metadata_string: String = String::new();
    if (headers.headers_map.get("guard_authentication_metadata").is_none() == false) {
        auth_metadata_string = headers.headers_map.get("guard_authentication_metadata").expect("Failed to parse header.").to_string();
    } else if (jar.get("guard_authentication_metadata").is_none() == false) {
        auth_metadata_string = jar.get("guard_authentication_metadata").map(|c| c.value()).expect("Failed to parse cookie.").to_string();
    } else {
        println!("Auth metadata not provided by client.");
        return (None, Some(error_message("neither cookies.authentication_method or headers.guard_authentication_metadata was provided.")));
    }

    let auth_metadata: Guard_authentication_metadata_cookie = serde_json::from_str(&auth_metadata_string).expect("Failed to parse auth_metadata_string");

    // FOR TMW: Implement this into a function, so that you can get a authentication method from auth_metadata. Then go to reverse_proxy_authentication.rs and finish the user_id preference to then get the forwarded user id/email. Actually there should be a function to parse all the necessary data from auth metadata, including the specified authentication method and checking that authentication method is valid for the endpoint - should all be done in a specific function.
    if (auth_metadata.authentication_method.is_none()) {
        println!("authentication_metadata.authentication_method is null.");
        return (None, Some(error_message("authentication_metadata.authentication_method is null.")));
    }
    let requested_authentication_method = auth_metadata.authentication_method.unwrap();
    let authentication_method: AuthMethod = get_authentication_method(requested_authentication_method, true).await.expect("Failed to get auth method.");
    
    is_valid_authentication_method_for_hostname(hostname.clone(), authentication_method.clone()).await.expect("Invalid authentication method for hostname.");

    let output = Guard_authentication_metadata {
        authentication_method: Some(authentication_method)
    };

    return (Some(output), None);
}