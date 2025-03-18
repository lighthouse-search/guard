use serde::{Serialize, Deserialize};
use serde_json::{Value, json};

use diesel::sql_query;
use diesel::prelude::*;
use diesel::sql_types::*;

use rocket::http::{Status, CookieJar, Cookie};

use crate::global::{generate_random_id, get_hostname, get_authentication_method, is_valid_authentication_method_for_hostname};
use crate::hostname::prepend_hostname_to_cookie;
use crate::protocols::misc_pipeline::device::{device_pipeline_server_oauth, device_pipeline_static_auth};
use crate::protocols::oauth::pipeline::oauth_pipeline;
use crate::responses::*;
use crate::structs::*;

use std::error::Error;
use std::net::SocketAddr;

pub async fn protocol_decision_to_pipeline(required_scopes: Vec<&str>, hostname: Guarded_Hostname, jar: &CookieJar<'_>, remote_addr: SocketAddr, headers: &Headers) -> Result<(bool, Option<Value>, Option<Guard_devices>,  Option<AuthMethod>, Option<Value>), String> {
    let (auth_metadata, error_to_respond_with) = get_guard_authentication_metadata(jar, remote_addr.clone(), hostname.clone(), headers.clone()).await;
    if (headers.headers_map.get("Authorization").is_none() == false) {
        let (success, user, device, verified_auth_method) = device_pipeline_server_oauth(required_scopes, hostname, jar, remote_addr, headers).await.expect("Device pipeline failed");

        let user_value: Value = serde_json::to_value(user).expect("Failed to convert user to value");

        println!("oauth_user_value: {}", user_value);

        return Ok((success, Some(user_value), device, verified_auth_method, None));
    } else if (auth_metadata.is_none() == false || error_to_respond_with.is_none() == false) {
        if (error_to_respond_with.is_none() == false) {
            println!("oauth_pipeline failed");
            return Ok((false, None, None, None, Some(error_to_respond_with.unwrap())));
        }

        // Client is authenticating via Cookie.
        let auth_metadata: Guard_authentication_metadata = auth_metadata.unwrap();
        let unverified_authentication_method = auth_metadata.unverified_authentication_method.unwrap();

        if (unverified_authentication_method.method_type == "oauth") {
            // WARNING: OAuth client (e.g. Login with Microsoft, NOT "Login with Guard") doesn't check scope!

            let (success, user) = oauth_pipeline(hostname, unverified_authentication_method.clone(), jar, remote_addr, headers).await.expect("Something went wrong during OAuth user info");

            if (success == false) {
                println!("oauth_pipeline failed");
                return Ok((false, None, None, None, None));
            }

            return Ok((true, user, None, Some(unverified_authentication_method), None));
        } else if (unverified_authentication_method.method_type == "email") {
            // Guard device authentication. Uses Hades-Auth and is used with email authentication. Much more secure than bearer tokens as everything is signed.

            let (success, user, device, verified_auth_method) = device_pipeline_static_auth(required_scopes, hostname, jar, remote_addr, headers).await.expect("Device pipeline failed");

            let user_value: Value = serde_json::to_value(user).expect("Failed to convert user to value");

            println!("email_user_value: {}", user_value);

            return Ok((success, Some(user_value), device, verified_auth_method, None));
        } else {
            return Err(format!("Unhandled guard_authentication_metadata.method_type type '{}'", unverified_authentication_method.method_type).into());
        }
    } else {
        return Err(format!("authentication_method.method_type and headers.Authorization unspecified.").into());
    }
}

pub async fn get_guard_authentication_metadata(jar: &CookieJar<'_>, remote_addr: SocketAddr, hostname: Guarded_Hostname, headers: &Headers) -> (Option<Guard_authentication_metadata>, Option<Value>) {
    // This cookie is used instead of [Guard hostname]_guard_static_auth because, for example, if we're using OAuth, there isn't a [Guard hostname]_guard_static_auth cookie.

    let mut auth_metadata_string: String = String::new();
    if (headers.headers_map.get("guard_authentication_metadata").is_none() == false) {
        auth_metadata_string = headers.headers_map.get("guard_authentication_metadata").expect("Failed to parse header.").to_string();
    } else if (jar.get(&prepend_hostname_to_cookie("guard_authentication_metadata")).is_none() == false) {
        auth_metadata_string = jar.get(&prepend_hostname_to_cookie("guard_authentication_metadata")).map(|c| c.value()).expect("Failed to parse cookie.").to_string();
    } else {
        println!("neither (cookie) {} or header {} was provided by the client.", &prepend_hostname_to_cookie("guard_authentication_metadata"), &prepend_hostname_to_cookie("guard_authentication_metadata"));
        return ((None, None)); // Some(error_message(&format!("neither cookies.{} or headers.guard_authentication_metadata was provided by the client.", &prepend_hostname_to_cookie("guard_authentication_metadata"))))
    }

    let auth_metadata: Guard_authentication_metadata_cookie = serde_json::from_str(&auth_metadata_string).expect("Failed to parse auth_metadata_string");

    // FOR TMW: Implement this into a function, so that you can get a authentication method from auth_metadata. Then go to reverse_proxy_authentication.rs and finish the user_id preference to then get the forwarded user id/email. Actually there should be a function to parse all the necessary data from auth metadata, including the specified authentication method and checking that authentication method is valid for the endpoint - should all be done in a specific function.
    if (auth_metadata.authentication_method.is_none()) {
        println!("authentication_metadata.authentication_method is null.");
        return ((None, Some(error_message("authentication_metadata.authentication_method is null."))));
    }
    let requested_authentication_method = auth_metadata.authentication_method.unwrap();
    let authentication_method: AuthMethod = get_authentication_method(requested_authentication_method, true).await.expect("Failed to get auth method.");
    
    is_valid_authentication_method_for_hostname(hostname.clone(), authentication_method.clone()).await.expect("Invalid authentication method for hostname.");

    // This authentication is not verified. The client has requested this authentication method, but we haven't verified they're authenticated for this method.
    let output = Guard_authentication_metadata {
        unverified_authentication_method: Some(authentication_method)
    };

    return ((Some(output), None));
}