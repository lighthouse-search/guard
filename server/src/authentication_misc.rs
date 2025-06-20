use serde::{Serialize, Deserialize};
use serde_json::{Value, json};

use diesel::sql_query;
use diesel::prelude::*;
use diesel::sql_types::*;

use rocket::http::{Status, CookieJar, Cookie};

use crate::global::{generate_random_id, get_authentication_method};
use crate::hostname::is_valid_authentication_method_for_hostname;
use crate::hostname::prepend_hostname_to_cookie;
use crate::protocols::misc_pipeline::device::{device_pipeline_server_oauth, device_pipeline_static_auth};
use crate::protocols::oauth::pipeline::oauth_pipeline;
use crate::responses::*;
use crate::structs::*;

use std::collections::HashMap;
use std::error::Error;
use std::net::SocketAddr;

pub async fn protocol_decision_to_pipeline(required_scopes: Vec<&str>, hostname: Guarded_Hostname, jar: &indexmap::IndexMap<String, String>, remote_addr: String, headers: &Headers) -> Result<Protocol_decision_to_pipeline_output, Error_response> {

    let mut authentication_type: Option<String> = None;

    let authentication_metadata_status = get_guard_authentication_metadata(&jar, remote_addr.clone(), hostname.clone(), headers.clone()).await;

    if (authentication_metadata_status.is_err() == true) {
        let error = authentication_metadata_status.err().unwrap();
        log::error!("An error occurred when checking Guard authentication metadata: {:?}", error);
        return Err(error);
    }

    let authentication_metadata_wrapped = authentication_metadata_status.expect("Failed to unwrap authentication_metadata_status"); // Unwrap Result<Option<Guard_authentication_metadata>, Error_response> to Option<Guard_authentication_metadata>
    if (authentication_metadata_wrapped.is_none() == false) { // Check if a Guard authentication metadata was provided by the client, if it wasn't, we should check other supported sources such as headers.Authorization.
        // Guard static auth metadata was provided.

        authentication_type = Some(String::from("static_auth"));

        // Client is authenticating via Cookie.
        let auth_metadata: Guard_authentication_metadata = authentication_metadata_wrapped.unwrap();

        let unverified_authentication_method = auth_metadata.unverified_authentication_method.unwrap();

        if (unverified_authentication_method.method_type == "oauth") {
            authentication_type = Some(String::from("bearer_token"));
            // WARNING: OAuth client (e.g. Login with Microsoft, NOT "Login with Guard") doesn't check scope!

            let oauth_status = oauth_pipeline(hostname, unverified_authentication_method.clone(), &jar, remote_addr, headers).await;

            // Check pipeline for response error.
            if (oauth_status.is_err() == true) {
                return Err(oauth_status.err().unwrap());
            }
            
            let oauth = oauth_status.expect("Failed to unwrap oauth");

            return Ok(Protocol_decision_to_pipeline_output {
                user: Some(oauth.external_user),
                device: None,
                authentication_method: Some(unverified_authentication_method),
                authentication_type: authentication_type.unwrap()
            });
        } else if (unverified_authentication_method.method_type == "email") {
            authentication_type = Some(String::from("static_auth"));
            // Guard device authentication. Uses Hades-Auth and is used with email authentication. Much more secure than bearer tokens as everything is signed.

            let device_pipeline_status = device_pipeline_static_auth(required_scopes, hostname, &jar, remote_addr, headers).await;

            // Check pipeline for response error.
            // TODO: Check this err returns successfully.
            if (device_pipeline_status.is_err() == true) {
                return Err(device_pipeline_status.err().unwrap());
            }

            let device_pipeline = device_pipeline_status.expect("Failed to unwrap device pipeline");
            
            let user_value: Value = serde_json::to_value(device_pipeline.user.unwrap()).expect("Failed to convert user to value");
            log::debug!("email_user_value: {}", user_value);

            return Ok(Protocol_decision_to_pipeline_output {
                user: Some(user_value),
                device: device_pipeline.device,
                authentication_method: device_pipeline.authentication_method,
                authentication_type: authentication_type.unwrap()
            });
        } else {
            // TODO: make this a not-terrible error message
            return Err(error_message(&format!("Unhandled guard_authentication_metadata.method_type, type: '{}'", unverified_authentication_method.method_type)).into());
        }
    } else if (headers.headers_map.get("Authorization").is_none() == false) {// TODO: This needs a config feature flag to check if OAuth-server is enabled on the server. // No authentication metadata was provided, let's check the "Authorization" header. It's important to check standard headers, like "Authorization", last as the client may not be intending for Guard to use it. We need to be careful how this IF statement evolves in the future - we don't want to reject a valid request because Guard is reading a standard header before checking if another Guard-specific method was provided.
        authentication_type = Some(String::from("oauth"));

        // TODO: investigate why this doesn't/pass need auth_metadata, is something duplicating?.
        let (user, device, verified_auth_method) = device_pipeline_server_oauth(required_scopes, hostname, &jar, remote_addr, headers).await.expect("Device pipeline failed");

        let user_value: Value = serde_json::to_value(user).expect("Failed to convert user to value");

        log::debug!("oauth_user_value: {}", user_value);

        return Ok(Protocol_decision_to_pipeline_output {
            user: Some(user_value),
            device: Some(device.unwrap()),
            authentication_method: verified_auth_method,
            authentication_type: authentication_type.unwrap()
        });
    } else {
        // TODO: make this a not-terrible error message
        return Err(error_message(&format!("guard_authentication_metadata.authentication_method.method_type and headers.Authorization are both unspecified.")).into());
    }
}

pub async fn get_guard_authentication_metadata(jar: &indexmap::IndexMap<String, String>, remote_addr: String, hostname: Guarded_Hostname, headers: &Headers) -> Result<Option<Guard_authentication_metadata>, Error_response> {
    // This cookie is used instead of [Guard hostname]_guard_static_auth because, for example, if we're using OAuth, there isn't a [Guard hostname]_guard_static_auth cookie.

    let mut auth_metadata_string: String = String::new();
    if (headers.headers_map.get("guard_authentication_metadata").is_none() == false) {
        auth_metadata_string = headers.headers_map.get("guard_authentication_metadata").expect("Failed to parse header.").to_string();
    } else if (jar.get(&prepend_hostname_to_cookie("guard_authentication_metadata")).is_none() == false) {
        auth_metadata_string = jar.get(&prepend_hostname_to_cookie("guard_authentication_metadata")).expect("Failed to parse cookie.").to_string();
    } else {
        log::info!("neither (cookie) {} or header {} was provided by the client.", &prepend_hostname_to_cookie("guard_authentication_metadata"), &prepend_hostname_to_cookie("guard_authentication_metadata"));
        return Err(error_message(&format!("neither cookies.{} or headers.guard_authentication_metadata was provided by the client.", &prepend_hostname_to_cookie("guard_authentication_metadata"))).into());
    }

    let auth_metadata: Guard_authentication_metadata_cookie = serde_json::from_str(&auth_metadata_string).expect("Failed to parse auth_metadata_string");

    // TODO: FOR TMW: Implement this into a function, so that you can get a authentication method from auth_metadata. Then go to reverse_proxy_authentication.rs and finish the user_id preference to then get the forwarded user id/email. Actually there should be a function to parse all the necessary data from auth metadata, including the specified authentication method and checking that authentication method is valid for the endpoint - should all be done in a specific function.
    if (auth_metadata.authentication_method.is_none()) {
        log::info!("guard_authentication_metadata.authentication_method is null.");
        return Err(error_message("guard_authentication_metadata.authentication_method is null.").into());
    }
    let requested_authentication_method = auth_metadata.authentication_method.unwrap();
    let authentication_method: AuthMethod = get_authentication_method(requested_authentication_method, true).await.expect("Failed to get auth method.");
    
    is_valid_authentication_method_for_hostname(hostname.clone(), authentication_method.clone()).await.expect("Invalid authentication method for hostname.");

    // This authentication is not verified. The client has requested this authentication method, but we haven't verified they're authenticated for this method.
    let output = Guard_authentication_metadata {
        unverified_authentication_method: Some(authentication_method)
    };

    return Ok(Some(output));
}