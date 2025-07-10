use crate::global::get_authentication_method;
use crate::responses::{self, *};
use crate::structs::*;

use crate::device::{device_signed_authentication, device_guard_static_auth_from_cookies};
use crate::users::user_get;
use crate::hostname::{is_valid_authentication_method_for_hostname, prepend_hostname_to_cookie};

pub async fn device_pipeline_server_oauth(required_scopes: Vec<&str>, hostname: GuardedHostname, _jar: &indexmap::IndexMap<String, String>, _remote_addr: String, headers: &Headers) -> Result<(Option<GuardUser>, Option<GuardDevices>, Option<AuthMethod>), ErrorResponse> {
    // This relates to OAuth server applications, but is easily confused with oauth_pipeline and even conflicts. This needs to be re-worked. This function checks bearer tokens match a hashed value in Guard's database and returns the matched user.
    
    // Check the Authroization header starts with ("Bearer "), consistent with OAuth standard.
    if headers.headers_map.get("Authorization").expect("Missing Authorization header.").clone().starts_with("Bearer ") == false {
        return Err(error_message("Authorization header does not start with 'Bearer '.").into());
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
    if oauth_general_authentication_method.is_none() == true && oauth_application_authentication_method.is_none() == true {
        log::error!("neither {} nor {} authentication methods exist.", "oauth", oauth_application_specific_id.clone());
        return Err(responses::internal_server_error_generic());
    }
    // >1 authentication method for this OAuth application is available. If the application specific authentication method is available, we'll use that.
    let using_authentication_method = if oauth_application_authentication_method.is_none() == false { oauth_application_authentication_method.unwrap() } else { oauth_general_authentication_method.unwrap() };

    // FUTURE: Should return error to client, saying authentication method is invalid for this hostname.
    is_valid_authentication_method_for_hostname(hostname.clone(), using_authentication_method.clone()).await.expect("Failed to validate authentication method for hostname");

    let user_result = user_get(Some(verify_token.user_id.clone()), None).await.expect("Failed to get user");
    let user: GuardUser = user_result.expect("User tied to token does not exist.");

    return Ok((Some(user), None, Some(using_authentication_method)));
}

pub async fn device_pipeline_static_auth(_required_scopes: Vec<&str>, hostname: GuardedHostname, jar: &indexmap::IndexMap<String, String>, _remote_addr: String, _headers: &Headers) -> Result<DevicePipelineStaticAuthResponse, ErrorResponse> {
    // Guard device authentication. Uses Hades-Auth and is used with email authentication. Much more secure than bearer tokens as everything is signed.

    let signed_data = device_guard_static_auth_from_cookies(jar);
    if signed_data.is_none() == true {
        log::info!("missing {}", prepend_hostname_to_cookie("guard_static_auth"));
        return Err(error_message(&format!("missing {}", prepend_hostname_to_cookie("guard_static_auth"))));
    }

    let device_authentication = device_signed_authentication(signed_data.unwrap()).await;
    if device_authentication.is_err() == true {
        return Err(error_message("device signed authentication failed."));
    }
    let (device, _additional_data) = device_authentication.unwrap();

    let device_authentication_method = get_authentication_method(device.authentication_method.clone(), true).await.expect("Invalid or missing authentication method.");
    
    // TODO: Return an error to client stating the authentication method is invalid for this hostname.
    is_valid_authentication_method_for_hostname(hostname.clone(), device_authentication_method.clone()).await.expect("Failed to validate authentication method for hostname");

    let user_result = user_get(Some(device.user_id.clone()), None).await.expect("Failed to get user");

    let user: GuardUser = user_result.expect("User tied to device does not exist.");

    return Ok(DevicePipelineStaticAuthResponse {
        user: Some(user),
        device: Some(device),
        authentication_method: Some(device_authentication_method)
    })
}