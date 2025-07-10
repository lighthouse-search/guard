use serde_json::Value;

use crate::hostname::prepend_hostname_to_cookie;
use crate::protocols::oauth::client::oauth_userinfo;
use crate::responses::error_message;
use crate::structs::*;

use url::Url;
use std::collections::HashMap;

pub async fn oauth_pipeline(_hostname: GuardedHostname, auth_method: AuthMethod, jar: &indexmap::IndexMap<String, String>, _remote_addr: String, headers: &Headers) -> Result<OauthPipelineResponse, ErrorResponse> {
    let mut _bearer_token: String = String::new();

    if headers.headers_map.get("Authorization").is_none() == false {
        _bearer_token = headers.headers_map.get("Authorization").expect("Missing Authorization header.").to_string();
    } else if jar.get(&prepend_hostname_to_cookie("guard_oauth_access_token")).is_none() == false {
        _bearer_token = jar.get(&prepend_hostname_to_cookie("guard_oauth_access_token")).expect("Failed to parse guard_oauth_access_token.").to_string();
    } else {
        log::info!("Bearer token not provided by client.");
        return Err(error_message("Bearer token is null or whitespace - please provide a Bearer token in your request when authenticating with OAuth."));
    }

    // TODO: Somehow this unwrap might not catch an empty (completely unspecified) oauth_client_user_info?
    let user_info_result = oauth_userinfo(auth_method.oauth_client_user_info.unwrap(), _bearer_token).await;
    if user_info_result.is_err() == true {
        log::info!("Failed to get user-info");
        return Err(error_message("Failed to get user information from relevant service"));
    }
    
    let attempted_external_user: Value = user_info_result.expect("Failed to get oauth userinfo.");

    return Ok(OauthPipelineResponse {
        external_user: attempted_external_user
    });
}

pub fn oauth_get_data_from_oauth_login_url(url: String) -> OauthLoginUrlInformation {
    let url = Url::parse(&url).expect("Failed to parse URL");
    let query_pairs: HashMap<_, _> = url.query_pairs().into_owned().collect();

    let redirect_uri: String = query_pairs.get("redirect_uri").expect("Oauth login URL missing 'redirect_uri'").to_string();
    let scope: String = query_pairs.get("scope").expect("Oauth login URL missing 'scope'").to_string();

    return OauthLoginUrlInformation {
        redirect_uri: Some(redirect_uri),
        scope: Some(scope)
    }
}