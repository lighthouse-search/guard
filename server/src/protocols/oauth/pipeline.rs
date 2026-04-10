use axum::response::Response;
use serde_json::Value;
use once_cell::sync::Lazy;
use rand::RngCore;
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::hostname::prepend_hostname_to_cookie;
use crate::protocols::oauth::client::oauth_userinfo;
use crate::responses::error_message;
use crate::structs::*;

use url::Url;

const OAUTH_CACHE_TTL: Duration = Duration::from_secs(300);

static OAUTH_USERINFO_CACHE: Lazy<Mutex<HashMap<String, (Value, Instant)>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

// Random salt generated once at startup. Without it, cache keys would be
// reversible via rainbow tables if memory is ever inspected.
// TODO: Check this.
static CACHE_KEY_SALT: Lazy<[u8; 32]> = Lazy::new(|| {
    let mut salt = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
});

fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(*CACHE_KEY_SALT);
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

pub async fn oauth_pipeline(_hostname: GuardedHostname, auth_method: AuthMethod, jar: &indexmap::IndexMap<String, String>, _remote_addr: String, headers: &axum::http::HeaderMap) -> Result<OauthPipelineResponse, Response> {
    let mut _bearer_token: String = String::new();

    if headers.get("Authorization").is_none() == false {
        _bearer_token = headers.get("Authorization").expect("Missing Authorization header.").to_str().unwrap().to_string();
    } else if jar.get(&prepend_hostname_to_cookie("guard_oauth_access_token")).is_none() == false {
        _bearer_token = jar.get(&prepend_hostname_to_cookie("guard_oauth_access_token")).expect("Failed to parse guard_oauth_access_token.").to_string();
    } else {
        log::info!("Bearer token not provided by client.");
        return Err(error_message(6001, axum::http::StatusCode::BAD_REQUEST, "Bearer token is null or whitespace - please provide a Bearer token in your request when authenticating with OAuth.".to_string()));
    }

    let token_hash = hash_token(&_bearer_token);

    // Check cache before hitting the OAuth userinfo endpoint.
    {
        let cache = OAUTH_USERINFO_CACHE.lock().unwrap();
        if let Some((cached_user, cached_at)) = cache.get(&token_hash) {
            if cached_at.elapsed() < OAUTH_CACHE_TTL {
                return Ok(OauthPipelineResponse {
                    external_user: cached_user.clone()
                });
            }
        }
    }

    // TODO: Somehow this unwrap might not catch an empty (completely unspecified) oauth_client_user_info?
    let user_info_result = oauth_userinfo(auth_method.oauth_client_user_info.unwrap(), _bearer_token).await;
    if user_info_result.is_err() == true {
        log::info!("Failed to get user-info");
        return Err(error_message(6002, axum::http::StatusCode::BAD_REQUEST, "Failed to get user information from relevant service".to_string()));
    }

    let attempted_external_user: Value = user_info_result.expect("Failed to get oauth userinfo.");

    {
        let mut cache = OAUTH_USERINFO_CACHE.lock().unwrap();
        cache.insert(token_hash, (attempted_external_user.clone(), Instant::now()));
    }

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