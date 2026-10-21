use axum::{
    Json, Router, extract::Path, http::StatusCode, response::{IntoResponse, Response}, routing::{get, post}
};
use axum::extract::Query;

use serde::Deserialize;
use serde_json::{json, Value};

use crate::hostname::{device_authentication_hostname, get_hostname, get_hostname_authentication_methods};
use crate::{error_message, AuthMethodPublic, FrontendMetadata, CONFIG_VALUE};

// Endpoint root: /api/metadata

// Rewrites a "media://<file>" reference into a path served by the local media
// folder (config.frontend.media.folder mounted at /guard/media). Any other
// value (e.g. a full http(s) URL) is returned unchanged.
fn resolve_media_url(value: Option<String>) -> Option<String> {
    value.map(|v| match v.strip_prefix("media://") {
        Some(rest) => format!("/guard/media/{}", rest.trim_start_matches('/')),
        None => v,
    })
}

#[derive(Deserialize)]
pub struct MetadataGet {
    hostname: Option<String>,
}

pub async fn metadata_get(params: Query<MetadataGet>) -> Response {
    let frontend_metadata: FrontendMetadata = CONFIG_VALUE.frontend.clone().unwrap().metadata.unwrap();

    let mut alias: Option<String> = frontend_metadata.alias;
    let mut public_description: Option<String> = frontend_metadata.public_description;
    let mut logo: Option<String> = frontend_metadata.logo;
    let mut image: Option<String> = frontend_metadata.image;
    let mut motd_banner: Option<String> = frontend_metadata.motd_banner;
    let mut domain_placeholder: Option<String> = frontend_metadata.domain_placeholder;
    let mut username_placeholder: Option<String> = frontend_metadata.username_placeholder;
    let mut background_colour: Option<String> = frontend_metadata.background_colour;
    let mut style: String = frontend_metadata.style.unwrap_or("login_1".to_string());

    // TODO: This should be an impl From<>.
    let hostname = get_hostname(params.hostname.clone().unwrap()).await;
    if hostname.is_ok() == true {
        let hostname_unwrapped = hostname.unwrap();
        if hostname_unwrapped.alias.is_none() == false {
            alias = Some(hostname_unwrapped.alias.unwrap());
        }
        if hostname_unwrapped.public_description.is_none() == false {
            public_description = Some(hostname_unwrapped.public_description.unwrap());
        }
        if hostname_unwrapped.logo.is_none() == false {
            logo = Some(hostname_unwrapped.logo.unwrap());
        }
        if hostname_unwrapped.image.is_none() == false {
            image = Some(hostname_unwrapped.image.unwrap());
        }
        if hostname_unwrapped.motd_banner.is_none() == false {
            motd_banner = Some(hostname_unwrapped.motd_banner.unwrap());
        }
        if hostname_unwrapped.domain_placeholder.is_none() == false {
            domain_placeholder = Some(hostname_unwrapped.domain_placeholder.unwrap());
        }
        if hostname_unwrapped.username_placeholder.is_none() == false {
            username_placeholder = Some(hostname_unwrapped.username_placeholder.unwrap());
        }
        if hostname_unwrapped.background_colour.is_none() == false {
            background_colour = Some(hostname_unwrapped.background_colour.unwrap());
        }
        if hostname_unwrapped.style.is_none() == false {
            style = hostname_unwrapped.style.unwrap();
        }
    }

    return (
        StatusCode::OK,
        serde_json::to_string(&json!({
            "ok": true,
            "data": {
                "alias": alias,
                "public_description": public_description,
                "logo": resolve_media_url(logo),
                "image": resolve_media_url(image),
                "motd_banner": motd_banner,
                "domain_placeholder": domain_placeholder,
                "username_placeholder": username_placeholder,
                "background_colour": background_colour,
                "style": style
            }
        })).unwrap(),
    ).into_response()
}

#[derive(Deserialize)]
pub struct MetadataGetAuthenticationMethods {
    hostname: Option<String>,
}

pub async fn metadata_get_authentication_methods(params: Query<MetadataGetAuthenticationMethods>) -> Response {
    let hostname_data = get_hostname(params.hostname.clone().unwrap()).await;
    if hostname_data.is_err() == true {
        return error_message(1001, StatusCode::BAD_REQUEST, "Invalid hostname.".to_string());
    }

    let active_authentication_methods_data = get_hostname_authentication_methods(hostname_data.unwrap(), true).await;

    let mut auth_methods_public: Vec<AuthMethodPublic> = Vec::new();
    for auth_method in &active_authentication_methods_data {
        auth_methods_public.push(auth_method.clone().into());
    }

    (
        StatusCode::OK,
        serde_json::to_string(&json!({
            "ok": true,
            "data": auth_methods_public
        })).unwrap(),
    ).into_response()
}

// Authentication methods available for device authentication (no hostname —
// devices authenticate generally). Configured under [device_authentication].
pub async fn metadata_get_device_authentication_methods() -> Response {
    let hostname = match device_authentication_hostname() {
        Ok(hostname) => hostname,
        Err(error) => return error_message(1002, StatusCode::BAD_REQUEST, error),
    };

    let active_authentication_methods_data = get_hostname_authentication_methods(hostname, true).await;

    let mut auth_methods_public: Vec<AuthMethodPublic> = Vec::new();
    for auth_method in &active_authentication_methods_data {
        auth_methods_public.push(auth_method.clone().into());
    }

    (
        StatusCode::OK,
        serde_json::to_string(&json!({
            "ok": true,
            "data": auth_methods_public
        })).unwrap(),
    ).into_response()
}