use axum::Json;
use axum::extract::ConnectInfo;
use axum::response::{Response, IntoResponse};
use axum_extra::extract::CookieJar;

use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;

use crate::hostname::get_current_valid_hostname;
use crate::global::jar_to_indexmap;
use crate::users::user_authentication_pipeline;
use crate::CONFIG_VALUE;

// fn headermap_to_headers(header_map: &axum::http::HeaderMap) -> Headers {
//     let mut headers_map = HashMap::new();
//     for (name, value) in header_map.iter() {
//         if let Ok(v) = value.to_str() {
//             headers_map.insert(name.to_string(), v.to_string());
//         }
//     }
//     Headers { headers_map }
// }

async fn reverse_proxy_authentication(jar: CookieJar, remote_addr: SocketAddr, headers: axum::http::HeaderMap) -> Response {
    // TODO: "pathname" is not processed.

    let mut header_to_use: String = "host".to_string();

    // Here, we need to get the reverse_proxy_authentication.config to check if a custom header is set. For example, NGINX auth-url overrides the "host" header, and instead gives a "x-original-url" (among others) header.
    // Check the output was ok, because there may not be a config for reverse_proxy_authentication.
    if let Some(reverse_proxy_authentication_config) = CONFIG_VALUE.reverse_proxy_authentication.clone().and_then(|value| value.config) {
        // We've found a config, but we need to make sure the header is actually set.
        if reverse_proxy_authentication_config.header.is_none() == false {
            // Set configured header as the header we should use.
            header_to_use = reverse_proxy_authentication_config.header.unwrap();
        }
    }
    
    let host = get_current_valid_hostname(headers.clone(), Some(header_to_use)).await.expect("Invalid or missing hostname.");

    // (result, user_result, device, authentication_method_wrapped, error_to_respond_with)

    let user_authentication = user_authentication_pipeline(vec!["access_applications"], &jar_to_indexmap(&jar), remote_addr.to_string(), host.domain_port, headers).await;
    
    // TODO: In the future athentication_method won't be returned as optional from user_authentication_pipelne (user_authentication_pipeline will be changed to from truple to Result<>). This is a temporary fix :)
    if user_authentication.is_ok() == true {
        let user_authentication_unwrapped = user_authentication.unwrap();
        
        let user_result = user_authentication_unwrapped.user;
        let authentication_method_wrapped = user_authentication_unwrapped.authentication_method;
        let user = user_result.unwrap();
        let authentication_method = authentication_method_wrapped.unwrap();

        // let user_get_id_preference = user_get_id_preference(user.clone(), authentication_method.clone()).expect("Failed to get user_get_id_preference");

        // TODO: This is wildly messy, I'll fix it.

        let mut device: Option<Value> = None;
        if user_authentication_unwrapped.device.is_none() == false {
            let device_unwrapped = user_authentication_unwrapped.device.unwrap();
            device = Some(json!({
                "id": device_unwrapped.id
            }));
        }

        return (
            axum::http::StatusCode::OK,
            Json(json!({
                "success": true,
                "destination_url": host.original_url,
                "guard": {
                    "user": user,
                    "device": device,
                    "authentication_method": json!({
                        "id": authentication_method.id
                    })
                }
            })),
        ).into_response()
    } else {
        return (
            axum::http::StatusCode::UNAUTHORIZED,
            Json(json!({
                "success": false,
                // "reason": error_to_respond_with
            })),
        ).into_response();
    }
}

pub async fn reverse_proxy_authentication_get(jar: CookieJar, ConnectInfo(remote_addr): ConnectInfo<SocketAddr>, headers: axum::http::HeaderMap) -> Response {
    return reverse_proxy_authentication(jar, remote_addr, headers).await;
}

pub async fn reverse_proxy_authentication_post(jar: CookieJar, ConnectInfo(remote_addr): ConnectInfo<SocketAddr>, headers: axum::http::HeaderMap) -> Response {
    return reverse_proxy_authentication(jar, remote_addr, headers).await;
}

pub async fn reverse_proxy_authentication_put(jar: CookieJar, ConnectInfo(remote_addr): ConnectInfo<SocketAddr>, headers: axum::http::HeaderMap) -> Response {
    return reverse_proxy_authentication(jar, remote_addr, headers).await;
}

pub async fn reverse_proxy_authentication_delete(jar: CookieJar, ConnectInfo(remote_addr): ConnectInfo<SocketAddr>, headers: axum::http::HeaderMap) -> Response {
    return reverse_proxy_authentication(jar, remote_addr, headers).await;
}

pub async fn reverse_proxy_authentication_head(jar: CookieJar, ConnectInfo(remote_addr): ConnectInfo<SocketAddr>, headers: axum::http::HeaderMap) -> Response {
    return reverse_proxy_authentication(jar, remote_addr, headers).await;
}

pub async fn reverse_proxy_authentication_options(jar: CookieJar, ConnectInfo(remote_addr): ConnectInfo<SocketAddr>, headers: axum::http::HeaderMap) -> Response {
    return reverse_proxy_authentication(jar, remote_addr, headers).await;
}

pub async fn reverse_proxy_authentication_patch(jar: CookieJar, ConnectInfo(remote_addr): ConnectInfo<SocketAddr>, headers: axum::http::HeaderMap) -> Response {
    return reverse_proxy_authentication(jar, remote_addr, headers).await;
}