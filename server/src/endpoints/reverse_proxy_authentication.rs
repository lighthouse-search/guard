use rocket::http::{CookieJar, Header, Status};
use rocket::{response::status, options, get, post, put, delete, head, patch};
use rocket::response::status::Custom;

use serde_json::{json, Value};
use std::net::SocketAddr;

use crate::hostname::get_current_valid_hostname;
use crate::structs::*;
use crate::global::jar_to_indexmap;
use crate::users::{ user_authentication_pipeline, user_get_id_preference };
use crate::Config_reverse_proxy_authentication_config;
use crate::{CONFIG_VALUE, Headers};

async fn reverse_proxy_authentication(jar: &CookieJar<'_>, remote_addr: SocketAddr, headers: &Headers) -> Custom<Value> {
    let mut header_to_use: String = "host".to_string();

    // Here, we need to get the reverse_proxy_authentication.config to check if a custom header is set. For example, NGINX auth-url overrides the "host" header, and instead gives a "x-original-url" (among others) header.
    // Check the output was ok, because there may not be a config for reverse_proxy_authentication.
    if let Some(reverse_proxy_authentication_config_value) = CONFIG_VALUE.get("reverse_proxy_authentication").and_then(|value| value.get("config")) {
        // The value we got is toml::Value, it needs to be converted to a json string.
        let reverse_proxy_authentication_config_json = serde_json::to_string(reverse_proxy_authentication_config_value).expect("Failed to serialize");
        // Parse json string we got to get config as struct.
        let reverse_proxy_authentication_config: Config_reverse_proxy_authentication_config = serde_json::from_str(&reverse_proxy_authentication_config_json).expect("Failed to parse");
        // We've found a config, but we need to make sure the header is actually set.
        if (reverse_proxy_authentication_config.header.is_none() == false) {
            // Set header as the header we should use.
            header_to_use = reverse_proxy_authentication_config.header.unwrap();
        }
    }
    
    let host = get_current_valid_hostname(headers, Some(header_to_use)).await.expect("Invalid or missing hostname.");

    let (result, user_result, device, authentication_method_wrapped, error_to_respond_with) = user_authentication_pipeline(vec!["access_applications"], &jar_to_indexmap(jar), remote_addr.to_string(), host.domain_port, headers).await.expect("User authentication pipeline failed");
    // TODO: In the future athentication_method won't be returned as optional from user_authentication_pipelne (user_authentication_pipeline will be changed to from truple to Result<>). This is a temporary fix :)
    let authentication_method = authentication_method_wrapped.unwrap();
    if (result == true) {
        let user = user_result.unwrap();

        let user_get_id_preference = user_get_id_preference(user.clone(), authentication_method.clone()).expect("Failed to get user_get_id_preference");

        let forwarded_user_details: Value = json!({
            "id": user_get_id_preference.id,
            "email": user_get_id_preference.email
        });

        let guard_header: Value = json!({
            "user": forwarded_user_details,
            "authentication_method": authentication_method.id
        });
        
        // Create a JSON response
        let response_body = json!({
            "success": true,
            "destination_url": host.original_url,
            "guard": guard_header
        });

        return status::Custom(Status::Ok, response_body);
    } else {
        // Create a JSON response
        let response_body = json!({
            "success": false,
            "reason": error_to_respond_with
        });

        return status::Custom(Status::Unauthorized, response_body);
    }
}

#[get("/authentication")]
pub async fn reverse_proxy_authentication_get(jar: &CookieJar<'_>, remote_addr: SocketAddr, headers: &Headers) -> Custom<Value> {
    return reverse_proxy_authentication(jar, remote_addr, headers).await;
}

#[post("/authentication")]
pub async fn reverse_proxy_authentication_post(jar: &CookieJar<'_>, remote_addr: SocketAddr, headers: &Headers) -> Custom<Value> {
    return reverse_proxy_authentication(jar, remote_addr, headers).await;
}

#[put("/authentication")]
pub async fn reverse_proxy_authentication_put(jar: &CookieJar<'_>, remote_addr: SocketAddr, headers: &Headers) -> Custom<Value> {
    return reverse_proxy_authentication(jar, remote_addr, headers).await;
}

#[delete("/authentication")]
pub async fn reverse_proxy_authentication_delete(jar: &CookieJar<'_>, remote_addr: SocketAddr, headers: &Headers) -> Custom<Value> {
    return reverse_proxy_authentication(jar, remote_addr, headers).await;
}

#[head("/authentication")]
pub async fn reverse_proxy_authentication_head(jar: &CookieJar<'_>, remote_addr: SocketAddr, headers: &Headers) -> Custom<Value> {
    return reverse_proxy_authentication(jar, remote_addr, headers).await;
}

#[options("/authentication")]
pub async fn reverse_proxy_authentication_options(jar: &CookieJar<'_>, remote_addr: SocketAddr, headers: &Headers) -> Custom<Value> {
    return reverse_proxy_authentication(jar, remote_addr, headers).await;
}

#[patch("/authentication")]
pub async fn reverse_proxy_authentication_patch(jar: &CookieJar<'_>, remote_addr: SocketAddr, headers: &Headers) -> Custom<Value> {
    return reverse_proxy_authentication(jar, remote_addr, headers).await;
}