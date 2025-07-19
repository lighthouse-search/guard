use rocket::http::{CookieJar, Status};
use rocket::{response::status, options, get, post, put, delete, head, patch};
use rocket::response::status::Custom;

use serde_json::{json, Value};
use std::net::SocketAddr;

use crate::hostname::get_current_valid_hostname;
use crate::global::jar_to_indexmap;
use crate::users::user_authentication_pipeline;
use crate::{CONFIG_VALUE, Headers};

async fn reverse_proxy_authentication(jar: &CookieJar<'_>, remote_addr: SocketAddr, headers: &Headers) -> Custom<Value> {
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
    
    let host = get_current_valid_hostname(headers, Some(header_to_use)).await.expect("Invalid or missing hostname.");

    // (result, user_result, device, authentication_method_wrapped, error_to_respond_with)

    let user_authentication = user_authentication_pipeline(vec!["access_applications"], &jar_to_indexmap(jar), remote_addr.to_string(), host.domain_port, headers).await;
    
    // TODO: In the future athentication_method won't be returned as optional from user_authentication_pipelne (user_authentication_pipeline will be changed to from truple to Result<>). This is a temporary fix :)
    if user_authentication.is_ok() == true {
        let user_authentication_unwrapped = user_authentication.unwrap();
        
        let user_result = user_authentication_unwrapped.user;
        let _device = user_authentication_unwrapped.device;
        let authentication_method_wrapped = user_authentication_unwrapped.authentication_method;
        let user = user_result.unwrap();
        let authentication_method = authentication_method_wrapped.unwrap();

        // let user_get_id_preference = user_get_id_preference(user.clone(), authentication_method.clone()).expect("Failed to get user_get_id_preference");

        let guard_header: Value = json!({
            "user": user,
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
            // "reason": error_to_respond_with
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