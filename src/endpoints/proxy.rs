use rocket::http::CookieJar;
use rocket::response::status::Custom;
use rocket::{http::Status, response::status, serde::json::Json};
use rocket_db_pools::{Database, Connection};
use rocket_db_pools::diesel::{MysqlPool, prelude::*};
use serde_json::{json, Value};
use std::net::SocketAddr;

use crate::global::get_current_valid_hostname;
use crate::users::user_authentication_pipeline;
use crate::Config_reverse_proxy_authentication_config;
use crate::{CONFIG_VALUE, Headers, Db};

async fn reverse_proxy_authentication(mut db: Connection<Db>, jar: &CookieJar<'_>, remote_addr: SocketAddr, headers: &Headers) -> Custom<Value> {
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
    
    let (result, user, device, error_to_respond_with, db) = user_authentication_pipeline(db, jar, remote_addr, host, headers).await.expect("User authentication pipeline failed");

    if (result == true) {
        return status::Custom(Status::Ok, json!({
            "success": true
        }));
    } else {
        return status::Custom(Status::Unauthorized, json!({
            "success": false,
            "reason": error_to_respond_with
        }));
    }
}

#[get("/authentication")]
pub async fn reverse_proxy_authentication_get(mut db: Connection<Db>, jar: &CookieJar<'_>, remote_addr: SocketAddr, headers: &Headers) -> Custom<Value> {
    return reverse_proxy_authentication(db, jar, remote_addr, headers).await;
}

#[put("/authentication")]
pub async fn reverse_proxy_authentication_put(mut db: Connection<Db>, jar: &CookieJar<'_>, remote_addr: SocketAddr, headers: &Headers) -> Custom<Value> {
    return reverse_proxy_authentication(db, jar, remote_addr, headers).await;
}

#[post("/authentication")]
pub async fn reverse_proxy_authentication_post(mut db: Connection<Db>, jar: &CookieJar<'_>, remote_addr: SocketAddr, headers: &Headers) -> Custom<Value> {
    return reverse_proxy_authentication(db, jar, remote_addr, headers).await;
}

#[delete("/authentication")]
pub async fn reverse_proxy_authentication_delete(mut db: Connection<Db>, jar: &CookieJar<'_>, remote_addr: SocketAddr, headers: &Headers) -> Custom<Value> {
    return reverse_proxy_authentication(db, jar, remote_addr, headers).await;
}

#[head("/authentication")]
pub async fn reverse_proxy_authentication_head(mut db: Connection<Db>, jar: &CookieJar<'_>, remote_addr: SocketAddr, headers: &Headers) -> Custom<Value> {
    return reverse_proxy_authentication(db, jar, remote_addr, headers).await;
}

#[options("/authentication")]
pub async fn reverse_proxy_authentication_options(mut db: Connection<Db>, jar: &CookieJar<'_>, remote_addr: SocketAddr, headers: &Headers) -> Custom<Value> {
    return reverse_proxy_authentication(db, jar, remote_addr, headers).await;
}

#[patch("/authentication")]
pub async fn reverse_proxy_authentication_patch(mut db: Connection<Db>, jar: &CookieJar<'_>, remote_addr: SocketAddr, headers: &Headers) -> Custom<Value> {
    return reverse_proxy_authentication(db, jar, remote_addr, headers).await;
}