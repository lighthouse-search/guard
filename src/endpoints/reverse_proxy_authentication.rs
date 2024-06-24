use rocket::http::{CookieJar, Header};
use rocket::response::status::Custom;
use rocket::{http::Status, response::status, serde::json::Json};
use rocket_db_pools::{Database, Connection};
use rocket_db_pools::diesel::{MysqlPool, prelude::*};
use serde_json::{json, Value};
use std::net::SocketAddr;

use crate::structs::*;
use crate::global::get_current_valid_hostname;
use crate::users::{ user_authentication_pipeline, user_get_id_preference };
use crate::Config_reverse_proxy_authentication_config;
use crate::authentication_misc::{ get_auth_metadata_from_cookies };
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

    let (result, user_result, device, error_to_respond_with, db) = user_authentication_pipeline(db, jar, remote_addr, host.domain_port, headers).await.expect("User authentication pipeline failed");

    let (auth_metadata_result, error_to_respond_to_client_with) = get_auth_metadata_from_cookies(jar, remote_addr.clone(), host.hostname.clone(), headers.clone()).await;
    if (auth_metadata_result.is_none() == true || error_to_respond_to_client_with.is_none() == false) {
        println!("get_auth_metadata_from_cookies failed");

        return status::Custom(Status::Unauthorized, json!({
            "success": false,
            "reason": error_to_respond_with
        }));
    }
    
    if (result == true) {
        let user = user_result.unwrap();

        let auth_metadata: Guard_authentication_metadata = auth_metadata_result.unwrap();
        let authentication_method = auth_metadata.authentication_method.unwrap();

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

        return status::Custom(Status::Ok, response_body);
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