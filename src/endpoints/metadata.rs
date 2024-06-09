use rocket::response::status::Custom;
use rocket::{http::Status, response::status, serde::json::Json};
use rocket_db_pools::{Database, Connection};
use rocket_db_pools::diesel::{MysqlPool, prelude::*};
use serde_json::{json, Value};

use crate::global::{get_hostname, get_hostname_authentication_methods};
use crate::{error_message, AuthMethod_Public, Db, Frontend_metadata, CONFIG_VALUE};

// Endpoint root: /api/metadata

#[get("/?<hostname>")]
pub async fn metadata_get(mut db: Connection<Db>, hostname: Option<String>) -> Custom<Value> {
    let metadata_json = serde_json::to_string(&CONFIG_VALUE["frontend"]["metadata"]).expect("Failed to serialize");
    let frontend_metadata: Frontend_metadata = serde_json::from_str(&metadata_json).expect("Failed to parse");

    let mut alias: Option<String> = frontend_metadata.alias;
    let mut public_description: Option<String> = frontend_metadata.public_description;
    let mut logo: Option<String> = frontend_metadata.logo;
    let mut image: Option<String> = frontend_metadata.image;
    let mut motd_banner: Option<String> = frontend_metadata.motd_banner;
    let mut email_domain_placeholder: Option<String> = frontend_metadata.email_domain_placeholder;
    let mut example_username_placeholder: Option<String> = frontend_metadata.example_username_placeholder;
    let mut background_colour: Option<String> = frontend_metadata.background_colour;

    let hostname = get_hostname(hostname.unwrap()).await;
    if (hostname.is_none() == false) {
        let hostname_unwrapped = hostname.unwrap();
        if (hostname_unwrapped.alias.is_none() == false) {
            alias = Some(hostname_unwrapped.alias.unwrap());
        }
        if (hostname_unwrapped.public_description.is_none() == false) {
            public_description = Some(hostname_unwrapped.public_description.unwrap());
        }
        if (hostname_unwrapped.logo.is_none() == false) {
            logo = Some(hostname_unwrapped.logo.unwrap());
        }
        if (hostname_unwrapped.image.is_none() == false) {
            image = Some(hostname_unwrapped.image.unwrap());
        }
        if (hostname_unwrapped.motd_banner.is_none() == false) {
            motd_banner = Some(hostname_unwrapped.motd_banner.unwrap());
        }
        if (hostname_unwrapped.email_domain_placeholder.is_none() == false) {
            email_domain_placeholder = Some(hostname_unwrapped.email_domain_placeholder.unwrap());
        }
        if (hostname_unwrapped.example_username_placeholder.is_none() == false) {
            example_username_placeholder = Some(hostname_unwrapped.example_username_placeholder.unwrap());
        }
        if (hostname_unwrapped.background_colour.is_none() == false) {
            background_colour = Some(hostname_unwrapped.background_colour.unwrap());
        }
    }

    return status::Custom(Status::Ok, json!({
        "ok": true,
        "data": {
            "alias": alias,
            "public_description": public_description,
            "logo": logo,
            "image": image,
            "motd_banner": motd_banner,
            "email_domain_placeholder": email_domain_placeholder,
            "example_username_placeholder": example_username_placeholder,
            "background_colour": background_colour
        }
    }));
}

#[get("/get-authentication-methods?<hostname>")]
pub async fn metadata_get_authentication_methods(mut db: Connection<Db>, hostname: Option<String>) -> Custom<Value> {
    let hostname_data = get_hostname(hostname.unwrap()).await;
    if (hostname_data.is_none() == true) {
        return status::Custom(Status::BadRequest, error_message("Invalid hostname."));
    }

    let active_authentication_methods_data = get_hostname_authentication_methods(hostname_data.unwrap(), true).await;

    let mut auth_methods_public: Vec<AuthMethod_Public> = Vec::new();
    for auth_method in &active_authentication_methods_data {
        auth_methods_public.push(auth_method.clone().into());
    }
    
    return status::Custom(Status::Ok, json!({
        "ok": true,
        "data": auth_methods_public
    }));
}