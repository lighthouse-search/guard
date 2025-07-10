use rocket::response::status::Custom;
use rocket::{http::Status, response::status, get};

use serde_json::{json, Value};

use crate::hostname::{get_hostname, get_hostname_authentication_methods};
use crate::{error_message, AuthMethodPublic, FrontendMetadata, CONFIG_VALUE};

// Endpoint root: /api/metadata

#[get("/?<hostname>")]
pub async fn metadata_get(hostname: Option<String>) -> Custom<Value> {
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
    let hostname = get_hostname(hostname.unwrap()).await;
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

    return status::Custom(Status::Ok, json!({
        "ok": true,
        "data": {
            "alias": alias,
            "public_description": public_description,
            "logo": logo,
            "image": image,
            "motd_banner": motd_banner,
            "domain_placeholder": domain_placeholder,
            "username_placeholder": username_placeholder,
            "background_colour": background_colour,
            "style": style
        }
    }));
}

#[get("/get-authentication-methods?<hostname>")]
pub async fn metadata_get_authentication_methods(hostname: Option<String>) -> Custom<Value> {
    let hostname_data = get_hostname(hostname.unwrap()).await;
    if hostname_data.is_err() == true {
        return status::Custom(Status::BadRequest, error_message("Invalid hostname.").into());
    }

    let active_authentication_methods_data = get_hostname_authentication_methods(hostname_data.unwrap(), true).await;

    let mut auth_methods_public: Vec<AuthMethodPublic> = Vec::new();
    for auth_method in &active_authentication_methods_data {
        auth_methods_public.push(auth_method.clone().into());
    }
    
    return status::Custom(Status::Ok, json!({
        "ok": true,
        "data": auth_methods_public
    }));
}