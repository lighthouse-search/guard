use serde::{Serialize, Deserialize};
use serde_json::{Value, json};

use rocket::response::{Debug, status::Created};
use rocket::serde::json::Json;
use rocket::response::status;
use rocket::http::Status;
use rocket::response::status::Custom;
use rocket::request::{self, Request, FromRequest};
use rocket::{fairing::{Fairing, Info, Kind}, State};
use rocket::fairing::AdHoc;
use rocket::fs::FileServer;
use rocket::http::{CookieJar, Cookie};

use rocket_db_pools::{Database, Connection};
use rocket_db_pools::diesel::{MysqlPool, prelude::*};
use diesel::sql_query;

use diesel::prelude::*;
use diesel::sql_types::*;

use crate::device::device_create;
use crate::{CONFIG_VALUE, SQL_TABLES};
use crate::global::{ is_valid_authentication_method, generate_random_id, is_null_or_whitespace, get_hostname, get_hostname_authentication_methods, get_current_valid_hostname, is_valid_authentication_method_for_hostname };
use crate::auth_method_handling::{handling_email_magiclink};
use crate::policy::*;
use crate::responses::*;
use crate::structs::*;
use crate::tables::*;
use crate::structs::*;
use crate::auth_method_request::{request_email};
use crate::users::user_authentication_pipeline;
use hades_auth::*;

use std::borrow::{Borrow, BorrowMut};
use std::error::Error;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};
use std::env;
use std::fs::{File};
use std::io::Write;
use std::net::SocketAddr;
use std::collections::HashMap;

use rand::prelude::*;

use rocket::serde::json::serde_json;

use core::sync::atomic::{AtomicUsize, Ordering};

type Result<T, E = Debug<diesel::result::Error>> = std::result::Result<T, E>;

#[get("/metadata?<hostname>")]
async fn metadata_get(mut db: Connection<Db>, hostname: Option<String>) -> Custom<Value> {
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

#[get("/metadata/get-authentication-methods?<hostname>")]
async fn metadata_get_authentication_methods(mut db: Connection<Db>, hostname: Option<String>) -> Custom<Value> {
    let get_active_authentication_methods_data = get_hostname_authentication_methods(get_hostname(hostname.unwrap()).await.expect("missing hostname"), true).await;

    return status::Custom(Status::Ok, json!({
        "ok": true,
        "data": get_active_authentication_methods_data
    }));
}

#[post("/request?<host>", format = "application/json", data = "<body>")]
async fn auth_method_request(mut db: Connection<Db>, mut host: Option<String>, mut body: Json<Method_request_body>, remote_addr: SocketAddr, headers: &Headers) -> Result<Custom<Value>, Status> {
    if (host.is_none() == true) {
        return Ok(status::Custom(Status::BadRequest, error_message("params.hostname is null or whitespace.")));
    }
    let hostname = get_hostname(host.unwrap()).await.expect("Invalid or missing hostname.");

    let authentication_method_result = is_valid_authentication_method(body.authentication_method.clone()).await;
    if (authentication_method_result.is_none() != false) {
        return Ok(status::Custom(Status::BadRequest, error_message("body.authentication_method is not a valid authentication method.")));
    }

    let authentication_method = authentication_method_result.unwrap();
    
    let is_valid_hostname_for_authmethod_result = is_valid_authentication_method_for_hostname(hostname.clone(), authentication_method.clone()).await.expect("Invalid authentication method for hostname.");;
    // if (is_valid_hostname_for_authmethod_result.is_ok() != true) {
    //     return Ok(status::Custom(Status::BadRequest, error_message("Invalid authentication method for hostname.".into())));
    // }

    if (authentication_method.method_type == "email") {
        let request_data: Magiclink_request_data = serde_json::from_value(body.request_data.clone()).unwrap();
        let mut requested_email = request_data.email.expect("Missing body.request_data.email");
        if (is_null_or_whitespace(requested_email.clone())) {
            // Return error.
            return Ok(status::Custom(Status::BadRequest, error_message("body.request_data.email is null or whitespace.")));
        }

        let (request_magiclink_response, request_magiclink_response_db): (Request_magiclink, Connection<Db>) = request_email(db, requested_email.clone(), authentication_method, remote_addr, hostname).await.expect("Failed to send magiclink.");
        if (request_magiclink_response.error_to_respond_to_client_with.is_none() == false) {
            return Ok(request_magiclink_response.error_to_respond_to_client_with.unwrap());
        }
        db = request_magiclink_response_db;
    } else {
        println!("authentication_method.method_type is invalid. Something went wrong in startup config validation.");
        return Err(Status::InternalServerError);
    }

    Ok(status::Custom(Status::Ok, json!({
        "ok": true
    })))
}

#[post("/authenticate?<host>", format = "application/json", data = "<body>")]
async fn authenticate(mut db: Connection<Db>, mut host: Option<String>, mut body: Json<Method_request_body>, remote_addr: SocketAddr, headers: &Headers) -> Result<Custom<Value>, Status> {
    let hostname = get_hostname(host.unwrap()).await.expect("Invalid or missing hostname.");

    let authentication_method_result = is_valid_authentication_method(body.authentication_method.clone()).await;
    if (authentication_method_result.is_none() != false) {
        return Ok(status::Custom(Status::BadRequest, error_message("body.authentication_method is not a valid authentication method.".into())));
    }

    let mut user_id: Option<String> = None;

    let authentication_method = authentication_method_result.unwrap();

    let is_valid_hostname_for_authmethod_result = is_valid_authentication_method_for_hostname(hostname.clone(), authentication_method.clone()).await.expect("Invalid authentication method for hostname.");
    // if (is_valid_hostname_for_authmethod_result.is_ok() != true) {
    //     return Ok(status::Custom(Status::BadRequest, error_message("Invalid authentication method for hostname.".into())));
    // }

    if (authentication_method.method_type == "email") {
        let request_data: Magiclink_handling_data = serde_json::from_value(body.request_data.clone()).unwrap();
        let (handling_magiclink, handling_magiclink_db) = handling_email_magiclink(db, request_data.clone(), authentication_method.clone(), remote_addr).await.expect("Failed to verify magiclink.");
        if (handling_magiclink.error_to_respond_to_client_with.is_none() == false) {
            return Ok(handling_magiclink.error_to_respond_to_client_with.unwrap());
        }
        db = handling_magiclink_db;

        let magiclink: Magiclink = handling_magiclink.magiclink.unwrap();
        user_id = Some(magiclink.user_id);
    } else {
        println!("authentication_method.method_type is invalid. Something went wrong in startup config validation.");
        return Err(Status::InternalServerError);
    }

    if (user_id.is_none() == true) {
        // Authentication failed... Something has definitely gone wrong if this fires.
        println!("Authentication method logic (where we run the unique authentication code for each type of authentication method) exited without returning a userid. If you're in production and you see this, please immediately report it as a bug.");
        return Err(Status::InternalServerError);
    }

    let essential_authenticate_request_data: Essential_authenticate_request_data = serde_json::from_value(body.request_data.clone()).unwrap();
    let public_key = essential_authenticate_request_data.public_key;
    // TODO: Collateral needs to be here, such as a userid or MS bearer token, so when that person loses access they immediately get kicked.

    let (device_id, device_db) = device_create(
        db,
        user_id.expect("missing user id").clone(),
        authentication_method.id.clone().unwrap(),
        Some("".to_string()),
        public_key
    ).await.expect("Failed to create device");

    db = device_db;

    let public_authmethod: AuthMethod_Public = authentication_method.into();

    Ok(status::Custom(Status::Ok, json!({
        "ok": true,
        "device_id": device_id,
        "authentication_method": public_authmethod
    })))
}

async fn proxy_authentication(mut db: Connection<Db>, jar: &CookieJar<'_>, remote_addr: SocketAddr, headers: &Headers) -> Custom<Value> {
    let host = get_current_valid_hostname(headers).await.expect("Invalid or missing hostname.");
    let (result, user, device, db): (bool, Option<Guard_user>, Option<Guard_devices>, Connection<Db>) = user_authentication_pipeline(db, jar, remote_addr, host).await.expect("User authentication pipeline failed");

    if (result == true) {
        return status::Custom(Status::Ok, json!({
            "success": true
        }));
    } else {
        return status::Custom(Status::Unauthorized, json!({
            "success": false
        }));
    }
}

#[get("/authentication")]
async fn proxy_authentication_get(mut db: Connection<Db>, jar: &CookieJar<'_>, remote_addr: SocketAddr, headers: &Headers) -> Custom<Value> {
    return proxy_authentication(db, jar, remote_addr, headers).await;
}

#[put("/authentication")]
async fn proxy_authentication_put(mut db: Connection<Db>, jar: &CookieJar<'_>, remote_addr: SocketAddr, headers: &Headers) -> Custom<Value> {
    return proxy_authentication(db, jar, remote_addr, headers).await;
}

#[post("/authentication")]
async fn proxy_authentication_post(mut db: Connection<Db>, jar: &CookieJar<'_>, remote_addr: SocketAddr, headers: &Headers) -> Custom<Value> {
    return proxy_authentication(db, jar, remote_addr, headers).await;
}

#[delete("/authentication")]
async fn proxy_authentication_delete(mut db: Connection<Db>, jar: &CookieJar<'_>, remote_addr: SocketAddr, headers: &Headers) -> Custom<Value> {
    return proxy_authentication(db, jar, remote_addr, headers).await;
}

#[head("/authentication")]
async fn proxy_authentication_head(mut db: Connection<Db>, jar: &CookieJar<'_>, remote_addr: SocketAddr, headers: &Headers) -> Custom<Value> {
    return proxy_authentication(db, jar, remote_addr, headers).await;
}

#[options("/authentication")]
async fn proxy_authentication_options(mut db: Connection<Db>, jar: &CookieJar<'_>, remote_addr: SocketAddr, headers: &Headers) -> Custom<Value> {
    return proxy_authentication(db, jar, remote_addr, headers).await;
}

#[patch("/authentication")]
async fn proxy_authentication_patch(mut db: Connection<Db>, jar: &CookieJar<'_>, remote_addr: SocketAddr, headers: &Headers) -> Custom<Value> {
    return proxy_authentication(db, jar, remote_addr, headers).await;
}

// this needs to be blocked for proxies.
#[options("/<_..>")]
fn options_handler() -> &'static str {
    ""
}

/// Returns the current request's ID, assigning one only as necessary.
#[rocket::async_trait]
impl<'r> FromRequest<'r> for &'r Query_string {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        // The closure passed to `local_cache` will be executed at most once per
        // request: the first time the `RequestId` guard is used. If it is
        // requested again, `local_cache` will return the same value.

        request::Outcome::Success(request.local_cache(|| {
            let query_params = request.uri().query().map(|query| query.as_str().to_owned()).unwrap_or_else(|| String::new());

            Query_string(query_params)
        }))
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for &'r Headers {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        request::Outcome::Success(request.local_cache(|| {
            let value = request.headers().iter()
                .map(|header| (header.name.to_string(), header.value.to_string()))
                .collect::<HashMap<String, String>>();

            Headers { headers_map: value }
        }))
    }
}

// #[rocket::async_trait]
// impl<'r> FromRequest<'r> for Host_header {
//     type Error = ();

//     async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
//         request::Outcome::Success(request.local_cache(|| {
//             let host = request.headers().get_one("host").unwrap().to_string();
//             Host_header(host)
//         }))
//     }
// }

pub fn stage() -> AdHoc {
    AdHoc::on_ignite("Diesel SQLite Stage", |rocket| async {
        let mut app = rocket.attach(Db::init())
        .mount("/frontend", FileServer::from("./frontend/_static"))
        .mount("/api", routes![metadata_get, metadata_get_authentication_methods, auth_method_request, authenticate, options_handler]);
        
        let config = (&*CONFIG_VALUE).clone();
        if (config["features"]["proxy_authentication"].to_string() == "true") {
            app = app.mount("/api/proxy", routes![
                proxy_authentication_get,
                proxy_authentication_put,
                proxy_authentication_post,
                proxy_authentication_delete,
                proxy_authentication_head,
                proxy_authentication_options,
                proxy_authentication_patch
            ]);
        }
        
        app
    })
}
