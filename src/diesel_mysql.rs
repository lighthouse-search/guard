use rocket::response::{Debug};
use rocket::request::{self, Request, FromRequest};
use rocket::{fairing::{Fairing, Info, Kind}, State};
use rocket::fairing::AdHoc;
use rocket::fs::FileServer;

use rocket_db_pools::{Database, Connection};
use crate::endpoints::auth::{auth_method_request, authenticate};
use crate::endpoints::metadata::{metadata_get, metadata_get_authentication_methods};
use crate::endpoints::proxy::{reverse_proxy_authentication_delete, reverse_proxy_authentication_get, reverse_proxy_authentication_head, reverse_proxy_authentication_options, reverse_proxy_authentication_patch, reverse_proxy_authentication_post, reverse_proxy_authentication_put};
use crate::protocols::oauth::endpoint::oauth_endpoint::oauth_exchange_code;
use crate::{CONFIG_VALUE, SQL_TABLES};
use crate::structs::*;

use std::collections::HashMap;

// type Result<T, E = Debug<diesel::result::Error>> = std::result::Result<T, E>;

// TODO: check this is blocked for proxies.
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

pub fn stage() -> AdHoc {
    AdHoc::on_ignite("Diesel SQLite Stage", |rocket| async {
        let mut app = rocket.attach(Db::init())
        .mount("/guard/frontend", FileServer::from("./frontend/_static"))
        .mount("/guard/api/metadata", routes![
            metadata_get,
            metadata_get_authentication_methods,
            options_handler
        ])
        .mount("/guard/api/auth", routes![
            auth_method_request,
            authenticate,
            options_handler
        ])
        .mount("/guard/api/oauth", routes![oauth_exchange_code]);
        
        let config = (&*CONFIG_VALUE).clone();
        // Attempt to extract "config.reverse_proxy_authentication"
        if let Some(features) = config.get("features") {
            if (features.get("reverse_proxy_authentication").is_none() == false && features["reverse_proxy_authentication"].to_string() == "true") {
                app = app.mount("/guard/api/proxy", routes![
                    reverse_proxy_authentication_get,
                    reverse_proxy_authentication_put,
                    reverse_proxy_authentication_post,
                    reverse_proxy_authentication_delete,
                    reverse_proxy_authentication_head,
                    reverse_proxy_authentication_options,   
                    reverse_proxy_authentication_patch
                ]);
            }
        }
        
        app
    })
}
