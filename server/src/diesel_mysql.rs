use rocket::{routes, options};
use rocket::fs::FileServer;
use rocket::fairing::AdHoc;
use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::Header;
use rocket::{Request, Response, request, request::FromRequest, catch, catchers, launch};

use crate::endpoints::auth::{auth_method_request, authenticate};
use crate::endpoints::metadata::{metadata_get, metadata_get_authentication_methods};
use crate::endpoints::reverse_proxy_authentication::{reverse_proxy_authentication_delete, reverse_proxy_authentication_get, reverse_proxy_authentication_head, reverse_proxy_authentication_options, reverse_proxy_authentication_patch, reverse_proxy_authentication_post, reverse_proxy_authentication_put};
use crate::protocols::oauth::endpoint::client::oauth_exchange_code;
use crate::protocols::oauth::endpoint::server::{oauth_server_token};
use crate::{CONFIG_VALUE, SQL_TABLES};

use crate::hostname::get_current_valid_hostname;
use crate::structs::*;
use crate::responses::*;

use std::collections::HashMap;
use std::env;
use std::path::PathBuf;

pub struct Cors;

pub fn stage() -> AdHoc {
    AdHoc::on_ignite("Diesel SQLite Stage", |rocket| async {
        let mut frontend_path: PathBuf = env::current_exe().expect("Failed to get current directory");

        if cfg!(debug_assertions) {
            // Program is debug (cargo run).
            // guard/server/frontend/_static
            frontend_path.pop();
            frontend_path.pop();
            frontend_path.pop();
            frontend_path.push("frontend");
            frontend_path.push("_static");
        } else {
            // Program is release (cargo build)
            // guard/frontend/_static (use packaged assets)
            frontend_path.pop();
            frontend_path.push("frontend");
            frontend_path.push("_static");
        }

        let mut app = rocket
        .mount("/guard/frontend", FileServer::from(frontend_path.display().to_string()))
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

        if let Some(features) = config.get("features") {
            if (features.get("oauth_server").is_none() == false && features["oauth_server"].to_string() == "true") {
                app = app.mount("/guard/api/oauth/server", routes![
                    oauth_server_token
                ]);
            }
        }

        if let Some(features) = config.get("features") {
            if (features.get("proxied_authentication").is_none() == false && features["proxied_authentication"].to_string() == "true") {
                // Initialize proxied authentication
            }
        }
        
        app
    })
}

// TODO: check this is blocked for proxies.
#[options("/<_..>")]
fn options_handler() -> &'static str {
    ""
}

#[catch(500)]
pub fn internal_error() -> serde_json::Value {
    error_message("Internal server error")
}

#[rocket::async_trait]
impl Fairing for Cors {
    fn info(&self) -> Info {
        Info {
            name: "Cross-Origin-Resource-Sharing Fairing",
            kind: Kind::Response,
        }
    }

    // TODO: Cors shouldn't be everything.

    async fn on_response<'r>(&self, _request: &'r Request<'_>, response: &mut Response<'r>) {
        // TODO: Finish this (CORS, 'server' and 'x-guard' is not updating).
        
        let value = _request.headers().iter()
        .map(|header| (header.name.to_string(), header.value.to_string()))
        .collect::<HashMap<String, String>>();

        let headers = Headers { headers_map: value };

        let get_current_valid_hostname = get_current_valid_hostname(&headers, None).await.expect("Invalid hostname");

        response.set_header(Header::new("Access-Control-Allow-Origin", get_current_valid_hostname.domain_port));
        response.set_header(Header::new(
            "Access-Control-Allow-Methods",
            "POST, PATCH, PUT, DELETE, HEAD, OPTIONS, GET",
        ));
        response.set_header(Header::new("Access-Control-Allow-Headers", "*"));
        response.set_header(Header::new("Access-Control-Allow-Credentials", "true"));
        response.set_header(Header::new("x-guard", "https://github.com/oracularhades/guard"));
        response.remove_header("server");
    }
}

// Returns the current request's ID, assigning one only as necessary.
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