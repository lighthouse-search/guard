use rocket::{routes, options};
use rocket::fairing::AdHoc;
use rocket::fs::FileServer;

use crate::endpoints::auth::{auth_method_request, authenticate};
use crate::endpoints::metadata::{metadata_get, metadata_get_authentication_methods};
use crate::endpoints::reverse_proxy_authentication::{reverse_proxy_authentication_delete, reverse_proxy_authentication_get, reverse_proxy_authentication_head, reverse_proxy_authentication_options, reverse_proxy_authentication_patch, reverse_proxy_authentication_post, reverse_proxy_authentication_put};
use crate::protocols::oauth::endpoint::oauth_endpoint::oauth_exchange_code;
use crate::{CONFIG_VALUE, SQL_TABLES};
use crate::structs::*;

// TODO: check this is blocked for proxies.
#[options("/<_..>")]
fn options_handler() -> &'static str {
    ""
}

pub fn stage() -> AdHoc {
    AdHoc::on_ignite("Diesel SQLite Stage", |rocket| async {
        let mut app = rocket
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

        if let Some(features) = config.get("features") {
            if (features.get("proxied_authentication").is_none() == false && features["proxied_authentication"].to_string() == "true") {
                // Initialize proxied authentication
            }
        }
        
        app
    })
}
