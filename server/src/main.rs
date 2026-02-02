pub struct Cors;

mod diesel_mysql;
mod global;
mod structs;
mod responses;
mod tables;
mod auth_method_request;
mod auth_method_handling;
mod users;
mod policy;
mod device;
mod database;
mod authentication_misc;
mod hostname;

pub mod endpoints {
    pub mod auth;
    pub mod metadata;
    pub mod reverse_proxy_authentication;
}
pub mod globals {
    pub mod environment_variables;
}
mod protocols {
    pub mod misc_pipeline {
        pub mod device;
    }
    pub mod email {
        pub mod magiclink;
    }
    pub mod oauth {
        pub mod client;
        pub mod pipeline;
        pub mod server {
            pub mod bearer_token;
        }
        pub mod endpoint {
            pub mod client;
            pub mod server;
        }
    }
}
pub mod cli {
    pub mod index;
    pub mod cli_structs;
    pub mod internal {
        pub mod validation {
            pub mod argument;
        }
    }
    pub mod mode {
        pub mod user;
        pub mod authenticate;
    }
}

pub mod misc {
    pub mod tls;
}

use axum::{
    Json, Router, http::StatusCode, routing::{delete, get, head, options, patch, post, put}
};
use axum_server::tls_rustls::RustlsConfig;

use once_cell::sync::Lazy;
use toml::Value;

use std::{env, path::PathBuf};

use crate::{endpoints::{auth::authenticate, metadata::{metadata_get, metadata_get_authentication_methods}, reverse_proxy_authentication::{reverse_proxy_authentication_delete, reverse_proxy_authentication_get, reverse_proxy_authentication_head, reverse_proxy_authentication_options, reverse_proxy_authentication_patch, reverse_proxy_authentication_post, reverse_proxy_authentication_put}}, protocols::oauth::endpoint::{client::oauth_exchange_code, server::oauth_server_token}};
use crate::database::validate_sql_table_inputs;
use crate::structs::*;
use crate::responses::*;

use diesel::MysqlConnection;
use diesel::r2d2::{self, ConnectionManager};

// Create a type alias for the connection pool
type Pool = r2d2::Pool<ConnectionManager<MysqlConnection>>;

// Create a Lazy static variable for the connection pool
static DB_POOL: Lazy<Pool> = Lazy::new(|| {
    let manager = ConnectionManager::<MysqlConnection>::new(crate::database::get_default_database_url());
    r2d2::Pool::builder()
        .build(manager)
        .expect("Failed to create pool.")
});

pub static CONFIG_VALUE: Lazy<Config> = Lazy::new(|| {
    get_config().expect("Failed to get config")
});

pub static SQL_TABLES: Lazy<ConfigSqlTables> = Lazy::new(|| {
    let config_sql_tables: ConfigSqlTables = serde_json::from_value(CONFIG_VALUE.sql.clone().expect("Missing config.sql").tables.expect("mssing config.sql.tables")).expect("Failed to convert config.sql.tables from value to struct");
    config_sql_tables
});

pub static ARGUMENTS: Lazy<crate::cli::cli_structs::ArgsToHashmap> = Lazy::new(|| {
    crate::cli::index::args_to_hashmap(env::args().collect())
});

fn get_config() -> Result<Config, String> {
    let environment_variable = "guard_config";
    let mut _config_str: String = String::new();
    if let Some(val) = env::var(environment_variable).ok() {
        println!("Value of {}: {}", environment_variable, val);

        _config_str = val;
    } else {
        return Err(format!("Missing \"{}\" environment variable", environment_variable).into());
    }

    let config_value: Value = toml::from_str(&_config_str).unwrap();
    let config: Config = serde_json::from_value(serde_json::to_value(config_value).expect("Failed to convert config value from toml to serde::json")).expect("Failed to parse config");

    Ok(config)
}

#[tokio::main]
async fn main() {
    env_logger::init();

    validate_sql_table_inputs(CONFIG_VALUE.sql.clone().expect("Missing config.sql").tables.expect("mssing config.sql.tables")).await.expect("Config validation failed.");

    if ARGUMENTS.modes.len() > 0 {
        // We're using CLI mode.
        log::info!("Using CLI mode - argument modes were specified.");
        crate::cli::index::parse().await;
    } else {
        log::info!("Using Web mode - zero arguments specified. Starting Rocket server.");
        start_web().await;
    }
}

async fn start_web() {
    // let mut rng = rand::thread_rng();
    let mut guard_port: u32 = 8000; // rng.gen_range(4000..65535)
    
    if ARGUMENTS.args.get("port").is_none() == false && ARGUMENTS.args.get("port").clone().unwrap().value.is_none() == false {
        guard_port = ARGUMENTS.args.get("port").unwrap().value.clone().unwrap().parse().expect("Failed to parse guard_port.");
    }

    print!("Starting Guard server on port {}...\n", guard_port);

    let mut figment = rocket::Config::figment()
    .merge(("port", guard_port))
    .merge(("address", "0.0.0.0"));

    let tls = crate::misc::tls::init_tls().await;
    if tls.is_none() == false {
        log::info!("Using TLS configuration.");
        figment = figment.merge(("tls", tls));
    } else {
        log::info!("Not using TLS configuration.");
    }

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

    let mut app = Router::new()
    .nest_service("/guard/frontend", ServeDir::new(frontend_path.display().to_string()))
    .route("/guard/api/metadata/get", get(metadata_get))
    .route("/guard/api/metadata/get-authentication-methods", get(metadata_get_authentication_methods))
    .route("/guard/api/auth/request", post(crate::endpoints::auth::auth_method_request))
    .route("/guard/api/auth/authenticate", post(authenticate))
    .route("/guard/api/oauth/exchange-code", get(oauth_exchange_code));
    
    let config = (&*CONFIG_VALUE).clone();
    
    // Attempt to extract "config.reverse_proxy_authentication"
    if let Some(features) = config.features {
        if features.reverse_proxy_authentication.unwrap_or(false) == true {
            app.route("/guard/api/proxy/authentication", get(reverse_proxy_authentication_get));
            app.route("/guard/api/proxy/authentication", put(reverse_proxy_authentication_put));
            app.route("/guard/api/proxy/authentication", post(reverse_proxy_authentication_post));
            app.route("/guard/api/proxy/authentication", delete(reverse_proxy_authentication_delete));
            app.route("/guard/api/proxy/authentication", head(reverse_proxy_authentication_head));
            app.route("/guard/api/proxy/authentication", options(reverse_proxy_authentication_options));
            app.route("/guard/api/proxy/authentication", patch(reverse_proxy_authentication_patch));
        }

        if features.oauth_server.unwrap_or(false) == true {
            app.route("/guard/api/oauth/server/token", post(oauth_server_token));
        }
    }

    // // configure certificate and private key used by https
    // let config = RustlsConfig::from_pem_file(
    //     PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    //         .join("self_signed_certs")
    //         .join("cert.pem"),
    //     PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    //         .join("self_signed_certs")
    //         .join("key.pem"),
    // )
    // .await
    // .unwrap();

    // run https server
    let addr = SocketAddr::from(([127, 0, 0, 1], guard_port));
    tracing::debug!("listening on {}", addr);
    axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service())
        .await
        .unwrap();
}