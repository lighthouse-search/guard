pub struct Cors;

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

pub mod request_proxy;

use axum::{
    Json, Router, http::StatusCode, routing::{any, delete, get, head, options, patch, post, put}
};

use axum_server::tls_rustls::RustlsConfig;
use tower_http::services::ServeDir;

use once_cell::sync::Lazy;
use toml::Value;

use std::{env, net::SocketAddr, path::PathBuf};

use crate::{endpoints::{auth::authenticate, metadata::{metadata_get, metadata_get_authentication_methods}, reverse_proxy_authentication::{reverse_proxy_authentication_delete, reverse_proxy_authentication_get, reverse_proxy_authentication_head, reverse_proxy_authentication_options, reverse_proxy_authentication_patch, reverse_proxy_authentication_post, reverse_proxy_authentication_put}}, protocols::oauth::endpoint::{client::oauth_exchange_code, server::oauth_server_token}};
use crate::database::validate_sql_table_inputs;
use crate::structs::*;
use crate::responses::*;

use diesel::MysqlConnection;
use diesel::r2d2::{self, ConnectionManager};

// Create a type alias for the connection pool
type Pool = r2d2::Pool<ConnectionManager<MysqlConnection>>;

use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;

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
    let mut guard_port: u16 = 8000;

    if ARGUMENTS.args.get("port").is_none() == false && ARGUMENTS.args.get("port").clone().unwrap().value.is_none() == false {
        guard_port = ARGUMENTS.args.get("port").unwrap().value.clone().unwrap().parse().expect("Failed to parse guard_port.");
    }

    print!("Starting Guard server on port {}...\n", guard_port);

    let tls_config = crate::misc::tls::init_tls().await;
    if tls_config.is_some() {
        log::info!("Using TLS configuration.");
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

    let client: Client<HttpConnector, axum::body::Body> =
        hyper_util::client::legacy::Client::builder(TokioExecutor::new())
            .build(HttpConnector::new());

    let frontend_path_arc = std::sync::Arc::new(frontend_path.clone());
    let html_fallback = tower::util::service_fn(move |req: axum::http::Request<axum::body::Body>| {
        let base = frontend_path_arc.clone();
        async move {
            let uri_path = req.uri().path();
            let rel_path = uri_path.trim_start_matches('/');

            // Sanitize: keep only Normal components to prevent path traversal
            let mut safe_path = std::path::PathBuf::new();
            for component in std::path::Path::new(rel_path).components() {
                if let std::path::Component::Normal(c) = component {
                    safe_path.push(c);
                }
            }

            let html_file = base.join(format!("{}.html", safe_path.display()));
            match tokio::fs::read(&html_file).await {
                Ok(content) => Ok::<_, std::convert::Infallible>(
                    axum::http::Response::builder()
                        .status(200)
                        .header("content-type", "text/html; charset=utf-8")
                        .body(axum::body::Body::from(content))
                        .unwrap()
                ),
                Err(_) => Ok::<_, std::convert::Infallible>(
                    axum::http::Response::builder()
                        .status(404)
                        .body(axum::body::Body::empty())
                        .unwrap()
                ),
            }
        }
    });

    let mut app = Router::new()
    .nest_service("/guard/frontend", ServeDir::new(frontend_path.display().to_string()).fallback(html_fallback))
    .route("/guard/api/metadata", get(metadata_get))
    .route("/guard/api/metadata/get-authentication-methods", get(metadata_get_authentication_methods))
    .route("/guard/api/auth/request", post(crate::endpoints::auth::auth_method_request))
    .route("/guard/api/auth/authenticate", post(authenticate))
    .route("/guard/api/oauth/exchange-code", get(oauth_exchange_code))
    // .route("/ws", any(crate::request_proxy::ws_handler))
    .route("/", get(root_handler))
    .with_state(client);
    // .layer(
    //     TraceLayer::new_for_http()
    //         .make_span_with(DefaultMakeSpan::default().include_headers(true)),
    // );

    let guard_config = (&*CONFIG_VALUE).clone();

    // Attempt to extract "config.reverse_proxy_authentication"
    if let Some(features) = guard_config.features {
        if features.reverse_proxy_authentication.unwrap_or(false) == true {
            app = app.route("/guard/api/proxy/authentication", get(reverse_proxy_authentication_get));
            app = app.route("/guard/api/proxy/authentication", put(reverse_proxy_authentication_put));
            app = app.route("/guard/api/proxy/authentication", post(reverse_proxy_authentication_post));
            app = app.route("/guard/api/proxy/authentication", delete(reverse_proxy_authentication_delete));
            app = app.route("/guard/api/proxy/authentication", head(reverse_proxy_authentication_head));
            app = app.route("/guard/api/proxy/authentication", options(reverse_proxy_authentication_options));
            app = app.route("/guard/api/proxy/authentication", patch(reverse_proxy_authentication_patch));
        }

        if features.oauth_server.unwrap_or(false) == true {
            app = app.route("/guard/api/oauth/server/token", post(oauth_server_token));
        }
    }

    let addr = SocketAddr::from(([0, 0, 0, 0], guard_port));
    log::info!("listening on {}", addr);

    if let Some(tls) = tls_config {
        axum_server::bind_rustls(addr, tls)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .unwrap();
    } else {
        axum_server::bind(addr)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .unwrap();
    }
}

async fn root_handler(
    axum::extract::State(client): axum::extract::State<Client<HttpConnector, axum::body::Body>>,
    jar: axum_extra::extract::CookieJar,
    axum::extract::ConnectInfo(remote_addr): axum::extract::ConnectInfo<SocketAddr>,
    mut headers: axum::http::HeaderMap,
    mut req: axum::extract::Request,
) -> axum::response::Response {
    use axum::http::HeaderValue;
    use axum::response::IntoResponse;

    // In HTTP/2, the Host header is absent — the host comes from the :authority pseudo-header,
    // which hyper maps to the URI authority rather than to a "host" header entry.
    if headers.get("host").is_none() {
        if let Some(authority) = req.uri().authority() {
            if let Ok(val) = HeaderValue::from_str(authority.as_str()) {
                headers.insert(axum::http::header::HOST, val.clone());
                req.headers_mut().insert(axum::http::header::HOST, val);
            }
        }
    }

    let instance_hostname = CONFIG_VALUE
        .frontend
        .as_ref()
        .and_then(|f| f.metadata.as_ref())
        .and_then(|m| m.instance_hostname.as_deref())
        .unwrap_or("");

    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if host == instance_hostname {
        let body = concat!(
            "<!DOCTYPE html>\n",
            "<html>\n",
            "<head><meta charset=\"utf-8\"><title>Guard</title></head>\n",
            "<body style=\"background:#0d1117;color:#e6edf3;font-family:monospace;padding:2rem\">\n",
            "<pre>  ____                     _\n",
            " / ___|_   _  __ _ _ __ __| |\n",
            "| |  _| | | |/ _` | '__/ _` |\n",
            "| |_| | |_| | (_| | | | (_| |\n",
            " \\____|\\ __,_|\\__,_|_|  \\__,_|</pre>\n",
            "<p>Guard is ready! Open a hostname to start.</p>\n",
            "<p>\n",
            "  <a href=\"https://github.com/lighthouse-search/guard\" style=\"color:#58a6ff\">Docs</a> &nbsp;|&nbsp;\n",
            "  <a href=\"https://lighthouse-search.github.io/guard/\" style=\"color:#58a6ff\">Quickstart</a>\n",
            "</p>\n",
            "</body>\n",
            "</html>\n"
        );
        return (
            axum::http::StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
            body,
        ).into_response();
    }

    crate::request_proxy::http_handler(
        axum::extract::State(client),
        jar,
        axum::extract::ConnectInfo(remote_addr),
        headers,
        req,
    ).await
}