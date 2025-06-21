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

use diesel_mysql::internal_error;
use misc::tls::generate_self_signed_certificate;
use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::Header;
use rocket::{Build, Rocket};
use rocket::{Request, Response, request, request::FromRequest, catch, catchers, launch};

use once_cell::sync::Lazy;
use toml::Value;

use std::error::Error;
use std::{env, fs};
use std::collections::HashMap;

use crate::global::validate_sql_table_inputs;
use crate::structs::*;
use crate::responses::*;

use diesel::MysqlConnection;
use diesel::prelude::*;
use diesel::sql_types::*;
use diesel::r2d2::{self, ConnectionManager};

use rand::Rng;

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

pub static SQL_TABLES: Lazy<Config_sql_tables> = Lazy::new(|| {
    let config_sql_tables: Config_sql_tables = serde_json::from_value(CONFIG_VALUE.sql.clone().expect("Missing config.sql").tables.expect("mssing config.sql.tables")).expect("Failed to convert config.sql.tables from value to struct");
    config_sql_tables
});

pub static ARGUMENTS: Lazy<crate::cli::cli_structs::Args_to_hashmap> = Lazy::new(|| {
    crate::cli::index::args_to_hashmap(env::args().collect())
});

fn get_config() -> Result<Config, String> {
    let environment_variable = "guard_config";
    let mut config_str: String = String::new();
    if let Some(val) = env::var(environment_variable).ok() {
        println!("Value of {}: {}", environment_variable, val);

        config_str = val;
    } else {
        return Err(format!("Missing \"{}\" environment variable", environment_variable).into());
    }

    let config_value: Value = toml::from_str(&config_str).unwrap();
    let config: Config = serde_json::from_value(serde_json::to_value(config_value).expect("Failed to convert config value from toml to serde::json")).expect("Failed to parse config");

    Ok(config)
}

#[tokio::main]
async fn main() {
    env_logger::init();

    validate_sql_table_inputs(CONFIG_VALUE.sql.clone().expect("Missing config.sql").tables.expect("mssing config.sql.tables")).await.expect("Config validation failed.");

    if (ARGUMENTS.modes.len() > 0) {
        // We're using CLI mode.
        log::info!("Using CLI mode - argument modes were specified.");
        crate::cli::index::parse().await;
    } else {
        log::info!("Using Web mode - zero arguments specified. Starting Rocket server.");
        rocket().await.launch().await.expect("Failed to start web server");
    }
}

async fn rocket() -> Rocket<Build> {
    let mut rng = rand::thread_rng();
    let mut guard_port: u32 = 8000; // rng.gen_range(4000..65535)
    
    if (ARGUMENTS.args.get("port").is_none() == false && ARGUMENTS.args.get("port").clone().unwrap().value.is_none() == false) {
        guard_port = ARGUMENTS.args.get("port").unwrap().value.clone().unwrap().parse().expect("Failed to parse guard_port.");
    }

    let mut figment = rocket::Config::figment()
    .merge(("port", guard_port))
    .merge(("address", "0.0.0.0"));

    let tls = crate::misc::tls::init_tls().await;
    if (tls.is_none() == false) {
        log::info!("Using TLS configuration.");
        figment = figment.merge(("tls", tls));
    } else {
        log::info!("Not using TLS configuration.");
    }

    // We're using Web mode.
    rocket::custom(figment)
    .register("/", catchers![internal_error])
    // .attach(Cors)
    .attach(diesel_mysql::stage())
}