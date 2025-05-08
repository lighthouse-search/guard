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

use diesel_mysql::internal_error;
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

pub static CONFIG_VALUE: Lazy<Value> = Lazy::new(|| {
    get_config().expect("Failed to get config")
});

pub static SQL_TABLES: Lazy<Config_sql> = Lazy::new(|| {
    let (sql_tables, raw_sql_tables) = get_sql_tables().expect("failed to get_sql_tables()");
    sql_tables
});

pub static ARGUMENTS: Lazy<crate::cli::cli_structs::Args_to_hashmap> = Lazy::new(|| {
    crate::cli::index::args_to_hashmap(env::args().collect())
});

fn get_config() -> Result<Value, Box<dyn Error>> {
    use std::env;

    let mut config_value: String = String::new();
    if let Some(val) = env::var("guard_config").ok() {
        log::info!("Value of guard_config (test 0): {}", val);

        config_value = val;
    } else {
        return Err("Missing \"guard_config\" environment variable".into());
    }

    // let contents = fs::read_to_string("./config.toml")
    //     .expect("Should have been able to read the file");

    let config: Value = toml::from_str(&config_value).unwrap();

    // let value = contents.parse::<toml::Value>().expect("lmao");
    // let table = value.as_table().unwrap();
    // let auth_methods = table.get("authentication_methods").unwrap().as_table().unwrap();

    // let mut valid: Option<AuthMethod> = None;
    // for (key, value) in auth_methods {
    //     if (key.to_string() == id) {
    //         valid = Some(serde_json::from_str(&value.to_string()).expect(&format!("Failed to parse authentication method: {}", key)));
    //     }
    // }

    Ok(config)
}

fn get_sql_tables() -> Result<(Config_sql, Value), String> {
    let config_value_sql = CONFIG_VALUE.get("sql");
    if (config_value_sql.is_none() == true) {
        return Err("Missing config.sql".into());
    }
    let config_value_sql_tables = config_value_sql.unwrap().get("tables");
    if (config_value_sql_tables.is_none() == true) {
        return Err("Missing config.sql.tables".into());
    }

    let sql_json = serde_json::to_string(&config_value_sql_tables).expect("Failed to serialize");
    let sql: Config_sql = serde_json::from_str(&sql_json).expect("Failed to parse");

    return Ok((sql, config_value_sql_tables.unwrap().clone()));
}

#[tokio::main]
async fn main() {
    env_logger::init();
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
    let (unsafe_do_not_use_sql_tables, unsafe_do_not_use_raw_sql_tables) = get_sql_tables().unwrap();
    validate_sql_table_inputs(unsafe_do_not_use_raw_sql_tables).await.expect("Config validation failed.");

    let mut rng = rand::thread_rng();
    let mut guard_port: u32 = rng.gen_range(4000..65535);
    
    if (ARGUMENTS.args.get("port").is_none() == false && ARGUMENTS.args.get("port").clone().unwrap().value.is_none() == false) {
        guard_port = ARGUMENTS.args.get("port").unwrap().value.clone().unwrap().parse().expect("Failed to parse guard_port.");
    }

    let figment = rocket::Config::figment()
    .merge(("port", guard_port))
    .merge(("address", "0.0.0.0"));

    // We're using Web mode.
    rocket::custom(figment)
    .register("/", catchers![internal_error])
    // .attach(Cors)
    .attach(diesel_mysql::stage())
}