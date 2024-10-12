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
mod files;

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
        pub mod oauth_client;
        pub mod oauth_pipeline;
        pub mod endpoint {
            pub mod oauth_endpoint;
        }
    }
}
pub mod proxied_authentication {
    pub mod general;
    pub mod nginx;
}

use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::Header;
use rocket::{Request, Response, request, request::FromRequest, catch, catchers, launch};

use once_cell::sync::Lazy;
use toml::Value;

use std::error::Error;
use std::fs;
use std::collections::HashMap;

use crate::global::{validate_sql_table_inputs, get_current_valid_hostname};
use crate::structs::*;
use crate::responses::*;

use diesel::MysqlConnection;
use diesel::prelude::*;
use diesel::sql_types::*;
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

pub static CONFIG_VALUE: Lazy<Value> = Lazy::new(|| {
    get_config().expect("Failed to get config")
});

pub static SQL_TABLES: Lazy<Config_sql> = Lazy::new(|| {
    let (sql_tables, raw_sql_tables) = get_sql_tables().expect("failed to get_sql_tables()");
    sql_tables
});

fn get_config() -> Result<Value, Box<dyn Error>> {
    use std::env;

    let mut config_value: String = String::new();
    if let Some(val) = env::var("guard_config").ok() {
        println!("Value of guard_config (test 0): {}", val);

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

#[catch(500)]
fn internal_error() -> serde_json::Value {
    error_message("Internal server error")
}

#[launch]
async fn rocket() -> _ {
    let (unsafe_do_not_use_sql_tables, unsafe_do_not_use_raw_sql_tables) = get_sql_tables().unwrap();
    validate_sql_table_inputs(unsafe_do_not_use_raw_sql_tables).await.expect("Config validation failed.");

    rocket::build()
    .register("/", catchers![internal_error])
    // .attach(Cors)
    .attach(diesel_mysql::stage())
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