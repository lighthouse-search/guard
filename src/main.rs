#[macro_use] extern crate rocket;
#[macro_use] extern crate rocket_sync_db_pools;

#[cfg(test)] mod tests;

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

use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::Header;
use rocket::{Request, Response};

use crate::responses::*;

use once_cell::sync::Lazy;
use structs::Config_sql;
use toml::Value;

use std::error::Error;
use std::fs;
use std::collections::HashMap;

use crate::global::{validate_sql_table_inputs, get_current_valid_hostname};
use crate::database::{check_database_environment};
use crate::structs::*;

pub static CONFIG_VALUE: Lazy<Value> = Lazy::new(|| {
    get_config().expect("Failed to get config")
});

pub static SQL_TABLES: Lazy<Config_sql> = Lazy::new(|| {
    get_sql_tables()
});

fn get_config() -> Result<Value, Box<dyn Error>> {
    use std::env;

    let mut config_value: String = String::new();
    if let Some(val) = env::var("guard_config").ok() {
        println!("Value of guard_config: {}", val);

        config_value = val;
    } else {
        return Err("Missing \"guard_config\" environment variable".into());
        // ROCKET_DATABASES is not set
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

fn get_sql_tables() -> Config_sql {
    let sql_json = serde_json::to_string(&CONFIG_VALUE["sql"]).expect("Failed to serialize");
    let sql: Config_sql = serde_json::from_str(&sql_json).expect("Failed to parse");

    return sql;
}

#[catch(500)]
fn internal_error() -> serde_json::Value {
    error_message("Internal server error")
}

#[launch]
async fn rocket() -> _ {
    validate_sql_table_inputs().await.expect("Config validation failed");
    check_database_environment().await.expect("Check database environment failed");

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
        // TODO: Finish this.
        
        let value = _request.headers().iter()
        .map(|header| (header.name.to_string(), header.value.to_string()))
        .collect::<HashMap<String, String>>();

        let headers = Headers { headers_map: value };

        let get_current_valid_hostname = get_current_valid_hostname(&headers).await.expect("Invalid hostname");

        response.set_header(Header::new("Access-Control-Allow-Origin", get_current_valid_hostname));
        response.set_header(Header::new(
            "Access-Control-Allow-Methods",
            "POST, PATCH, PUT, DELETE, HEAD, OPTIONS, GET",
        ));
        response.set_header(Header::new("Access-Control-Allow-Headers", "*"));
        response.set_header(Header::new("Access-Control-Allow-Credentials", "true"));
        response.remove_header("server");
    }
}