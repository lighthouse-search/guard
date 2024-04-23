use std::fmt::format;
use std::process::{Command, Stdio};
use std::error::Error;
use std::collections::{HashMap};
use std::time::{SystemTime, UNIX_EPOCH};
use std::fs;
use std::fs::{File};
use std::io::Write;
use url::Url;

use rand::prelude::*;

use crate::structs::*;
use crate::tables::*;
use rocket_db_pools::{Database, Connection};
use rocket_db_pools::diesel::{MysqlPool, prelude::*};
use regex::Regex;
use std::env;

use crate::CONFIG_VALUE;

pub async fn check_database_environment() -> Result<bool, Box<dyn Error>> {
    let sql_json = serde_json::to_string(&CONFIG_VALUE["database"]["mysql"]).expect("Failed to serialize");
    let sql: Config_database_mysql = serde_json::from_str(&sql_json).expect("Failed to parse");

    let username = sql.username.expect("Missing username.");
    let password = sql.password.expect("Missing password.");
    let hostname = sql.hostname.expect("Missing hostname.");
    let port = sql.port.expect("Missing port.");
    let database = sql.database.expect("Missing database.");

    let db = format!("mysql://{}:{}@{}:{}/{}", username, password, hostname, port, database);
    let rocket_db: String = format!("{{guard_database={{url=\"{}\"}}}}", db).to_string();

    if let Some(val) = env::var("ROCKET_DATABASES").ok() {
        println!("Value of ROCKET_DATABASES: {}", val);

        if (val != rocket_db.clone()) {
            return Err(format!("Tried to put connection string from configuration file into environment variable \"ROCKET_DATABASES\", however, \"ROCKET_DATABASE\" already has a value of \"{}\". For safety, we won't override this value. You need to make the value of \"ROCKET_DATABASES\" \"{}\", or merge them together. Here's more information: https://stackoverflow.com/a/60024168", val, rocket_db).into());
        }
    } else {
        // ROCKET_DATABASES is not set
    }

    env::set_var("ROCKET_DATABASES", rocket_db.clone());

    Ok(true)
}