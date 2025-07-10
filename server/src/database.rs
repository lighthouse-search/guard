use std::error::Error;

use crate::globals::environment_variables;
use crate::structs::*;
use regex::Regex;

use crate::CONFIG_VALUE;

fn validate_table_name(input: &str) -> bool {
    let re = Regex::new(r"^[A-Za-z1-9_]+$").unwrap();
    re.is_match(input)
}

pub async fn validate_sql_table_inputs(sql_tables: serde_json::Value) -> Result<bool, Box<dyn Error>> {
    // log::info!("sql_tables: {:?}", sql_tables);

    let sql_tables_map: &serde_json::Map<String, serde_json::Value> = sql_tables
        .as_object()
        .ok_or("expected a JSON object at top level")?;

    for (key, value) in sql_tables_map {
        if let Some(table_name) = value.as_str() {
            let output = validate_table_name(table_name);
            if output != true {
                return Err(format!("\"{}\" does not match A-Za-z1-9. This is necessary for SQL security, as table names are not bind-able.", key).into());
            }
        }
    }

    Ok(true)
}

pub fn create_database_url(username: String, password: String, hostname: String, port: u16, database: String) -> String {
    return format!("mysql://{}:{}@{}:{}/{}", username, password, hostname, port, database);
}

pub fn get_default_database_url() -> String {
    let sql: ConfigDatabaseMysql = CONFIG_VALUE.database.clone().and_then(|d| d.mysql).expect("missing config.database.mysql");

    let password_env = environment_variables::get(sql.password_env.clone().expect("config.sql.password_env is missing.")).expect(&format!("The environment variable specified in config.sql.password_env ('{:?}') is missing.", sql.password_env.clone()));

    let username = sql.username.expect("Missing username.");
    let hostname = sql.hostname.expect("Missing hostname.");
    let port = sql.port.expect("Missing port.");
    let database = sql.database.expect("Missing database.");

    return create_database_url(username, password_env, hostname, port, database);
}