use serde::{Serialize, Deserialize};
use serde_json::{Value, json};
use rocket::response::status;
use rocket::http::Status;

use diesel::sql_query;
use diesel::prelude::*;
use diesel::sql_types::*;

use crate::global::{is_null_or_whitespace, get_epoch};
use crate::responses::*;
use crate::structs::*;
use crate::tables::*;
use hades_auth::*;
use std::error::Error;
use std::net::SocketAddr;

use crate::{CONFIG_VALUE, SQL_TABLES};

pub async fn get_magiclink(code: String) -> (Option<Magiclink>) {
    let mut db = crate::DB_POOL.get().expect("Failed to get a connection from the pool.");

    let sql: Config_sql = (&*SQL_TABLES).clone();
    let magiclink_table = sql.magiclink.unwrap();

    let query = format!("SELECT user_id, code, ip, created, authentication_method FROM {} WHERE code=?", magiclink_table.clone());
    let result: Vec<Magiclink> = sql_query(query)
    .bind::<Text, _>(code.clone())
    .load::<Magiclink>(&mut db)
    .expect("Something went wrong querying the DB.");

    if (result.len() == 0) {
        // Magiclink invalid, not found.
        return (None);
    }
    let magiclink = result[0].clone();

    return (Some(magiclink));
}