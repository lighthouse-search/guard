use serde::{Serialize, Deserialize};
use serde_json::{Value, json};
use rocket_db_pools::{Database, Connection};
use rocket_db_pools::diesel::{MysqlPool, prelude::*};
use rocket::response::status;
use rocket::http::Status;
use diesel::sql_query;

use diesel::prelude::*;
use diesel::sql_types::*;

use crate::global::{is_valid_authentication_method_for_hostname, is_null_or_whitespace, get_hostname, get_epoch};
use crate::responses::*;
use crate::structs::*;
use crate::tables::*;
use hades_auth::*;
use std::error::Error;
use std::net::SocketAddr;

use crate::{CONFIG_VALUE, SQL_TABLES};

pub async fn get_magiclink(mut db: Connection<Db>, code: String) -> (Option<Magiclink>, Connection<Db>) {
    let sql: Config_sql = (&*SQL_TABLES).clone();
    let magiclink_table = sql.magiclink_table.unwrap();

    let query = format!("SELECT user_id, code, ip, created, authentication_method FROM {} WHERE code=?", magiclink_table.clone());
    let result: Vec<Magiclink> = sql_query(query)
    .bind::<Text, _>(code.clone())
    .load::<Magiclink>(&mut db)
    .await
    .expect("Something went wrong querying the DB.");

    if (result.len() == 0) {
        // Magiclink invalid, not found.
        return (None, db);
    }
    let magiclink = result[0].clone();

    return (Some(magiclink), db);
}