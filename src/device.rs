use serde::{Serialize, Deserialize};
use serde_json::{Value, json};

use rocket_db_pools::{Database, Connection};
use rocket_db_pools::diesel::{MysqlPool, prelude::*};
use rocket::http::{Status, CookieJar, Cookie};
use rocket::response::status;

use diesel::sql_query;
use diesel::prelude::*;
use diesel::sql_types::*;

use crate::global::{send_email, generate_random_id, get_epoch};
use crate::responses::*;
use crate::structs::*;
use crate::tables::*;
use hades_auth::*;
use std::error::Error;
use std::net::SocketAddr;

use crate::{CONFIG_VALUE, SQL_TABLES};

// Some authenticatiom methods, such as email require action (such as sending a magiclink) before the user can present credentials to authenticate. This is where that logic is kept.

pub async fn device_get(mut db: Connection<Db>, id: String) -> Result<(Option<Guard_devices>, Connection<Db>), Box<dyn Error>> {
    let sql: Config_sql = (&*SQL_TABLES).clone();

    let query = format!("SELECT id, user_id, authentication_method, collateral, public_key, created FROM {} WHERE id=?", sql.devices_table.unwrap());

    let result: Vec<Guard_devices> = sql_query(query)
    .bind::<Text, _>(id)
    .load::<Guard_devices>(&mut db)
    .await
    .expect("Something went wrong querying the DB.");

    if (result.len() == 0) {
        // Device not found.
        return Ok((None, db));
    }

    let device = result[0].clone();

    Ok((Some(device), db))
}

pub async fn device_create(mut db: Connection<Db>, user_id: String, authentication_method_id: String, collateral: Option<String>, public_key: String) -> Result<(String, Connection<Db>), Box<dyn Error>> {
    let device_id = generate_random_id();

    let sql: Config_sql = (&*SQL_TABLES).clone();
    let query = format!("INSERT INTO {} (id, user_id, authentication_method, collateral, public_key, created) VALUES (?, ?, ?, ?, ?, ?)", sql.devices_table.unwrap());
    let result = sql_query(query)
    .bind::<Text, _>(device_id.clone())
    .bind::<Text, _>(user_id.clone())
    .bind::<Text, _>(authentication_method_id.clone())
    .bind::<Text, _>(collateral.unwrap_or("".to_string()))
    .bind::<Text, _>(public_key.clone())
    .bind::<BigInt, _>(get_epoch())
    .execute(&mut db)
    .await
    .expect("Something went wrong querying the DB.");

    Ok((device_id, db))
}