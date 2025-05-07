use serde::{Serialize, Deserialize};
use serde_json::{Value, json};

use rocket::http::{Status, CookieJar, Cookie};
use rocket::response::status;

use diesel::sql_query;
use diesel::prelude::*;
use diesel::sql_types::*;

use crate::global::{send_email, generate_random_id, get_epoch};
use crate::hostname::prepend_hostname_to_cookie;
use crate::responses::*;
use crate::structs::*;
use crate::tables::*;
use hades_auth::*;
use std::error::Error;
use std::net::SocketAddr;

use crate::{CONFIG_VALUE, SQL_TABLES};

// Some authenticatiom methods, such as email require action (such as sending a magiclink) before the user can present credentials to authenticate. This is where that logic is kept.

pub async fn device_get(id: String) -> Result<(Option<Guard_devices>), Box<dyn Error>> {
    let mut db = crate::DB_POOL.get().expect("Failed to get a connection from the pool.");
    let sql: Config_sql = (&*SQL_TABLES).clone();

    let query = format!("SELECT id, user_id, authentication_method, collateral, public_key, created FROM {} WHERE id=?", sql.device.unwrap());

    let result: Vec<Guard_devices> = sql_query(query)
    .bind::<Text, _>(id)
    .load::<Guard_devices>(&mut db)
    .expect("Something went wrong querying the DB.");

    if (result.len() == 0) {
        // Device not found.
        return Ok((None));
    }

    let device = result[0].clone();

    Ok((Some(device)))
}

pub async fn device_create(user_id: String, authentication_method_id: String, collateral: Option<String>, public_key: String) -> Result<String, Box<dyn Error>> {
    let mut db = crate::DB_POOL.get().expect("Failed to get a connection from the pool.");
    let device_id = generate_random_id();

    let sql: Config_sql = (&*SQL_TABLES).clone();
    let query = format!("INSERT INTO {} (id, user_id, authentication_method, collateral, public_key, created) VALUES (?, ?, ?, ?, ?, ?)", sql.device.unwrap());
    let result = sql_query(query)
    .bind::<Text, _>(device_id.clone())
    .bind::<Text, _>(user_id.clone())
    .bind::<Text, _>(authentication_method_id.clone())
    .bind::<Text, _>(collateral.unwrap_or("".to_string()))
    .bind::<Text, _>(public_key.clone())
    .bind::<BigInt, _>(get_epoch())
    .execute(&mut db)
    .expect("Something went wrong querying the DB.");

    Ok(device_id)
}

pub fn device_guard_static_auth_from_cookies(jar: &indexmap::IndexMap<String, String>) -> Option<String> {
    let mut signed_data: String = String::new();

    let cookie_name = prepend_hostname_to_cookie("guard_static_auth");
    if (jar.get(&cookie_name.clone()).is_none() == false) {
        signed_data = jar.get(&cookie_name.clone()).expect("Failed to parse signed_data.").to_string();
        log::debug!("Signed_data cookie: {:?}", signed_data);
    } else {
        log::debug!("Signed_data cookie: None");
        return None;
    }

    return Some(signed_data);
}

pub async fn device_signed_authentication(signed_data: String) -> Result<(Guard_devices, Option<Value>), String> {
    let mut db = crate::DB_POOL.get().expect("Failed to get a connection from the pool.");
    let unsigned_data: Static_auth_sign = serde_json::from_value(get_unsafe_noverification_jwt_payload(signed_data.clone()).expect("Failed to parse payload.")).expect("Failed to prase JWT");
    
    // TODO: Instead of things like .expect("Missing additional data"), return an actual response.
    // TODO: device_id here (in Signed_data_identifier) should get moved to being a main field and not part of additional_data.
    let unsigned_data_deviceinfo: Signed_data_identifier = serde_json::from_value(unsigned_data.additional_data.expect("Missing additional data")).expect("Failed to parse identifier data.");
    
    let device_id: String = unsigned_data_deviceinfo.device_id;
    let (device_wrapped) = device_get(device_id).await.expect("Failed to query for device.");
    let device = device_wrapped.expect("Device not found");

    let output = static_auth_verify(&signed_data, &device.public_key.clone(), None).await;

    // Invalid static auth.
    if (output.is_err() == true) {
        log::info!("Invalid static auth (output.is_err)");
        return Err(String::from("Invalid static auth (output.is_err)"));
    }

    let additional_data = output.expect("Missing result");
    // We use is_none() here, because we're expecting additional data.
    if (additional_data.is_none() == true) {
        log::info!("Invalid static auth (missing additional data)");
        return Err(String::from("Invalid static auth (missing additional data)"));
    }
    // ----

    return Ok((device, additional_data));
}