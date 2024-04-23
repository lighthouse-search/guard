use serde::{Serialize, Deserialize};
use serde_json::{Value, json};

use rocket_db_pools::{Database, Connection};
use rocket_db_pools::diesel::{MysqlPool, prelude::*};

use rocket::response::status;
use rocket::http::{Status, CookieJar, Cookie};

use diesel::prelude::*;
use diesel::sql_types::*;
use diesel::sql_query;

use crate::global::{generate_random_id, get_hostname, get_authentication_method, is_valid_authentication_method_for_hostname};
use crate::responses::*;
use crate::structs::*;
use crate::tables::*;
use crate::policy::*;
use crate::device::{device_get};

use std::error::Error;
use std::net::SocketAddr;

use hades_auth::*;

use crate::{CONFIG_VALUE, SQL_TABLES};

// Some authenticatiom methods, such as email require action (such as sending a magiclink) before the user can present credentials to authenticate. This is where that logic is kept.

pub async fn user_get(mut db: Connection<Db>, id: String) -> Result<(Option<Guard_user>, Connection<Db>), Box<dyn Error>> {
    let sql: Config_sql = (&*SQL_TABLES).clone();

    let query = format!("SELECT id, email FROM {} WHERE id=?", sql.users_table.unwrap());

    let result: Vec<Guard_user> = sql_query(query)
    .bind::<Text, _>(id)
    .load::<Guard_user>(&mut db)
    .await
    .expect("Something went wrong querying the DB.");

    if (result.len() == 0) {
        // Device not found.
        return Ok((None, db));
    }

    let user = result[0].clone();

    Ok((Some(user), db))
}

pub async fn user_create(mut db: Connection<Db>, email: String) -> Result<(User_create, Connection<Db>), Box<dyn Error>> {
    // Set limit on email characters, in-case someone wants to have a laugh. 500 is very generous.
    if (email.len() > 500) {
        return Err("The email provided is over 500 characters.".into());
    }

    let id = generate_random_id();

    let sql: Config_sql = (&*SQL_TABLES).clone();

    let query = format!("INSERT INTO {} (id, email) VALUES (?, ?)", sql.users_table.unwrap());
    let result = sql_query(query)
    .bind::<Text, _>(id.clone())
    .bind::<Text, _>(email)
    .execute(&mut db)
    .await
    .expect("Something went wrong querying the DB.");

    Ok((User_create {
        user_id: id
    }, db))
}

pub async fn user_authentication_pipeline(mut db: Connection<Db>, jar: &CookieJar<'_>, remote_addr: SocketAddr, host: String) -> Result<(bool, Option<Guard_user>, Option<Guard_devices>, Connection<Db>), Box<dyn Error>> {
    let mut signed_data: String = String::new();
    if (jar.get("guard_static_auth").is_none() == false) {
        signed_data = jar.get("guard_static_auth").map(|c| c.value()).expect("Failed to parse signed_data.").to_string();
        println!("Signed_data cookie: {:?}", signed_data);
    } else {
        // TODO: Return error.
        println!("Signed_data cookie: None");
        return Ok((false, None, None, db));
    }

    let unsigned_data: Static_auth_sign = serde_json::from_value(get_unsafe_noverification_jwt_payload(signed_data.clone()).expect("Failed to parse payload.")).expect("Failed to prase JWT");
    
    // TODO: Instead of things like .expect("Missing additional data"), return an actual response.
    let unsigned_data_deviceinfo: Signed_data_identifier = serde_json::from_value(unsigned_data.additional_data.expect("Missing additional data")).expect("Failed to parse identifier data.");
    
    let device_id = unsigned_data_deviceinfo.device_id;
    let (device_wrapped, db) = device_get(db, device_id).await.expect("Failed to query for device.");
    let device = device_wrapped.expect("Device not found");

    let result = static_auth_verify(signed_data, device.public_key.clone()).await.expect("Failed to verify static auth.");
    if (result.is_none() == true) { // Invalid static auth.
        return Ok((false, None, None, db));
    }

    let hostname = get_hostname(host).await.expect("Missing hostname");

    let device_authentication_method = get_authentication_method(device.authentication_method.clone()).await.expect("Invalid or missing authentication method.");
    
    // FUTURE: Should return error to client, saying authentication method is invalid for this hostname.
    is_valid_authentication_method_for_hostname(hostname.clone(), device_authentication_method).await.expect("Fail");

    // FUTURE: Checking for things like if the user is "suspended" (or whatever policy the config has for denying users) needs to be implemented in the user.
    let (user_wrapped, db): (Option<Guard_user>, Connection<Db>) = user_get(db, device.user_id.clone()).await.expect("Missing user");
    let user = user_wrapped.expect("Missing user.");

    let result = policy_authentication(get_hostname_policies(hostname, true).await, user.clone(), remote_addr.to_string()).await;

    return Ok((result, Some(user), Some(device), db));
}