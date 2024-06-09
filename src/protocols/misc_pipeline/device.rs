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
use crate::device::{device_authentication, device_get, device_guard_static_auth_from_cookies};
use crate::users::user_get;

use std::error::Error;
use std::fmt::format;
use std::net::SocketAddr;

use hades_auth::*;

use crate::{CONFIG_VALUE, SQL_TABLES};

pub async fn device_pipeline(mut db: Connection<Db>, hostname: Guarded_Hostname, jar: &CookieJar<'_>, remote_addr: SocketAddr, host: String, headers: &Headers) -> Result<(bool, Option<Guard_user>, Option<Guard_devices>, Connection<Db>), Box<dyn Error>> {
    // Guard device authentication. Uses Hades-Auth and is used with email authentication. Much more secure than bearer tokens as everything is signed.
    let signed_data = device_guard_static_auth_from_cookies(jar);
    if (signed_data.is_none() == true) {
        println!("signed_data was none.");
        return Ok((false, None, None, db));
    }

    let (device_result, device_db) = device_authentication(db, signed_data.unwrap()).await;
    db = device_db;

    if (device_result.is_none()) {
        return Ok((false, None, None, db));
    }
    let device: Guard_devices = device_result.unwrap();

    let device_authentication_method = get_authentication_method(device.authentication_method.clone(), true).await.expect("Invalid or missing authentication method.");
    
    // FUTURE: Should return error to client, saying authentication method is invalid for this hostname.
    is_valid_authentication_method_for_hostname(hostname.clone(), device_authentication_method.clone()).await.expect("Fail");

    let (user_result, user_db) = user_get(db, Some(device.user_id.clone()), None).await.expect("Failed to get user");
    db = user_db;

    let user: Guard_user = user_result.expect("User tied to device does not exist.");

    return Ok((true, Some(user), Some(device), db));
}