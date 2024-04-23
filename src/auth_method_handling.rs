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

// Some authenticatiom methods, such as email require action (such as sending a magiclink) before the user can present credentials to authenticate. This is where that logic is kept.

pub async fn handling_email_magiclink(mut db: Connection<Db>, request_data: Magiclink_handling_data, authentication_method: AuthMethod, remote_addr: SocketAddr) -> Result<(Handling_magiclink, Connection<Db>), Box<dyn Error>> {
    let code: String = request_data.code.unwrap();
    let referer: String = request_data.referer.unwrap();

    if (is_null_or_whitespace(code.clone())) {
        // Return error.
        return Ok((Handling_magiclink {
            magiclink: None,
            error_to_respond_to_client_with: Some(status::Custom(Status::BadRequest, error_message("body.request_data.code is null or whitespace.")))
        }, db));
    }

    // referrer is validating where the person came from.
    let invalid_referer = status::Custom(Status::BadRequest, error_message("body.request_data.referer is invalid."));
    let hostname = get_hostname(referer.clone()).await;
    if (hostname.is_none() == true) {
        println!("Missing hostname");
        return Ok((Handling_magiclink {
            magiclink: None,
            error_to_respond_to_client_with: Some(invalid_referer)
        }, db));
    }

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
        return Ok((Handling_magiclink {
            magiclink: None,
            error_to_respond_to_client_with: Some(status::Custom(Status::BadRequest, error_message("Magiclink not found.")))
        }, db));
    }
    let magiclink = result[0].clone();

    let created = magiclink.created.expect("Missing created");
    let diff = get_epoch() - created;
    
    if (created < 0 || diff >= 600000) { // (10 minute expiry. FUTURE: this should be configurable in the config file).
        // Invalid magiclink, expired.
        return Ok((Handling_magiclink {
            magiclink: None,
            error_to_respond_to_client_with: Some(status::Custom(Status::BadRequest, error_message("Magiclink expired.")))
        }, db));
    }

    if (magiclink.ip != remote_addr.ip().to_string()) {
        // Invalid magiclink, mismatched IP.
        return Ok((Handling_magiclink {
            magiclink: None,
            error_to_respond_to_client_with: Some(status::Custom(Status::BadRequest, error_message("Magiclink invalid, mismatched IP.")))
        }, db));
    }

    let query = format!("DELETE FROM {} WHERE code=?", magiclink_table.clone());
    let result = sql_query(query)
    .bind::<Text, _>(code)
    .execute(&mut db)
    .await
    .expect("Something went wrong querying the DB.");

    Ok((Handling_magiclink {
        magiclink: Some(magiclink),
        error_to_respond_to_client_with: None
    }, db))
}