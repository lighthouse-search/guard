use serde::{Serialize, Deserialize};
use serde_json::{Value, json};
use rocket::response::status;
use rocket::http::Status;

use diesel::sql_query;
use diesel::prelude::*;
use diesel::sql_types::*;

use crate::global::{ is_null_or_whitespace, get_epoch, is_valid_authentication_method };
use crate::globals::environment_variables;
use crate::protocols::oauth::client::{oauth_code_exchange_for_access_key, oauth_userinfo};
use crate::responses::*;
use crate::structs::*;
use crate::tables::*;
use crate::users::user_get;
use hades_auth::*;
use std::error::Error;
use std::net::SocketAddr;

use crate::{CONFIG_VALUE, SQL_TABLES};

// Some authenticatiom methods, such as email require action (such as sending a magiclink) before the user can present credentials to authenticate. This is where that logic is kept.

pub async fn handling_email_magiclink(request_data: Magiclink_handling_data, authentication_method: AuthMethod, remote_addr: SocketAddr) -> Result<(Handling_magiclink), Box<dyn Error>> {
    let mut db = crate::DB_POOL.get().expect("Failed to get a connection from the pool.");
    let code: String = request_data.code.unwrap();

    if (is_null_or_whitespace(Some(code.clone()))) {
        // Return error.
        return Ok((Handling_magiclink {
            magiclink: None,
            user: None,
            error_to_respond_to_client_with: Some(status::Custom(Status::BadRequest, error_message("body.request_data.code is null or whitespace.").into()))
        }));
    }

    let sql: Config_sql_tables = (&*SQL_TABLES).clone();
    let magiclink_table = sql.magiclink.unwrap();

    // TODO: This should be a function, like magiclink_get.
    let query = format!("SELECT user_id, code, ip, created, authentication_method FROM {} WHERE code=?", magiclink_table.clone());
    let (magiclink_result) = crate::protocols::email::magiclink::get_magiclink(code.clone()).await;

    if (magiclink_result.is_none() == true) {
        // Magiclink invalid, not found.
        return Ok((Handling_magiclink {
            magiclink: None,
            user: None,
            error_to_respond_to_client_with: Some(status::Custom(Status::BadRequest, error_message("Magiclink not found.").into()))
        }));
    }

    let magiclink = magiclink_result.unwrap();
    let created = magiclink.created.expect("Missing created");
    let diff = get_epoch() - created;
    
    if (created < 0 || diff >= 600000) { // (10 minute expiry. FUTURE: this should be configurable in the config file).
        // Invalid magiclink, expired.
        return Ok((Handling_magiclink {
            magiclink: None,
            user: None,
            error_to_respond_to_client_with: Some(status::Custom(Status::BadRequest, error_message("Magiclink expired.").into()))
        }));
    }

    if (magiclink.ip != remote_addr.ip().to_string()) {
        // Invalid magiclink, mismatched IP.
        return Ok((Handling_magiclink {
            magiclink: None,
            user: None,
            error_to_respond_to_client_with: Some(status::Custom(Status::BadRequest, error_message("Magiclink invalid, mismatched IP.").into()))
        }));
    }

    let query = format!("DELETE FROM {} WHERE code=?", magiclink_table.clone());
    let result = sql_query(query)
    .bind::<Text, _>(code)
    .execute(&mut db)
    .expect("Something went wrong querying the DB.");

    let (user) = user_get(Some(magiclink.clone().user_id), None).await.expect("Failed to get magiclink user.");

    user.clone().expect("Missing magiclink user.");

    Ok((Handling_magiclink {
        magiclink: Some(magiclink),
        user: user,
        error_to_respond_to_client_with: None
    }))
}