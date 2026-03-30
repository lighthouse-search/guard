use diesel::sql_query;
use diesel::prelude::*;
use diesel::sql_types::*;

use crate::global::{ is_null_or_whitespace, get_epoch };
use crate::responses::*;
use crate::structs::*;
use crate::users::user_get;
use std::error::Error;
use std::net::SocketAddr;

use crate::SQL_TABLES;

// Some authenticatiom methods, such as email require action (such as sending a magiclink) before the user can present credentials to authenticate. This is where that logic is kept.

pub async fn handling_email_magiclink(request_data: MagiclinkHandlingData, _authentication_method: AuthMethod, remote_addr: SocketAddr) -> Result<HandlingMagiclink, Box<dyn Error>> {
    let mut db = crate::DB_POOL.get().expect("Failed to get a connection from the pool.");
    let code: String = request_data.code.unwrap();

    if is_null_or_whitespace(Some(code.clone())) {
        // Return error.
        return Ok(HandlingMagiclink {
            magiclink: None,
            user: None,
            error_to_respond_to_client_with: Some(error_message(4001, axum::http::StatusCode::BAD_REQUEST, "body.request_data.code is null or whitespace.".to_string()))
        });
    }

    let sql: ConfigSqlTables = (&*SQL_TABLES).clone();
    let magiclink_table = sql.magiclink.unwrap();

    let magiclink_result = crate::protocols::email::magiclink::get_magiclink(code.clone()).await;
    if magiclink_result.is_none() == true {
        // Magiclink invalid, not found.
        return Ok(HandlingMagiclink {
            magiclink: None,
            user: None,
            error_to_respond_to_client_with: Some(error_message(4002, axum::http::StatusCode::BAD_REQUEST, "Magiclink not found.".to_string()))
        });
    }

    let magiclink = magiclink_result.unwrap();
    let created = magiclink.created.expect("Missing created");
    let diff = get_epoch() - created;
    
    if created < 0 || diff >= 600000 { // (10 minute expiry. FUTURE: this should be configurable in the config file).
        // Invalid magiclink, expired.
        return Ok(HandlingMagiclink {
            magiclink: None,
            user: None,
            error_to_respond_to_client_with: Some(error_message(4003, axum::http::StatusCode::UNAUTHORIZED, "Magiclink expired.".to_string()))
        });
    }

    if magiclink.ip != remote_addr.ip().to_string() {
        // Invalid magiclink, mismatched IP.
        return Ok(HandlingMagiclink {
            magiclink: None,
            user: None,
            error_to_respond_to_client_with: Some(error_message(4004, axum::http::StatusCode::UNAUTHORIZED, "Magiclink invalid, mismatched IP.".to_string()))
        });
    }

    let query = format!("DELETE FROM {} WHERE code=?", magiclink_table.clone());
    sql_query(query)
    .bind::<Text, _>(code)
    .execute(&mut db)
    .expect("Something went wrong querying the DB.");

    let user = user_get(Some(magiclink.clone().user_id), None).await.expect("Failed to get magiclink user.");

    user.clone().expect("Missing magiclink user.");

    Ok(HandlingMagiclink {
        magiclink: Some(magiclink),
        user: user,
        error_to_respond_to_client_with: None
    })
}