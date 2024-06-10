use serde::{Serialize, Deserialize};
use serde_json::{Value, json};

use rocket_db_pools::{Database, Connection};
use rocket_db_pools::diesel::{MysqlPool, prelude::*};

use rocket::http::{Status, CookieJar, Cookie};

use crate::global::{generate_random_id, get_hostname, get_authentication_method, is_valid_authentication_method_for_hostname};
use crate::protocols::misc_pipeline::device::device_pipeline;
use crate::protocols::oauth::oauth_pipeline::oauth_pipeline;
use crate::responses::*;
use crate::structs::*;

use std::error::Error;
use std::net::SocketAddr;

pub async fn protocol_decision_to_pipeline(mut db: Connection<Db>, hostname: Guarded_Hostname, jar: &CookieJar<'_>, remote_addr: SocketAddr, host: String, headers: &Headers) -> Result<(bool, Option<Value>, Option<Guard_devices>, Option<Value>, Connection<Db>), Box<dyn Error>> {
    let mut auth_metadata_string: String = String::new();
    if (headers.headers_map.get("guard_authentication_metadata").is_none() == false) {
        auth_metadata_string = headers.headers_map.get("guard_authentication_metadata").expect("Failed to parse header.").to_string();
    } else if (jar.get("guard_authentication_metadata").is_none() == false) {
        auth_metadata_string = jar.get("guard_authentication_metadata").map(|c| c.value()).expect("Failed to parse cookie.").to_string();
    } else {
        println!("Auth metadata not provided by client.");
        return Ok((false, None, None, Some(error_message("headers.guard_authentication_metadata or cookies.guard_authentication_metadata not specified.")), db));
    }

    let auth_metadata: Guard_authentication_metadata = serde_json::from_str(&auth_metadata_string).expect("Failed to parse auth_metadata_string");

    if (auth_metadata.authentication_method.is_none()) {
        return Ok((false, None, None, Some(error_message("authentication_metadata.authentication_method is null.")), db));
    }
    let requested_authentication_method = auth_metadata.authentication_method.unwrap();

    let authentication_method: AuthMethod = get_authentication_method(requested_authentication_method, true).await.expect("Failed to get auth method.");
    
    is_valid_authentication_method_for_hostname(hostname.clone(), authentication_method.clone()).await.expect("Invalid authentication method for hostname.");

    if (authentication_method.method_type == "oauth") {
        // OAuth.

        let (success, user, user_db) = oauth_pipeline(db, hostname, authentication_method, jar, remote_addr, host, headers).await.expect("Something went wrong during OAuth user info");
        db = user_db;

        if (success == false) {
            println!("oauth_pipeline failed");
            return Ok((false, None, None, None, db));
        }

        return Ok((true, user, None, None, db));
    } else if (authentication_method.method_type == "email") {
        // Guard device authentication. Uses Hades-Auth and is used with email authentication. Much more secure than bearer tokens as everything is signed.

        let (success, user, device, device_db) = device_pipeline(db, hostname, jar, remote_addr, host, headers).await.expect("Device pipeline failed");
        db = device_db;

        let user_value: Value = serde_json::to_value(user).expect("Failed ot convert user to value");

        println!("email_user_value: {}", user_value);

        return Ok((success, Some(user_value), device, None, db));
    } else {
        return Err(format!("Unhandled authentication_method.method_type type '{}'", authentication_method.method_type).into());
    }
}