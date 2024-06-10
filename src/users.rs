use serde::{Serialize, Deserialize};
use serde_json::{Value, json};

use rocket_db_pools::{Database, Connection};
use rocket_db_pools::diesel::{MysqlPool, prelude::*};

use rocket::response::status;
use rocket::http::{Status, CookieJar, Cookie};

use diesel::prelude::*;
use diesel::sql_types::*;
use diesel::sql_query;

use crate::authentication_misc::protocol_decision_to_pipeline;
use crate::global::{generate_random_id, get_hostname, get_authentication_method, is_valid_authentication_method_for_hostname};
use crate::responses::*;
use crate::structs::*;
use crate::tables::*;
use crate::policy::*;
use crate::device::{device_authentication, device_get, device_guard_static_auth_from_cookies};

use std::error::Error;
use std::fmt::format;
use std::net::SocketAddr;

use hades_auth::*;

use crate::{CONFIG_VALUE, SQL_TABLES};

// Some authenticatiom methods, such as email require action (such as sending a magiclink) before the user can present credentials to authenticate. This is where that logic is kept.

pub async fn user_get(mut db: Connection<Db>, id: Option<String>, email: Option<String>) -> Result<(Option<Guard_user>, Connection<Db>), Box<dyn Error>> {
    let sql: Config_sql = (&*SQL_TABLES).clone();

    // SECURITY: This is inserted as RAW SQL. DO NOT, UNDER ANY CIRCUMSTANCE, MAKE 'CONDITION' THE VALUE OF A VARIABLE, THAT WOULD ALLOW SQL INJECTION. KEEP THIS TO JUST THE STRING 'id' AND 'email'.
    let mut condition: String = String::new();
    let mut value: String = String::new();
    if (id.is_none() == false) {
        value = id.unwrap();
        condition = "id".to_string();
    } else if (email.is_none() == false) {
        value = email.unwrap();
        condition = "email".to_string();
    } else {
        return Err(format!("Both id and email are null.").into());
    }

    let result: Vec<Guard_user> = sql_query(format!("SELECT id, email FROM {} WHERE {}=?", sql.users_table.unwrap(), condition))
    .bind::<Text, _>(value)
    .load::<Guard_user>(&mut db)
    .await
    .expect("Something went wrong querying the DB.");

    println!("USER_GET RESULT: {:?}", result.clone());

    if (result.len() == 0) {
        // Device not found.
        return Ok((None, db));
    }

    let user = result[0].clone();

    Ok((Some(user), db))
}

pub async fn user_create(mut db: Connection<Db>, id_input: Option<String>, email_input: Option<String>) -> Result<(User_create, Connection<Db>), Box<dyn Error>> {
    let id: String = id_input.unwrap_or(generate_random_id());
    let email: String = email_input.clone().unwrap_or("null".to_string());

    // Set limit on email characters, in-case someone wants to have a laugh. 500 is very generous.
    if (email.len() > 500) {
        return Err("The email provided is over 500 characters.".into());
    }

    // Check for existing ID.
    let (exists_id, user_db)= user_get(db, Some(id.clone()), None).await.expect("Failed to get user for ID check.");
    db = user_db;
    
    // If a user was returned, the id is already in-use.
    if (exists_id.is_none() == false) {
        // A user with this ID already exists.
        return Err(format!("A user with the ID '{}' already exists.", id).into());
    }

    // Check for existing email, provided it was originally supplied (and not default null).
    if (email_input.is_none() == false) {
        // Attempt to call a user with the email address candidate.
        let (exists_email, user_db) = user_get(db, None, Some(email.clone())).await.expect("Failed to get user for email check.");
        
        // We passed the DB connection to user_get, let's bring it back.
        db = user_db;

        // If a user was returned, it means the email is already in-use.
        if (exists_email.is_none() == false) {
            // A user with this ID already exists.
            return Err(format!("A user with the email '{}' already exists.", email).into());
        }
    }

    // Get the admin's SQL tables. Config_sql is filtered to A-Za-z1-9 (may be outdated, check validate_sql_table_inputs in global.rs) and is provided in the configuration file, to prevent SQL injection attacks.
    let sql: Config_sql = (&*SQL_TABLES).clone();
 
    let query = format!("INSERT INTO {} (id, email) VALUES (?, ?)", sql.users_table.unwrap());
    let result = sql_query(query)
    .bind::<Text, _>(id.clone())
    .bind::<Text, _>(email.clone())
    .execute(&mut db)
    .await
    .expect("Something went wrong querying the DB.");

    Ok((User_create {
        user_id: id.clone()
    }, db))
}

pub async fn user_authentication_pipeline(mut db: Connection<Db>, jar: &CookieJar<'_>, remote_addr: SocketAddr, host: String, headers: &Headers) -> Result<(bool, Option<Value>, Option<Guard_devices>, Option<Value>, Connection<Db>), Box<dyn Error>> {
    let hostname = get_hostname(host.clone()).await.expect("Missing hostname");
    
    let (success, user_result, device, error_to_respond_with, user_db) = protocol_decision_to_pipeline(db, hostname.clone(), jar, remote_addr, host.clone(), headers).await.expect("An error occurred during protocol_decision_to_pipeline");
    db = user_db;
    if (success == false) {
        println!("protocol_decision_to_pipeline failed, error message: {:?}", error_to_respond_with);
        return Ok((false, None, None, error_to_respond_with, db));
    }

    let user_as_value = user_result.expect("Missing user");

    let result = policy_authentication(get_hostname_policies(hostname, true).await, user_as_value.clone(), remote_addr.to_string()).await;

    return Ok((result, Some(user_as_value), device, None, db));
}

pub fn user_get_id_preference(user_data: Value, authentication_method: AuthMethod) -> Result<User_get_id_preference_struct, Box<dyn Error>> {
    let reference_type: String = authentication_method.user_info_reference_type.unwrap();
    let mut reference_key: String = reference_type.clone();
    if (authentication_method.user_info_reference_key.is_none() == true) {
        reference_key = reference_type.clone();
    }

    let mut has_value: bool = false;
    let mut id: Option<String> = None;
    let mut email: Option<String> = None;

    println!("user_get_id_preference user_data: {}", user_data.clone());

    if (user_data.get(reference_key.clone()).is_none() == false) {
        let value: String = user_data.get(reference_key.clone()).unwrap().as_str().unwrap().to_string();
        has_value = true;
        
        if (reference_type == "id") {
            id = Some(value);
        } else if (reference_type == "email") {
            email = Some(value);
        } else {
            return Err(format!("'{}' is not a valid authentication_method.user_info_reference_key type. Examples of valid authentication_method.user_info_reference_key: 'id', 'email'", reference_type).into())
        }
    } else {
        println!("user_get_id_preference: User data did not include key '{}'", reference_key.clone());
    }

    let output: User_get_id_preference_struct = User_get_id_preference_struct {
        has_value: has_value,
        id: id,
        email: email
    };

    return Ok(output);
}

pub async fn attempted_external_user_handling(mut db: Connection<Db>, attempted_external_user: Value, authentication_method: AuthMethod) -> Result<(Option<String>, Connection<Db>), Box<dyn Error>> {
    // An authentication method can authentication either by an ID or email directly provided by a protocol, like OAuth. This function checks what the admin's preference for the specified authentication method is.
    let user_get_id_preference_status: User_get_id_preference_struct = user_get_id_preference(attempted_external_user, authentication_method.clone()).expect("Failed to get user_get_id_preference");
    if (user_get_id_preference_status.has_value == false) {
        // User information did not return an identifier, like id or email.
        println!("User information did not return an identifier, like id or email.");
        return Err(format!("User information did not return an identifier, like id or email.").into());
    }

    let (user_check, user_db) = user_get(db, user_get_id_preference_status.id.clone(), user_get_id_preference_status.email.clone()).await.expect("Failed to (attempt to) get user");
    db = user_db;

    let mut user_id: Option<String> = None;
    if (user_check.is_none() == false) {
        user_id = Some(user_check.clone().unwrap().id);
    } else if (user_get_id_preference_status.id.is_none() == false) {
        user_id = Some(user_get_id_preference_status.id.clone().unwrap());
    }

    if (user_check.is_none() == true) {
        if (authentication_method.clone().should_create_new_users.unwrap_or(false) == true) {
            println!("USER CREATE EMAIL: {}", user_get_id_preference_status.email.clone().unwrap());
            let (user_create, user_create_db) = user_create(db, user_get_id_preference_status.id.clone(), user_get_id_preference_status.email.clone()).await.expect("Failed to create user.");
            db = user_create_db;
            user_id = Some(user_create.user_id);
        } else {
            // Authentication failed... User is not in database.
            return Ok((None, db));
        }
    }

    return Ok((Some(user_id.unwrap()), db));
}