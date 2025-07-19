use serde_json::{Value, json};

use diesel::prelude::*;
use diesel::sql_types::*;
use diesel::sql_query;

use crate::authentication_misc::protocol_decision_to_pipeline;
use crate::global::generate_uuid;
use crate::hostname::get_hostname;
use crate::responses::*;
use crate::structs::*;
use crate::policy::*;

use std::error::Error;
use std::net::SocketAddr;

use crate::SQL_TABLES;

// Some authenticatiom methods, such as email require action (such as sending a magiclink) before the user can present credentials to authenticate. This is where that logic is kept.

pub async fn user_get(id: Option<String>, email: Option<String>) -> Result<Option<GuardUser>, Box<dyn Error>> {
    let mut db = crate::DB_POOL.get().expect("Failed to get a connection from the pool.");
    let sql: ConfigSqlTables = (&*SQL_TABLES).clone();

    // SECURITY: This is inserted as RAW SQL. DO NOT, UNDER ANY CIRCUMSTANCE, MAKE 'CONDITION' THE VALUE OF A VARIABLE, THAT WOULD ALLOW SQL INJECTION. KEEP THIS TO JUST THE STRING 'id' AND 'email'.
    let mut _condition: String = String::new();
    let mut _value: String = String::new();
    if id.is_none() == false {
        _value = id.unwrap();
        _condition = "id".to_string();
    } else if email.is_none() == false {
        _value = email.unwrap();
        _condition = "email".to_string();
    } else {
        return Err(format!("Both id and email are null.").into());
    }

    let result: Vec<GuardUser> = sql_query(format!("SELECT id, email FROM {} WHERE {}=?", sql.user.unwrap(), _condition))
    .bind::<Text, _>(_value)
    .load::<GuardUser>(&mut db)
    .expect("Something went wrong querying the DB.");

    log::info!("USER_GET RESULT: {:?}", result.clone());

    if result.len() == 0 {
        // Device not found.
        return Ok(None);
    }

    let user = result[0].clone();

    Ok(Some(user))
}

pub async fn user_create(id_input: Option<String>, email_input: Option<String>) -> Result<UserCreate, String> {
    let mut db = crate::DB_POOL.get().expect("Failed to get a connection from the pool.");

    let id: String = id_input.unwrap_or(generate_uuid());
    let email: String = email_input.clone().unwrap_or("null".to_string());

    // Set limit on email characters, in-case someone wants to have a laugh. 500 is very generous.
    if email.len() > 500 {
        return Err("The email provided is over 500 characters.".into());
    }

    // Check for existing ID.
    let exists_id= user_get(Some(id.clone()), None).await.expect("Failed to get user for ID check.");
    
    // If a user was returned, the id is already in-use.
    if exists_id.is_none() == false {
        // A user with this ID already exists.
        return Err(format!("A user with the ID '{}' already exists.", id).into());
    }

    // Check for existing email, provided it was originally supplied (and not default null).
    if email_input.is_none() == false {
        // Attempt to call a user with the email address candidate.
        let exists_email = user_get(None, Some(email.clone())).await.expect("Failed to get user for email check.");

        // If a user was returned, it means the email is already in-use.
        if exists_email.is_none() == false {
            // A user with this ID already exists.
            return Err(format!("A user with the email '{}' already exists.", email).into());
        }
    }

    // Get the admin's SQL tables. ConfigSql is filtered to A-Za-z1-9 (may be outdated, check validate_sql_table_inputs in global.rs) and is provided in the configuration file, to prevent SQL injection attacks.
    let sql: ConfigSqlTables = (&*SQL_TABLES).clone();
 
    let query = format!("INSERT INTO {} (id, email) VALUES (?, ?)", sql.user.unwrap());
    sql_query(query)
    .bind::<Text, _>(id.clone())
    .bind::<Text, _>(email.clone())
    .execute(&mut db)
    .expect("Something went wrong querying the DB.");

    Ok(UserCreate {
        user_id: id.clone()
    })
}

pub async fn user_authentication_pipeline(required_scopes: Vec<&str>, jar: &indexmap::IndexMap<String, String>, remote_addr: String, host: String, headers: &Headers) -> Result<UserAuthenticationPipelineResponse, ErrorResponse> {
    // Match incoming hostname to configuration.
    let hostname_result = get_hostname(host.clone()).await;
    if hostname_result.is_err() == true {
        log::info!("(user_authentication_pipeline) hostname is invalid: {:?}", host.clone());
        return Err(error_message("Invalid hostname").into())
    }
    let hostname = hostname_result.unwrap();
    
    // Authenticate user for specific authentication method.
    let protocol_decision_status = protocol_decision_to_pipeline(required_scopes, hostname.clone(), jar, remote_addr.to_string(), headers).await;
    // Check pipeline for response error.
    if protocol_decision_status.is_err() == true {
        // TODO: This looks like it could potentially return unsafe error data? Will need to test. It's not directly against a web endpoint so should be fine for now.
        return Err(protocol_decision_status.err().unwrap());
    }
    let protocol_decision = protocol_decision_status.expect("Failed to unwrap protocol decision");

    // Unwrap user's information.
    let user_as_value = protocol_decision.user.expect("Missing user");

    // Verify the user's authentication method is valid for this hostname.
    let result = policy_authentication(get_hostname_policies(hostname, true).await, user_as_value.clone(), remote_addr.to_string()).await;

    if result != true {
        log::debug!("policy_authentication returned {}", result);
        return Err(error_message("Unauthorized (due to policy)").into());
    }

    return Ok(UserAuthenticationPipelineResponse {
        user: Some(user_as_value),
        device: protocol_decision.device,
        authentication_method: protocol_decision.authentication_method,
        authentication_type: protocol_decision.authentication_type
    });
}

// pub fn user_get_id_preference(user_data: Value, authentication_method: AuthMethod) -> Result<UserGetIdPreferenceStruct, String> {
//     // TODO: I am not sure this is needed? We should be generating UUIDs for users. This only makes sense when there is no database - I suspect that's what this is for. I will return to this.

//     let reference_type: String = authentication_method.user_info_reference_type.unwrap_or("id".to_string()); // TODO: maybe revist this later, but this will fail any proxy authentication if not specified. I doubt it will get used in email contexts, so we'll just default to 'id'.
//     let mut reference_key: String = reference_type.clone();
//     if authentication_method.user_info_reference_key.is_none() == true {
//         reference_key = reference_type.clone();
//     }

//     let mut _has_value: bool = false;
//     let mut id: Option<String> = None;
//     let mut email: Option<String> = None;

//     log::info!("user_get_id_preference user_data: {}", user_data.clone());

//     if user_data.get(reference_key.clone()).is_none() == false {
//         let value: String = user_data.get(reference_key.clone()).unwrap().as_str().unwrap().to_string();
//         _has_value = true;
        
//         if reference_type == "id" {
//             id = Some(value);
//         } else if reference_type == "email" {
//             email = Some(value);
//         } else {
//             return Err(format!("'{}' is not a valid authentication_method.user_info_reference_key type. Examples of valid authentication_method.user_info_reference_key: 'id', 'email'", reference_type));
//         }
//     } else {
//         return Err(format!("user_get_id_preference: User data did not include key '{}'", reference_key.clone()))
//     }

//     let output: UserGetIdPreferenceStruct = UserGetIdPreferenceStruct {
//         has_value: _has_value,
//         id: id,
//         email: email
//     };

//     return Ok(output);
// }


pub async fn user_get_otherwise_create(host: GuardedHostname, email: String, remote_addr: SocketAddr) -> Result<Option<GuardUser>, String> {
    let email_user_as_value: Value = json!({
        "email": email
    });

    let policy_authentication = policy_authentication(get_hostname_policies(host.clone(), true).await, email_user_as_value, remote_addr.to_string()).await;
    if policy_authentication == false {
        // Unauthorized user.
        return Ok(None);
    }

    let mut user_result = user_get(None, Some(email.clone())).await.expect("Failed to get user.");

    if user_result.is_none() == true {
        // User not found, however, the user is authorized, so we need to create a user entry.
        let user_create_struct = user_create(None, Some(email.clone())).await.expect("Failed to create user.");

        let after_create_user_result = user_get(Some(user_create_struct.user_id), None).await.expect("Failed to get user after creation.");
        user_result = after_create_user_result;
    }

    return Ok(Some(user_result.unwrap()));
}