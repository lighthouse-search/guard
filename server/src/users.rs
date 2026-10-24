use axum::http;
use axum::response::Response;
use serde_json::{Value, json};

use diesel::prelude::*;
use diesel::sql_types::*;
use diesel::sql_query;

use crate::authentication_misc::protocol_decision_to_pipeline;
use crate::global::generate_uuid;
use crate::global::get_authentication_method;
use crate::hostname::{get_hostname, is_valid_authentication_method_for_hostname};
use crate::responses::*;
use crate::structs::*;
use crate::policy::*;

use std::error::Error;
use std::net::{IpAddr, SocketAddr};

use crate::{CONFIG_VALUE, SQL_TABLES};

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

pub async fn user_authentication_pipeline(required_scopes: Vec<&str>, jar: &indexmap::IndexMap<String, String>, remote_addr: String, host: String, headers: &axum::http::HeaderMap, original_path_and_query: Option<String>) -> Result<UserAuthenticationPipelineResponse, Response> {
    // Match incoming hostname to configuration.
    let hostname_result = get_hostname(host.clone()).await;
    if hostname_result.is_err() == true {
        log::info!("(user_authentication_pipeline) hostname is invalid: {:?}", host.clone());
        return Err(error_message(5001, axum::http::StatusCode::BAD_REQUEST, "Invalid hostname".to_string()))
    }
    let hostname = hostname_result.unwrap();
    
    // A request over the tunnel already carries a proven device identity in its
    // source address, so it does not need to prove one again interactively.
    // Policy is still evaluated below — this replaces authentication, not
    // authorisation.
    let protocol_decision = match tunnel_identity(&hostname, &remote_addr).await {
        Some(decision) => decision,
        None => {
            // Authenticate user for specific authentication method.
            let protocol_decision_status = protocol_decision_to_pipeline(required_scopes, hostname.clone(), jar, remote_addr.to_string(), headers, original_path_and_query).await;
            // Check pipeline for response error.
            if protocol_decision_status.is_err() == true {
                // TODO: This looks like it could potentially return unsafe error data? Will need to test. It's not directly against a web endpoint so should be fine for now.
                return Err(protocol_decision_status.err().unwrap());
            }
            protocol_decision_status.expect("Failed to unwrap protocol decision")
        }
    };

    // Unwrap user's information.
    let user_as_value = protocol_decision.user.expect("Missing user");

    // Verify the user's authentication method is valid for this hostname.
    let result = policy_authentication(get_hostname_policies(hostname, true).await, user_as_value.clone(), remote_addr.to_string()).await;

    if result != true {
        log::debug!("policy_authentication returned {}", result);
        return Err(error_message(5002, axum::http::StatusCode::UNAUTHORIZED, "Unauthorized due to policy".to_string()));
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

// The client address from a `remote_addr` string.
//
// Callers render a SocketAddr ("10.8.0.2:54321", "[::1]:443"), but a bare
// address is accepted too. Returning None here means tunnel identity simply
// does not apply and normal authentication runs, so an unparseable value costs
// a login page rather than access.
fn source_ip(remote_addr: &str) -> Option<IpAddr> {
    let remote_addr = remote_addr.trim();
    if let Ok(socket) = remote_addr.parse::<SocketAddr>() {
        return Some(socket.ip());
    }
    remote_addr.parse::<IpAddr>().ok()
}

// Identify the device behind a request that arrived over the WireGuard tunnel.
//
// WireGuard will only ever emit a given tunnel address from the peer holding
// the matching private key, so the source address identifies the device as
// firmly as a signature would — and the device already proved itself to get
// that address. Returning a decision here lets a tunnel request skip the login
// page; `user_authentication_pipeline` still applies the hostname's policies to
// the resulting user.
//
// Returns None whenever tunnel identity does not apply, so the caller falls
// back to normal authentication rather than failing.
async fn tunnel_identity(hostname: &GuardedHostname, remote_addr: &str) -> Option<ProtocolDecisionToPipelineOutput> {
    let wireguard = CONFIG_VALUE.wireguard.clone()?;
    // Opt-in. Unlike wireguard_only and the service proxy, which use the source
    // address to *refuse*, this uses it to *grant* — so it is off unless the
    // operator has decided arrival detection is trustworthy on their host.
    if wireguard.tunnel_identity.unwrap_or(false) == false {
        return None;
    }

    let source = source_ip(remote_addr)?;

    // SECURITY: this is the whole basis of the identity, so it must be the
    // arrival check and not merely "looks like a tunnel address". See
    // wireguard::arrival_from for what that check does and does not guarantee.
    if crate::wireguard::arrival_from(source) != crate::wireguard::Arrival::Wireguard {
        return None;
    }

    // Stored tunnel addresses are IPv4, so a mapped source has to be unwrapped
    // before it will match.
    let lookup = crate::wireguard::canonical_ip(source).to_string();
    let device = match crate::device::device_get_by_wireguard_ip(&lookup).await {
        Ok(Some(device)) => device,
        Ok(None) => return None,
        Err(error) => {
            // Fall back to interactive authentication rather than locking the
            // user out because of a transient lookup failure.
            log::error!("Could not resolve a device for tunnel address {}: {}", source, error);
            return None;
        }
    };

    // The device enrolled with some authentication method; a hostname that does
    // not accept that method must not accept it here either, or the tunnel
    // would be a way around the hostname's configuration.
    let authentication_method = get_authentication_method(device.authentication_method.clone(), true).await?;
    if is_valid_authentication_method_for_hostname(hostname.clone(), authentication_method.clone()).await.unwrap_or(false) == false {
        log::info!(
            "Device '{}' reached '{}' over the tunnel, but its authentication method is not accepted there.",
            device.id, hostname.host
        );
        return None;
    }

    let user = match user_get(Some(device.user_id.clone()), None).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            log::info!("Tunnel device '{}' refers to a user that no longer exists.", device.id);
            return None;
        }
        Err(error) => {
            log::error!("Could not load the user for tunnel device '{}': {}", device.id, error);
            return None;
        }
    };

    log::debug!("Device '{}' authenticated by tunnel address {}.", device.id, source);

    Some(ProtocolDecisionToPipelineOutput {
        // Same shape every other path hands the policy engine.
        user: Some(json!({
            "id": user.id,
            "email": user.email
        })),
        device: Some(device),
        authentication_method: Some(authentication_method),
        authentication_type: String::from("wireguard"),
    })
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_ip_reads_a_rendered_socket_address() {
        // The form every caller actually passes.
        assert_eq!(source_ip("10.8.0.2:54321"), Some("10.8.0.2".parse().unwrap()));
    }

    #[test]
    fn source_ip_reads_a_bare_address() {
        assert_eq!(source_ip("10.8.0.2"), Some("10.8.0.2".parse().unwrap()));
    }

    #[test]
    fn source_ip_reads_a_bracketed_ipv6_socket_address() {
        // A dual-stack listener reports v4 peers in mapped form; failing to
        // parse this would silently disable tunnel identity for them.
        assert_eq!(
            source_ip("[::ffff:10.8.0.2]:443"),
            Some("::ffff:10.8.0.2".parse::<IpAddr>().unwrap())
        );
    }

    #[test]
    fn source_ip_rejects_nonsense() {
        assert_eq!(source_ip(""), None);
        assert_eq!(source_ip("not-an-address"), None);
        assert_eq!(source_ip("10.8.0.2:notaport"), None);
    }
}
