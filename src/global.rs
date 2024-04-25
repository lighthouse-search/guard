use std::fmt::format;
use std::process::{Command, Stdio};
use std::error::Error;
use std::collections::{HashMap};
use std::time::{SystemTime, UNIX_EPOCH};
use std::fs;
use std::fs::{File};
use std::io::Write;
use std::env;

use url::Url;

use rand::prelude::*;

use rocket_db_pools::{Database, Connection};
use rocket_db_pools::diesel::{MysqlPool, prelude::*};
use regex::Regex;
use rocket::http::HeaderMap;

use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};

use crate::structs::*;
use crate::tables::*;
use crate::CONFIG_VALUE;

use hades_auth::authenticate;

fn validate_table_name(input: &str) -> bool {
    let re = Regex::new(r"^[A-Za-z1-9]+$").unwrap();
    re.is_match(input)
}

pub async fn validate_sql_table_inputs() -> Result<bool, Box<dyn Error>> {
    if let Ok(current_dir) = env::current_dir() {
        if let Some(path) = current_dir.to_str() {
            println!("Current directory: {}", path);
        } else {
            println!("Failed to get current directory path.");
        }
    } else {
        println!("Failed to get current directory.");
    }

    let value = (*CONFIG_VALUE).clone();
    let table = value.as_table().unwrap();
    let sql_tables = table.get("sql").unwrap().as_table().unwrap();

    for (key, value) in sql_tables {
        if let Some(table_name) = value.as_str() {
            let output = validate_table_name(table_name);
            if (output != true) {
                return Err(format!("\"{}\" does not match A-Za-z1-9. This is necessary for SQL security, as table names are not bind-able.", key).into());
            }
        }
    }

    Ok(true)
}

pub async fn get_authentication_methods() -> HashMap<String, AuthMethod> {
    let value = (*CONFIG_VALUE).clone();
    let table = value.as_table().unwrap();
    let auth_methods = table.get("authentication_methods").unwrap().as_table().unwrap();

    let mut methods: HashMap<String, AuthMethod> = HashMap::new();

    for (key, value) in auth_methods {
        let parts: Vec<&str> = key.split('.').collect();
        if parts.len() == 1 {
            let mut method: AuthMethod = value.clone().try_into().expect("lmao");
            method.id = Some(key.clone());
            methods.insert(key.clone(), method);
        }
    }

    return methods;
}

pub async fn get_authentication_method(id: String) -> Option<AuthMethod> {
    let auth_methods = get_authentication_methods().await;
    
    let mut authentication_method: Option<AuthMethod> = None;
    for (key, value) in auth_methods {
        if value.clone().id.expect("Missing id") == id && authentication_method.is_none() == true {
            authentication_method = Some(value.clone());
        }
    }

    authentication_method
}

pub async fn get_policies() -> HashMap<String, Guard_Policy> {
    let value = (*CONFIG_VALUE).clone();
    let table = value.as_table().unwrap();
    let auth_methods = table.get("policies").unwrap().as_table().unwrap();

    let mut methods: HashMap<String, Guard_Policy> = HashMap::new();

    for (key, value) in auth_methods {
        let parts: Vec<&str> = key.split('.').collect();
        if parts.len() == 1 {
            let mut method: Guard_Policy = value.clone().try_into().expect("lmao");
            method.id = Some(key.clone());
            methods.insert(key.clone(), method);
        }
    }

    return methods;
}

pub async fn get_policy(id: String) -> Option<Guard_Policy> {
    let policies = get_policies().await;
    
    let mut policy: Option<Guard_Policy> = None;
    for (key, value) in policies {
        if value.clone().id.expect("Missing id") == id && policy.is_none() == true {
            policy = Some(value.clone());
        }
    }

    policy
}

pub async fn get_active_authentication_methods() -> Vec<AuthMethod_Public> {
    let auth_methods = get_authentication_methods().await;
    
    let mut public_active_methods: Vec<AuthMethod_Public> = Vec::new();
    for (key, value) in auth_methods {
        if value.active == true {
            let method: AuthMethod_Public = value.try_into().expect("Failed");
            public_active_methods.push(method);
        }
    }

    public_active_methods
}

// TODO: Why is this here? It should be removed. get_authentication_method solves this?
pub async fn is_valid_authentication_method(id: String) -> Option<AuthMethod> {
    let auth_methods = get_authentication_methods().await;

    let mut valid: Option<AuthMethod> = None;
    for (key, value) in auth_methods {
        if (key.to_string() == id) {
            valid = Some(value);
        }
    }

    return valid;
}

pub async fn send_email(email: String, subject: String, message: String) -> Result<bool, Box<dyn Error>> {
    // Set limit on email characters, in-case someone wants to have a laugh. 500 is very generous.
    if (email.len() > 500) {
        return Err("The email provided is over 500 characters.".into());
    }

    let smtp_json = serde_json::to_string(&CONFIG_VALUE["smtp"]).expect("Failed to serialize");
    let smtp: Config_smtp = serde_json::from_str(&smtp_json).expect("Failed to parse");

    // NOTE: We're not stupid, Lettre validates the input here via .parse. It's absolutely vital .parse is here for safety.

    let from = format!("{} <{}>", smtp.from_alias.expect("Missing from_alias"), smtp.from_header.clone().expect("Missing from_header"));
    let mut reply_to = format!("<{}>", smtp.from_header.expect("Missing from_header"));
    let to = format!("<{}>", email);

    if (smtp.reply_to_address.is_none() == false) {
        reply_to = format!("<{}>", smtp.reply_to_address.expect("Missing reply_to_address"));
    }

    // NOTE: IT IS ABSOLUTELY VITAL .PARSE IS HERE FOR SAFETY. Lettre validates the input here via .parse, injection is possible without .parse.
    let mut email_packet = Message::builder()
    .from(from.parse().unwrap())
    .reply_to(reply_to.parse().unwrap())
    .to(to.parse().unwrap())
    .subject(subject)
    .header(ContentType::TEXT_PLAIN)
    .body(String::from(message))
    .unwrap();

    // Check for password and get it.
    let mut password: String = String::new();
    if let Some(val) = env::var(smtp.password_env.expect("Missing password_env")).ok() {
        password = val;
    } else {
        return Err("The environment variable specified in config.smtp.password_env is missing.".into());
    }

    let creds = Credentials::new(smtp.username.expect("Missing username"), password);

    // Open a remote connection to SMTP server
    let mailer = SmtpTransport::relay(&smtp.host.expect("Missing host"))
        .unwrap()
        .credentials(creds)
        .build();

    // Send the email
    match mailer.send(&email_packet) {
        Ok(_) => Ok(true),
        Err(e) => Err("Could not send email: {e:?}".into()),
    }
}

pub fn generate_random_id() -> String {
    let mut random_string = String::new();
    const CHARACTERS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ";
    for _ in 0..CHARACTERS.len() {
        let index = rand::thread_rng().gen_range(0..CHARACTERS.len());
        random_string.push(CHARACTERS.chars().nth(index).unwrap());
    }
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    random_string.truncate(20);
    random_string + &timestamp.to_string()
}

pub fn generate_longer_random_id() -> String {
    let characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let mut random_string = String::new();

    for _ in 0..100 {
        let random_index = rand::random::<usize>() % characters.len();
        random_string.push(characters.chars().nth(random_index).unwrap());
    }

    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis();

    random_string.push_str(&timestamp.to_string());
    random_string
}

pub fn is_null_or_whitespace(s: String) -> bool {
    match s {
        string if string == "null" || string == "undefined" => true,
        string => string.trim().is_empty(),
    }
}

pub fn get_epoch() -> i64 {
    return TryInto::<i64>::try_into(SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .expect("Failed to get duration since unix epoch")
    .as_millis()).expect("Failed to get timestamp");
}

pub async fn list_hostnames(only_active: bool) -> Vec<Guarded_Hostname> {
    let value = (*CONFIG_VALUE).clone();
    let table = value.as_table().unwrap();
    let auth_methods = table.get("hostname").unwrap().as_table().unwrap();

    let mut hostnames: Vec<Guarded_Hostname> = Vec::new();

    for (key, value) in auth_methods {
        let parts: Vec<&str> = key.split('.').collect();
        if parts.len() == 1 {
            let mut hostname: Guarded_Hostname = value.clone().try_into().expect("lmao");
            if (only_active == true) {
                // We care if hostnames are active.
                if (hostname.active == true) {
                    // Hostname is active, we can return it.
                    hostnames.push(hostname);
                }
            } else if (only_active == false) {
                // We don't care if hostnames are active or not.
                hostnames.push(hostname);
            }
        }
    }

    return hostnames;
}

pub async fn get_active_hostnames() -> Vec<Guarded_Hostname> {
    let hostnames: Vec<Guarded_Hostname> = list_hostnames(true).await;
    
    let mut active_hostnames: Vec<Guarded_Hostname> = Vec::new();
    for value in hostnames {
        if value.active == true {
            let method: Guarded_Hostname = value;
            active_hostnames.push(method);
        }
    }

    active_hostnames
}

pub async fn get_hostname_authentication_methods(hostname: Guarded_Hostname, only_active: bool) -> Vec<AuthMethod> {
    let mut authentication_methods: Vec<AuthMethod> = Vec::new();

    for authentication_method_id in hostname.authentication_methods {
        let authentication_method = get_authentication_method(authentication_method_id.clone()).await.expect("Missing");
        if (only_active == true && authentication_method.active == true) {
            authentication_methods.push(authentication_method.clone());
        }
        if (only_active == false) {
            authentication_methods.push(authentication_method.clone());
        }
    }

    authentication_methods
}

pub async fn is_valid_authentication_method_for_hostname(hostname: Guarded_Hostname, authentication_method: AuthMethod) -> Result<bool, Box<dyn Error>> {
    // FUTURE: In ths future. multistep_authentication_methods should be implemented.
    let mut is_valid_hostname_authentication_method: bool = false;
    let hostname_authentication_methods = get_hostname_authentication_methods(hostname, true).await;
    for hostname_authentication_method in hostname_authentication_methods {
        if (authentication_method.id == hostname_authentication_method.id) {
            // Matches, is valid.
            is_valid_hostname_authentication_method = true;
        }
    }

    if (is_valid_hostname_authentication_method != true) {
        return Err("The user is attempting to authenticate with a hostname that does not support the provided authentication method.".into());
    }

    Ok(is_valid_hostname_authentication_method)
}

pub async fn get_hostname(hostname: String) -> Option<Guarded_Hostname> {
    let hostnames = get_active_hostnames().await;
    
    let mut hostname_output: Option<Guarded_Hostname> = None;
    for value in hostnames {
        println!("{} {}", value.hostname, hostname);
        if value.hostname == hostname {
            hostname_output = Some(value);
        }
    }

    hostname_output
}

pub async fn get_current_valid_hostname(headers: &Headers) -> Option<String> {
    let hostnames: Vec<Guarded_Hostname> = list_hostnames(true).await;

    let headers_cloned = headers.headers_map.clone();
    if (headers_cloned.get("host").is_none() == true) {
        println!("Missing \"host\" header");
        return None;
    }

    let host = headers_cloned.get("host").unwrap().to_owned();

    let mut is_valid_guarded_hostname: bool = false;
    for item in hostnames {
        if (item.hostname == host) {
            // Valid Guarded hostname!
            is_valid_guarded_hostname = true;
            break;
        }
    }

    if (is_valid_guarded_hostname == true) {
        return Some(host);
    } else {
        return None;
    }
}

// pub async fn check_against_policy(user: Guard_user, policy: Guard_Policy, request: Value) -> bool {
//     let mut matches: bool = false;
//     let property = "".to_string();
//     if (policy.is.is_none() && policy.is.unwrap().contains(&property)) {
//         let mut is_match: bool = false;
//         for item in policy.is {
//             if (item == property) {
//                 is_match = true;
//             }
//         }

//         if (is_match == true) {
//             matches = true;
//         }
//     } else if (policy.not.is_none() && policy.not.unwrap().contains(&property)) {
//         let mut not_match: bool = false;
//         for item in policy.not {
//             if (item == property) {
//                 not_match = true;
//             }
//         }

//         if (not_match == true) {
//             matches = true;
//         }
//     } else if (policy.starts_with.is_none() && policy.starts_with.unwrap().starts_with(property)) {
//         matches = true;
//     } else if (policy.ends_with.is_none() && policy.ends_with.unwrap().ends_with(property)) {
//         matches = true;
//     };

//     return false;
// }