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
use regex::Regex;

use diesel::sql_query;
use diesel::prelude::*;
use diesel::sql_types::*;

use rocket::http::HeaderMap;

use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};

use lettre::transport::smtp::client::{Tls, TlsParameters};

use crate::structs::*;
use crate::tables::*;
use crate::CONFIG_VALUE;

use hades_auth::authenticate;

fn validate_table_name(input: &str) -> bool {
    let re = Regex::new(r"^[A-Za-z1-9_]+$").unwrap();
    re.is_match(input)
}

pub async fn validate_sql_table_inputs(raw_sql_tables: toml::Value) -> Result<bool, Box<dyn Error>> {
    let sql_tables = raw_sql_tables.as_table().unwrap();
    // println!("sql_tables: {:?}", sql_tables);

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
            let mut method: AuthMethod = value.clone().try_into().expect("Missing authentication method.");
            println!("METHOD: {:?}", method.clone());
            method.id = Some(key.clone());
            methods.insert(key.clone(), method);
        }
    }

    return methods;
}

pub async fn get_authentication_method(id: String, only_active: bool) -> Option<AuthMethod> {
    let auth_methods = get_authentication_methods().await;
    
    let mut authentication_method_candidate: Option<AuthMethod> = None;
    for (key, value) in auth_methods {
        if value.clone().id.expect("Missing id") == id && authentication_method_candidate.is_none() == true {
            authentication_method_candidate = Some(value.clone());
        }
    }

    if (authentication_method_candidate.is_none()) {
        return None;
    }

    // Caller has required the authentication-method be active.
    let authentication_method = authentication_method_candidate.unwrap();
    if (authentication_method.active != true && only_active == true) {
        return None;
    }

    return Some(authentication_method);
}

pub async fn get_policies() -> HashMap<String, Guard_Policy> {
    let value = (*CONFIG_VALUE).clone();
    let table = value.as_table().unwrap();
    let auth_methods = table.get("policies").unwrap().as_table().unwrap();

    let mut methods: HashMap<String, Guard_Policy> = HashMap::new();

    for (key, value) in auth_methods {
        let parts: Vec<&str> = key.split('.').collect();
        if parts.len() == 1 {
            let mut method: Guard_Policy = value.clone().try_into().expect(&format!("Failed to parse policy in '{}'", key));
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

pub async fn send_email(email: String, subject: String, message: String) -> Result<bool, String> {
    // Set limit on email characters, in-case someone wants to have a laugh. 500 is very generous.
    if (email.len() > 500) {
        return Err("The email provided is over 500 characters.".into());
    }

    let smtp_json = serde_json::to_string(&CONFIG_VALUE["smtp"]).expect("Failed to serialize");
    let smtp: Config_smtp = serde_json::from_str(&smtp_json).expect("Failed to parse");

    println!("[Debug] SMTP: {:?}", smtp.host.clone());

    // NOTE: We're not stupid, Lettre validates the input here via .parse. It's absolutely vital .parse is here for safety.

    let from = format!("{} <{}>", smtp.from_alias.expect("Missing from_alias"), smtp.from_header.clone().expect("Missing from_header"));
    let mut reply_to = format!("<{}>", smtp.from_header.expect("Missing from_header"));
    let to = format!("<{}>", email);

    if (smtp.reply_to_address.is_none() == false) {
        reply_to = format!("<{}>", smtp.reply_to_address.expect("Missing reply_to_address"));
    }

    // NOTE: IT IS ABSOLUTELY VITAL .PARSE IS HERE, ON ALL INPUTS, FOR SAFETY. Lettre validates the input here via .parse, injection is possible without .parse.
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

    let creds = Credentials::new(smtp.username.clone().expect("Missing username"), password);
    
    let tls = TlsParameters::builder(smtp.host.clone().expect("Missing host"))
    .build().unwrap();

    let mailer = SmtpTransport::relay(&smtp.host.clone().expect("Missing host"))
    .unwrap()
    .tls(Tls::Required(tls)) 
    .credentials(creds)
    .build();

    // Send the email
    match mailer.send(&email_packet) {
        Ok(_) => Ok(true),
        Err(e) => Err(e.to_string()),
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

pub fn is_null_or_whitespace(data: Option<String>) -> bool {
    if (data.is_none()) {
        return true;
    }
    let s = data.unwrap();
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
        let authentication_method = get_authentication_method(authentication_method_id.clone(), false).await.expect("Missing");
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

pub async fn get_hostname(hostname: String) -> Result<Guarded_Hostname, String> {
    let hostnames = get_active_hostnames().await;
    
    let mut hostname_output: Option<Guarded_Hostname> = None;
    for value in hostnames {
        println!("{} {}", value.host, hostname);
        if value.host == hostname {
            hostname_output = Some(value);
        }
    }

    if (hostname_output.is_none()) {
        return Err("Invalid hostname.".into());
    }

    return Ok(hostname_output.unwrap());
}

pub fn url_to_domain_port(host_unparsed: String) -> Result<String, Box<dyn Error>> {
    // Parse URL through parser to get host.
    let mut host = Url::parse(&host_unparsed).unwrap(); // Future: Handle bad value here, otherwise it will just error.

    // Set the result as output_host. This streamlines the value.
    let mut output_host = host.host_str().unwrap().to_string();

    // Sometimes, the header has a port set (e.g example.com:1234, instead of example.com). Guard allows having the same hostnames with different ports, we need to add that information if the port is not 443, otherwise the hostname won't be found.
    if (host.port().is_none() == false) {
        if (host.port().unwrap() != 443) {
            output_host = format!("{}:{}", host.host_str().unwrap().to_string(), host.port().unwrap())
        }
    }

    return Ok(output_host);
}

// Bad name. But this function returns get_hostname alongside parsed URL strings (domain port) and the original_url.
pub async fn get_current_valid_hostname(headers: &Headers, header_to_use: Option<String>) -> Option<Get_current_valid_hostname_struct> {
    let mut header: String = "host".to_string();
    if (header_to_use.is_none() == false) {
        header = header_to_use.unwrap();
    }

    let headers_cloned = headers.headers_map.clone();
    if (headers_cloned.get(&header).is_none() == true) {
        println!("Missing header: {}", header);
        return None;
    }

    let mut host_unparsed = headers_cloned.get(&header).unwrap().to_owned();
    // host_unparsed.contains("://") == false, could pick up something in the pathname, but this isn't for security's sake, this is for error handling sake. The URL parser validates the URL.
    if (host_unparsed.starts_with("https://") == false && host_unparsed.starts_with("http://") == false && host_unparsed.contains("://") == false) {
        // Add HTTPS to protocol in URL, since none was specified (which is always going to happen in "host" headers).
        host_unparsed = format!("https://{}", host_unparsed);
    }

    let domain_port = url_to_domain_port(host_unparsed.clone()).expect("Failed to get output_host");
    let hostname = get_hostname(domain_port.clone()).await;

    if (hostname.is_ok() == true) {
        // domain_port is a valid hostname.
        return Some(Get_current_valid_hostname_struct {
            hostname: hostname.unwrap(),
            domain_port: domain_port,
            original_url: host_unparsed
        });
    } else {
        println!("Invalid hostname");
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