use std::collections::{HashMap};
use std::time::{SystemTime, UNIX_EPOCH};
use std::env;

use indexmap::IndexMap;

use rand::prelude::*;

use rocket::http::CookieJar;

use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};

use crate::structs::*;
use crate::CONFIG_VALUE;

pub async fn get_authentication_methods() -> HashMap<String, AuthMethod> {
    let auth_methods = (*CONFIG_VALUE).clone().authentication_methods.unwrap();

    let mut methods: HashMap<String, AuthMethod> = HashMap::new();

    for (key, value) in auth_methods {
        let parts: Vec<&str> = key.split('.').collect();
        if parts.len() == 1 {
            let mut method: AuthMethod = value.clone().try_into().expect("Missing authentication method.");
            log::info!("METHOD: {:?}", method.clone());
            method.id = Some(key.clone());
            methods.insert(key.clone(), method);
        }
    }

    return methods;
}

pub async fn get_authentication_method(id: String, only_active: bool) -> Option<AuthMethod> {
    let auth_methods = get_authentication_methods().await;
    
    let mut authentication_method_candidate: Option<AuthMethod> = None;
    for (_key, value) in auth_methods {
        if value.clone().id.expect("Missing id") == id && authentication_method_candidate.is_none() == true {
            authentication_method_candidate = Some(value.clone());
        }
    }

    if authentication_method_candidate.is_none() {
        return None;
    }

    // Caller has required the authentication-method be active.
    let authentication_method = authentication_method_candidate.unwrap();
    if authentication_method.active != true && only_active == true {
        return None;
    }

    return Some(authentication_method);
}

pub async fn get_policies() -> HashMap<String, GuardPolicy> {
    let policies = (*CONFIG_VALUE).clone().policies.unwrap();

    let mut methods: HashMap<String, GuardPolicy> = HashMap::new();

    for (key, value) in policies {
        let parts: Vec<&str> = key.split('.').collect();
        if parts.len() == 1 {
            let mut method: GuardPolicy = value.clone().try_into().expect(&format!("Failed to parse policy in '{}'", key));
            method.id = Some(key.clone());
            methods.insert(key.clone(), method);
        }
    }

    return methods;
}

pub async fn get_policy(id: String) -> Option<GuardPolicy> {
    let policies = get_policies().await;
    
    let mut policy: Option<GuardPolicy> = None;
    for (_key, value) in policies {
        if value.clone().id.expect("Missing id") == id && policy.is_none() == true {
            policy = Some(value.clone());
        }
    }

    policy
}

// pub async fn get_active_authentication_methods() -> Vec<AuthMethod_Public> {
//     let auth_methods = get_authentication_methods().await;
    
//     let mut public_active_methods: Vec<AuthMethod_Public> = Vec::new();
//     for (_key, value) in auth_methods {
//         if value.active == true {
//             let method: AuthMethod_Public = value.try_into().expect("Failed");
//             public_active_methods.push(method);
//         }
//     }

//     public_active_methods
// }

// TODO: Why is this here? It should be removed. get_authentication_method solves this?
pub async fn is_valid_authentication_method(id: String) -> Option<AuthMethod> {
    let auth_methods = get_authentication_methods().await;

    let mut valid: Option<AuthMethod> = None;
    for (key, value) in auth_methods {
        if key.to_string() == id {
            valid = Some(value);
        }
    }

    return valid;
}

pub async fn send_email(email: String, subject: String, message: String) -> Result<bool, String> {
    // Set limit on email characters, in-case someone wants to have a laugh. 500 is very generous.
    if email.len() > 500 {
        return Err("The email provided is over 500 characters.".into());
    }

    let smtp: ConfigSmtp = CONFIG_VALUE.smtp.clone().unwrap();

    log::info!("[Debug] SMTP: {:?}", smtp.clone());

    let from = format!("{} <{}>", smtp.from_alias.expect("Missing from_alias"), smtp.from_header.clone().expect("Missing from_header"));
    let mut reply_to = format!("<{}>", smtp.from_header.expect("Missing from_header"));
    let to = format!("<{}>", email);

    if smtp.reply_to_address.is_none() == false {
        reply_to = format!("<{}>", smtp.reply_to_address.expect("Missing reply_to_address"));
    }

    // NOTE: IT IS ABSOLUTELY VITAL .PARSE IS USED ON ALL INPUTS FOR SAFETY. Lettre validates the input here via .parse. Input injection isn't possible with .parse().
    let email_packet = Message::builder()
    .from(from.parse().unwrap())
    .reply_to(reply_to.parse().unwrap())
    .to(to.parse().unwrap())
    .subject(subject)
    .header(ContentType::TEXT_PLAIN)
    .body(String::from(message))
    .unwrap();

    // Check for password and get it.
    let mut _password: String = String::new();
    if let Some(val) = env::var(smtp.password_env.expect("Missing password_env")).ok() {
        _password = val;
    } else {
        return Err("The environment variable specified in config.smtp.password_env is missing.".into());
    }

    log::debug!("Sending mail...");

    let creds = Credentials::new(smtp.username.expect("Missing smtp.username"), _password);

    log::debug!("Passed creds");
 
    // Open a remote connection to specified SMTP host using STARTTLS
    let mailer = SmtpTransport::starttls_relay(&smtp.host.expect("Missing smtp.host"))
        .unwrap()
        .credentials(creds)
        .build();

    log::debug!("Passed mailer");

    let result = tokio::task::spawn_blocking(move || {
        let send_result = mailer.send(&email_packet);
        log::debug!("Passed internal mail send");
        send_result
    }).await;

    log::debug!("Passed mail send");

    match result {
        Ok(Ok(_)) => {
            log::error!("Email sent successfully.");
            Ok(true)
        },
        Ok(Err(e)) => {
            log::error!("Error sending email: {e:?}");
            Err(e.to_string())
        },
        Err(e) => {
            log::error!("Task join error: {e:?}");
            Err("Failed to send email due to task error.".into())
        }
    }
}

pub fn generate_uuid() -> String {
    let id = uuid::Uuid::new_v4();
    return id.to_string();
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
    if data.is_none() {
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

pub fn jar_to_indexmap(jar: &CookieJar) -> IndexMap<String, String> {
    jar.iter()
        .map(|c| (c.name().to_owned(), c.value().to_owned()))
        .collect()
}

// pub async fn check_against_policy(user: GuardUser, policy: Guard_Policy, request: Value) -> bool {
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