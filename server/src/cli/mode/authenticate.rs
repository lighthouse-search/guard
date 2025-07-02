use std::collections::HashMap;

use crate::cli::internal::validation::argument::{get_value, has_no_value};
use crate::global::is_null_or_whitespace;
use crate::structs::*;
use crate::cli::cli_structs::*;
use crate::users::user_authentication_pipeline;

// In this file, we're authenticating active sessions. For example, we wouldn't accept username/passwords or allow users to request a magiclink here. Instead, we'd use ./guard session create --type username-password --email hi@example.com --password [you_shouldnt_be_typing_passwords_into_an_unsafe_cli] or ./guard session create --type magiclink --email hi@example.com

pub async fn handle(arguments: HashMap<String, Command_argument>, modes: Vec<String>) -> Result<(), String> {
    // PLACEHOLDER EXAMPLE: ./guard authenticate handle --type request --host example.com --body {"post": "💞"} --headers {"Content-Type": "application/json"} --parameters referer=my%20awesome%20post%20composer&status=cool --nonce 1746447427345+40
    log::debug!("Initalised");

    if (arguments.contains_key("type") == false) {
        return Err("--type requires a value. E.g. try ./guard --type request".to_string());
    }
    if (has_no_value(&arguments, "type") == true) {
        return Err("--type requires a value. E.g. try ./guard --type request".to_string());
    }
    
    let type_value = arguments.get("type").unwrap().value.clone().unwrap(); // E.g: ./guard authenticate handle --type [SOME_VALUE]
    if (type_value == "request") {
        // E.g. ./guard authentication handle --type request
        // We're using request authentication. Let's pass this to the CLI request authentication pipeline.
        return request(arguments, modes).await;
    } else {
        return Err(format!("./guard --type {} is invalid.", type_value));
    }
}

async fn request(arguments: HashMap<String, Command_argument>, modes: Vec<String>) -> Result<(), String> {
    // TODO: Some of these need to be optional.
    if (has_no_value(&arguments, "host") == true) {
        return Err("--host requires a value.".to_string());
    }
    if (has_no_value(&arguments, "headers") == true) {
        return Err("--headers requires a value.".to_string());
    }
    if (has_no_value(&arguments, "parameters") == true) {
        return Err("--parameters requires a value.".to_string());
    }
    if (has_no_value(&arguments, "nonce") == true) {
        return Err("--nonce requires a value.".to_string());
    }
    if (has_no_value(&arguments, "ip-address") == true) {
        return Err("--ip-address requires a value.".to_string());
    }
    if (has_no_value(&arguments, "cookies") == true) {
        return Err("--cookies requires a value.".to_string());
    }

    // TODO: Need to support body signature verification in user_authentication_pipeline(), Guard is currently only verifying static JWTs. Remember to be specific when handling signed requests vs static JWTs. You don't want a downgrade attack.
    // For now, we'll comment out the --body value check and throw an error if it's called.
    // let body = get_value(arguments, "body");
    if (has_no_value(&arguments, "body") == false) {
        return Err("--body is currently unsupported.".to_string());
    }

    let host = get_value(&arguments, "host").unwrap();
    let parameters = get_value(&arguments, "parameters");
    let nonce = get_value(&arguments, "nonce");
    let ip_address = get_value(&arguments, "ip-address").expect("Failed to get IP address value");
    let headers: HashMap<String, String> = serde_json::from_str(&get_value(&arguments, "headers").expect("Failed to get headers value")).expect("Failed to parse headers");
    let cookies: indexmap::IndexMap<String, String> = serde_json::from_str(&get_value(&arguments, "cookies").expect("Failed to get cookies value")).expect("Failed to parse cookies");
    // TODO: This needs to include request body.
    
    // let (valid, user, device, authentication_method, error_to_respond_with)
    let user_authentication = user_authentication_pipeline(
        vec!["access_applications"],
        &cookies,
        ip_address,
        host,
        &Headers { headers_map: headers }
    ).await;

    if (user_authentication.is_err() == false) {
        log::error!("{:?}", user_authentication.err().unwrap());
        // TODO: An actual error body should be returned here.
        return Err(serde_json::to_string(&Cli_authenticate_handle_response {
            error: false,
            nonce: nonce.unwrap(),
            valid: false, // The authentication failed.
            user: None,
            device: None,
            authentication_method: None,
            dev_note: "For debugging information, specify \"RUST_LOG=info ./guard\"".to_string()
        }).unwrap());
    }

    let user_authentication_unwrapped = user_authentication.unwrap();

    println!("{}", serde_json::to_string(&Cli_authenticate_handle_response {
        error: false,
        nonce: nonce.unwrap(),
        valid: true, // The authentication was successful.
        user: Some(user_authentication_unwrapped.user.unwrap()),
        device: Some(user_authentication_unwrapped.device.unwrap()),
        authentication_method: Some(user_authentication_unwrapped.authentication_method.unwrap()),
        dev_note: "For debugging information, specify \"RUST_LOG=info ./guard\"".to_string()
    }).unwrap());

    return Ok(());
}