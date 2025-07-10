use std::collections::HashMap;

use crate::cli::internal::validation::argument::{get_value, has_no_value};
use crate::global::generate_uuid;
use crate::cli::cli_structs::*;
use crate::users::user_create;

pub async fn create(arguments: HashMap<String, CommandArgument>, _modes: Vec<String>) -> Result<(), String> {
    log::debug!("Initalised");

    if has_no_value(&arguments, "email") == true {
        return Err("--email requires a value.".to_string());
    }

    let id = get_value(&arguments, "email").unwrap_or(generate_uuid());
    let email = get_value(&arguments, "email").unwrap();

    // if (get_value(&arguments, "test-account").is_none() == false) {
    // }

    // if (get_value(&arguments, "generate-credentials").is_none() == false) {
    // }

    user_create(Some(id.clone()), Some(email.clone())).await.expect("Failed to create user");
    
    println!("{}", serde_json::to_string(&CliUserCreateResponse {
        error: false,
        id: Some(id),
        email: Some(email)
    }).unwrap());

    return Ok(());
}