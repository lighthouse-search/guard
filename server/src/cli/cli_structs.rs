use std::collections::HashMap;

use serde::{Serialize, Deserialize};
use serde_json::{Value, json};
use crate::structs::*;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Command_argument {
    pub value: Option<String>
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Cli_authenticate_handle_response {
    pub error: bool,
    pub nonce: String,
    pub valid: bool,
    pub user: Option<Value>,
    pub device: Option<GuardDevices>,
    pub authentication_method: Option<AuthMethod>,
    pub dev_note: String
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Cli_user_create_response {
    pub error: bool,
    pub id: Option<String>,
    pub email: Option<String>
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Args_to_hashmap {
    pub args: HashMap<String, Command_argument>,
    pub modes: Vec<String>
}