use std::collections::HashMap;

use serde::{Serialize, Deserialize};
use serde_json::Value;
use crate::structs::*;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CommandArgument {
    pub value: Option<String>
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CliAuthenticateHandleResponse {
    pub error: bool,
    pub nonce: String,
    pub valid: bool,
    pub user: Option<Value>,
    pub device: Option<GuardDevices>,
    pub authentication_method: Option<AuthMethod>,
    pub dev_note: String
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CliUserCreateResponse {
    pub error: bool,
    pub id: Option<String>,
    pub email: Option<String>
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ArgsToHashmap {
    pub args: HashMap<String, CommandArgument>,
    pub modes: Vec<String>
}