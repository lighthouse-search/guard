use std::collections::HashMap;

use serde::{Serialize, Deserialize};
use serde_json::{Value, json};
use yaml_rust::Yaml;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Command_argument {
    pub value: String
}

#[derive(Debug, Clone)]
pub struct Test_config {
    pub env: Option<Vec<Test_env>>,
    pub commands: Option<Vec<Test_command>>
}

#[derive(Clone, Debug)]
pub struct Test_env {
    pub key: String,
    pub value: String
}

#[derive(Clone, Debug)]
pub struct Test_command {
    pub name: String,
    pub run: String,
    pub env: Option<Yaml>
}