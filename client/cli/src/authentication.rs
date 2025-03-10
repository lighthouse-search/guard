use crate::structs::Get_asset_id;

use std::env;
use std::collections::HashMap;

use serde::{Serialize, Deserialize};
use serde_json::json;

use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use url::Url;

use std::process::Command;

pub async fn initalise() -> Option<Get_asset_id> {
    let url: String = "https://example.com".to_string();
    Command::new("open")
        .args([url])
        .output()
        .expect("failed to execute process")
}