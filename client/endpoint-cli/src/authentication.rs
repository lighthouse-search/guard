use crate::webserver::server::CHANNEL;
use crate::{structs::*, webserver::server::rocket_launch};

use serde::{Serialize, Deserialize};
use serde_json::{json, Value};

use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use url::Url;

use rocket::{Request, Response, request, request::FromRequest, catch, catchers, launch, routes, options, get, State};
use rocket::fairing::{Fairing, Info, Kind, AdHoc};
use rocket::http::Header;
use rocket::fs::FileServer;
use std::net::SocketAddr;

use rocket::{http::Status, response::status::{self, Custom}};
use rocket::form::Form;
use rocket::FromForm;
use rocket::post;
use rocket::Shutdown;

use std::error::Error;
use std::fs;
use std::collections::HashMap;

use std::process::Command;

use tokio::sync::oneshot;

pub async fn initalise(arguments: HashMap<String, Command_argument>) -> Result<(), String> {
    let guard_url = arguments.get("guard_url").expect("Missing arguments.guard_url");

    let mut url = Url::parse(&guard_url.value).expect("Failed to parse arguments.guard_url (is your Guard URL correctly formatted?)");

    if (url.scheme() != "https" && url.host_str().unwrap() != "127.0.0.1") {
        return Err(String::from("arguments.guard_url must start with https://"));
    }

    url.set_path("/guard/frontend/oauth/authorise");
    // Add query parameters
    url.query_pairs_mut()
        .append_pair("redirect_uri", "https://127.0.0.1:7676/oauth/callback")
        .append_pair("grant_type", "authorization_code")
        .append_pair("scope", "access_applications");

    Command::new("open")
        .args([url.as_str()])
        .output()
        .expect("failed to execute process");

    rocket_launch().await;

    Ok(())
}

pub async fn handle_callback(code: String, state: String) -> Result<(), String> {
    
}