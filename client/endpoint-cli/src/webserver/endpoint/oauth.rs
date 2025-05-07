use serde_json::{json, Value};
use std::net::SocketAddr;

use rocket::{http::Status, response::status::{self, Custom}, Shutdown, get};
use rocket::form::Form;
use rocket::FromForm;
use rocket::post;
use serde::Deserialize;

use crate::webserver::server::CHANNEL;

#[get("/callback?<code>&<state>")]
pub async fn oauth_callback(code: Option<String>, state: Option<String>, shutdown: Shutdown) -> Result<Custom<Value>, Status> {
    
    
    shutdown.await;

    if let Some((tx, _)) = CHANNEL.lock().await.take() {
        let _ = tx.send(());
    }

    Ok(status::Custom(Status::Ok, json!(
        {
            "token_type": "Bearer",
            "expires_in": 3600,
        }
    )))
}