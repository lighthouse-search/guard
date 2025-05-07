use rocket::{Request, Response, request, request::FromRequest, catch, catchers, launch, routes, options};
use rocket::fairing::{Fairing, Info, Kind, AdHoc};
use rocket::http::Header;
use rocket::fs::FileServer;

use std::error::Error;
use std::fs;
use std::collections::HashMap;

use once_cell::sync::Lazy;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex, watch};
use tokio_tungstenite::{accept_async, tungstenite::protocol::Message, tungstenite::protocol::CloseFrame};

use tokio::sync::oneshot;
use tokio::task;

use super::endpoint::oauth::oauth_callback;
use super::response::error_message;

pub static CHANNEL: Lazy<Mutex<Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>>> = Lazy::new(|| {
    let (tx, rx) = oneshot::channel();
    Mutex::new(Some((tx, rx)))
});

#[catch(500)]
pub fn internal_error() -> serde_json::Value {
    error_message("Internal server error")
}

#[options("/<_..>")]
pub fn options_handler() -> &'static str {
    ""
}

// #[launch]
pub async fn rocket_launch() {
    let rocket = rocket::build()
    .register("/", catchers![internal_error])
    .mount("/oauth", routes![oauth_callback])
    .configure(rocket::Config::figment().merge(("port", 7676)));
    
    // Spawn Rocket in a separate task
    let rocket_handle = task::spawn(async {
        rocket.launch().await;
    });

    // Spawn a non-blocking listener for OAuth
    let channel_waiter = task::spawn(async {
        if let Some((_, rx)) = CHANNEL.lock().await.take() {
            if let Err(_) = rx.await {
                log::info!("Failed waiting for OAuth callback route, but continuing shutdown...");
            }
        }
    });

    // Wait for either Rocket to finish or the OAuth listener to complete
    tokio::select! {
        _ = rocket_handle => {
            log::info!("Rocket server has shut down.");
        }
        _ = channel_waiter => {
            log::info!("OAuth callback route signaled shutdown.");
        }
    }

    log::info!("Should shutdown.");
}