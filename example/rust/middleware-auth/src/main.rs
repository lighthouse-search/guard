use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::Header;
use rocket::{Build, Rocket};
use rocket::{Request, Response, request, request::FromRequest, catch, catchers, launch};

use serde_json::{Value, json};

#[tokio::main]
async fn main() {
    rocket().await.launch().await.expect("Failed to start web server");
}

#[catch(500)]
pub fn internal_error() -> serde_json::Value {
    json!({
        "error": true,
        "message": "Internal server error"
    })
}

async fn rocket() -> Rocket<Build> {
    let mut figment = rocket::Config::figment()
    .merge(("port", 8080))
    .merge(("address", "0.0.0.0"));

    rocket::custom(figment)
    .register("/", catchers![internal_error])
    .mount("/", guard_auth::guard_routes())
}