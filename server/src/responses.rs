use serde_json::{Value, json};
use rocket::response::status;
use rocket::http::Status;
use rocket::response::status::Custom;
use crate::structs::*;

pub fn error_message(message: &str) -> Error_response {
    return Error_response {
        error: true,
        message: message.to_string()
    }
}

impl From<Error_response> for Value {
    fn from(err: Error_response) -> Self {
        json!({
            "error": err.error,
            "message": err.message,
        })
    }
}

pub fn internal_server_error_generic() -> Error_response {
    return Error_response {
        error: true,
        message: "Internal server error".to_string()
    }
}

pub fn not_authorized() -> Value {
    return json!({
        "error": true,
        "message": "Authentication failed (you must authenticate).",
        "unauthorized": true
    })
}