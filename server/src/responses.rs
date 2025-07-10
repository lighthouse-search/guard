use serde_json::{Value, json};
use crate::structs::*;

pub fn error_message(message: &str) -> ErrorResponse {
    return ErrorResponse {
        error: true,
        message: message.to_string()
    }
}

impl From<ErrorResponse> for Value {
    fn from(err: ErrorResponse) -> Self {
        json!({
            "error": err.error,
            "message": err.message,
        })
    }
}

pub fn internal_server_error_generic() -> ErrorResponse {
    return ErrorResponse {
        error: true,
        message: "Internal server error".to_string()
    }
}

// pub fn not_authorized() -> Value {
//     return json!({
//         "error": true,
//         "message": "Authentication failed (you must authenticate).",
//         "unauthorized": true
//     })
// }