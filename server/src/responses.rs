use axum::{Json, http::StatusCode};
use axum::response::IntoResponse;

use serde_json::{Value, json};
use crate::structs::*;

pub fn error_message(code: i64, status_code: StatusCode, message: String) -> axum::response::Response {
    (
        status_code,
        Json(&ErrorResponse { error: true, message: message, code: code }),
    ).into_response()
}

pub fn fatal_error() -> axum::response::Response {
    (
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        Json(&ErrorResponse { error: true, message: "Internal server error".to_string(), code: 1000 }),
    ).into_response()
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
        message: "Internal server error".to_string(),
        code: 0
    }
}

// pub fn not_authorized() -> Value {
//     return json!({
//         "error": true,
//         "message": "Authentication failed (you must authenticate).",
//         "unauthorized": true
//     })
// }