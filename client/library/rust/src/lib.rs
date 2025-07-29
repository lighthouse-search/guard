use std::collections::HashMap;
use std::io::Cursor;
use std::sync::atomic::{AtomicUsize, Ordering};

use reqwest::header;
use rocket::response::status;
use rocket::{Request, Data, Response};
use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::{Method, ContentType, Status};
use url::Url;

use std::str::FromStr;

mod request_proxy;

// TODO: Enforce a minimum Guard version both with the internal binary and an external server address.

#[derive(Default)]
pub struct Proxy_middleware {
    get: AtomicUsize,
    post: AtomicUsize,
}

impl Proxy_middleware {
    pub fn new() -> Self {
        Self::default()
    }
}

#[rocket::async_trait]
impl Fairing for Proxy_middleware {
    // This is a request and response fairing named "GET/POST Counter".
    fn info(&self) -> Info {
        Info {
            name: "GET/POST Counter",
            kind: Kind::Request | Kind::Response
        }
    }

    // Increment the counter for `GET` and `POST` requests.
    async fn on_request(&self, request: &mut Request<'_>, _: &mut Data<'_>) {
        if (request.uri().path().starts_with("/guard/")) {
            let forward_to_guard_status = crate::request_proxy::forward_to_guard(request).await;
            if (forward_to_guard_status.is_err()) {
                response.set_status(Status::BadGateway);
                response.set_sized_body(0, Cursor::new("Failed to forward request to guard"));
                return;
            }
            let resp = forward_to_guard_status.unwrap();

            let status = Status::new(resp.status().as_u16());
            let headers = resp.headers().clone();

            let body = resp.text().await.unwrap_or_else(|_| "Failed to read response".to_string());
            response.set_status(status);
            headers.get(header::CONTENT_TYPE).map(|ct| {
                if let Ok(content_type) = ct.to_str() {
                    response.set_header(ContentType::from_str(content_type).unwrap_or(ContentType::Plain));
                }
            });

            response.set_sized_body(body.len(), Cursor::new(body));
            return;
        }
    }
}
