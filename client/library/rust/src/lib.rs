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
        match request.method() {
            Method::Get => self.get.fetch_add(1, Ordering::Relaxed),
            Method::Post => self.post.fetch_add(1, Ordering::Relaxed),
            _ => return
        };
    }

    async fn on_response<'r>(&self, request: &'r Request<'_>, response: &mut Response<'r>) {
        // Don't change a successful user's response, ever.
        if response.status() != Status::NotFound {
            return
        }

        // // Rewrite the response to return the current counts.
        // if request.method() == Method::Get && request.uri().path() == "/counts" {
        //     let get_count = self.get.load(Ordering::Relaxed);
        //     let post_count = self.post.load(Ordering::Relaxed);
        //     let body = format!("Get: {}\nPost: {}", get_count, post_count);

        //     response.set_status(Status::Ok);
        //     response.set_header(ContentType::Plain);
        //     response.set_sized_body(body.len(), Cursor::new(body));
        // }

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
        }
    }
}
