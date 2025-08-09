use std::collections::HashMap;

use rocket::{options, get, post, put, Request};
use rocket::request::FromRequest;
use rocket::request;

use rocket::Data;
use rocket::fairing::{Fairing, Info, Kind};

use serde_json::Value;

use crate::request_proxy::{package_response_body, proxy_to_guard};

mod request_proxy;
mod validation;

// TODO: Enforce a minimum Guard version both with the internal binary and an external server address.

#[derive(Debug)]
pub struct ConfigGuard {
    url: Option<String>,
    config: Option<String>, // Pass the config TOML as a string.
    config_path: Option<String>, // Pass path to config.
    config_env: Option<String>, // Pass the config environment variable.
}

#[derive(Debug)]
pub struct Config {
    guard: Option<ConfigGuard>,
}

#[derive(Default)]
pub struct ProxyRocketMiddleware {
    config: Option<Config>,
}

#[derive(Debug)]
pub struct QueryString(pub String);

#[derive(Debug)]
pub struct UrlUri(pub String);

#[derive(Debug, Clone)]
pub struct RequestMetadata {
    uri: String,
    path: String,
    query: String,
    headers: Headers,
    method: rocket::http::Method,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct GuardMetadata {
    user: Option<Value>,
    device: Option<Value>,
    authentication_method: Option<Value>
}

#[derive(Debug, Clone)]
pub struct Headers {
    pub headers_map: HashMap<String, String>,
}

pub fn guard_routes() -> Vec<rocket::Route> {
    rocket::routes![guard_options, guard_get, guard_post, guard_put]
}

#[options("/guard/<_..>")]
async fn guard_options(request_metadata: &RequestMetadata) -> request_proxy::ProxyResponse {
    package_response_body(request_proxy::proxy_to_guard(request_metadata.clone(), None).await.expect("Failed to proxy request to guard")).await
}

#[get("/guard/<_..>")]
async fn guard_get(request_metadata: &RequestMetadata) -> request_proxy::ProxyResponse {
    package_response_body(request_proxy::proxy_to_guard(request_metadata.clone(), None).await.expect("Failed to proxy request to guard")).await
}

#[post("/guard/<_..>", format = "application/json", data = "<body_raw>")]
async fn guard_post(request_metadata: &RequestMetadata, body_raw: String) -> request_proxy::ProxyResponse {
    // let body = serde_json::from_str(&body_raw).unwrap();
    package_response_body(request_proxy::proxy_to_guard(request_metadata.clone(), Some(body_raw)).await.expect("Failed to proxy request to guard")).await
}

#[put("/guard/<_..>", format = "application/json", data = "<body_raw>")]
async fn guard_put(request_metadata: &RequestMetadata, body_raw: String) -> request_proxy::ProxyResponse {
    // let body = serde_json::from_str(&body_raw).unwrap();
    package_response_body(request_proxy::proxy_to_guard(request_metadata.clone(), Some(body_raw)).await.expect("Failed to proxy request to guard")).await
}

fn request_metadata(request: &Request<'_>) -> RequestMetadata {
    let query_params = request.uri().query().map(|query| query.as_str().to_owned()).unwrap_or_else(|| String::new());

    // Headers
    let headers = request.headers().iter()
        .map(|header| (header.name.to_string(), header.value.to_string()))
        .collect::<HashMap<String, String>>();

    RequestMetadata {
        query: query_params,
        uri: request.uri().to_string(),
        path: request.uri().path().to_string(),
        method: request.method(),
        headers: Headers { headers_map: headers },
    }
}

// TODO: RequestMetadata might be useable in depdendent codebases, which wouldn't be great. This should be internal only.
#[rocket::async_trait]
impl<'r> FromRequest<'r> for &'r RequestMetadata {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        // The closure passed to `local_cache` will be executed at most once per
        // request: the first time the `RequestId` guard is used. If it is
        // requested again, `local_cache` will return the same value.

        request::Outcome::Success(request.local_cache(|| {
            request_metadata(request)
        }))
    }
}

#[rocket::async_trait]
impl Fairing for GuardMetadata {
    // This is a request and response fairing named "GET/POST Counter".
    fn info(&self) -> Info {
        Info {
            name: "GET/POST Counter",
            kind: Kind::Request | Kind::Response
        }
    }

    async fn on_request(&self, request: &mut Request<'_>, data: &mut Data<'_>) {
        let mut request_metadata = request_metadata(request);
        
        // let stream = data.open(2.mebibytes());

        // let body_data = data.open(20.mebibytes()).into_string().await.expect("Failed to get body").to_string();
        // auth_via_https(request_metadata, Some(body_data)).await;

        request.local_cache(|| {
            let query_params = request.uri().query().map(|query| query.as_str().to_owned()).unwrap_or_else(|| String::new());

            // Headers
            let headers = request.headers().iter()
                .map(|header| (header.name.to_string(), header.value.to_string()))
                .collect::<HashMap<String, String>>();

            GuardMetadata {
                user: None,
                device: None,
                authentication_method: None
            }
        });
    }
}