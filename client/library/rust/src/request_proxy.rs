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

pub async fn forward_to_guard(request: &Request<'_>) -> Result<reqwest::Response, Status> {
    let mut url = Url::parse("http://127.0.0.1:8000").expect("Failed to parse preset URL");
    url.set_path(request.uri().path().as_str());

    // Convert Rocket headers to reqwest headers
    let mut reqwest_headers = reqwest::header::HeaderMap::new();
    for header in request.headers().iter() {
        if let Ok(name) = reqwest::header::HeaderName::from_bytes(header.name().as_str().as_bytes()) {
            if let Ok(value) = reqwest::header::HeaderValue::from_str(header.value()) {
                reqwest_headers.append(name, value);
            }
        }
    }

    // Request params
    let query_params = request.uri().query().map(|query| query.as_str().to_owned()).unwrap_or_else(|| String::new());
    let mut params_object: HashMap<String, String> = HashMap::new();
    let params_string: String = query_params.clone();
    if !params_string.is_empty() {
        params_object = Url::parse(&format!("http://localhost/?{}", params_string))
        .map(|url| url.query_pairs().into_owned().collect())
        .unwrap_or_default();
    }

    let client = reqwest::Client::builder()
        .build()
        .expect("Failed to build client");

    let resp = match request.method() {
        Method::Get => client.get(url).headers(reqwest_headers).query(&params_object),
        Method::Post => client.post(url).headers(reqwest_headers).query(&params_object),
        Method::Put => client.put(url).headers(reqwest_headers).query(&params_object),
        Method::Delete => client.delete(url).headers(reqwest_headers).query(&params_object),
        Method::Patch => client.patch(url).headers(reqwest_headers).query(&params_object),
        Method::Head => client.head(url).headers(reqwest_headers).query(&params_object),
        Method::Options => client.request(reqwest::Method::OPTIONS, url).headers(reqwest_headers).query(&params_object),
        _ => client.get(url).headers(reqwest_headers).query(&params_object), // Default to GET
    }
    .send()
    .await.expect("Failed to fetch upstream");

    if (resp.status().is_success() == false) {
        return Err(Status::InternalServerError);
    }

    println!("OK!");

    Ok(resp)
}