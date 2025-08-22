use std::collections::HashMap;

use rocket::http::{Method, Status};
use rocket::Response;
use rocket::response::{self, Responder};
use rocket::Request;

use url::Url;
use std::str::FromStr;

use crate::RequestMetadata;

pub struct ProxyResponse(Response<'static>);

impl<'r> Responder<'r, 'static> for ProxyResponse {
    fn respond_to(self, _: &'r Request<'_>) -> response::Result<'static> {
        Ok(self.0)
    }
}

pub async fn proxy_to_guard(request_metadata: RequestMetadata, _body: Option<String>) -> Result<reqwest::Response, Status> {
    let mut url = Url::parse("http://127.0.0.1:8000").expect("Failed to parse preset URL");
    url.set_path(&request_metadata.path);

    // Convert Rocket headers to reqwest headers
    let mut reqwest_headers = reqwest::header::HeaderMap::new();
    for header in request_metadata.headers.headers_map.iter() {
        let header_name = header.0.as_str();
        if header_name == "content-length" {
            continue;
        }

        if let Ok(name) = reqwest::header::HeaderName::from_bytes(header_name.as_bytes()) {
            if let Ok(value) = reqwest::header::HeaderValue::from_str(header.1.as_str()) {
                reqwest_headers.append(name, value);
            }
        }
    }

    // Request params
    let query_params = request_metadata.query;
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

    let req_response = match request_metadata.method {
        Method::Get => client.get(url).headers(reqwest_headers).query(&params_object),
        Method::Post => client.post(url).headers(reqwest_headers).query(&params_object).body(_body.unwrap_or_default()),
        Method::Put => client.put(url).headers(reqwest_headers).query(&params_object).body(_body.unwrap_or_default()),
        Method::Delete => client.delete(url).headers(reqwest_headers).query(&params_object).body(_body.unwrap_or_default()),
        Method::Patch => client.patch(url).headers(reqwest_headers).query(&params_object).body(_body.unwrap_or_default()),
        Method::Head => client.head(url).headers(reqwest_headers).query(&params_object).body(_body.unwrap_or_default()),
        Method::Options => client.request(reqwest::Method::OPTIONS, url).headers(reqwest_headers).query(&params_object).body(_body.unwrap_or_default()),
        _ => client.get(url).headers(reqwest_headers).query(&params_object), // Default to GET
    }
    .send()
    .await.expect("Failed to fetch upstream");

    if req_response.status().is_success() == false {
        return Err(Status::InternalServerError);
    }

    println!("OK!");

    Ok(req_response)
}

pub async fn package_response_body(req_response: reqwest::Response) -> ProxyResponse {
    let status = Status::new(req_response.status().as_u16());
    let headers = req_response.headers().clone();
    let body = req_response.text().await.unwrap_or_else(|_| "Failed to read response".to_string());
    
    let mut response = Response::new();
    response.set_status(status);
    
    // Copy headers from the upstream response
    for (name, value) in headers.iter() {
        let header_name = name.as_str();
        if let Ok(header_value) = value.to_str() {
            // Skip certain headers that shouldn't be forwarded
            match header_name.to_lowercase().as_str() {
                "content-length" | "transfer-encoding" | "connection" => continue,
                "content-type" => {
                    if let Ok(content_type) = rocket::http::ContentType::from_str(header_value) {
                        response.set_header(content_type);
                    }
                },
                _ => {
                    response.adjoin_raw_header(header_name.to_string(), header_value.to_string());
                }
            }
        }
    }
    
    response.set_sized_body(body.len(), std::io::Cursor::new(body));
    ProxyResponse(response)
}