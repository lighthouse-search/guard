use std::env;
use std::collections::HashMap;

use serde::{Serialize, Deserialize};
use serde_json::json;

use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use reqwest::multipart;

use url::Url;

pub async fn upload(url: String, asset_id: String, mode: String, file_type: String, chunk: i64, binary_value: Vec<u8>) {
    // Replace these with your actual values
    let signed_object = json!({
        "asset_id": asset_id,
        "mode": mode,
        "file_type": file_type,
        "chunk": chunk
    });

    // Create multipart form data
    let form = multipart::Form::new()
        .text("metadata", signed_object.to_string())
        .part(
            "file",
            multipart::Part::bytes(binary_value)
                .file_name("filename.bin")
                .mime_str("application/octet-stream").expect("Failed to set multipart bytes"),
        );

    // Set up headers
    let mut headers = HeaderMap::new();
    // headers.insert("size", HeaderValue::from(file_size));
    headers.insert(AUTHORIZATION, HeaderValue::from_static("EXAMPLE_BEARER_TOKEN"));

    let mut url_href = Url::parse(&url).unwrap();
    url_href.set_path(&format!("{}upload-chunk", url_href.path()));

    // Send POST request
    let client = reqwest::Client::new();
    let response = client
        .post(url_href)
        .headers(headers)
        .multipart(form)
        .send()
        .await.expect("Failed to send request.");

    // Handle the response
    if response.status().is_success() {
        let response_json: serde_json::Value = response.json().await.expect("Failed to parse response.");
        // println!("Response JSON: {:?}", response_json);
    } else {
        eprintln!("Request failed with status: {}", response.status());
    }
}