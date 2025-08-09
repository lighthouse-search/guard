use crate::{request_proxy::proxy_to_guard, GuardMetadata, RequestMetadata};
use serde_json::Value;

pub async fn auth_via_https(mut request_metadata: RequestMetadata, body: Option<String>) -> GuardMetadata {
    request_metadata.path = "/guard/api/proxy/authenticate".to_string();
    let response = proxy_to_guard(request_metadata, body).await;

    let response_json = serde_json::from_str::<GuardMetadata>(&response.text().await.expect("Failed to read response text")).expect("Failed to parse response JSON");
    println!("Response JSON: {:?}", response_json);

    response_json
}