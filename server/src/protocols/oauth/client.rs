use reqwest::header::HeaderMap;
use serde_json::Value;
use crate::structs::*;
use serde_json::json;

pub async fn oauth_code_exchange_for_access_key(url: String, client_id: String, client_secret: String, code: String, scope: String, redirect_uri: String) -> Result<Option<OauthCodeAccessExchangeResponse>, String> {
    let params = json!({
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "scope": scope,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code"
    });
    
    log::debug!("oauth_code_exchange_for_access_key: params: {:?}", params);

    let output_body = serde_urlencoded::to_string(json!(params)).expect("Failed to encode URL parameters");
    
    // Build the client.
    let client = reqwest::Client::builder()
        .user_agent("Guard/1.0")
        .build().expect("Failed to build client.");

    // Execute the request.
    let response = client.post(url.clone())
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(output_body)
        .send()
        .await.expect("Failed to send request.");

    // if response.status().is_success() {
    // }

    let text: String = response.text().await.expect(&format!("Failed to get contents of request from '{}'.", url.clone()));

    // Print the response text
    log::info!("{}", text);

    // Parse the response body as JSON
    // Try to parse as JSON first
    let oauth_code_access_exchange_response = match serde_json::from_str(&text) {
        Ok(resp) => resp,
        Err(_) => {
            // If JSON parsing fails, try to parse as url-encoded
            serde_urlencoded::from_str::<OauthCodeAccessExchangeResponse>(&text)
                .expect(&format!(
                    "Failed to parse response from '{}' as JSON or url-encoded. Response: {}",
                    url.clone(),
                    text.clone()
                ))
        }
    };

    if oauth_code_access_exchange_response.access_token.is_none() {
        log::info!("access_token not returned in 'oauth code exchange for access key' response.");
        return Ok(None);
    }

    return Ok(Some(oauth_code_access_exchange_response));
}

pub async fn oauth_userinfo(url: String, access_token: String) -> Result<Value, String> {
    // Create headers for the request.
    let mut headers = HeaderMap::new();
    headers.insert("Authorization", format!("Bearer {}", access_token).parse().unwrap());

    // Build the client.
    let client = reqwest::Client::builder()
        .user_agent("Guard/1.0")
        .default_headers(headers)
        .build()
        .expect("Failed to build client.");

    // Execute the request.
    let response = client.get(url.clone()).send().await.expect("Failed to send request.");

    // Handle the response.
    if response.status().is_success() == false {
        let status = response.status().clone();
        let text: String = response.text().await.expect(&format!("Failed to get contents of request from '{}'.", url.clone()));

        return Err(format!("Request failed with status '{}': {}", status, text).into());
    }

    let text: String = response.text().await.expect(&format!("Failed to get contents of request from '{}'.", url.clone()));

    // Print the response text
    log::info!("{}", text);

    // Parse the response body as JSON
    let json: Value = serde_json::from_str(&text).expect(&format!("Failed to parse (json) response from '{}', is the response json?", url.clone()));

    return Ok(json);
}