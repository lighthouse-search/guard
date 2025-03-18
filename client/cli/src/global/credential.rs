use serde_json::{json, Value};
use serde::Deserialize;
use crate::global::macos::{retrieve_password, store_password};

static SERVICE: &str = "guard_agent";

#[derive(Clone, Debug, Deserialize)]
pub struct Credential {
    pub host: String,
    pub device_id: String,
    pub private_key: String
}

#[derive(Clone, Debug, Deserialize)]
pub struct States {
    pub state: Vec<String>,
}

pub fn credentials_get() -> Credential {
    let mut output: Option<Credential> = None;
    if let Some(retrieved_password) = retrieve_password(SERVICE, "credential") {
        // println!("Retrieved password: {}", retrieved_password);
        output = Some(serde_json::from_str(&retrieved_password).expect("Failed to parse string"));
    } else {
        println!("Failed to retrieve password.");
    }

    return output.expect("Failed to get credentials");
}

pub fn credentials_set(host: String, access_token: String, refresh_token: String) -> Value {
    let credentials = json!({
        "host": host,
        "access_token": access_token,
        "refresh_token": refresh_token
    });

    store_password(SERVICE, "credential", &serde_json::to_string(&credentials).expect("Failed to serialize value"));

    return credentials;
}

pub fn state_list() -> Vec<String> {
    let mut output: Option<States> = None;
    if let Some(retrieved_password) = retrieve_password(SERVICE, "oauth_state") {
        // println!("Retrieved password: {}", retrieved_password);
        output = Some(serde_json::from_str(&retrieved_password).expect("Failed to parse string"));
    } else {
        println!("Failed to retrieve password.");
    }

    return output.expect("Failed to get state").state;
}

pub fn state_set(state: Vec<String>) -> Value {
    let state_json = json!({
        "state": state,
    });

    store_password(SERVICE, "oauth_state", &serde_json::to_string(&state_json).expect("Failed to serialize value"));

    return state_json;
}