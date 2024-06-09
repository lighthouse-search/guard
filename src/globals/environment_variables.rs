use std::env;

pub async fn get(variable: String) -> Option<String> {
    let mut value: Option<String> = None;

    if let Some(val) = env::var(variable).ok() {
        value = Some(val.to_string());
    };

    return value;
}