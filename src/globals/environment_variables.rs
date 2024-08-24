use std::env;

pub fn get(variable: String) -> Option<String> {
    // # Sometimes doesn't like - for some reason?
    let mut value: Option<String> = None;

    if let Some(val) = env::var(variable).ok() {
        value = Some(val.to_string());
    };

    return value;
}