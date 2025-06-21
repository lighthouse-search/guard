use crate::structs::*;
use crate::tables::*;
use crate::global::*;
use std::error::Error;
use serde_json::Value;

pub async fn get_hostname_policies(hostname: Guarded_Hostname, only_active: bool) -> Vec<Guard_Policy> {
    let mut policies: Vec<Guard_Policy> = Vec::new();

    for authentication_method_id in hostname.applied_policies {
        let authentication_method = get_policy(authentication_method_id.clone()).await.expect("Missing");
        if (only_active == true && authentication_method.active == true) {
            policies.push(authentication_method.clone());
        }
        if (only_active == false) {
            policies.push(authentication_method.clone());
        }
    }

    policies
}

pub async fn policy_authentication(policies: Vec<Guard_Policy>, user: Value, ip: String) -> bool {
    let mut action: String = "block".to_string();

    for policy in policies {
        let matches_output: bool = matches_policy(policy.clone(), user.clone(), ip.clone()).await.expect("Failed to match policy.");
        if (matches_output == true) {
            action = policy.action.clone();
            if (action == "block") {
                // User has met a condition where they have been blocked, if we keep moving, we might override it. We already know they're not authorized. 
                break;
            }
        }
    }

    // Check though internal policy loop. If one of the policies are block (or otherwise not allow), THEN we block the policy. We don't return the action of the last policy, because that's not representative of the main actual policy, but if the internal policies fail, then that's definitely a no go.

    if (action == "allow") {
        return true;
    } else {
        return false;
    }
}

pub async fn matches_policy(policy: Guard_Policy, user: Value, ip: String) -> Result<bool, String> {
    let mut matches: bool = false;
    let mut property = String::new();

    if let Some(property_value) = user.get(policy.property.clone()) {
        if property_value.is_null() || property_value.as_str().map_or(false, |s| s.is_empty()) {
            log::info!("The property is empty");
        } else {
            property = property_value.as_str().unwrap_or_default().to_string();;
        }
    } else {
        log::info!("The property does not exist");
    }

    if (property == String::new()) {
        return Err(format!("'{}' is null or does not exist in the user data", policy.property));
    }

    // let requested_property = policy.property.to_lowercase(); // So we can always get the property as lower-case without 
    // if (requested_property == "email") {
    //     property = user.email;
    // } else if (requested_property == "ip") {
    //     property = ip;
    // } else {
    //     // Throw error, invalid property.
    //     return Err("Invalid property specified for policy. This should have been caught in a config integrity check.".into());
    // }

    if (policy.is.is_none() == false) {
        let is_vec = policy.is.unwrap();

        if (is_vec.contains(&property)) {
            let mut is_match: bool = false;
            for item in is_vec {
                if (item == property) {
                    is_match = true;
                }
            }

            if (is_match == true) {
                matches = true;
            }
        } else {
            matches = false;
        }
    }
    
    if (policy.not.is_none() == false) {
        let not_vec = policy.not.unwrap();
        if (not_vec.contains(&property)) {
            let mut not_match: bool = false;
            for item in not_vec {
                if (item == property) {
                    not_match = true;
                }
            }

            if (not_match == true) {
                matches = true;
            }
        } else {
            matches = false;
        }
    }

    if (policy.starts_with.is_none() == false) {
        let starts_with = policy.starts_with.expect("");
        if (property.starts_with(&starts_with)) {
            matches = true;
        } else {
            matches = false;
        }
    }

    if (policy.ends_with.is_none() == false) {
        let ends_with = policy.ends_with.expect("");
        if (property.ends_with(&ends_with) == true) {
            matches = true;
        } else {
            matches = false;
        };
    }

    Ok(matches)
}