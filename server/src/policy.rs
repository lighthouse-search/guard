use crate::structs::*;
use crate::global::*;
use serde_json::Value;

pub async fn get_hostname_policies(hostname: GuardedHostname, only_active: bool) -> Vec<GuardPolicy> {
    let mut policies: Vec<GuardPolicy> = Vec::new();

    for authentication_method_id in hostname.applied_policies {
        let authentication_method = get_policy(authentication_method_id.clone()).await.expect("Missing");
        if only_active == true && authentication_method.active == true {
            policies.push(authentication_method.clone());
        }
        if only_active == false {
            policies.push(authentication_method.clone());
        }
    }

    policies
}

pub async fn policy_authentication(policies: Vec<GuardPolicy>, user: Value, ip: String) -> bool {
    let mut action: String = "block".to_string();

    for policy in policies {
        let matches_output: bool = matches_policy(policy.clone(), user.clone(), ip.clone()).await.expect("Failed to match policy.");
        if matches_output == true {
            action = policy.action.clone();
            if action == "block" {
                // User has met a condition where they have been blocked, if we keep moving, we might override it. We already know they're not authorized. 
                break;
            }
        }
    }

    // Check though internal policy loop. If one of the policies are block (or otherwise not allow), THEN we block the policy. We don't return the action of the last policy, because that's not representative of the main actual policy, but if the internal policies fail, then that's definitely a no go.
    if action == "allow" {
        return true;
    } else {
        return false;
    }
}

pub async fn matches_policy(policy: GuardPolicy, user: Value, _ip: String) -> Result<bool, String> {
    let mut matches: bool = false;
    let mut property = String::new();

    // Check if user data was provided by authentication provider, check that user data is not empty.
    if let Some(property_value) = user.get(policy.property.clone()) {
        if property_value.is_null() || property_value.as_str().map_or(false, |s| s.is_empty()) {
            log::info!("The property is empty");
        } else {
            property = property_value.as_str().unwrap_or_default().to_string();
        }
    } else {
        log::info!("The property does not exist");
    }

    // Check if property was provided by authentication provider.
    if property == String::new() {
        return Err(format!("'{}' is null or does not exist in the user data", policy.property));
    }

    // If "is" condition is supplied, check it.
    if policy.is.is_none() == false {
        // Array of possible values.
        let is_vec = policy.is.unwrap();

        // Check if property is within array of possible values.
        if is_vec.contains(&property) {
            let mut is_match: bool = false;
            // Loop through array, try and find match.
            for item in is_vec {
                if item == property {
                    // Property is within possible values.
                    is_match = true;
                }
            }

            // Update overall policy match variable accordingly.
            if is_match == true {
                matches = true;
            }
        } else {
            // Failed a policy stage, we cannot authorise the user.
            matches = false;
        }
    }
    
    // If "not" condition is supplied, check it.
    if policy.not.is_none() == false {
        let not_vec = policy.not.unwrap();
        if not_vec.contains(&property) {
            let mut not_match: bool = false;
            // Loop through array, check property doesn't match with an illegal value.
            for item in not_vec {
                if item == property {
                    // Property is not an illegal value.
                    not_match = true;
                }
            }

            // Update overall policy match variable accordingly.
            if not_match == true {
                matches = true;
            }
        } else {
            // Failed a policy stage, we cannot authorise the user.
            matches = false;
        }
    }

    // If "starts_with" condition is supplied, check it.
    if policy.starts_with.is_none() == false {
        let starts_with = policy.starts_with.expect("");
        // Check if property starts with specific value.
        if property.starts_with(&starts_with) {
            matches = true;
        } else {
            // Failed a policy stage, we cannot authorise the user.
            matches = false;
        }
    }

    // If "ends_with" condition is supplied, check it.
    if policy.ends_with.is_none() == false {
        let ends_with = policy.ends_with.expect("");
        // Check if property ends with specific value.
        if property.ends_with(&ends_with) == true {
            matches = true;
        } else {
            // Failed a policy stage, we cannot authorise the user.
            matches = false;
        };
    }

    // TODO: .and doesn't work

    // If matches = true, the user will be authorised. This means they haven't failed any policies.

    Ok(matches)
}