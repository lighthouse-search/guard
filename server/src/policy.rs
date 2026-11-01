use std::collections::HashMap;

use crate::structs::*;
use crate::global::*;
use crate::CONFIG_VALUE;
use serde_json::Value;

pub async fn get_hostname_policies(hostname: GuardedHostname, only_active: bool) -> Vec<GuardPolicy> {
    resolve_policies(hostname.applied_policies, only_active).await
}

// Resolve a list of policy ids into policies. Shared by the per-hostname lookup
// above and by contexts that carry their own `applied_policies` (device
// authentication, WireGuard registration) rather than a [hostname.*] entry.
//
// Named `resolve_policies` rather than `get_policies` so it cannot be confused
// with `global::get_policies`, which returns every *defined* policy and is in
// scope here through the glob import.
pub async fn resolve_policies(policy_ids: Vec<String>, only_active: bool) -> Vec<GuardPolicy> {
    let mut policies: Vec<GuardPolicy> = Vec::new();

    for policy_id in policy_ids {
        // A reference to a policy that does not exist means the configuration is
        // not intact, and Guard cannot know what the operator intended to
        // enforce. Continuing would evaluate a *different*, weaker policy set
        // than the one that was written down, so fail the request outright
        // rather than guess. `validate_policy_references` is meant to catch this
        // at startup; reaching here means the config changed underneath us.
        let policy = get_policy(policy_id.clone()).await.unwrap_or_else(|| {
            panic!(
                "Policy '{}' is referenced but not defined in [policies]. Guard cannot evaluate an \
                 incomplete policy set, so this request is being failed rather than authorised \
                 against a partial one. Fix the reference or define the policy.",
                policy_id
            )
        });
        if only_active == false || policy.active == true {
            policies.push(policy);
        }
    }

    policies
}

// Check at startup that every policy reference in the config resolves, so a typo
// surfaces before Guard serves a request rather than as a failed request later.
//
// Covers every place a policy id can appear: [hostname.*], [device_authentication],
// [wireguard], and the `and` chains between policies themselves. Reports every
// problem at once, so a config with several typos takes one pass to fix.
pub fn validate_policy_references() -> Result<(), String> {
    // Mirrors global::get_policies: nested keys ("a.b") are not policies.
    let defined: HashMap<String, GuardPolicy> = CONFIG_VALUE
        .policies
        .clone()
        .unwrap_or_default()
        .into_iter()
        .filter(|(key, _)| key.split('.').count() == 1)
        .collect();

    // (where the reference lives, the id it points at)
    let mut references: Vec<(String, String)> = Vec::new();

    for hostname in CONFIG_VALUE.hostname.clone().unwrap_or_default().values() {
        for policy_id in &hostname.applied_policies {
            references.push((format!("hostname '{}'", hostname.host), policy_id.clone()));
        }
    }
    if let Some(device) = CONFIG_VALUE.device_authentication.clone() {
        for policy_id in device.applied_policies.unwrap_or_default() {
            references.push(("[device_authentication].applied_policies".to_string(), policy_id));
        }
    }
    if let Some(wireguard) = CONFIG_VALUE.wireguard.clone() {
        for policy_id in wireguard.applied_policies.unwrap_or_default() {
            references.push(("[wireguard].applied_policies".to_string(), policy_id));
        }
    }
    for (key, policy) in &defined {
        for policy_id in policy.and.clone().unwrap_or_default() {
            references.push((format!("policy '{}' ('and')", key), policy_id));
        }
    }

    check_policy_references(&defined, &references)
}

// The pure half of `validate_policy_references`: given the defined policies and
// every (source, referenced id) pair found in the config, report what is broken.
fn check_policy_references(defined: &HashMap<String, GuardPolicy>, references: &[(String, String)]) -> Result<(), String> {
    let mut problems: Vec<String> = references
        .iter()
        .filter(|(_, policy_id)| defined.contains_key(policy_id) == false)
        .map(|(source, policy_id)| format!("  {} references undefined policy '{}'", source, policy_id))
        .collect();

    // A cycle in the `and` chains is the same class of broken config: it is
    // handled defensively at request time (treated as a failure), but it can
    // only ever mean the operator made a mistake, so say so now.
    for key in defined.keys() {
        if and_chain_has_cycle(defined, key, &mut Vec::new()) {
            problems.push(format!("  policy '{}' is part of a cyclic 'and' reference", key));
        }
    }

    if problems.is_empty() {
        return Ok(());
    }

    problems.sort();
    problems.dedup();
    Err(format!("The policy configuration is not intact:\n{}", problems.join("\n")))
}

// Depth-first walk of a policy's `and` references looking for a loop back to
// something already on the path.
fn and_chain_has_cycle(defined: &HashMap<String, GuardPolicy>, policy_id: &str, path: &mut Vec<String>) -> bool {
    if path.iter().any(|seen| seen == policy_id) {
        return true;
    }
    let policy = match defined.get(policy_id) {
        Some(policy) => policy,
        // Undefined references are reported separately; not a cycle.
        None => return false,
    };

    path.push(policy_id.to_string());
    let found = policy
        .and
        .clone()
        .unwrap_or_default()
        .iter()
        .any(|next| and_chain_has_cycle(defined, next, path));
    path.pop();

    found
}

pub async fn policy_authentication(policies: Vec<GuardPolicy>, user: Value, ip: String) -> bool {
    let mut action: String = "block".to_string();

    for policy in policies {
        // matches_policy returns Err when the policy's property is absent from the
        // user data the authentication method returned (providers differ in which
        // claims they expose). That is "this policy does not match", not a reason to
        // unwind the request — and since `action` stays "block" unless an allow
        // policy matches, treating it as a non-match keeps the deny-by-default
        // behaviour. This matches how the nested 'and' evaluation below already
        // handles the same Err (`and_matches.unwrap_or(false)`).
        let matches_output: bool = match matches_policy(policy.clone(), user.clone(), ip.clone()).await {
            Ok(matches_output) => matches_output,
            Err(error) => {
                log::info!("Policy '{}' could not be evaluated, treating as no match: {}", policy.id.clone().unwrap_or_default(), error);
                false
            }
        };
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

pub async fn matches_policy(policy: GuardPolicy, user: Value, ip: String) -> Result<bool, String> {
    Box::pin(matches_policy_chain(policy, user, ip, Vec::new())).await
}

// `chain` holds the ids of policies currently being evaluated up the `and`
// recursion, so a cyclic reference (A -> B -> A) can be detected instead of
// recursing forever.
async fn matches_policy_chain(policy: GuardPolicy, user: Value, _ip: String, chain: Vec<String>) -> Result<bool, String> {
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

    // If "and" is supplied, every referenced policy must ALSO match for this
    // policy to be honoured (logical conjunction). A referenced policy that
    // doesn't exist, or that the user fails (including a missing property, which
    // makes matches_policy return an Err), counts as a failure.
    if matches == true {
        if let Some(and_vec) = policy.and {
            // Record this policy in the chain so downstream 'and' references that
            // loop back to it can be detected as cycles.
            let mut chain = chain;
            if let Some(id) = policy.id.clone() {
                chain.push(id);
            }

            for and_id in and_vec {
                if chain.contains(&and_id) {
                    log::warn!("Cyclic 'and' reference to policy '{}' detected; treating as failure.", and_id);
                    matches = false;
                    break;
                }

                let and_policy = match get_policy(and_id.clone()).await {
                    Some(and_policy) => and_policy,
                    None => {
                        log::warn!("Policy '{}' referenced in 'and' does not exist; treating as failure.", and_id);
                        matches = false;
                        break;
                    }
                };

                // Box::pin because matches_policy_chain is recursive and async.
                let and_matches = Box::pin(matches_policy_chain(and_policy, user.clone(), _ip.clone(), chain.clone())).await;
                if and_matches.unwrap_or(false) == false {
                    matches = false;
                    break;
                }
            }
        }
    }

    // If matches = true, the user will be authorised. This means they haven't failed any policies.

    Ok(matches)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(id: &str, and: Option<Vec<&str>>) -> (String, GuardPolicy) {
        (
            id.to_string(),
            GuardPolicy {
                active: true,
                id: Some(id.to_string()),
                action: "allow".to_string(),
                alias: None,
                property: "email".to_string(),
                starts_with: None,
                ends_with: None,
                not: None,
                is: None,
                and: and.map(|ids| ids.into_iter().map(str::to_string).collect()),
            },
        )
    }

    fn defined(policies: Vec<(String, GuardPolicy)>) -> HashMap<String, GuardPolicy> {
        policies.into_iter().collect()
    }

    #[test]
    fn intact_config_passes() {
        let policies = defined(vec![policy("staff_only", None), policy("au_only", None)]);
        let references = vec![
            ("hostname 'a.example.com'".to_string(), "staff_only".to_string()),
            ("[wireguard].applied_policies".to_string(), "au_only".to_string()),
        ];
        assert!(check_policy_references(&policies, &references).is_ok());
    }

    #[test]
    fn undefined_reference_is_reported_with_its_source() {
        let policies = defined(vec![policy("staff_only", None)]);
        let references = vec![("hostname 'a.example.com'".to_string(), "staff_onl".to_string())];
        let error = check_policy_references(&policies, &references).unwrap_err();
        assert!(error.contains("staff_onl"), "{}", error);
        assert!(error.contains("hostname 'a.example.com'"), "{}", error);
    }

    #[test]
    fn every_problem_is_reported_in_one_pass() {
        // A config with several typos should take one fix cycle, not three.
        let policies = defined(vec![policy("staff_only", None)]);
        let references = vec![
            ("hostname 'a.example.com'".to_string(), "typo_one".to_string()),
            ("hostname 'b.example.com'".to_string(), "typo_two".to_string()),
            ("[device_authentication].applied_policies".to_string(), "typo_three".to_string()),
        ];
        let error = check_policy_references(&policies, &references).unwrap_err();
        assert!(error.contains("typo_one"), "{}", error);
        assert!(error.contains("typo_two"), "{}", error);
        assert!(error.contains("typo_three"), "{}", error);
    }

    #[test]
    fn duplicate_problems_are_reported_once() {
        let policies = defined(vec![]);
        let references = vec![
            ("hostname 'a.example.com'".to_string(), "missing".to_string()),
            ("hostname 'a.example.com'".to_string(), "missing".to_string()),
        ];
        let error = check_policy_references(&policies, &references).unwrap_err();
        assert_eq!(error.matches("references undefined policy 'missing'").count(), 1, "{}", error);
    }

    #[test]
    fn dangling_and_reference_is_reported() {
        let policies = defined(vec![policy("staff_only", Some(vec!["nonexistent"]))]);
        let references = vec![("policy 'staff_only' ('and')".to_string(), "nonexistent".to_string())];
        let error = check_policy_references(&policies, &references).unwrap_err();
        assert!(error.contains("nonexistent"), "{}", error);
    }

    #[test]
    fn direct_and_cycle_is_detected() {
        let policies = defined(vec![policy("a", Some(vec!["b"])), policy("b", Some(vec!["a"]))]);
        let error = check_policy_references(&policies, &[]).unwrap_err();
        assert!(error.contains("cyclic 'and' reference"), "{}", error);
    }

    #[test]
    fn indirect_and_cycle_is_detected() {
        let policies = defined(vec![
            policy("a", Some(vec!["b"])),
            policy("b", Some(vec!["c"])),
            policy("c", Some(vec!["a"])),
        ]);
        let error = check_policy_references(&policies, &[]).unwrap_err();
        assert!(error.contains("cyclic 'and' reference"), "{}", error);
    }

    #[test]
    fn a_shared_and_target_is_not_a_cycle() {
        // Two policies both requiring the same third is a diamond, not a loop.
        let policies = defined(vec![
            policy("a", Some(vec!["shared"])),
            policy("b", Some(vec!["shared"])),
            policy("shared", None),
        ]);
        assert!(check_policy_references(&policies, &[]).is_ok());
    }
}
