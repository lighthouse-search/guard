//! Guard instance discovery and device-authentication launch.
//!
//! Flow:
//!   1. The user enters their email. We derive candidate domains from it
//!      (the full mail domain and its registrable root) and probe DNS for a
//!      `guard.<domain>` record — that subdomain points at the org's Guard
//!      instance. See [`discover_guard_instance`].
//!   2. We open the system browser at the instance's device-authenticate page
//!      with a random `state`. See [`start_device_authentication`].
//!   3. The web page finishes auth and deep-links credentials back to the app
//!      via the `guard://` scheme; that is handled in `lib.rs`.

use serde::Serialize;
use tauri::AppHandle;
use tauri_plugin_opener::OpenerExt;

/// The `guard.<domain>` label we probe for. Change this if your convention
/// differs (e.g. a TXT record or a different subdomain).
const GUARD_SUBDOMAIN: &str = "guard";

#[derive(Serialize, Clone)]
pub struct GuardInstance {
    /// Hostname that resolved, e.g. `guard.example.com`.
    pub host: String,
    /// The email's mail domain, e.g. `mail.example.com`.
    pub email_domain: String,
}

#[derive(Serialize, Clone)]
pub struct DeviceAuthStart {
    /// Opaque value echoed back on the deep-link callback to prevent
    /// cross-session mix-ups.
    pub state: String,
    /// The URL that was opened in the browser.
    pub url: String,
}

/// Candidate base domains to probe, most-specific first:
/// `mail.example.com` then its registrable root `example.com`.
fn candidate_domains(email: &str) -> Result<Vec<String>, String> {
    let domain = email
        .split('@')
        .nth(1)
        .map(|d| d.trim().to_lowercase())
        .filter(|d| !d.is_empty() && d.contains('.'))
        .ok_or_else(|| "Enter a valid email address.".to_string())?;

    let mut domains = vec![domain.clone()];
    // Registrable domain via the Public Suffix List (handles multi-part TLDs
    // like example.co.uk correctly).
    if let Some(root) = psl::domain_str(&domain) {
        if root != domain {
            domains.push(root.to_string());
        }
    }
    Ok(domains)
}

/// Resolve the org's Guard instance by probing `guard.<domain>` for each
/// candidate domain. A CNAME or A record (anything that resolves to an IP)
/// counts as a hit.
#[tauri::command]
pub async fn discover_guard_instance(email: String) -> Result<GuardInstance, String> {
    use hickory_resolver::config::{ResolverConfig, ResolverOpts};
    use hickory_resolver::TokioAsyncResolver;

    let domains = candidate_domains(&email)?;
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

    for base in &domains {
        let host = format!("{GUARD_SUBDOMAIN}.{base}");
        if let Ok(lookup) = resolver.lookup_ip(host.clone()).await {
            if lookup.iter().next().is_some() {
                return Ok(GuardInstance {
                    host,
                    email_domain: domains[0].clone(),
                });
            }
        }
    }

    let probed = domains
        .iter()
        .map(|d| format!("{GUARD_SUBDOMAIN}.{d}"))
        .collect::<Vec<_>>()
        .join(", ");
    Err(format!(
        "No Guard instance found for {}. Checked: {probed}.",
        domains[0]
    ))
}

/// Open the browser at the instance's device-authenticate page and return the
/// `state` the caller should expect on the deep-link callback.
#[tauri::command]
pub async fn start_device_authentication(
    app: AppHandle,
    host: String,
) -> Result<DeviceAuthStart, String> {
    let state = uuid::Uuid::new_v4().to_string();
    let url =
        format!("https://{host}/guard/frontend/device-authenticate?state={state}");

    app.opener()
        .open_url(url.clone(), None::<&str>)
        .map_err(|e| format!("Could not open browser: {e}"))?;

    Ok(DeviceAuthStart { state, url })
}
