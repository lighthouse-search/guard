//! One-time, short-lived device-enrollment setup tokens.
//!
//! When a user finishes device authentication in the browser, the server does
//! NOT trust a public key from the page (an attacker could preset it in a
//! phishing URL and have their own device enrolled under the victim). Instead
//! we issue a setup token bound to the authenticated user, deep-link it to the
//! desktop app, and the app posts *its own* public key together with the token
//! to `/guard/api/auth/device/enroll`.
//!
//! Tokens are single-use (removed on consume) and expire after
//! `SETUP_TOKEN_TTL_SECS`. Storage is in-memory: fine for a single Guard
//! process; a multi-instance deployment would need a shared store (DB/Redis).

use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::Mutex;

use crate::global::{generate_longer_random_id, get_epoch};

// get_epoch() is in milliseconds, so the TTL is too.
const SETUP_TOKEN_TTL_MS: i64 = 5 * 60 * 1000; // 5 minutes

struct PendingEnrollment {
    user_id: String,
    authentication_method: String,
    expires_at: i64,
}

static STORE: Lazy<Mutex<HashMap<String, PendingEnrollment>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Issue a setup token for an authenticated user. Returns the opaque token.
pub fn issue(user_id: String, authentication_method: String) -> String {
    let token = generate_longer_random_id();
    let now = get_epoch();

    let mut store = STORE.lock().expect("setup_token store poisoned");
    // Opportunistically drop expired tokens so the map can't grow unbounded.
    store.retain(|_, pending| pending.expires_at > now);
    store.insert(
        token.clone(),
        PendingEnrollment {
            user_id,
            authentication_method,
            expires_at: now + SETUP_TOKEN_TTL_MS,
        },
    );

    token
}

/// Validate and consume a setup token (single use). Returns
/// `(user_id, authentication_method)` if the token exists and is unexpired.
pub fn consume(token: &str) -> Option<(String, String)> {
    let now = get_epoch();
    let mut store = STORE.lock().expect("setup_token store poisoned");

    match store.remove(token) {
        Some(pending) if pending.expires_at > now => {
            Some((pending.user_id, pending.authentication_method))
        }
        _ => None,
    }
}
