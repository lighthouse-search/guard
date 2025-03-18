use serde::{Serialize, Deserialize};
use serde_json::{Value, json};

use rocket::request::{self, Request, FromRequest};
use rocket::response::{Debug, status::Created};
use rocket::{fairing::{Fairing, Info, Kind}, State};

use std::borrow::{Borrow, BorrowMut};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use std::fs::{File};
use crate::global::{ send_email, generate_random_id, is_null_or_whitespace };
use core::sync::atomic::{AtomicUsize, Ordering};

type Result<T, E = Debug<diesel::result::Error>> = std::result::Result<T, E>;

diesel::table! {
    guard_user (email) {
        id -> Text,
        email -> Text
    }
}

diesel::table! {
    guard_devices (id) {
        id -> Text,
        user_id -> Text,
        authentication_method -> Text,
        collateral -> Nullable<Text>,
        public_key -> Text,
        created -> Nullable<BigInt>
    }
}

diesel::table! {
    magiclinks (code) {
        user_id -> Text,
        code -> Text,
        ip -> Text,
        authentication_method -> Text,
        created -> Nullable<BigInt>
    }
}

diesel::table! {
    bearer_token (access_token_hash) {
        access_token_hash -> Text,
        access_token_salt -> Text,
        refresh_token_hash -> Text,
        refresh_token_salt -> Text,
        user_id -> Text,
        application_clientid -> Text,
        nonce -> Text,
        created -> Nullable<BigInt>
    }
}