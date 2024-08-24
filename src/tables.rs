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