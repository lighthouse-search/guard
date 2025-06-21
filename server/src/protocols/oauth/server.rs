use rand::{distributions::Alphanumeric, Rng, thread_rng};
use argon2::{password_hash::{rand_core::OsRng, SaltString}, PasswordHasher};
use base64::{Engine as _, engine::general_purpose};

use crate::structs::*;