use rocket::{routes, options};
use rocket::fs::FileServer;
use rocket::fairing::AdHoc;

use crate::endpoints::auth::{auth_method_request, authenticate};
use crate::endpoints::metadata::{metadata_get, metadata_get_authentication_methods};
use crate::endpoints::reverse_proxy_authentication::{reverse_proxy_authentication_delete, reverse_proxy_authentication_get, reverse_proxy_authentication_head, reverse_proxy_authentication_options, reverse_proxy_authentication_patch, reverse_proxy_authentication_post, reverse_proxy_authentication_put};
use crate::protocols::oauth::endpoint::client::oauth_exchange_code;
use crate::protocols::oauth::endpoint::server::{oauth_server_token};
use crate::CONFIG_VALUE;

use crate::hostname::get_current_valid_hostname;
use crate::structs::*;
use crate::responses::*;

use std::collections::HashMap;
use std::env;
use std::path::PathBuf;
pub struct Cors;