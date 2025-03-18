use guard_devices::authentication_method;
use reqwest::redirect;
use serde::{Serialize, Deserialize};
use serde_json::{Value, json};

use diesel::sql_query;
use diesel::prelude::*;
use diesel::sql_types::*;

use rocket::http::{Status, CookieJar, Cookie};

use crate::protocols::oauth::client::oauth_userinfo;
use crate::structs::*;
use crate::tables::*;
use crate::device::{device_signed_authentication, device_get, device_guard_static_auth_from_cookies};

use std::error::Error;
use std::net::SocketAddr;

use url::Url;
use std::collections::HashMap;

use crate::{CONFIG_VALUE, SQL_TABLES};

pub async fn oauth_pipeline(hostname: Guarded_Hostname, auth_method: AuthMethod, jar: &CookieJar<'_>, remote_addr: SocketAddr, headers: &Headers) -> Result<(bool, Option<Value>), Box<dyn Error>> {
    let mut bearer_token: String = String::new();

    if (headers.headers_map.get("Authorization").is_none() == false) {
        bearer_token = headers.headers_map.get("Authorization").expect("Missing Authorization header.").to_string();
    } else if (jar.get("guard_oauth_access_token").is_none() == false) {
        bearer_token = jar.get("guard_oauth_access_token").map(|c| c.value()).expect("Failed to parse guard_oauth_access_token.").to_string();
    } else {
        println!("Bearer token not provided by client.");
        return Ok((false, None));
    }

    let user_info_result = oauth_userinfo(auth_method.oauth_client_user_info.unwrap(), bearer_token).await;
    if (user_info_result.is_err() == true) {
        println!("Failed to get user-info");
        return Ok((false, None));
    }
    
    let attempted_external_user: Value = user_info_result.expect("Failed to get oauth userinfo.");

    return Ok((true, Some(attempted_external_user)));
}

pub fn oauth_get_data_from_oauth_login_url(url: String) -> OAuth_login_url_information {
    let url = Url::parse(&url).expect("Failed to parse URL");
    let query_pairs: HashMap<_, _> = url.query_pairs().into_owned().collect();

    let redirect_uri: String = query_pairs.get("redirect_uri").expect("Oauth login URL missing 'redirect_uri'").to_string();
    let scope: String = query_pairs.get("scope").expect("Oauth login URL missing 'scope'").to_string();

    return OAuth_login_url_information {
        redirect_uri: Some(redirect_uri),
        scope: Some(scope)
    }
}