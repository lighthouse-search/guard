use serde::{Serialize, Deserialize};
use serde_json::{Value, json};

use std::collections::HashMap;

use rocket::response::status::Custom;

use crate::diesel_mysql::*;
use crate::tables::*;

use diesel::prelude::*;
use crate::tables::*;
use diesel::r2d2::{self, ConnectionManager};

type DbPool = r2d2::Pool<ConnectionManager<MysqlConnection>>;

// Incoming body structs
#[derive(Clone, Debug, Deserialize)]
pub struct Method_request_body {
    pub authentication_method: String,
    pub request_data: Value
}

#[derive(Clone, Debug, Deserialize)]
pub struct Authenticate_Body {
    pub attempt_id: String,
    pub code: Option<i64>,
    pub public_key: String
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct System_users {
    pub username: String,
    pub is_admin: bool,
    pub permissions: String
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Device_startup_struct {
    pub os_type: String,
    pub os_version: Option<i64>,
    pub alias: Option<i64>,
    pub users: Vec<System_users>,
    pub rover_permissions: Vec<String>
}

#[derive(Debug, Clone, Deserialize, Serialize, Queryable, Insertable, Selectable, QueryableByName)]
#[diesel(table_name = guard_user)]
pub struct Guard_user {
    pub id: String,
    pub email: String
}

#[derive(Debug, Clone, Deserialize, Serialize, Queryable, Insertable, Selectable, QueryableByName)]
#[diesel(table_name = magiclinks)]
pub struct Magiclink {
    pub user_id: String,
    pub code: String,
    pub ip: String,
    pub authentication_method: String,
    pub created: Option<i64>
}

#[derive(Debug, Clone, Deserialize, Serialize, Queryable, Insertable, Selectable, QueryableByName)]
#[diesel(table_name = guard_devices)]
pub struct Guard_devices {
    // #[serde(skip_deserializing)]
    pub id: String,
    pub user_id: String,
    pub authentication_method: String,
    pub collateral: Option<String>,
    pub public_key: String,
    pub created: Option<i64>
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Essential_authenticate_request_data {
    pub public_key: String
}

// #[derive(Debug, Clone, Deserialize, Serialize, Queryable, Insertable, Selectable)]
// #[diesel(table_name = magiclinks)]
// pub struct Magiclink {
//     #[serde(skip_deserializing)]
//     pub account_id: String,
//     pub created: Option<i64>,
//     pub ip: String,
//     pub code: String
// }

// Internal structs
#[derive(Debug)]
pub struct Query_string(pub String);

pub struct Request_authentication_output {
    // #[derive(Clone, Debug, Deserialize)]
    pub user_id: String,
    pub device_id: String
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Frontend_metadata {
    pub instance_hostname: Option<String>,
    pub alias: Option<String>,
    pub public_description: Option<String>,
    pub logo: Option<String>,
    pub image: Option<String>,
    pub motd_banner: Option<String>,
    pub background_colour: Option<String>,
    pub domain_placeholder: Option<String>,
    pub username_placeholder: Option<String>,
    pub style: Option<String>
}

impl Default for Frontend_metadata {
    fn default() -> Self {
        Frontend_metadata {
            instance_hostname: None,
            alias: None,
            public_description: None,
            logo: None,
            image: None,
            motd_banner: None,
            background_colour: None,
            domain_placeholder: None,
            username_placeholder: None,
            style: Some("login_1".to_string()),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthMethod {
    pub active: bool,
    pub id: Option<String>,
    pub alias: Option<String>,
    pub icon: Option<String>,
    pub method_type: String,
    pub login_page: String,
    // pub applied_policies: Vec<String>,
    pub ratelimit: u32,
    pub ratelimit_cooldown: u32,
    pub should_create_new_users: Option<bool>,
    pub user_info_reference_type: Option<String>,
    pub user_info_reference_key: Option<String>,
    pub oauth_api: Option<String>,
    pub oauth_user_info: Option<String>,
    pub oauth_user_info_id: Option<String>,
    pub oauth_token_endpoint: Option<String>,
    // pub oauth_token_endpoint_redirect_uri: Option<String>,
    // pub oauth_scope: Option<String>,
    pub oauth_client_id: Option<String>,
    pub oauth_client_secret_env: Option<String>
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthMethod_Public {
    pub active: bool,
    pub id: Option<String>,
    pub alias: Option<String>,
    pub icon: Option<String>,
    pub method_type: String,
    pub login_page: String
}

impl From<AuthMethod> for AuthMethod_Public {
    fn from(auth_method: AuthMethod) -> Self {
        AuthMethod_Public {
            active: auth_method.active,
            id: auth_method.id,
            alias: auth_method.alias,
            icon: auth_method.icon,
            method_type: auth_method.method_type,
            login_page: auth_method.login_page,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Oauth_code_access_exchange_response {
    pub access_token: Option<String>,
    pub token_type: Option<String>,
    pub expires_in: Option<i64>,
    pub scope: Option<String>,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Guarded_Hostname {
    pub active: bool,
    pub host: String,
    pub authentication_methods: Vec<String>,
    pub multistep_authentication_methods: bool,
    pub applied_policies: Vec<String>,
    pub alias: Option<String>,
    pub public_description: Option<String>,
    pub logo: Option<String>,
    pub image: Option<String>,
    pub motd_banner: Option<String>,
    pub background_colour: Option<String>,
    pub domain_placeholder: Option<String>,
    pub username_placeholder: Option<String>,
    pub style: Option<String>
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Guarded_Hostname_Pub {
    pub host: String,
    pub alias: Option<String>,
    pub public_description: Option<String>,
    pub logo: Option<String>,
    pub image: Option<String>,
    pub motd_banner: Option<String>,
    pub background_colour: Option<String>,
    pub domain_placeholder: Option<String>,
    pub username_placeholder: Option<String>
}

impl From<Guarded_Hostname> for Guarded_Hostname_Pub {
    fn from(hostname: Guarded_Hostname) -> Self {
        Guarded_Hostname_Pub {
            host: hostname.host,
            alias: hostname.alias,
            public_description: hostname.public_description,
            logo: hostname.logo,
            image: hostname.image,
            motd_banner: hostname.motd_banner,
            background_colour: hostname.background_colour,
            domain_placeholder: hostname.domain_placeholder,
            username_placeholder: hostname.username_placeholder
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Guard_Policy {
    pub active: bool,
    pub id: Option<String>,
    pub action: String,
    pub alias: Option<String>,
    pub property: String,
    pub starts_with: Option<String>,
    pub ends_with: Option<String>,
    pub not: Option<Vec<String>>,
    pub is: Option<Vec<String>>,
}

pub struct Handling_magiclink {
    pub error_to_respond_to_client_with: Option<Custom<Value>>,
    pub magiclink: Option<Magiclink>,
    pub user: Option<Guard_user>
}

pub struct Request_magiclink {
    pub error_to_respond_to_client_with: Option<Custom<Value>>,
    pub email: Option<String>
}

pub struct User_create {
    pub user_id: String
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Magiclink_request_data {
    pub email: Option<String>,
    pub state: Option<String>
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Magiclink_handling_data {
    pub code: Option<String>,
    pub referer: Option<String>
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OAuth_authentication_data {
    pub bearer_token: String
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Oauth_handling_data {
    pub authorization_code: Option<String>
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config_reverse_proxy_authentication_config {
    pub header: Option<String>
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config_sql {
    pub user: Option<String>,
    pub device: Option<String>,
    pub magiclink: Option<String>
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config_database_mysql {
    pub username: Option<String>,
    pub password_env: Option<String>,
    pub hostname: Option<String>,
    pub port: Option<i64>,
    pub database: Option<String>
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config_smtp {
    pub host: Option<String>,
    pub port: Option<i64>,
    pub username: Option<String>,
    pub from_alias: Option<String>,
    pub from_header: Option<String>,
    pub reply_to_address: Option<String>,
    pub password_env: Option<String>
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthMethod_sql {
    pub table: Option<String>
    // pub column: Option<String>
}

pub struct Headers {
    pub headers_map: HashMap<String, String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct User_get_id_preference_struct {
    pub has_value: bool,
    pub id: Option<String>,
    pub email: Option<String>
}

// #[derive(Debug, Clone, Deserialize, Serialize)]
// pub struct Signed_data {
//     pub authentication_method: bool,
//     pub value: Option<String>,
//     pub email: Option<String>
// }

// The cookie data the user provides.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Guard_authentication_metadata_cookie {
    pub authentication_method: Option<String>,
}

// The fetched Guard authentication metadata after the server receives the original cookie and gets all the relevant information.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Guard_authentication_metadata {
    pub authentication_method: Option<AuthMethod>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OAuth_login_url_information {
    pub redirect_uri: Option<String>,
    pub scope: Option<String>
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Get_current_valid_hostname_struct {
    pub hostname: Guarded_Hostname,
    pub domain_port: String,
    pub original_url: String
}