use std::collections::HashMap;

use serde::{Serialize, Deserialize};
use serde_json::Value;

use crate::tables::*;
use diesel::prelude::*;

use rocket::response::status::Custom;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub features: Option<ConfigFeatures>,
    pub reverse_proxy_authentication: Option<ConfigReverseProxyAuthentication>,
    // pub tls: Option<HashMap<String, TlsHost>>,
    pub tls: Option<TlsHost>,
    pub frontend: Option<ConfigFrontend>,
    pub database: Option<ConfigDatabase>,
    pub sql: Option<ConfigSql>,
    pub smtp: Option<ConfigSmtp>,
    pub captcha: Option<ConfigCaptcha>,
    pub authentication_methods: Option<HashMap<String, AuthMethod>>,
    pub policies: Option<HashMap<String, GuardPolicy>>,
    pub hostname: Option<HashMap<String, GuardedHostname>>
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConfigFeatures {
    pub reverse_proxy_authentication: Option<bool>,
    pub oauth_server: Option<bool>,
    pub tls: Option<bool>
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConfigReverseProxyAuthentication {
    pub config: Option<ConfigReverseProxyAuthenticationConfig>
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConfigReverseProxyAuthenticationConfig {
    pub header: Option<String>
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConfigFrontend {
    pub metadata: Option<FrontendMetadata>
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConfigDatabase {
    pub mysql: Option<ConfigDatabaseMysql>
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConfigDatabaseMysql {
    pub username: Option<String>,
    pub password_env: Option<String>,
    pub hostname: Option<String>,
    pub port: Option<u16>,
    pub database: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConfigSql {
    pub tables: Option<Value>
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConfigSqlTables {
    pub user: Option<String>,
    pub device: Option<String>,
    pub magiclink: Option<String>,
    pub bearer_token: Option<String>
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConfigSmtp {
    pub host: Option<String>,
    pub port: Option<u16>,
    pub username: Option<String>,
    pub from_alias: Option<String>,
    pub from_header: Option<String>,
    pub reply_to_address: Option<String>,
    pub password_env: Option<String>
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConfigCaptcha {
    pub hcaptcha: Option<HashMap<String, ConfigCaptchaHcaptcha>>
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConfigCaptchaHcaptcha {
    pub site_key: Option<String>,
    pub hcaptcha_secret_env: Option<String>,
    pub size: Option<String>
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TlsHost {
    pub certificate: Option<String>,
    // pub hostname: String,

    #[serde(rename = "private-key")]
    pub private_key: Option<String>,
}

// Incoming body structs
#[derive(Clone, Debug, Deserialize)]
pub struct MethodRequestBody {
    pub authentication_method: String,
    pub request_data: Value
}

#[derive(Debug, Clone, Deserialize, Serialize, Queryable, Insertable, Selectable, QueryableByName)]
#[diesel(table_name = guard_user)]
pub struct GuardUser {
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
pub struct GuardDevices {
    // #[serde(skip_deserializing)]
    pub id: String,
    pub user_id: String,
    pub authentication_method: String,
    pub collateral: Option<String>,
    pub public_key: String,
    pub created: Option<i64>
}

#[derive(Debug, Clone, Deserialize, Serialize, Queryable, Insertable, Selectable, QueryableByName)]
#[diesel(table_name = bearer_token)]
pub struct BearerToken {
    pub access_token_hash: String,
    pub access_token_salt: String,
    pub refresh_token_hash: String,
    pub refresh_token_salt: String,
    pub user_id: String,
    pub application_clientid: String,
    pub nonce: String,
    pub created: Option<i64>
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VerifyBearerTokenOutput {
    pub user_id: String,
    pub application_clientid: String,
    pub scope: Vec<String>
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VerifyBearerTokenHashOutput {
    pub user_id: String,
    pub application_clientid: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EssentialAuthenticateRequestData {
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
pub struct QueryString(pub String);

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FrontendMetadata {
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

impl Default for FrontendMetadata {
    fn default() -> Self {
        FrontendMetadata {
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
    // pub user_info_reference_type: Option<String>,
    // pub user_info_reference_key: Option<String>,
    pub oauth_client_api: Option<String>,
    pub oauth_client_user_info: Option<String>,
    pub oauth_client_user_info_id: Option<String>,
    pub oauth_client_token_endpoint: Option<String>,
    // pub oauth_token_endpoint_redirect_uri: Option<String>,
    // pub oauth_scope: Option<String>,
    pub oauth_client_id: Option<String>,
    pub oauth_client_secret_env: Option<String>
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthMethodPublic {
    pub active: bool,
    pub id: Option<String>,
    pub alias: Option<String>,
    pub icon: Option<String>,
    pub method_type: String,
    pub login_page: String
}

impl From<AuthMethod> for AuthMethodPublic {
    fn from(auth_method: AuthMethod) -> Self {
        AuthMethodPublic {
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
pub struct OauthCodeAccessExchangeResponse {
    pub access_token: Option<String>,
    pub token_type: Option<String>,
    pub expires_in: Option<i64>,
    pub scope: Option<String>,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GuardedHostname {
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
pub struct GuardedHostnamePub {
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

impl From<GuardedHostname> for GuardedHostnamePub {
    fn from(hostname: GuardedHostname) -> Self {
        GuardedHostnamePub {
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
pub struct GuardPolicy {
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

pub struct HandlingMagiclink {
    pub error_to_respond_to_client_with: Option<Custom<Value>>,
    pub magiclink: Option<Magiclink>,
    pub user: Option<GuardUser>
}

pub struct RequestMagiclink {
    pub error_to_respond_to_client_with: Option<Custom<Value>>,
    pub _email: Option<String>
}

pub struct UserCreate {
    pub user_id: String
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MagiclinkRequestData {
    pub email: Option<String>,
    pub state: Option<String>
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MagiclinkHandlingData {
    pub code: Option<String>,
    pub referer: Option<String>
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OauthAuthenticationData {
    pub bearer_token: String
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OauthHandlingData {
    pub authorization_code: Option<String>
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthMethodSql {
    pub table: Option<String>
    // pub column: Option<String>
}

pub struct Headers {
    pub headers_map: HashMap<String, String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UserGetIdPreferenceStruct {
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
pub struct GuardAuthenticationMetadataCookie {
    pub authentication_method: Option<String>,
}

// The fetched Guard authentication metadata after the server receives the original cookie and gets all the relevant information.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GuardAuthenticationMetadata {
    pub unverified_authentication_method: Option<AuthMethod>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OauthLoginUrlInformation {
    pub redirect_uri: Option<String>,
    pub scope: Option<String>
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GetCurrentValidHostnameStruct {
    pub hostname: GuardedHostname,
    pub domain_port: String,
    pub original_url: String
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OauthServerTokenInternals {
    pub random: String,
    pub scope: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OauthServerTokenCode {
    pub client_id: Option<String>,
    pub scope: Option<String>,
    pub redirect_uri: Option<String>,
    pub grant_type: Option<String>,
    pub nonce: Option<String>
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TokenCreate {
    pub hash: String,
    pub salt: String
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CreatedAccessAndRefreshTokens {
    pub access_token: TokenCreate,
    pub refresh_token: TokenCreate
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TlsCertificate {
    pub private_key: String,
    pub certificate: String
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProtocolDecisionToPipelineOutput {
    pub user: Option<Value>,
    pub device: Option<GuardDevices>,
    pub authentication_method: Option<AuthMethod>, // The authentication method, e.g. "email", "oauth"
    pub authentication_type: String // The underlying authentication technology, e.g. "signed_request", "static_auth", "bearer_token"
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ErrorResponse {
    pub error: bool,
    pub message: String
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OauthPipelineResponse {
    pub external_user: Value
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DevicePipelineStaticAuthResponse {
    pub user: Option<GuardUser>,
    pub device: Option<GuardDevices>,
    pub authentication_method: Option<AuthMethod>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserAuthenticationPipelineResponse {
    pub user: Option<Value>,
    pub device: Option<GuardDevices>,
    pub authentication_method: Option<AuthMethod>,
    pub authentication_type: String
}