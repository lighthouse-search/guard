use std::collections::HashMap;

use axum::response::Response;
use serde::{Serialize, Deserialize};
use serde_json::Value;

use crate::tables::*;
use diesel::prelude::*;

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
    pub hostname: Option<HashMap<String, GuardedHostname>>,
    // Devices authenticate generally (not per hostname), so their allowed
    // authentication methods and policies are configured here rather than under
    // a [hostname.*] entry.
    pub device_authentication: Option<ConfigDeviceAuthentication>,
    // WireGuard server Guard manages peers for. Optional — the wireguard
    // registration endpoint is only available when this is configured.
    pub wireguard: Option<ConfigWireguard>
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ConfigWireguard {
    // The WireGuard interface Guard applies peers to, e.g. "wg0". Guard must run
    // on this host with permission to run `wg`.
    pub interface: Option<String>,
    // CIDR the tunnel addresses of peers are allocated from, e.g. "10.8.0.0/24".
    // Guard hands out the next free host address (skipping `server_address`).
    pub peer_subnet: Option<String>,
    // The server's own tunnel address within `peer_subnet` (never handed out),
    // e.g. "10.8.0.1".
    pub server_address: Option<String>,
    // The UDP port the interface listens on. Defaults to 51820.
    pub listen_port: Option<u16>,
    // Where Guard stores the interface's generated private key. Defaults to
    // /etc/wireguard/<interface>.key. Guard generates it on first run and reuses
    // it thereafter, so the server public key stays stable across restarts.
    pub key_path: Option<String>,
    // Optional override for the server's WireGuard public key returned to
    // clients. Normally left unset — Guard derives it from the key it manages.
    pub server_public_key: Option<String>,
    // The public "host:port" clients dial to reach the WireGuard server, e.g.
    // "vpn.example.com:51820".
    pub endpoint: Option<String>,
    // What the client should route through the tunnel (its peer AllowedIPs).
    // Defaults to `peer_subnet` when unset — enough to reach the gateway and
    // other peers (split tunnel). Set to "0.0.0.0/0" for a full tunnel.
    pub allowed_ips: Option<String>,
    // Optional tunnel DNS + keepalive returned to clients for their config.
    pub dns: Option<String>,
    pub persistent_keepalive: Option<u32>,
    // CIDR the per-endpoint service addresses are allocated from. Never handed
    // out to peers; Guard answers on these addresses itself. Included in the
    // AllowedIPs returned to clients so the range routes into the tunnel.
    pub service_subnet: Option<String>,
    // Policies a device's user must satisfy to hold a WireGuard registration.
    // Falls back to [device_authentication].applied_policies when unset.
    // Evaluated at registration AND periodically thereafter, so revoking a
    // user's access tears their peer down rather than waiting for a reconnect.
    pub applied_policies: Option<Vec<String>>,
    // How often (seconds) every registered peer is re-checked against policy.
    // Defaults to 60.
    pub reevaluation_interval_secs: Option<u64>,
    // Run the tunnel DNS resolver on server_address:53. Defaults to true.
    pub dns_server: Option<bool>,
    // Where names Guard does not own are forwarded. Required in practice:
    // wg-quick's DNS= replaces the client's resolver, so without an upstream a
    // connected peer cannot resolve anything but Guard's own hostnames.
    pub dns_upstream: Option<Vec<String>>,
    // Port the tunnel resolver listens on. Defaults to 53.
    pub dns_port: Option<u16>,
    // Authenticate HTTP requests arriving over the tunnel from the source
    // address alone, skipping the login page. WireGuard only ever emits a
    // given tunnel address from the peer holding the matching private key, so
    // the address is a cryptographically attested device identity.
    //
    // Policies still apply — this replaces proving *who you are*, not the check
    // of whether you are allowed.
    //
    // DEFAULTS TO FALSE, and is opt-in deliberately. Everything else Guard does
    // with the source address is a *restriction*: wireguard_only refuses a
    // request, and a service proxy refuses a connection. Getting those wrong
    // fails towards "you still have to log in". This one is a *grant* — getting
    // it wrong is an authentication bypass — so it should not arrive as a side
    // effect of configuring WireGuard. Turn it on once you are satisfied that
    // arrival detection holds on your host (see wireguard::arrival_from, and
    // enable rp_filter).
    pub tunnel_identity: Option<bool>,
    // Services reachable over the tunnel that are not addressed by a Host
    // header — SSH, SMB, printing, databases. Each gets its own address from
    // service_subnet, which Guard listens on and proxies from.
    //
    // Named `service` rather than `endpoint` because `endpoint` above already
    // means the public host:port that clients dial to reach WireGuard itself.
    pub service: Option<HashMap<String, ConfigWireguardService>>,
    // Maximum simultaneous proxied connections across all endpoints.
    // Defaults to 512.
    pub max_connections: Option<usize>,
    // Maximum simultaneous proxied connections from any one device.
    // Defaults to 64.
    pub max_connections_per_device: Option<usize>,
    // Downstream WireGuard instances Guard routes through, keyed by name.
    // Each one puts the networks behind it within Guard's reach, so a
    // [hostname.*] proxy_to pointing into them resolves and connects.
    pub site: Option<HashMap<String, ConfigWireguardSite>>
}

// A downstream WireGuard peer with networks behind it — a home or branch
// instance Guard chains through.
//
// Unlike a device peer (one /32, dialled in), a site peer carries whole
// subnets and may sit behind NAT, dialling out to Guard and holding the tunnel
// open with a keepalive.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ConfigWireguardSite {
    #[serde(default = "default_true")]
    pub active: bool,
    // The site's WireGuard public key.
    pub public_key: Option<String>,
    // Networks reachable behind this site, e.g. ["10.0.1.0/24"]. These become
    // the peer's AllowedIPs, so they must not overlap peer_subnet or another
    // site: WireGuard routes by longest-prefix match across peers and the same
    // range cannot belong to two of them.
    pub subnets: Option<Vec<String>>,
    // Where to reach the site, if it has a stable address. Omit when the site
    // dials out to Guard (the usual case behind NAT).
    pub endpoint: Option<String>,
    // Seconds between keepalives. Needed when the site is behind NAT so the
    // mapping stays open. Defaults to 25 when `endpoint` is unset.
    pub persistent_keepalive: Option<u32>
}

fn default_true() -> bool {
    true
}

// A service reachable over the tunnel that cannot be addressed by a Host
// header. Guard gives it an address of its own, listens there, authorises the
// connecting device, and splices bytes to `destination`.
//
// Because the proxy never parses the payload, this works for any single
// -connection TCP protocol: SSH, SMB, IPP, Postgres, an HTTPS API you cannot
// set a Host on.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ConfigWireguardService {
    #[serde(default = "default_true")]
    pub active: bool,
    // What Guard dials, as "host:port". Same spirit as a hostname's proxy_to:
    // Guard connects to it, so a name resolvable from the Guard host is fine.
    pub destination: Option<String>,
    // Name the tunnel resolver answers for this endpoint. Optional; without it
    // the endpoint is reachable only by its service address.
    pub dns_name: Option<String>,
    // Pin the service address instead of letting Guard allocate one. Allocated
    // addresses are assigned in sorted endpoint-name order, so adding an
    // endpoint can shift later ones; pin any address you reference elsewhere.
    pub service_address: Option<String>,
    // Policies the connecting device's user must satisfy. As everywhere else,
    // an empty list denies.
    pub applied_policies: Option<Vec<String>>
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConfigDeviceAuthentication {
    pub authentication_methods: Option<Vec<String>>,
    pub applied_policies: Option<Vec<String>>
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConfigFeatures {
    pub proxy: Option<bool>,
    pub reverse_proxy_authentication: Option<bool>,
    pub oauth_server: Option<bool>,
    pub tls: Option<bool>,
    // Extra browser origins allowed to call the /guard/api endpoints cross-origin
    // (e.g. a separate frontend dev server). Same-origin production requests
    // don't need this. In debug builds localhost:8484 is allowed automatically.
    pub cors_allowed_origins: Option<Vec<String>>
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
    pub metadata: Option<FrontendMetadata>,
    pub media: Option<ConfigFrontendMedia>
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConfigFrontendMedia {
    pub folder: Option<String>
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
    pub created: Option<i64>,
    // At most one WireGuard public key per device (enforced at registration to
    // stop a device claiming multiple/forged peers). NULL until the device
    // registers a WireGuard key. `wireguard_ip` is its allocated tunnel address.
    pub wireguard_public_key: Option<String>,
    pub wireguard_ip: Option<String>
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
    pub login_page: Option<String>,
    // pub applied_policies: Vec<String>,
    pub ratelimit: Option<u32>,
    pub ratelimit_cooldown: Option<u32>,
    pub should_create_new_users: Option<bool>,
    // method_type = "mtls": PEM bundle of the certificate authorities whose
    // client certificates this method accepts. Every mtls method's CAs are
    // loaded into one trust store at startup, because rustls fixes the client
    // verifier per ServerConfig and cannot vary it per SNI — so verification is
    // offered to every connection and which hostnames *require* it is decided
    // per request.
    pub mtls_ca: Option<String>,
    // pub user_info_reference_type: Option<String>,
    // pub user_info_reference_key: Option<String>,
    pub oauth_client_api: Option<String>,
    pub oauth_client_user_info: Option<String>,
    // Which claim in the userinfo response carries the provider's stable user
    // id. Not standardised across providers, so it has to be configurable —
    // see oauth_user_id_from_userinfo in protocols/oauth/endpoint/client.rs.
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
    pub login_page: Option<String>
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
    pub proxy_to: Option<String>,
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
    pub style: Option<String>,
    // Refuse this hostname unless the request arrived over the WireGuard tunnel.
    // The service then has no public surface at all. Defaults to false.
    #[serde(default)]
    pub wireguard_only: Option<bool>,
    // Set false to exclude this hostname from the tunnel entirely (it stays
    // reachable publicly). Defaults to reachable over both.
    #[serde(default)]
    pub wireguard: Option<bool>
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
    pub and: Option<Vec<String>>,
}

pub struct HandlingMagiclink {
    pub error_to_respond_to_client_with: Option<Response>,
    pub magiclink: Option<Magiclink>,
    pub user: Option<GuardUser>
}

pub struct RequestMagiclink {
    pub error_to_respond_to_client_with: Option<Response>,
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

#[derive(Serialize, Clone, Debug)]
pub struct ErrorResponse {
    pub error: bool,
    pub message: String,
    pub code: i64
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