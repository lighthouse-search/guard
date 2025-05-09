use serde::{Serialize, Deserialize};
use serde_json::{Value, json};

use rocket::response::status;
use rocket::http::Status;

use diesel::sql_query;
use diesel::prelude::*;
use diesel::sql_types::*;

use crate::global::{ send_email, generate_longer_random_id, get_epoch };
use crate::responses::*;
use crate::structs::*;
use crate::tables::*;
use crate::users::{user_get_otherwise_create};
use hades_auth::*;
use std::error::Error;
use std::net::SocketAddr;

use url::Url;

use crate::{CONFIG_VALUE, SQL_TABLES};

// Some authenticatiom methods, such as email, require action before the user can present credentials to authenticate. This is where that logic is kept.

pub async fn request_email(email: String, authentication_method: AuthMethod, request_data: Magiclink_request_data, remote_addr: SocketAddr, host: Guarded_Hostname) -> Result<(Request_magiclink), Box<dyn Error>> {
    let mut db: diesel::r2d2::PooledConnection<diesel::r2d2::ConnectionManager<MysqlConnection>> = crate::DB_POOL.get().expect("Failed to get a connection from the pool.");
    let sql: Config_sql_tables = (&*SQL_TABLES).clone();

    // Here, we're checking the email is authorized. If the email is authorized but no user account exists, this function will automatically create a user.
    let (user_result) = user_get_otherwise_create(host.clone(), email.clone(), remote_addr.clone()).await.expect("Failed to get or otherwise create user.");

    if (user_result.is_none()) {
        // Because the user_get_otherwise_create will always return a user (after all, it's creating a user if it doesn't exist), a None result means the user is unauthorized and we will not create one.
        return Ok((Request_magiclink {
            error_to_respond_to_client_with: Some(status::Custom(Status::BadRequest, error_message(&format!("Access denied - '{}' is not an authorized email", email)))),
            email: None,
        }));
    }

    let user = user_result.unwrap();
    let email = user.email;

    let code = generate_longer_random_id();

    let state: Option<String> = request_data.state;

    let params: Value = json!({
        "authentication_method": authentication_method.id,
        "magiclink_code": code,
        "redirect": format!("https://{}", host.host),
        "state": state.unwrap_or("none".to_string())
    });

    let output_params = serde_urlencoded::to_string(params).expect("Failed to encode URL parameters");

    let frontend_metadata: Frontend_metadata = CONFIG_VALUE.clone().frontend.and_then(|f| f.metadata).expect("Failed to parse");

    let mut url = Url::parse(&format!("https://example.com/guard/frontend/magiclink?{}", output_params)).unwrap();
    // Update the hostname
    url.set_host(Some(&frontend_metadata.instance_hostname.expect("Missing instance_hostname"))).unwrap();

    // FUTURE: Magiclink codes should be encrypted (via a public-key), so if you get access to the SQL database, it's not possible to use magiclink codes you find via the DB....but it would still be possible to update the account email address if you had access, which is why this is "future".
    let query = format!("INSERT INTO {} (user_id, code, ip, authentication_method, created) VALUES (?, ?, ?, ?, ?)", sql.magiclink.unwrap());
    let result = sql_query(query)
    .bind::<Text, _>(user.id.clone())
    .bind::<Text, _>(code.clone())
    .bind::<Text, _>(remote_addr.ip().to_string())
    .bind::<Text, _>(authentication_method.id.expect("Missing authentication method in magiclink").clone())
    .bind::<BigInt, _>(get_epoch())
    .execute(&mut db)
    .expect("Something went wrong querying the DB.");

    // TODO: Add custom magiclink message option via config.
    send_email(email.clone(), "Your MagicLink".to_string(), format!("Do not share this with anyone. This code serves no purpose except logging you into your account. If you didn't request this code, you can safely ignore this.\n\nThis MagicLink expires within 10 minutes of requesting it.\n\n{}", url.as_str())).await.expect("Failed to send email");

    Ok((Request_magiclink {
        error_to_respond_to_client_with: None,
        email: Some(email),
    }))
}