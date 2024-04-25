use serde::{Serialize, Deserialize};
use serde_json::{Value, json};

use rocket_db_pools::{Database, Connection};
use rocket_db_pools::diesel::{MysqlPool, prelude::*};
use rocket::response::status;
use rocket::http::Status;
use diesel::sql_query;

use diesel::prelude::*;
use diesel::sql_types::*;

use crate::global::{ send_email, generate_longer_random_id, get_epoch };
use crate::responses::*;
use crate::structs::*;
use crate::tables::*;
use hades_auth::*;
use std::error::Error;
use std::net::SocketAddr;

use url::Url;

use crate::{CONFIG_VALUE, SQL_TABLES};

// Some authenticatiom methods, such as email require action (such as sending a magiclink) before the user can present credentials to authenticate. This is where that logic is kept.

pub async fn request_email(mut db: Connection<Db>, email: String, authentication_method: AuthMethod, remote_addr: SocketAddr, host: Guarded_Hostname) -> Result<(Request_magiclink, Connection<Db>), Box<dyn Error>> {
    let sql: Config_sql = (&*SQL_TABLES).clone();

    // TODO: This needs to be get_user.

    // TODO: Add fail conditions from config, such as if the account is suspended. Like values that if true then we should fail.
    let query = format!("SELECT id, email FROM {} WHERE email=LOWER(?)", sql.users_table.unwrap());
    let result: Vec<Guard_user> = sql_query(query)
        .bind::<Text, _>(email)
        // .bind::<Text, _>(json!({"hm":"true"}))
        .load::<Guard_user>(&mut db)
        .await
        .expect("Something went wrong querying the DB.");

    if (result.len() == 0) {
        // User not found.
        return Ok((Request_magiclink {
            error_to_respond_to_client_with: Some(status::Custom(Status::BadRequest, error_message("User not found."))),
            email: None,
        }, db));
    }

    let user = result[0].clone();
    let email = user.email;

    let code = generate_longer_random_id();

    let params: Value = json!({
        "authentication_method": authentication_method.id,
        "code": code,
        "host": host.hostname
    });

    let output_params = serde_urlencoded::to_string(params).expect("Failed to encode URL parameters");

    let metadata_json = serde_json::to_string(&CONFIG_VALUE["frontend"]["metadata"]).expect("Failed to serialize");
    let frontend_metadata: Frontend_metadata = serde_json::from_str(&metadata_json).expect("Failed to parse");

    let mut url = Url::parse(&format!("https://example.com/frontend/magiclink?{}", output_params)).unwrap();
    // Update the hostname
    url.set_host(Some(&frontend_metadata.instance_hostname.expect("Missing instance_hostname"))).unwrap();

    // TODO: Add custom magiclink message option via config.
    send_email(email.clone(), "Your MagicLink".to_string(), format!("Do not share this with anyone. This code serves no purpose except logging you into your account. If you didn't request this code, you can safely ignore this.\n\n{}", url.as_str())).await.expect("Failed to send email");

    // FUTURE: Magiclink codes should be encrypted (via a public-key), so if you get access to the SQL database, it's not possible to use magiclink codes you find via the DB....but it would still be possible to update the account email address if you had access, which is why this is "future".
    let query = format!("INSERT INTO {} (user_id, code, ip, authentication_method, created) VALUES (?, ?, ?, ?, ?)", sql.magiclink_table.unwrap());
    let result = sql_query(query)
    .bind::<Text, _>(user.id.clone())
    .bind::<Text, _>(code.clone())
    .bind::<Text, _>(remote_addr.ip().to_string())
    .bind::<Text, _>(authentication_method.id.expect("Missing authentication method in magiclink").clone())
    .bind::<BigInt, _>(get_epoch())
    .execute(&mut db)
    .await
    .expect("Something went wrong querying the DB.");

    Ok((Request_magiclink {
        error_to_respond_to_client_with: None,
        email: Some(email),
    }, db))
}