use diesel::sql_query;
use diesel::prelude::*;
use diesel::sql_types::*;

use rand::{distributions::Alphanumeric, Rng, thread_rng};
use argon2::{password_hash::{rand_core::OsRng, SaltString}, PasswordHasher};
use base64::{Engine as _, engine::general_purpose};

use crate::global::get_epoch;
use crate::structs::*;

use crate::SQL_TABLES;

pub fn generate_token_string(scope: Vec<String>) -> TokenCreate {
    let mut rng = thread_rng();

    // Generate a 128-character-long string consisting of [0-9, A-Z, a-z].
    let random: String = (0..128)
        .map(|_| rng.sample(Alphanumeric) as char)
        .collect();

    let token_internal = OauthServerTokenInternals {
        scope: scope.join(" "),
        random: random
    };
    let token_json: String = serde_json::to_string(&token_internal).unwrap();
    let token_string = general_purpose::STANDARD.encode(token_json.as_bytes());

    // OsRng OS's random number generator 
    let salt=SaltString::generate(OsRng);
    let argon2=argon2::Argon2::default();
    let password_hash=argon2.hash_password(token_string.as_bytes(), &salt).unwrap();

    return TokenCreate {
        hash: password_hash.hash.unwrap().to_string(),
        salt: password_hash.salt.unwrap().to_string()
    }
}

pub async fn insert_token(user_id: &str, access_token: TokenCreate, refresh_token: TokenCreate, application_clientid: &str, nonce: &str) -> Result<(), String> {
    let mut db = crate::DB_POOL.get().expect("Failed to get a connection from the pool.");
    let sql: ConfigSqlTables = (&*SQL_TABLES).clone();

    check_nonce(user_id, nonce).await.expect("Failed to check nonce.");

    let query = format!("INSERT INTO {} (access_token_hash, access_token_salt, refresh_token_hash, refresh_token_salt, user_id, application_clientid, nonce, created) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", sql.bearer_token.unwrap());
    sql_query(query)
    .bind::<Text, _>(access_token.hash.clone())
    .bind::<Text, _>(access_token.salt.clone())
    .bind::<Text, _>(refresh_token.hash.clone())
    .bind::<Text, _>(refresh_token.salt.clone())
    .bind::<Text, _>(user_id)
    .bind::<Text, _>(application_clientid)
    .bind::<Text, _>(nonce)
    .bind::<BigInt, _>(get_epoch())
    .execute(&mut db)
    .expect("Something went wrong querying the DB.");

    return Ok(());
}

pub async fn check_nonce(user_id: &str, nonce: &str) -> Result<(), String> {
    let mut db = crate::DB_POOL.get().expect("Failed to get a connection from the pool.");

    let sql: ConfigSqlTables = (&*SQL_TABLES).clone();
    let query = format!("SELECT * FROM {} WHERE user_id=? AND nonce=?", sql.bearer_token.unwrap());
    let result = sql_query(query)
    .bind::<Text, _>(user_id)
    .bind::<Text, _>(nonce)
    .load::<BearerToken>(&mut db)
    .expect("Something went wrong querying the DB.");

    if result.len() > 0 {
        return Err(String::from("params.code.nonce is already in-use. The client is trying to use the same params.code twice."));
    }

    return Ok(());
}

// pub async fn applications_clear(user_id: &str, application_clientid: &str) -> Result<(), String> {
//     let mut db = crate::DB_POOL.get().expect("Failed to get a connection from the pool.");

//     let sql: ConfigSqlTables = (&*SQL_TABLES).clone();
//     let query = format!("DELETE FROM {} WHERE user_id=? AND application_clientid=?", sql.bearer_token.unwrap());
//     sql_query(query)
//     .bind::<Text, _>(user_id.clone())
//     .bind::<Text, _>(application_clientid.clone())
//     .execute(&mut db)
//     .expect("Something went wrong querying the DB.");

//     return Ok(());
// }

pub async fn create_access_and_refresh_tokens(user_id: &str, application_clientid: &str, nonce: &str, scope: Vec<String>) -> CreatedAccessAndRefreshTokens {
    let access_token = generate_token_string(scope.clone());
    let refresh_token = generate_token_string(scope.clone());

    // We've generated tokens with a scope, let's insert them into the database.
    insert_token(user_id, access_token.clone(), refresh_token.clone(), application_clientid, nonce).await.expect("Failed to add bearer token to database");

    return CreatedAccessAndRefreshTokens {
        access_token: access_token,
        refresh_token: refresh_token
    }
}

pub async fn verify(bearer_token: &str, required_scopes: Vec<&str>) -> Result<VerifyBearerTokenOutput, String> {
    let _db = crate::DB_POOL.get().expect("Failed to get a connection from the pool.");

    // Check if there is a corresponding bearer token by hashing the input bearer_token value.
    let hash_verification = verify_hash(bearer_token).await.expect("Failed to verify bearer token hash");

    // The client has given us the unhashed bearer token value. We've verified it's integrity (as we have the original hash within the db), which means we can trust the data within it. Bearer tokens in Guard are helpfully base64-encoded json. Here, we'll unencode base64, get json and read the token's internals.
    let bearer_token_base64_decoded_bytes = general_purpose::STANDARD.decode(bearer_token).expect("Failed to decode token base64.");
    let bearer_token_base64_decoded_string = String::from_utf8(bearer_token_base64_decoded_bytes).expect("Failed to convert decoded bytes to string.");

    // Cool, now we have the token's internals.
    let token_internals: OauthServerTokenInternals = serde_json::from_str(&bearer_token_base64_decoded_string).expect("Failed to parse token internal json");

    // Let's verify the token's scope.
    let token_scope: Vec<&str> = token_internals.scope.split(" ").collect();
    let _scope_verification = verify_scope(required_scopes.clone(), token_scope.clone()).await.expect("Failed to verify scope.");

    return Ok(VerifyBearerTokenOutput {
        application_clientid: hash_verification.application_clientid,
        scope: token_scope.into_iter().map(|s| s.to_string()).collect(),
        user_id: hash_verification.user_id
    });
}

async fn verify_hash(bearer_token: &str) -> Result<VerifyBearerTokenHashOutput, String> {
    let mut db = crate::DB_POOL.get().expect("Failed to get a connection from the pool.");

    let sql: ConfigSqlTables = (&*SQL_TABLES).clone();
    let query = format!("SELECT * FROM {} WHERE access_token_hash=?", sql.bearer_token.unwrap());
    let result = sql_query(query)
    .bind::<Text, _>(bearer_token)
    .load::<BearerToken>(&mut db)
    .expect("Something went wrong querying the DB.");

    if result.len() == 0 {
        return Err(String::from("Bearer token not found."));
    }

    return Ok(VerifyBearerTokenHashOutput {
        application_clientid: result[0].application_clientid.clone(),
        user_id: result[0].user_id.clone(),
    });
}

// required_scope: What permissions an endpoint requires.
// token_scope: What permissions the token actually has.
async fn verify_scope(required_scopes: Vec<&str>, token_scope: Vec<&str>) -> Result<(), String> {
    let mut missing_scopes: Vec<&str> = Vec::new();

    for required_scope in required_scopes {
        // Check if scope is specified in token_scope.
        let scope_position = token_scope.iter().position(|s| s.to_owned() == required_scope);
        if scope_position.is_none() == true {
            // This token isn't valid for a required scope (the client is attempting an unauthorised action).
            missing_scopes.push(required_scope);
        }
    }

    if missing_scopes.len() > 0 {
        // We've collected missing scopes, we'll throw an error, but include the missing scopes in the error message to help admin's debug.
        return Err(format!("Missing scopes: {:?}", missing_scopes.join(",")));
    }

    // Cool, we've got all the required scopes. Let's finish up!
    return Ok(());
}