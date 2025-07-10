use diesel::sql_query;
use diesel::prelude::*;
use diesel::sql_types::*;

use crate::structs::*;

use crate::SQL_TABLES;

pub async fn get_magiclink(code: String) -> Option<Magiclink> {
    let mut db = crate::DB_POOL.get().expect("Failed to get a connection from the pool.");

    let sql: ConfigSqlTables = (&*SQL_TABLES).clone();
    let magiclink_table = sql.magiclink.unwrap();

    let query = format!("SELECT user_id, code, ip, created, authentication_method FROM {} WHERE code=?", magiclink_table.clone());
    let result: Vec<Magiclink> = sql_query(query)
    .bind::<Text, _>(code.clone())
    .load::<Magiclink>(&mut db)
    .expect("Something went wrong querying the DB.");

    if result.len() == 0 {
        // Magiclink invalid, not found.
        return None;
    }
    let magiclink = result[0].clone();

    return Some(magiclink);
}