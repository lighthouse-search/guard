use serde::{Serialize, Deserialize};
use serde_json::{Value, json};
use rocket_db_pools::{Database, Connection};
use rocket_db_pools::diesel::{MysqlPool, prelude::*};

use crate::responses::*;
use crate::structs::*;
use std::error::Error;
use std::net::SocketAddr;

use crate::{CONFIG_VALUE, SQL_TABLES};

pub async fn start_nginx() {

}