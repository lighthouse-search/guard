use serde::{Serialize, Deserialize};
use serde_json::{Value, json};

use crate::responses::*;
use crate::structs::*;
use std::error::Error;
use std::net::SocketAddr;

use crate::{CONFIG_VALUE, SQL_TABLES};

pub async fn start_nginx() {

}