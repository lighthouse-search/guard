pub mod structs;
pub mod test;

use std::fs;
use std::env;
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use serde::{Serialize, Deserialize};
use serde_json::json;

use test::parse_yaml;
use tokio::task;

use crate::structs::*;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    let mut mode_locked = false;
    let mut modes: Vec<&String> = Vec::new();

    // Parse arguments and move into a hashmap.
    let mut arguments: HashMap<String, Command_argument> = HashMap::new();
    let mut args_iter = args.iter();
    args_iter.next();
    while let Some(arg) = args_iter.next() {
        if (arg.starts_with("--") == true || arg.starts_with("-") == true) {
            mode_locked = true;
        }
        if arg.starts_with("--") {
            if let Some(value) = args_iter.next() {
                arguments.insert(arg.replace("--", ""), Command_argument {
                    value: value.clone()
                });
            } else {
                eprintln!("Error: -- requires a value.");
                return;
            }
        } else {
            // Any argument that doesn't have "--" oin it. e.g. in "interstellar upload --url example.com", "upload" would get caught here.
            println!("arg COOL: {}", arg);
            modes.push(arg);
        }
    }

    if (modes == vec!["tunnel", "connect"]) {
        test::run(arguments).await;
    } else {
        panic!("Command not found.");
    }

    println!("Finished.");
}