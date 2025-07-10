use std::collections::HashMap;
use crate::cli::cli_structs::*;

pub fn has_no_value(arguments: &HashMap<String, CommandArgument>, argument: &str) -> bool {
    if arguments.get(argument).is_none() == false {
        // The argument (e.g. request-authentication) had a value E.g. ./guard --request-authentication example.com
        return false;
    } else {
        // The argument (e.g. request-authentication) did not have a value E.g. ./guard --request-authentication
        return true;
    }
}

pub fn get_value(arguments: &HashMap<String, CommandArgument>, argument: &str) -> Option<String> {
    if arguments.get(argument).is_none() == false {
        // The argument (e.g. request-authentication) had a value E.g. ./guard --request-authentication example.com
        return Some(arguments.get(argument).unwrap().value.clone().unwrap());
    } else {
        // The argument (e.g. request-authentication) did not have a value E.g. ./guard --request-authentication
        return None;
    }
}