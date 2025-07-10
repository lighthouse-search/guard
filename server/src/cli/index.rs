use std::collections::HashMap;
use crate::ARGUMENTS;
use crate::cli::cli_structs::*;

pub async fn parse() {
    // Convert program arguments to a convient arguments+values Hashmap.
    let arguments = ARGUMENTS.args.clone();
    let modes = ARGUMENTS.modes.clone(); // In "./guard authentication handle --request", "authentication" and "handle" are "modes" as they do not start with "--" (which would indicate a more traditional argument or flag). Modes are used for comprehensive routing.

    // We have our arguments and modes. Let's start routing.
    if modes == vec!["socket", "open"] {
        // TODO: Lock this socket to specific functions. E.g. you can validate authentication requests but cannot edit accounts. This helps mitigate any command injection attacks. Require the admin to specify socket permissions and initalisation.
        // test::run(arguments, modes).await;
    } else if modes == vec!["authenticate", "handle"] {
        crate::cli::mode::authenticate::handle(arguments, modes).await.expect("");
    } else if modes == vec!["user", "create"] {
        crate::cli::mode::user::create(arguments, modes).await.expect("");
    } else {
        panic!("Command not found.");
    }
}

pub fn args_to_hashmap(args: Vec<String>) -> ArgsToHashmap {
    log::debug!("args: {:?}", args);
    let mut modes: Vec<String> = Vec::new();

    // TODO: For security reasons, this CLI parsing needs to be handed off to a dedicated CLI parsing library.

    // Parse arguments and move into a hashmap.
    let mut arguments: HashMap<String, CommandArgument> = HashMap::new();
    let mut args_iter = args.iter();
    args_iter.next();
    while let Some(arg) = args_iter.next() {
        if arg.starts_with("--") {
            if let Some(value) = args_iter.next() {
                log::debug!("New flag: {}\nNew value: {}", arg, value);
                arguments.insert(arg.replace("--", ""), CommandArgument {
                    value: Some(value.clone())
                });
            } else {
                log::debug!("New flag: {}\nNew value: None", arg);
                arguments.insert(arg.replace("--", ""), CommandArgument {
                    value: None
                });
            }
        } else {
            // Any argument that doesn't have "--" on it. e.g. in "interstellar upload --url example.com", "upload" would get caught here.
            log::debug!("New mode: {}", arg);
            modes.push(arg.to_string());
        }
    }

    let args_to_hashmap = ArgsToHashmap {
        args: arguments,
        modes: modes
    };

    log::debug!("args_to_hashmap: {:?}", args_to_hashmap);

    return args_to_hashmap;
}