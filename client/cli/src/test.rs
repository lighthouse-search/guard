use crate::structs::*;

use serde::{Serialize, Deserialize};
use serde_json::json;

use std::fs;
use std::collections::HashMap;
use std::process::Command;

use yaml_rust::{Yaml, YamlLoader, YamlEmitter};

pub async fn parse_yaml(arguments: HashMap<String, Command_argument>, file_path: Option<&str>, yaml_string: Option<&str>) -> Test_config {
    // let contents = fs::read_to_string(file_path).expect("Should have been able to read the file");
    if (file_path.is_none() == true && yaml_string.is_none() == true) {
        panic!("Missing both file_path and yaml_string");
    }
    let yaml = YamlLoader::load_from_str(yaml_string.unwrap_or(&fs::read_to_string(file_path.unwrap()).expect("Should have been able to read the file"))).unwrap();

    // Multi document support, doc is a yaml::Yaml
    let doc = &yaml[0];
    
    let test_config = Test_config {
        env: Some(parse_env_from_test_yaml(arguments.clone(), doc.clone()).await),
        commands: Some(parse_commands_from_test_yaml(arguments.clone(), doc.clone()).await)
    };

    return test_config;
}

pub async fn parse_env_from_test_yaml(arguments: HashMap<String, Command_argument>, yaml: Yaml) -> Vec<Test_env> {
    let raw_envs = yaml["jobs"]["build"]["env"].clone();
    println!("raw_envs {:?}", raw_envs.clone());

    let mut envs: Vec<Test_env> = Vec::new();
    if !raw_envs.is_badvalue() {
        let env = raw_envs;
        let env_map = env.as_hash().expect("Failed to parse env as hash");
        for (key, value) in env_map {
            let key_unwrapped = key.as_str();
            let value_unwrapped = value.as_str();
            if (value_unwrapped.is_none() == true) {
                println!("Skipping '{}' environment variable because value is null.", key_unwrapped.unwrap());
            } else {
                envs.push(Test_env {
                    key: key_unwrapped.unwrap().to_string(),
                    value: value.as_str().unwrap().to_string(),
                });
            }
        }
    }

    return envs;
}

pub async fn parse_commands_from_test_yaml(arguments: HashMap<String, Command_argument>, yaml: Yaml) -> Vec<Test_command> {
    let commands = yaml["jobs"]["build"]["commands"].clone();
    let mut test_commands: Vec<Test_command> = Vec::new();
    for command in commands {
        // println!("command: {:?}", command);
        test_commands.push(Test_command {
            name: command["name"].as_str().expect("Failed to parse command.name").to_string(),
            run: command["run"].as_str().expect("Failed to parse command.run").to_string(),
            env: Some(command["env"].clone()),
        });
    }

    return test_commands;
}

pub async fn run(arguments: HashMap<String, Command_argument>) {
    let file_path: String = arguments.get("file").unwrap().value.clone();
    
    let config = parse_yaml(arguments, Some(&file_path), None).await;
    println!("config: {:?}", config.clone());

    for command in config.commands.unwrap() {
        println!("run: {:?}", command.run);
        // println!("run: {:?}", command.env);

        let mut envs: HashMap<String, String> = HashMap::new();

        for env in config.env.clone().unwrap() {
            envs.insert(env.key, env.value);
        }

        if let Some(env) = command.env {
            if env.is_badvalue() == false {
                let env_map = env.as_hash().expect("Failed to parse env as hash");
                for (key, value) in env_map {
                    let key_unwrapped = key.as_str();
                    let value_unwrapped = value.as_str();
                    if (value_unwrapped.is_none() == true) {
                        println!("Skipping '{}' environment variable because value is null.", key_unwrapped.unwrap());
                    } else {
                        envs.insert(key_unwrapped.unwrap().to_string(), value.as_str().unwrap().to_string());
                    }
                }
            }
        }

        let cmd = Command::new("sh")
        .envs(envs.clone())
        .arg("-c")
        .arg(command.run.clone())
        .output()
        .expect("failed to execute process");

        // let cmd_readable = Command::new("sh")
        // .envs(envs)
        // .arg("-c")
        // .arg(format!("echo \"{}\"", command.run.replace('"', "\"")))
        // .output()
        // .expect("failed to execute process");
        // println!("COMMAND: {}", String::from_utf8(cmd_readable.stdout).unwrap());
        println!("OUTPUT: {}", String::from_utf8(cmd.stdout).unwrap_or("No output".to_string()));
        if (cmd.status.success() == false) {
            panic!("Failed at: {}", command.name.clone());
        }
    }
}