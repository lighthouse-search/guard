Development
==============

Thanks for contributing to Guard! Here's a guide to creating a local development server.
- [Dev server (Rust/Cargo)](#start-dev-server)
- [Docker](#build-docker-container)

## Start dev server
Intended for developing code.

### Prerequisites
[Install Rust](https://www.rust-lang.org/) (You may need to restart your terminal for your system path to update!)

### Set environment variables
```
export guard_config=$(cat ~/Desktop/guard-dev-config.toml) && export example_user_mysql_password='[your password]' && export elastic_username="[your username]" && export elastic_password="[your password]" && export elastic_host="https://127.0.0.1:9200" && export smtp_password="[your SMTP key]"
```

### Start server
```
cargo run
```

## Build Docker container

> ⚠️ **Please note:** You still need to set environment variables, as shown above. 

> ⚠️ **IF YOU ARE LOOKING FOR THE RELEASE GUARD DOCKER CONTAINER**, you don't need this! The official Guard Docker container is available at registry.gitlab.com/oracularhades/interstellar

Intended for building custom Guard Docker containers. You can use this deploy Guard to test Kubernetes environments (or whatever else!).

### Prerequisites
[Install Docker](https://www.docker.com/) (You may need to restart your terminal for your system path to update!)

### Build image
```
docker build -t guard .
```

### Run image
```
docker run -e MY_VARIABLE="$guard_config" -e example_user_mysql_password="$example_user_mysql_password" -e elastic_username="$elastic_username" -e "$elastic_password" -e "$elastic_host" -e smtp_password "$smtp_password" guard
```