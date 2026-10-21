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
export guard_config=$(cat ../example/guard-dev-config.toml) && export example_user_mysql_password='[your password]' && export smtp_password="[your SMTP key]"
```

### Start server
```
cargo run
```

## Run Release Docker container

> ⚠️ **Please note:** You still need to set environment variables, as shown above. 

### Prerequisites
[Install Docker](https://www.docker.com/) (You may need to restart your terminal for your system path to update!)

```
docker run -e guard_config="$guard_config" -e example_user_mysql_password="$example_user_mysql_password" -e smtp_password="$smtp_password" guard
```

## Build Custom Docker container

> ⚠️ **Please note:** You still need to set environment variables, as shown above. 

> ⚠️ **IF YOU ARE LOOKING FOR THE RELEASE GUARD DOCKER CONTAINER**, you don't need this! The official Guard Docker container is available at registry.gitlab.com/oracularhades/guard

Intended for building custom Guard Docker containers. You can use this deploy Guard to test Kubernetes environments (or whatever else!).

### Prerequisites
[Install Docker](https://www.docker.com/) (You may need to restart your terminal for your system path to update!)

### Build image
```
docker build -t guard .
```

### Run image
```
docker run -e guard_config="$guard_config" -e example_user_mysql_password="$example_user_mysql_password" -e smtp_password="$smtp_password" guard
```

## Serving local media (backgrounds, logos)
Instead of hosting login-page images on an external service (e.g. an S3 bucket),
you can point Guard at a folder on disk and reference files from config.

Set the media folder:
```toml
[frontend.media]
folder = "/srv/guard/media"
```

Then reference any file in that folder with the `media://` prefix from the
frontend metadata (works for `image` and `logo`, both globally and per-hostname):
```toml
[frontend.metadata]
image = "media://background.jpg"
logo = "media://logo.png"
```

The folder is served at `/guard/media` (so `media://background.jpg` resolves to
`/guard/media/background.jpg`). Values that are already full `http(s)` URLs are
left unchanged, so existing configs keep working.
```