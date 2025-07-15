.PHONY: example-config dev build build-dependencies

example-config:
# This doesn't work
	export guard_config=$(cat ../example/guard-dev-config.toml)

dev:
# TODO: Conditioninally add "RUST_LOG" variable, only add it if RUST_LOG is empty (e.g you'd add if user ran "make dev" instead of "RUST_LOG=info make dev")
	cd server && RUST_LOG=info cargo run -- --port 8091

build-dependencies:
	curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSf | sh -s -- -y
	. "$(HOME)/.cargo/env"

BASE=/builds/oracularhades

build:
	rustc --version && cargo --version  # For any future debugging.
	apt update -y && apt install zip tree -y
	tree /
	cd $(BASE)/guard/server && \
		cargo build --verbose --release && \
		cargo test --verbose
	mkdir $(BASE)/release
	apt-get update -y && \
		apt-get install -y build-essential curl file git unzip && \
		curl -fsSL https://deno.land/install.sh | sh && \
		/bin/bash -c "export PATH=\"$$HOME/.deno/bin:$$PATH\" && cd $(BASE)/guard/server/frontend && deno task build && cd .."
	mv $(BASE)/guard/server/target/release/guard-server $(BASE)/release
	mkdir $(BASE)/release/frontend/
	mv $(BASE)/guard/server/frontend/_static $(BASE)/release/frontend/_static
	cd $(BASE)/release && zip -r $(BASE)/guard/guard.zip .
