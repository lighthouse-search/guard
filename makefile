example-config:
# This doesn't work
	export guard_config=$(cat ../example/guard-dev-config.toml)

dev:
# TODO: Conditioninally add "RUST_LOG" variable, only add it if RUST_LOG is empty (e.g you'd add if user ran "make dev" instead of "RUST_LOG=info make dev")
	cd server && RUST_LOG=info cargo run -- --port 65535