.PHONY: build test lint clean check run

build:
	npm run tauri -- build --no-bundle

check:
	cargo check --manifest-path src-tauri/Cargo.toml --locked

test:
	cargo test --manifest-path src-tauri/Cargo.toml --locked --lib

lint:
	cargo clippy --manifest-path src-tauri/Cargo.toml --locked --all-targets -- -D warnings

run:
	npm run tauri -- dev

clean:
	cargo clean --manifest-path src-tauri/Cargo.toml
