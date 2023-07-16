PINNED_TOOLCHAIN := $(shell cat rust-toolchain)
prepare:
	rustup target add wasm32-unknown-unknown
	rustup component add clippy --toolchain ${PINNED_TOOLCHAIN}
	rustup component add rustfmt --toolchain ${PINNED_TOOLCHAIN}

build-contract:
	cd examples/contract-v1 && cargo build --release --target wasm32-unknown-unknown
	cd examples/contract-v2 && cargo build --release --target wasm32-unknown-unknown
	cd examples/counter-call && cargo build --release --target wasm32-unknown-unknown

	wasm-strip target/wasm32-unknown-unknown/release/contract-v1.wasm 2>/dev/null | true
	wasm-strip target/wasm32-unknown-unknown/release/contract-v2.wasm 2>/dev/null | true
	wasm-strip target/wasm32-unknown-unknown/release/counter-call.wasm 2>/dev/null | true

test-only:
	cd tests && cargo test

test: build-contract
	mkdir -p tests/wasm
	cp target/wasm32-unknown-unknown/release/counter-v1.wasm tests/wasm
	cp target/wasm32-unknown-unknown/release/counter-v2.wasm tests/wasm
	cp target/wasm32-unknown-unknown/release/counter-call.wasm tests/wasm
	cd tests && cargo test

clippy:
	cd contract-storage && cargo clippy --all-targets -- -D warnings
	cd contract-utilities && cargo clippy --all-targets -- -D warnings
	cd examples/contract-v1 && cargo clippy --all-targets -- -D warnings
	cd examples/contract-v2 && cargo clippy --all-targets -- -D warnings
	cd examples/counter-call && cargo clippy --all-targets -- -D warnings
	cd tests && cargo clippy --all-targets -- -D warnings

check-lint: clippy
	cd contract-storage && cargo fmt -- --check
	cd contract-utilities && cargo fmt -- --check
	cd examples/contract-v1 && cargo fmt -- --check
	cd examples/contract-v2 && cargo fmt -- --check
	cd examples/counter-call && cargo fmt -- --check
	cd tests && cargo fmt -- --check

lint: clippy
	cd contract-storage && cargo fmt
	cd contract-utilities && cargo fmt
	cd examples/contract-v1 && cargo fmt
	cd examples/contract-v2 && cargo fmt
	cd examples/counter-call && cargo fmt
	cd tests && cargo fmt

