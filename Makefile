


.PHONY: all build test clean check

all: build

build:
	cargo build --all-targets

test: build
	cargo test --lib && cargo test --bins && cargo test

check:
	cargo fmt --check && cargo rustc --lib -- -D warnings && cargo rustc --bin zplc -- -D warnings && cargo rustc --bin zpdump -- -D warnings

clean:
	cargo clean

.DEFAULT_GOAL := all
