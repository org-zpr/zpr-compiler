


.PHONY: all build test clean check

all: build

build:
	cargo build --all-targets

test: build
	cargo test --verbose

check:
	cargo fmt --check && cargo rustc --lib -- -D warnings && cargo rustc --bin zpc -- -D warnings && cargo rustc --bin zpdump -- -D warnings

clean:
	cargo clean

.DEFAULT_GOAL := all
