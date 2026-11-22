#!/usr/bin/env bash
# wasm32 target + wasm-bindgen-cli matching the wasm-bindgen version in Cargo.lock.
set -euo pipefail
rustup target add wasm32-unknown-unknown
ver=$(awk '/^name = "wasm-bindgen"$/{getline; gsub(/version = |"/,""); print; exit}' Cargo.lock)
echo "wasm-bindgen $ver"
if ! wasm-bindgen --version 2>/dev/null | grep -q "$ver"; then
  cargo install wasm-bindgen-cli --version "$ver" --locked
fi
