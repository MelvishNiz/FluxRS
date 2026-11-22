#!/usr/bin/env bash
# Build the browser UI into crates/fluxrs-app/web/dist (served by `fluxrs --serve`).
# Needs: rustup target add wasm32-unknown-unknown
#        cargo install wasm-bindgen-cli --version <version of wasm-bindgen in Cargo.lock>
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../../.." && pwd)"
out="$here/dist"
cargo build --manifest-path "$root/Cargo.toml" -p fluxrs-app --release --locked --target wasm32-unknown-unknown
rm -rf "$out" && mkdir -p "$out"
wasm-bindgen --target web --no-typescript --out-dir "$out" --out-name fluxrs \
  "$root/target/wasm32-unknown-unknown/release/fluxrs.wasm"
cp "$here/index.html" "$out/"
cp "$here/../assets/linux/fluxrs.png" "$out/"
echo "web UI built in $out"
ls -la "$out"
