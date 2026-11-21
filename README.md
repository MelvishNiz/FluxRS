# FluxRS — proxyless HTTP debugger for Windows

FluxRS is an HTTP/HTTPS debugger written in Rust, both the engine and the
GUI. It can capture traffic **without any proxy configuration**: on
Windows the WinDivert driver redirects outgoing HTTP/HTTPS connections into
the built-in MITM engine.

The engine (`crates/fluxrs-core`) is a Rust re-implementation of the main
ideas of [fluxzy.core](https://github.com/haga-rak/fluxzy.core):
on-the-fly certificates, filters and actions, breakpoints, and transparent
capture.

![Traffic view](docs/traffic.png)

## Features

| | |
|---|---|
| **Proxyless capture** | WinDivert redirects outbound TCP 80/443 to the engine, so every app (browser, CLI, desktop) is captured with no proxy settings. QUIC (UDP 443) is blocked during capture so browsers fall back to TCP. |
| **Explicit proxy mode** | Classic HTTP proxy (`127.0.0.1:44344` by default) with `CONNECT` support, for other OSes or devices. |
| **HTTPS decryption** | Local root CA (ECDSA P-256) with leaf certificates generated per host and cached. One-click install into the Windows trust store. Host bypass list for certificate-pinned apps. |
| **Intercept (breakpoints)** | Pause requests and/or responses that match a filter, edit them as raw HTTP text, then forward, forward unchanged, or drop. |
| **Rewrite rules** | Filters (URL / host / path / method / header × contains / equals / starts / ends / regex, NOT, case) + actions: set/remove headers, method, path regex rewrite, redirect to another host, replace or find/replace bodies (gzip/br/deflate are decoded first), status, mock response, block, delay. Changes apply live. |
| **Inspector** | Request/response headers, decoded and pretty-printed bodies, hex view for binary bodies, timings, copy as cURL, create a rule from an exchange. WebSocket upgrades are tunneled. |

![Intercept](docs/intercept.png)
![Rules](docs/rules.png)

## Download and run (Windows)

1. Download the `FluxRS-…-windows-x64` artifact from the **Build** workflow
   (Actions → Build → Run workflow), or build it yourself (see below).
2. Keep `fluxrs.exe`, `WinDivert.dll` and `WinDivert64.sys` in the same folder.
3. Start `fluxrs.exe`. It asks for Administrator rights, which loading the
   WinDivert driver requires.
4. **Settings → Install in Windows trust store** installs the root CA once.
   Firefox uses its own store: import `fluxrs-root-ca.crt` there or enable
   `security.enterprise_roots.enabled`.
5. Press **Start capture**.

Data (CA, `settings.json`, `rules.json`) lives in `%APPDATA%\FluxRS`.

Command-line flags: `--start` starts capturing at launch;
`--view traffic|intercept|rules|settings|logs` opens that page.

### Limitations

* Only HTTP/1.1 is used between clients and FluxRS (ALPN offers only
  `http/1.1`). HTTP/2 and HTTP/3 are not decoded.
* Proxyless mode redirects IPv4 on ports 80 and 443. New IPv6 connections
  to those ports are dropped, so clients fall back to IPv4.
* Apps that pin certificates fail the TLS handshake. Add their hosts to
  **Settings → Never decrypt**.
* WinDivert needs a 64-bit Windows that can load signed kernel drivers.
  Some anti-cheat and security tools block it.

## How proxyless capture works

```
app A:p ──SYN──▶ S:443          (outbound, captured by WinDivert)
        rewritten to  S:p ──▶ A:44344   (re-injected as inbound)
FluxRS accepts a connection from "S:p" → knows the real server S,
looks up the original port (443) in the NAT table, decrypts with a
forged certificate for the SNI, forwards to S:443 from its own socket
(that socket's port is marked "owned" so it is never redirected).
replies A:44344 ──▶ S:p  are rewritten back to  S:443 ──▶ A:p
```

The packet logic is in `crates/fluxrs-core/src/nat.rs`. It is pure Rust
and unit tested. `divert.rs` loads `WinDivert.dll` at runtime, so building
does not need the WinDivert SDK.

## Build from source

Requires the stable Rust toolchain.

```bash
cargo test --workspace
```

```bash
cargo build --release -p fluxrs-app
```

The binary is `target/release/fluxrs.exe`. For proxyless mode, copy
`WinDivert.dll` and `WinDivert64.sys` (x64 folder of
[WinDivert 2.2.2](https://github.com/basil00/WinDivert/releases/tag/v2.2.2))
next to it.

## Project layout

```
crates/fluxrs-core   engine: proxy, TLS MITM, certificates, rules, intercept, NAT, WinDivert
crates/fluxrs-app    egui/eframe desktop UI (dark theme)
.github/workflows    ci.yml (fmt, clippy, tests on every push), build.yml (manual release build)
```

## CI

* **CI** (`ci.yml`) runs on every push and pull request: `cargo fmt`,
  `clippy -D warnings` and every test on Windows, plus core tests on Linux.
* **Build** (`build.yml`) is started manually from the Actions tab
  (*Run workflow*). It tests, builds the release exe, downloads WinDivert
  (SHA-256 checked) and uploads a ready-to-run package.

## License

GPL-3.0. See [LICENSE](LICENSE).
