# NetworkDecoder

[![Rust](https://img.shields.io/badge/Rust-%23dea584?style=flat-square&logo=rust)](#) [![TypeScript](https://img.shields.io/badge/TypeScript-3178c6?style=flat-square&logo=typescript)](#) [![Status](https://img.shields.io/badge/status-v1.0.0-green?style=flat-square)](#)

> macOS desktop packet decoder with layer-by-layer protocol analysis and three visual modes.

NetworkDecoder captures live network traffic or imports PCAP files and decodes packets from Ethernet through HTTP/DNS/TLS. Three viewing modes — a Wireshark-style packet list, a per-connection swimlane timeline, and protocol card summaries — let you inspect traffic at the level you need.

## Features

- **Live capture or PCAP import** — Capture from any interface (elevated privileges required) or open `.pcap`/`.pcapng` files
- **Layer-by-layer decoding** — Ethernet → IPv4 → TCP/UDP → HTTP/1.1, DNS, TLS handshake metadata
- **Three view modes** — Packet List, Swimlane (per-connection timeline), Protocol Cards
- **Detail pane + hex dump** — Field-by-field breakdown with plain-English hover explanations; layer-aware byte highlighting
- **Filter bar** — Client-side: `proto:tcp`, `ip:192.168.1.1`, `port:443`, `stream:5`
- **TCP stream tracking** — Bidirectional connection identification via FNV hash

## Quick Start

```bash
git clone https://github.com/saagpatel/NetworkDecoder.git
cd NetworkDecoder
npm ci
# PCAP import only (no root required)
npm run tauri dev
```

## Verification

Run from the repository root. Use Node 22.12+ with npm (the locked Vite requires
`^20.19.0 || >=22.12.0`), Rust/Cargo with Clippy, and the macOS native build
prerequisites: Xcode Command Line Tools and libpcap. The app targets macOS 13+.
Install the checked-in JavaScript lockfile with `npm ci`; Cargo commands below use
`--locked` and the actual manifest in `src-tauri/`.

```bash
npm ci
npm run build
# Focused in-memory buffer fixtures; no packet capture or application launch.
cargo test --manifest-path src-tauri/Cargo.toml --locked --lib buffer::ring::tests
make test
make check
make lint
make build
```

`npm run build` runs TypeScript checking and Vite production compilation. There
is no configured frontend test or lint script. `make test` runs the Rust library
unit tests; its export fixtures write `nd_test_magic.pcap`,
`nd_test_single.pcap`, `nd_test_ts.pcap`, and `nd_test_count.pcap` in the system
temporary directory, plus `/tmp/test_export_round_trip.pcap`. Confirm those paths
are unused before the full suite; use the focused buffer fixtures for a smoke check.
`make lint` runs Clippy. `make build` uses Tauri's build command, which
runs the frontend build before the native build, without producing an installer
bundle. These native commands require the macOS SDK and libpcap even for fixtures.

For UI changes, use `make run` and import a disposable, non-sensitive PCAP fixture;
check the affected packet list, swimlane, protocol cards, filters, detail pane,
and export. Compile/unit-test success does not verify the desktop UI. Live capture
is a separate explicitly authorized manual activity requiring elevated capture
privileges; it is not part of routine verification. Do not run package installation
or fixture checks with `sudo`, or capture workstation traffic as a smoke test.

## Tech Stack

| Layer | Technology |
|-------|------------|
| Desktop shell | Tauri 2 |
| Packet engine | Rust |
| Frontend | React + TypeScript |
| Platform | macOS 13+ |

> **Status: v1.0.0** — Live capture, PCAP import/export, and all three view modes implemented; privilege escalation is not implemented.

## License

MIT