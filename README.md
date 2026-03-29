# NetworkDecoder

[![Rust](https://img.shields.io/badge/Rust-%23dea584?style=flat-square&logo=rust)](#) [![TypeScript](https://img.shields.io/badge/TypeScript-3178c6?style=flat-square&logo=typescript)](#) [![Status](https://img.shields.io/badge/status-WIP-yellow?style=flat-square)](#)

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
npm install
# PCAP import only (no root required)
npm run tauri dev
# Live capture (requires root)
sudo npm run tauri dev
```

## Tech Stack

| Layer | Technology |
|-------|------------|
| Desktop shell | Tauri 2 |
| Packet engine | Rust |
| Frontend | React + TypeScript |
| Platform | macOS 13+ |

> **Status: Work in Progress** — Core decoding and all three views functional on macOS. PCAP export and live-capture UI in progress.

## License

MIT