# Network Protocol Decoder

A macOS desktop app that captures network packets from live interfaces or imported PCAP files, decodes them layer by layer (Ethernet → IPv4 → TCP/UDP → HTTP/DNS/TLS), and presents them in three switchable visual modes. Makes packet structure legible to someone who finds Wireshark impenetrable.

## Tech Stack
- **Rust**: edition 2021 (Tauri backend, packet capture, protocol parsing; no minimum Rust version declared)
- **React**: 19.x (frontend UI, hooks only)
- **TypeScript**: 7.x (strict mode)
- **Tauri**: 2.x (desktop shell)
- **Zustand**: 5.x (state management)
- **@tanstack/react-virtual**: 3.x (packet list virtualization for up to 50k packets)
- **pcap**: 2.x (Rust — wraps libpcap, live capture + .pcap/.pcapng files)
- **pnet**: 0.35 (Rust — Ethernet/IPv4/TCP/UDP parsing; ICMP classified with raw payload)
- **Tailwind CSS**: 4.x
- **Vite**: 8.x

## Status
Core packet capture and visualization implemented; privilege-escalation helper not implemented:
- Protocol decoders: HTTP, DNS, TLS (handshake metadata)
- Live capture from network interfaces + PCAP file import
- Three switchable visual modes
- 50k-packet ring buffer; live batches emitted at 200 packets or on a 100ms capture timeout
- Live capture runs in an app-process thread; no privilege-escalation helper binary

## Build & Run
```bash
npm install
npm run tauri dev

# Production build
npm run tauri build
```

Requires libpcap installed on the system (`brew install libpcap` on macOS). Live capture requires the app process to have capture permissions.

## Architecture
- `src-tauri/src/` — Rust: packet capture loop, protocol decoders, ring buffer, Tauri commands + events
- `src/components/` — React UI: packet list (virtualized), protocol tree view, three visual modes
- `src/stores/` — Zustand stores for packet data (never localStorage or sessionStorage)
- Tauri events (not commands) for streaming packet data — max 200 packets/batch; live capture also flushes on a 100ms capture timeout, file import flushes at EOF
- TLS scope: handshake metadata only (SNI, cipher suite, TLS version) — no payload decryption

## Known Issues
- TLS payload decryption not supported — requires SSLKEYLOGFILE integration (out of scope)
- Live capture shows a privilege warning but does not elevate permissions; capture permissions must be configured manually

<!-- portfolio-context:start -->
# Portfolio Context

## What This Project Is

NetworkDecoder is a local desktop network-inspection tool for capturing live traffic or importing PCAP files, decoding protocol metadata, and visualizing packet streams without sending data off-machine. It is built around a Tauri app with a Rust packet pipeline and a React/TypeScript interface for switching between packet-list, flow, and protocol-oriented views.

## Current State

Core packet capture and visualization implemented; privilege-escalation helper not implemented:
- Protocol decoders: HTTP, DNS, TLS (handshake metadata)
- Live capture from network interfaces + PCAP file import
- Three switchable visual modes
- 50k-packet ring buffer; live batches emitted at 200 packets or on a 100ms capture timeout
- Live capture runs in an app-process thread; no privilege-escalation helper binary

## Stack

- **Rust**: edition 2021 (Tauri backend, packet capture, protocol parsing; no minimum Rust version declared)
- **React**: 19.x (frontend UI, hooks only)
- **TypeScript**: 7.x (strict mode)
- **Tauri**: 2.x (desktop shell)
- **Zustand**: 5.x (state management)
- **@tanstack/react-virtual**: 3.x (packet list virtualization for up to 50k packets)
- **pcap**: 2.x (Rust — wraps libpcap, live capture + .pcap/.pcapng files)
- **pnet**: 0.35 (Rust — Ethernet/IPv4/TCP/UDP parsing; ICMP classified with raw payload)
- **Tailwind CSS**: 4.x
- **Vite**: 8.x

## How To Run

```bash
npm install
npm run tauri dev

# Production build
npm run tauri build
```

Requires libpcap installed on the system (`brew install libpcap` on macOS). Live capture requires the app process to have capture permissions.

## Known Risks

- TLS payload decryption not supported — requires SSLKEYLOGFILE integration (out of scope)
- Live capture shows a privilege warning but does not elevate permissions; capture permissions must be configured manually

## Next Recommended Move

Use this context plus the README and supporting docs to resume the next active task, then promote the repo beyond minimum-viable by capturing a dedicated handoff, roadmap, or discovery artifact.

<!-- portfolio-context:end -->
