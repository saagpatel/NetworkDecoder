# Network Protocol Decoder

A macOS desktop app that captures network packets from live interfaces or imported PCAP files, decodes them layer by layer (Ethernet → IP → TCP/UDP → HTTP/DNS/TLS/QUIC), and presents them in three switchable visual modes. Makes packet structure legible to someone who finds Wireshark impenetrable.

## Tech Stack
- **Rust**: 1.77+ (Tauri backend, packet capture, protocol parsing)
- **React**: 18.x (frontend UI, hooks only)
- **TypeScript**: 5.x (strict mode)
- **Tauri**: 2.x (desktop shell)
- **Zustand**: 4.x (state management)
- **@tanstack/react-virtual**: 3.x (packet list virtualization for 50k+ packets)
- **pcap**: 2.x (Rust — wraps libpcap, live capture + .pcap/.pcapng files)
- **pnet**: 0.35 (Rust — Ethernet/IP/TCP/UDP/ICMP parsing)
- **Tailwind CSS**: 3.x
- **Vite**: 5.x

## Status
Phases 0-4 complete — all planned functionality shipped in a single comprehensive commit:
- Protocol decoders: HTTP, DNS, TLS (handshake metadata), QUIC
- Live capture from network interfaces + PCAP file import
- Three switchable visual modes
- 50k-packet ring buffer with batched 100ms Tauri event emission
- Privilege-escalation helper binary for capture (main app never runs as root)

## Build & Run
```bash
npm install
npm run tauri dev

# Production build
npm run tauri build
```

Requires libpcap installed on the system (`brew install libpcap` on macOS). Live capture requires the helper binary to be granted capture permissions.

## Architecture
- `src-tauri/src/` — Rust: packet capture loop, protocol decoders, ring buffer, Tauri commands + events
- `src/components/` — React UI: packet list (virtualized), protocol tree view, three visual modes
- `src/stores/` — Zustand stores for packet data (never localStorage or sessionStorage)
- Tauri events (not commands) for streaming packet data — batched at 100ms intervals, max 200 packets/batch
- TLS scope: handshake metadata only (SNI, cipher suite, TLS version) — no payload decryption

## Known Issues
- TLS payload decryption not supported — requires SSLKEYLOGFILE integration (out of scope)
- Privilege escalation UX for live capture may require manual permissions on first run
