# Network Protocol Decoder

## Overview
A macOS desktop app that captures network packets from live interfaces or imported PCAP files, decodes them layer by layer (Ethernet → IP → TCP/UDP → HTTP/DNS/TLS), and presents them in three switchable visual modes. Built as a portfolio piece with genuine educational value — makes packet structure legible to someone who finds Wireshark impenetrable.

## Tech Stack
- Rust: 1.77+ (Tauri backend, packet capture, parsing)
- React: 18.x (frontend UI, hooks only — no class components)
- TypeScript: 5.x (strict mode)
- Tauri: 2.x (desktop shell)
- Zustand: 4.x (state management)
- @tanstack/react-virtual: 3.x (packet list virtualization — required for 50k+ packets)
- pcap: 2.x (Rust — wraps libpcap, handles live capture + .pcap/.pcapng files)
- pnet: 0.35 (Rust — layer-by-layer Ethernet/IP/TCP/UDP/ICMP parsing)
- Tailwind CSS: 3.x (styling)
- Vite: 5.x (build tooling)

## Development Conventions
- TypeScript strict mode — no `any` types, no type assertions without a comment explaining why
- kebab-case for files, PascalCase for React components, snake_case for Rust
- Conventional commits: `feat:`, `fix:`, `chore:`, `refactor:`
- Rust unit tests for all parser logic before moving to the next parser
- React components: functional only, custom hooks for all side effects and subscriptions
- Tauri events (not commands) for streaming packet data to the frontend

## Current Phase
**Phase 0: Foundation**
See IMPLEMENTATION-ROADMAP.md for full phase details and acceptance criteria.

## Key Decisions
| Decision | Choice | Why |
|----------|--------|-----|
| Packet parsing | pnet 0.35 | Better protocol coverage than etherparse for IP options and ICMP |
| PCAP library | pcap 2.x | Handles both .pcap and .pcapng; wraps battle-tested libpcap |
| IPC model | Tauri events for capture stream | Fire-and-forget suits continuous streaming; commands are request-response |
| Packet ring buffer | 50,000 packets in Rust | ~200MB worst case; fits comfortably in available RAM |
| Frontend batch interval | 100ms | Balances UI responsiveness against render thrash |
| TLS scope | Handshake metadata only | Payload decryption requires SSLKEYLOGFILE; scope to SNI + cipher suite |
| Virtual list | @tanstack/react-virtual | Required — 50k+ rows without virtualization will freeze the UI |

## Do NOT
- Do not build all views in one session — build phase by phase per IMPLEMENTATION-ROADMAP.md
- Do not emit one Tauri event per packet — always batch at 100ms intervals, max 200 packets per batch
- Do not attempt TLS payload decryption — handshake metadata only (SNI, cipher suite, TLS version)
- Do not use localStorage or sessionStorage for any packet data — keep all state in Zustand
- Do not add features not in the current phase of IMPLEMENTATION-ROADMAP.md
- Do not run the main app process as root — privilege escalation for capture must go through a helper binary
- Do not use class components — React hooks only throughout
