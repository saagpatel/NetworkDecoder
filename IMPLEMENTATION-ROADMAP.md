# Network Protocol Decoder — Implementation Roadmap

## Architecture

### System Overview
```
[Network Interface / .pcap file]
        ↓
[Rust: pcap capture thread]
        ↓
[Rust: pnet packet parser] → PacketRecord structs
        ↓
[Rust: RingBuffer<PacketRecord> (50k cap)] → batch every 100ms
        ↓
[Tauri event: "packets_batch"]
        ↓
[React: usePacketStore (Zustand)]
        ↓
[PacketListView] | [SwimLaneView] | [ProtocolCardView]
        ↓                ↓                  ↓
[DetailPane]    [ConnectionPanel]    [FieldExplainer]
        ↓
[HexDump]
```

### File Structure
```
network-decoder/
├── src-tauri/
│   ├── src/
│   │   ├── main.rs                    # Tauri app entry, command + event registration
│   │   ├── capture/
│   │   │   ├── mod.rs                 # CaptureSource trait definition
│   │   │   ├── live.rs                # Live interface capture via pcap
│   │   │   └── file.rs                # PCAP file import via pcap
│   │   ├── parser/
│   │   │   ├── mod.rs                 # Top-level parse_packet() dispatch
│   │   │   ├── ethernet.rs            # Ethernet frame parsing
│   │   │   ├── ip.rs                  # IPv4/IPv6 parsing
│   │   │   ├── transport.rs           # TCP/UDP parsing
│   │   │   ├── application.rs         # HTTP/DNS/TLS parsing (Phase 3)
│   │   │   └── types.rs               # PacketRecord, LayerData, all shared types
│   │   ├── buffer/
│   │   │   └── ring.rs                # RingBuffer<PacketRecord> — 50k cap, evicts oldest
│   │   ├── state.rs                   # AppState struct (Mutex-wrapped capture handle)
│   │   └── commands.rs                # All Tauri commands
│   ├── Cargo.toml
│   └── tauri.conf.json
├── src/
│   ├── main.tsx                       # React entry point
│   ├── App.tsx                        # View router, Tauri event listener setup
│   ├── store/
│   │   ├── packetStore.ts             # Zustand: packet ring buffer (50k), append logic
│   │   └── captureStore.ts            # Zustand: capture state, interface list, connection map
│   ├── components/
│   │   ├── views/
│   │   │   ├── PacketListView.tsx     # Virtualized packet table (@tanstack/react-virtual)
│   │   │   ├── SwimLaneView.tsx       # Connection swimlane timeline (SVG-based)
│   │   │   └── ProtocolCardView.tsx   # Per-protocol card grid
│   │   ├── panels/
│   │   │   ├── DetailPane.tsx         # Layer-by-layer field breakdown for selected packet
│   │   │   ├── HexDump.tsx            # Raw hex + ASCII, highlights selected layer byte range
│   │   │   └── ConnectionPanel.tsx    # TCP stream details (4-tuple, duration, byte counts)
│   │   ├── controls/
│   │   │   ├── CaptureBar.tsx         # Interface picker, Start/Stop, Import File
│   │   │   ├── FilterBar.tsx          # Filter input: proto:http, ip:x.x.x.x, port:443
│   │   │   └── ViewSwitcher.tsx       # Toggle between 3 view modes
│   │   └── common/
│   │       ├── ProtocolBadge.tsx      # Color-coded protocol label
│   │       ├── ByteField.tsx          # Individual byte field with offset tooltip
│   │       └── LoadingState.tsx       # Spinner + message for import/capture init
│   ├── hooks/
│   │   ├── usePacketStream.ts         # Subscribes to Tauri "packets_batch" event
│   │   └── useVirtualPacketList.ts    # @tanstack/react-virtual wrapper with variable heights
│   ├── types/
│   │   └── packets.ts                 # TypeScript mirrors of all Rust packet types
│   └── lib/
│       ├── protocolColors.ts          # Color map: DNS=purple, HTTP=blue, TLS=teal, TCP=gray, UDP=orange
│       └── formatters.ts              # IP, MAC, port, timestamp, bytes formatters
├── package.json
├── tsconfig.json
├── vite.config.ts
└── CLAUDE.md
```

### Core Rust Types
```rust
// src-tauri/src/parser/types.rs — define these first, everything else derives from them

#[derive(Debug, Clone, Serialize)]
pub struct PacketRecord {
    pub id: u64,
    pub timestamp_us: i64,          // microseconds since Unix epoch
    pub capture_len: u32,           // bytes actually captured
    pub original_len: u32,          // bytes on the wire
    pub interface: String,
    pub layers: Vec<LayerData>,
    pub protocol: TopProtocol,      // highest-layer protocol identified
    pub src_addr: Option<String>,   // "192.168.1.1:443" or bare IP if no port
    pub dst_addr: Option<String>,
    pub stream_id: Option<u64>,     // TCP stream: FNV hash of sorted 4-tuple
    pub info: String,               // human summary: "GET /api/v1 HTTP/1.1" or "DNS A example.com"
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "layer", content = "fields")]
pub enum LayerData {
    Ethernet(EthernetFields),
    Ipv4(Ipv4Fields),
    Ipv6(Ipv6Fields),
    Tcp(TcpFields),
    Udp(UdpFields),
    Http(HttpFields),       // Phase 3
    Dns(DnsFields),         // Phase 3
    Tls(TlsFields),         // Phase 3
    Raw(Vec<u8>),           // unrecognized payload bytes
}

#[derive(Debug, Clone, Serialize)]
pub struct EthernetFields {
    pub src_mac: String,    // "aa:bb:cc:dd:ee:ff"
    pub dst_mac: String,
    pub ethertype: u16,
    pub ethertype_name: String,  // "IPv4", "ARP", "IPv6"
}

#[derive(Debug, Clone, Serialize)]
pub struct Ipv4Fields {
    pub src: String,        // dotted decimal
    pub dst: String,
    pub ttl: u8,
    pub protocol: u8,
    pub protocol_name: String,  // "TCP", "UDP", "ICMP"
    pub total_len: u16,
    pub flags: Ipv4Flags,
    pub fragment_offset: u16,
    pub checksum: u16,
}

#[derive(Debug, Clone, Serialize)]
pub struct Ipv4Flags {
    pub dont_fragment: bool,
    pub more_fragments: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct TcpFields {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: TcpFlags,
    pub window: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
    pub payload_len: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct UdpFields {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
    pub payload_len: u32,
}

// Phase 3 types — define stubs now, implement later
#[derive(Debug, Clone, Serialize)]
pub struct HttpFields {
    pub method: Option<String>,
    pub path: Option<String>,
    pub status_code: Option<u16>,
    pub status_text: Option<String>,
    pub version: String,
    pub headers: Vec<(String, String)>,
    pub is_request: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct DnsFields {
    pub transaction_id: u16,
    pub is_response: bool,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: String,  // "A", "AAAA", "CNAME", "MX", etc.
}

#[derive(Debug, Clone, Serialize)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: String,
    pub ttl: u32,
    pub data: String,   // human-readable: IP for A, hostname for CNAME
}

#[derive(Debug, Clone, Serialize)]
pub struct TlsFields {
    pub record_type: String,    // "ClientHello", "ServerHello", "Certificate", etc.
    pub tls_version: String,    // "TLS 1.3", "TLS 1.2"
    pub sni: Option<String>,    // Server Name Indication from ClientHello
    pub cipher_suites: Vec<String>,  // human names, not hex
    pub session_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub enum TopProtocol {
    Ethernet, Arp, Ipv4, Ipv6,
    Tcp, Udp, Icmp,
    Http, Https, Dns, Tls,
    Unknown,
}
```

### TypeScript Type Mirrors
```typescript
// src/types/packets.ts — must stay in sync with Rust types above

export interface PacketRecord {
  id: number;
  timestamp_us: number;
  capture_len: number;
  original_len: number;
  interface: string;
  layers: LayerData[];
  protocol: TopProtocol;
  src_addr: string | null;
  dst_addr: string | null;
  stream_id: number | null;
  info: string;
}

export type LayerData =
  | { layer: 'Ethernet'; fields: EthernetFields }
  | { layer: 'Ipv4';     fields: Ipv4Fields }
  | { layer: 'Ipv6';     fields: Ipv6Fields }
  | { layer: 'Tcp';      fields: TcpFields }
  | { layer: 'Udp';      fields: UdpFields }
  | { layer: 'Http';     fields: HttpFields }
  | { layer: 'Dns';      fields: DnsFields }
  | { layer: 'Tls';      fields: TlsFields }
  | { layer: 'Raw';      fields: number[] };

export interface TcpFields {
  src_port: number; dst_port: number;
  seq: number; ack: number;
  flags: TcpFlags; window: number;
  checksum: number; urgent_ptr: number;
  payload_len: number;
}

export interface TcpFlags {
  syn: boolean; ack: boolean; fin: boolean;
  rst: boolean; psh: boolean; urg: boolean;
  ece: boolean; cwr: boolean;
}

export interface UdpFields {
  src_port: number; dst_port: number;
  length: number; checksum: number; payload_len: number;
}

export interface EthernetFields {
  src_mac: string; dst_mac: string;
  ethertype: number; ethertype_name: string;
}

export interface Ipv4Fields {
  src: string; dst: string; ttl: number;
  protocol: number; protocol_name: string;
  total_len: number; flags: { dont_fragment: boolean; more_fragments: boolean };
  fragment_offset: number; checksum: number;
}

export interface HttpFields {
  method: string | null; path: string | null;
  status_code: number | null; status_text: string | null;
  version: string; headers: [string, string][];
  is_request: boolean;
}

export interface DnsFields {
  transaction_id: number; is_response: boolean;
  questions: { name: string; qtype: string }[];
  answers: { name: string; rtype: string; ttl: number; data: string }[];
}

export interface TlsFields {
  record_type: string; tls_version: string;
  sni: string | null; cipher_suites: string[];
  session_id: string | null;
}

export type TopProtocol =
  | 'Ethernet' | 'Arp' | 'Ipv4' | 'Ipv6'
  | 'Tcp' | 'Udp' | 'Icmp'
  | 'Http' | 'Https' | 'Dns' | 'Tls'
  | 'Unknown';

// Connection tracking (built client-side in captureStore)
export interface ConnectionRecord {
  stream_id: number;
  src_addr: string;
  dst_addr: string;
  protocol: 'Tcp' | 'Udp';
  packet_count: number;
  byte_count: number;
  syn_time: number | null;    // timestamp_us of SYN packet
  fin_time: number | null;    // timestamp_us of FIN or RST
  first_seen: number;
  last_seen: number;
}
```

### Tauri Commands & Events

| Name | Type | Direction | Payload | Purpose |
|------|------|-----------|---------|---------|
| `get_interfaces` | Command | FE → Rust | → `InterfaceInfo[]` | List available network interfaces |
| `start_capture` | Command | FE → Rust | `{ interface: string }` → `void` | Start live capture on named interface |
| `stop_capture` | Command | FE → Rust | → `void` | Stop capture, flush remaining buffer |
| `import_file` | Command | FE → Rust | `{ path: string }` → `{ total: number }` | Parse PCAP file, emit batches via event |
| `get_packet` | Command | FE → Rust | `{ id: number }` → `PacketRecord` | Fetch full packet by ID for detail pane |
| `clear_buffer` | Command | FE → Rust | → `void` | Wipe ring buffer, reset counter |
| `export_pcap` | Command | FE → Rust | `{ path: string }` → `{ written: number }` | Export current buffer to .pcap file (Phase 4) |
| `packets_batch` | Event | Rust → FE | `PacketRecord[]` (max 200) | Emitted every 100ms during capture |
| `capture_stats` | Event | Rust → FE | `{ received: number, dropped: number, rate_pps: number }` | Emitted every 1s during capture |
| `import_progress` | Event | Rust → FE | `{ parsed: number, total: number }` | Progress during large file import |

```rust
// InterfaceInfo struct in Rust
#[derive(Debug, Serialize)]
pub struct InterfaceInfo {
    pub name: String,           // "en0", "lo0"
    pub description: String,    // "Wi-Fi", "Loopback"
    pub is_up: bool,
    pub is_loopback: bool,
}
```

### Dependencies

```toml
# src-tauri/Cargo.toml
[dependencies]
tauri = { version = "2", features = ["protocol-asset"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
pcap = "2"
pnet = "0.35"
pnet_datalink = "0.35"
tokio = { version = "1", features = ["full"] }
chrono = { version = "0.4", features = ["serde"] }
```

```bash
# Frontend dependencies
npm install zustand @tanstack/react-virtual

# Dev dependencies (added by Tauri scaffold, verify present)
npm install -D tailwindcss typescript @types/react @tauri-apps/api vite

# System dependency — libpcap ships with Xcode Command Line Tools
xcode-select --install

# Scaffold command (run once to create the project)
npm create tauri-app@latest network-decoder -- --template react-ts
```

---

## Scope Boundaries

**In scope:**
- Live capture from macOS network interfaces (en0, en1, lo0, etc.)
- PCAP (.pcap and .pcapng) file import
- Ethernet, IPv4, IPv6, TCP, UDP, ICMP parsing
- HTTP/1.1 header decoding (Phase 3)
- DNS query/response decoding (Phase 3)
- TLS handshake metadata: SNI, cipher suite, TLS version (Phase 3)
- Three switchable views: Packet List, Swimlane, Protocol Cards
- Layer-by-layer detail pane with hex dump
- TCP stream tracking and reassembly
- Filter bar: proto:, ip:, port:, stream: grammar
- PCAP export of captured session
- macOS only

**Out of scope:**
- TLS payload decryption (requires SSLKEYLOGFILE integration — a separate future project)
- HTTP/2 or HTTP/3 decoding
- Windows or Linux support
- Cloud sync or remote capture
- PCAP editing or packet injection
- Protocol dissectors beyond HTTP/DNS/TLS
- Custom BPF filter compilation (filter is client-side only)

**Deferred to future:**
- SSLKEYLOGFILE integration for TLS decryption
- Windows support (pcap crate supports it; Tauri supports it — just untested)
- Plugin system for custom protocol dissectors
- Capture scheduling / background capture daemon

---

## Security & Credentials

- **No credentials.** No API keys, no user accounts, no tokens.
- **Live capture privilege:** Raw socket access requires root on macOS. For development: `sudo cargo tauri dev`. For distribution: implement a privileged helper binary using macOS `AuthorizationExecuteWithPrivileges` — the main app process must never run as root.
- **Data stays local:** No telemetry, no outbound connections. Lock down Tauri's `allowlist` in `tauri.conf.json` to block all HTTP from the frontend.
- **Sensitive data warning:** Display a dialog on first capture start: "This app captures raw network traffic which may include passwords, tokens, and private data. Only use on networks you own or have permission to monitor."
- **PCAP export permissions:** Write exported files with `0600` permissions (owner read/write only).

---

## Phase 0: Foundation (Week 1, Days 1–3)

**Objective:** Tauri project scaffolded, Rust backend builds cleanly, `pcap` + `pnet` integrated and tested against a real PCAP file, all types defined, TypeScript compiles with 0 errors.

**Tasks:**
1. Scaffold with `npm create tauri-app@latest network-decoder -- --template react-ts` — **Acceptance:** `cargo tauri dev` opens a window with the default React app, no build errors.
2. Add `pcap`, `pnet`, `serde`, `serde_json`, `tokio`, `chrono` to `Cargo.toml` — **Acceptance:** `cargo build` completes with no errors (libpcap found via `xcode-select`).
3. Define all types in `src-tauri/src/parser/types.rs` exactly as specified in this doc — **Acceptance:** `cargo check` passes, no unused-import warnings.
4. Write `parse_packet()` stub in `src-tauri/src/parser/mod.rs` that opens the Wireshark sample `http.cap`, iterates packets, and prints `{id, src, dst}` for the first 5 — run as a `#[test]` — **Acceptance:** `cargo test` prints 5 lines each with valid IPs.
5. Mirror all Rust types in `src/types/packets.ts` exactly as specified in this doc — **Acceptance:** `npx tsc --noEmit` reports 0 errors.
6. Implement `get_interfaces` Tauri command in `commands.rs` — **Acceptance:** `console.log` from `App.tsx` on mount shows array with at least 1 interface entry (en0 or similar).
7. Implement `RingBuffer<T>` in `src-tauri/src/buffer/ring.rs` with `push(item)`, `drain() -> Vec<T>`, `clear()`, `len()` — **Acceptance:** unit test confirms that pushing 50,001 items into a cap-50,000 buffer results in `len() == 50,000` and the oldest item is gone.

**Verification checklist:**
- [ ] `cargo test` → all tests pass, first 5 http.cap packets printed with valid IPs
- [ ] `npx tsc --noEmit` → 0 TypeScript errors
- [ ] `cargo tauri dev` → window opens, browser console shows ≥1 interface name
- [ ] `cargo test ring_buffer` → 50,001 push → len == 50,000, oldest evicted

**Sample PCAP files for testing (download before Phase 0):**
- http.cap: https://wiki.wireshark.org/uploads/27707187aeb30df68e70c8fb9d614981/http.cap
- dns.cap: https://wiki.wireshark.org/uploads/a03e62060ea87d3b43a0c9c26d4fb5c5/dns.cap

**Risks:**
- libpcap not found at compile time → Run `xcode-select --install`; verify with `ls /usr/lib/libpcap.dylib`
- pnet 0.35 API changes → Pin exact version in Cargo.toml; consult https://docs.rs/pnet/0.35.0

---

## Phase 1: Capture Pipeline + Packet List View (Week 1 Day 4 – Week 2)

**Objective:** Live capture and PCAP file import both work end-to-end. Virtualized packet list renders. Detail pane shows layer-by-layer fields. Hex dump shows raw bytes.

**Tasks:**
1. Implement `CaptureSource` trait in `capture/mod.rs` — `fn start(&self, tx: Sender<PacketRecord>)` and `fn stop(&self)` — **Acceptance:** trait compiles; `live.rs` and `file.rs` both implement it.
2. Implement `capture/live.rs` — spawns a Tokio task, reads from `pcap::Capture::from_device`, parses each packet via `parse_packet()`, pushes to ring buffer, drains and emits `packets_batch` event every 100ms — **Acceptance:** starting capture on `en0` for 10 seconds results in ≥1 `packets_batch` event received in React (log it to console).
3. Implement `capture/file.rs` — opens PCAP file via `pcap::Capture::from_file`, parses all packets, emits batches of 200, emits `import_progress` events — **Acceptance:** importing `http.cap` (4,915 packets) emits `import_progress` events and final batch arrives within 5 seconds; packet count logged in React matches 4,915.
4. Implement `parse_packet()` in `parser/mod.rs` → `ethernet.rs` → `ip.rs` → `transport.rs` — dispatch based on ethertype and IP protocol — **Acceptance:** a TCP packet from `http.cap` parses to `PacketRecord` with 3 layers (Ethernet, Ipv4, Tcp), all fields populated with correct values (verify against Wireshark's display of the same packet).
5. Build `usePacketStream.ts` hook — subscribes to `packets_batch` Tauri event, appends to Zustand `packetStore`, maintains client-side 50k ring buffer — **Acceptance:** after `http.cap` import, `packetStore.packets.length === 4915`.
6. Build `PacketListView.tsx` — virtualized table using `@tanstack/react-virtual` with columns: No. / Time / Source / Destination / Protocol / Length / Info — rows colored by `protocolColors.ts` — **Acceptance:** 50,000 synthetic packets render without jank; scroll is smooth at ≥60fps (measure with React DevTools Profiler).
7. Build `DetailPane.tsx` — clicking a row shows layer accordion (Ethernet → IPv4 → TCP/UDP), each field labeled with name + value + byte offset — **Acceptance:** clicking a TCP packet from `http.cap` shows all 3 layers; TCP `flags` section shows SYN/ACK/FIN/RST/PSH as labeled booleans.
8. Build `HexDump.tsx` — 16 bytes per row, hex left + ASCII right, row offsets shown — hovering a layer in DetailPane highlights that layer's byte range in the hex dump — **Acceptance:** hovering the TCP layer highlights bytes 34–53 for a standard Ethernet/IPv4/TCP packet (14 + 20 + 20 bytes).
9. Build `CaptureBar.tsx` — interface dropdown populated from `get_interfaces`, Start/Stop toggle, Import File button (Tauri `dialog.open`) — **Acceptance:** full flow — select en0 → Start → wait 5s → Stop → packet list populated.

**Verification checklist:**
- [ ] Live capture on `en0` → ≥1 packet in list within 10 seconds
- [ ] Import `http.cap` → exactly 4,915 rows in packet list
- [ ] Click TCP packet → DetailPane shows Ethernet + IPv4 + TCP layers with all fields labeled
- [ ] HexDump → hovering TCP layer highlights correct byte range
- [ ] 50k packet scroll → no visible frame drop (React Profiler shows <16ms renders)
- [ ] Protocol colors: DNS rows purple, HTTP rows blue, TCP rows gray, UDP rows orange

**Risks:**
- pcap on macOS requires root for live capture → Development: run `sudo cargo tauri dev`; add note in README. Production: defer privilege escalation helper to Phase 4.
- Tauri event throughput on a busy interface (en0 at a coffee shop can hit 500+ pps) → Hard cap: if ring buffer drains >200 packets in a 100ms window, emit first 200 and discard the rest for that batch. This is acceptable — we show capture_stats.dropped in the UI.
- React hydration lag on large imports → Import fires batches of 200 packets; Zustand append is O(1). If UI still lags, add `startTransition()` around the append.

---

## Phase 2: TCP Stream Tracking + Swimlane View (Weeks 3–4)

**Objective:** TCP streams identified and tracked. Swimlane view renders per-connection timelines. Filter bar narrows packet list.

**Tasks:**
1. Implement `stream_id` in Rust — FNV hash of `(min(src_ip:src_port, dst_ip:dst_port), max(...))` so both directions of a connection share one ID — **Acceptance:** `http.cap` import produces ≤20 unique stream IDs; verify 2 consecutive packets in same HTTP exchange share a stream ID.
2. Build `ConnectionRecord` tracking in `captureStore.ts` — maintain `Map<stream_id, ConnectionRecord>` updated on each `packets_batch` event; set `syn_time` on SYN packets, `fin_time` on FIN or RST — **Acceptance:** after `http.cap` import, store contains ≥5 `ConnectionRecord` entries with `syn_time` and `fin_time` populated.
3. Build `SwimLaneView.tsx` — SVG-based, horizontal lane per connection, x-axis = relative time in ms, each packet = a vertical tick mark colored by `TopProtocol`, lane label = `src:port → dst:port` — **Acceptance:** `http.cap` renders ≥5 lanes; clicking a tick selects that packet (updates selected packet ID in shared state → DetailPane updates).
4. Build `FilterBar.tsx` with grammar: `proto:tcp`, `ip:192.168.1.1`, `port:80`, `stream:5` — filter runs as a Zustand selector, not a new API call — **Acceptance:** `port:80` on `http.cap` import reduces visible packets to only port-80 TCP packets; `proto:tcp` shows all TCP; clearing filter restores all.
5. Add TCP flag badges to `DetailPane.tsx` — SYN/ACK/FIN/RST/PSH shown as colored pill badges (green=set, gray=unset) — **Acceptance:** a SYN-ACK packet shows green SYN + green ACK badges, gray FIN/RST/PSH.
6. Add `ViewSwitcher.tsx` — three-way toggle (List / Swimlane / Cards) in the toolbar — switching updates shared view state, no data re-fetch required — **Acceptance:** all three view switches complete in <200ms (measure with Performance tab in DevTools).

**Verification checklist:**
- [ ] Import `http.cap` → SwimLaneView shows ≥5 distinct swimlanes
- [ ] Click swimlane tick → DetailPane updates to show that packet's layers
- [ ] Filter `port:80` on `http.cap` → only port-80 packets visible
- [ ] Filter `proto:dns` on a live capture → only DNS packets visible
- [ ] View switch List ↔ Swimlane ↔ Cards → all complete in <200ms

**Risks:**
- SVG performance with 4,915 ticks → Use `<canvas>` instead of SVG if >1,000 ticks makes SwimLane sluggish. Fallback: virtualize by only rendering ticks within the visible time window (pan/zoom).

---

## Phase 3: Application-Layer Protocol Decoding (Weeks 5–6)

**Objective:** HTTP/1.1 headers, DNS queries/responses, and TLS handshake metadata decoded and displayed in ProtocolCardView with human-readable field explainers.

**Tasks:**
1. Implement TCP stream reassembly buffer in `application.rs` — per-stream `HashMap<u64, Vec<u8>>` payload accumulator; attempt HTTP parse when PSH flag is set — **Acceptance:** `http.cap` yields ≥1 `PacketRecord` with `LayerData::Http` containing method, path, and ≥3 headers (verify the first GET request).
2. Implement DNS parser in `application.rs` — manual byte parsing, no external crate — parse question section (QNAME, QTYPE) and answer section (NAME, TYPE, TTL, RDATA for A/AAAA/CNAME) — **Acceptance:** a live DNS `A` record lookup for any domain parses to `DnsFields` with correct `query` name and ≥1 answer IP.
3. Implement TLS handshake parser — identify TLS record type (22 = Handshake), parse ClientHello (type 1) to extract SNI from extension type 0, cipher suites list (map hex codes to IANA names), TLS version — **Acceptance:** connecting to any HTTPS site while capturing yields a `TlsFields` record with non-null `sni` and ≥5 named cipher suites.
4. Build `ProtocolCardView.tsx` — responsive card grid, one card per unique connection/protocol combination — HTTP card (method, path, status, headers), DNS card (question, answers, RTT), TLS card (SNI, version, cipher suites), TCP/UDP card (4-tuple, flags, byte counts) — **Acceptance:** importing `http.cap` shows ≥1 HTTP card with correct method + path + status code.
5. Build `FieldExplainer.tsx` — tooltip component triggered on hover over any field label — contains plain English explanation of what each field means — implement for: TCP flags, IP TTL, TCP window, DNS TTL, TLS SNI, HTTP status codes — **Acceptance:** hovering TCP `window` field shows "How much data the receiver can accept before the sender must pause and wait for an acknowledgement."

**Cipher suite name map (partial — implement full IANA list):**
```typescript
// src/lib/cipherSuites.ts
export const CIPHER_SUITE_NAMES: Record<number, string> = {
  0x1301: 'TLS_AES_128_GCM_SHA256',
  0x1302: 'TLS_AES_256_GCM_SHA384',
  0x1303: 'TLS_CHACHA20_POLY1305_SHA256',
  0xC02B: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
  0xC02C: 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
  0xC02F: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
  0xC030: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
  // ... continue with full IANA list
};
```

**Verification checklist:**
- [ ] Import `http.cap` → ProtocolCardView shows ≥1 HTTP card with method + path + status
- [ ] Live capture + `dig example.com` → DNS card shows question "example.com A" and answer IP within 3 seconds
- [ ] Live capture + open any HTTPS URL → TLS card shows SNI hostname (not null) and ≥5 named cipher suites
- [ ] FieldExplainer appears within 300ms of hovering any labeled field
- [ ] TLS card never shows decrypted payload (encrypted data must show "Encrypted — payload not visible")

**Risks:**
- HTTP reassembly fails on chunked encoding or compressed bodies → Scope to header parsing only (Content-Length/Transfer-Encoding header tells us where headers end); don't attempt body decoding.
- TLS 1.3 encrypts most of the handshake beyond ClientHello → SNI + cipher suites from ClientHello are still visible in cleartext; ServerHello parameters are available in TLS 1.3 before encryption. Document this limitation in the UI.

---

## Phase 4: Polish + Packaging (Week 7)

**Objective:** App packaged as a macOS .dmg. PCAP export works. Keyboard shortcuts. Onboarding flow. Portfolio-ready README with screenshots.

**Tasks:**
1. Implement `export_pcap` Tauri command — writes current ring buffer to `.pcap` file using libpcap's write API — **Acceptance:** exported file re-imports into the same app with same packet count ±0; also opens in Wireshark with valid packets.
2. Add keyboard shortcuts — `Space` = start/stop capture, `Cmd+O` = import file, `1` / `2` / `3` = switch views, `Cmd+F` = focus filter bar, `Esc` = clear filter — **Acceptance:** all shortcuts work when no input element is focused; `Cmd+F` focuses filter bar without triggering browser find.
3. Build first-launch onboarding — shown once (persisted in Tauri store), 3-step modal: (1) select interface, (2) click Start, (3) click a packet — dismissible, re-triggerable via Help menu — **Acceptance:** a new user following onboarding can capture and decode their first packet in ≤60 seconds.
4. Add privilege escalation warning dialog — shown before first live capture attempt, explains root requirement, offers "Open with elevated privileges" — **Acceptance:** dialog appears on first Start click; user can dismiss and proceed (accepting the sudo workflow for now).
5. Package with `cargo tauri build` — ad-hoc code signing for local distribution — **Acceptance:** generated `.dmg` in `src-tauri/target/release/bundle/dmg/` installs and runs on a fresh macOS session after manual "Open Anyway" in Security & Privacy.
6. Write README.md — setup instructions, system requirements (Xcode CLT, macOS 13+), demo walkthrough with 3 screenshots, link to Wireshark sample PCAP files, known limitations (TLS payload, root for live capture) — **Acceptance:** a developer with no prior context can build and run the app following only the README, verified by following it fresh in a new terminal session.

**Verification checklist:**
- [ ] Export current session → re-import → packet count matches exactly
- [ ] Exported .pcap opens in Wireshark without "malformed" errors
- [ ] All 5 keyboard shortcuts work without any input focused
- [ ] `.dmg` installs and launches on a clean macOS session
- [ ] README setup instructions run without errors end-to-end in a fresh terminal

---

## Protocol Color Reference
```typescript
// src/lib/protocolColors.ts
export const PROTOCOL_COLORS: Record<TopProtocol, { bg: string; text: string }> = {
  Http:     { bg: 'bg-blue-900',   text: 'text-blue-300' },
  Https:    { bg: 'bg-blue-900',   text: 'text-blue-300' },
  Dns:      { bg: 'bg-purple-900', text: 'text-purple-300' },
  Tls:      { bg: 'bg-teal-900',   text: 'text-teal-300' },
  Tcp:      { bg: 'bg-gray-800',   text: 'text-gray-300' },
  Udp:      { bg: 'bg-orange-900', text: 'text-orange-300' },
  Icmp:     { bg: 'bg-yellow-900', text: 'text-yellow-300' },
  Ipv4:     { bg: 'bg-gray-800',   text: 'text-gray-400' },
  Ipv6:     { bg: 'bg-gray-800',   text: 'text-gray-400' },
  Arp:      { bg: 'bg-green-900',  text: 'text-green-300' },
  Ethernet: { bg: 'bg-gray-800',   text: 'text-gray-400' },
  Unknown:  { bg: 'bg-gray-900',   text: 'text-gray-500' },
};
```

---

## Test PCAP Files
Download before starting Phase 0:
- **http.cap** (4,915 packets, HTTP/1.1): https://wiki.wireshark.org/uploads/27707187aeb30df68e70c8fb9d614981/http.cap
- **dns.cap** (DNS queries/responses): https://wiki.wireshark.org/uploads/a03e62060ea87d3b43a0c9c26d4fb5c5/dns.cap
- **TLS sample**: Capture your own by running `curl https://example.com` while the app is capturing — TLS 1.3 ClientHello is always visible in cleartext
