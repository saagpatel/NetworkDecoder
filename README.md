# Network Protocol Decoder

A macOS desktop app that captures network packets from live interfaces or imported PCAP files, decodes them layer by layer (Ethernet -> IP -> TCP/UDP -> HTTP/DNS/TLS), and presents them in three visual modes. Built with Rust and React.

## Screenshots

*Import a PCAP file or start a live capture to see decoded packets in the List, Swimlane, or Protocol Cards view.*

## Features

- **Live Capture** -- Capture packets from any network interface (requires elevated privileges)
- **PCAP Import/Export** -- Open .pcap and .pcapng files; export captured sessions
- **Layer-by-Layer Decoding** -- Ethernet, IPv4, TCP, UDP, HTTP/1.1 headers, DNS queries/responses, TLS handshake metadata
- **Three Views** -- Packet List (Wireshark-style table), Swimlane (per-connection timeline), Protocol Cards (application-layer summaries)
- **Detail Pane** -- Field-by-field breakdown with plain-English explanations on hover
- **Hex Dump** -- Raw bytes with layer-aware highlighting
- **Filter Bar** -- Client-side filtering: `proto:tcp`, `ip:192.168.1.1`, `port:443`, `stream:5`
- **TCP Stream Tracking** -- Bidirectional connection identification via FNV hash

## System Requirements

- macOS 13+ (Ventura or later)
- Xcode Command Line Tools (`xcode-select --install`)
- Rust 1.77+ (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)
- Node.js 18+ and npm

## Setup

```bash
git clone <repo-url> && cd NetworkDecoder
npm install
```

### Development

```bash
# Without live capture (PCAP import only)
npm run tauri dev

# With live capture (requires root for raw socket access)
sudo npm run tauri dev
```

### Build

```bash
npm run tauri build
# Output: src-tauri/target/release/bundle/dmg/Network Decoder.dmg
```

## Usage

1. **Import a PCAP** -- Click "Import File" or press `Cmd+O`, select a .pcap/.pcapng file
2. **Browse packets** -- Scroll the packet list; rows are color-coded by protocol
3. **Inspect a packet** -- Click any row to see decoded layers and hex dump below
4. **Switch views** -- Use the List/Swimlane/Cards toggle or press `1`/`2`/`3`
5. **Filter** -- Type in the filter bar (`Cmd+F`): `proto:dns`, `port:443`, `ip:10.0.0.1`
6. **Export** -- Click "Export" or press `Cmd+E` to save the current session as .pcap

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Space` | Stop active capture |
| `Cmd+O` | Import PCAP file |
| `Cmd+E` | Export PCAP file |
| `Cmd+F` | Focus filter bar |
| `Esc` | Clear filter |
| `1` / `2` / `3` | Switch to List / Swimlane / Cards view |

## Sample PCAP Files

- [http.cap](https://wiki.wireshark.org/uploads/27707187aeb30df68e70c8fb9d614981/http.cap) -- HTTP/1.1 traffic (43 packets)
- [dns.cap](https://wiki.wireshark.org/uploads/a03e62060ea87d3b43a0c9c26d4fb5c5/dns.cap) -- DNS queries and responses

## Tech Stack

- **Rust** -- Packet capture (libpcap), parsing (pnet), ring buffer
- **Tauri 2** -- Desktop shell, IPC bridge
- **React 19** -- UI components
- **TypeScript** -- Strict mode throughout
- **Zustand** -- State management
- **@tanstack/react-virtual** -- Virtualized packet list (50k+ packets)
- **Tailwind CSS 4** -- Styling

## Known Limitations

- **TLS decryption** -- Only handshake metadata (SNI, cipher suites) is visible; payload decryption requires SSLKEYLOGFILE integration (not implemented)
- **Root required** -- Live capture needs `sudo` on macOS; a privilege helper binary is planned for future releases
- **macOS only** -- The pcap and Tauri dependencies support other platforms, but only macOS is tested
- **HTTP/1.1 only** -- HTTP/2 and HTTP/3 are not decoded
- **No packet editing** -- This is a read-only analyzer; packet injection is out of scope

## License

MIT
