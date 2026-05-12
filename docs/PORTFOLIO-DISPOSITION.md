# NetworkDecoder — Portfolio Disposition

**Status:** Release Frozen — Tauri 2 + Rust packet engine + React +
TypeScript macOS-only packet decoder at **v1.0.0** on `origin/main`,
with .dmg distribution build dependencies, baseline Rust tests for
parser modules and ring buffer, CSP hardened Tauri webview, full OSS
scaffolding wave, and a single comprehensive feat commit covering
Phases 0-4 (Ethernet → HTTP/DNS/TLS decoding + Wireshark-style packet
list + per-connection swimlane timeline + protocol card summaries).
Joins the signing cluster as the **24th member**. Same v1.0.0
release closeout cadence as APIReverse (R12.5) — Tauri 2 + Rust +
React + .dmg build deps + baseline tests + CSP = "ready to sign and
ship" signature is now stable across two signing cluster members.

> Disposition uses strict `origin/main` verification.
> **Confirms the Tauri 2 v1.0 release closeout signature** by
> applying it to a second app from the same shape.

---

## Verification posture

This repo has **only `origin`** (`saagpatel/NetworkDecoder`) — no
`legacy-origin` remote. Clean migration state. Local clone's `main`
is tracking `origin/main` correctly.

Specifically verified on `origin/main`:

- Tip: `458bc46` chore: update build dependencies for .dmg
  distribution
- **v1.0.0 release closeout cadence**:
  - `458bc46` chore: update build dependencies for .dmg distribution
  - `f430505` chore: update Cargo.lock for version 1.0.0
  - `2fd9f74` test: add baseline Rust tests for parser modules and
    ring buffer
  - `0c1d906` chore: bump version to 1.0.0
  - `58edd7f` fix(security): add Content Security Policy to Tauri
    webview
- **Phase 0-4 monolithic feat commit**:
  - `f00362d feat: complete Network Protocol Decoder (Phases 0-4)`
- **OSS scaffolding wave** on canonical main: CHANGELOG, PR
  template, issue templates, CoC, Makefile, .env.example,
  Dependabot, contributing, security policy, MIT license, README
  docs
- `init: empty main branch` at `43f3a06` — repo was bootstrapped
  empty then filled with the single Phase 0-4 feature commit
- Default branch: `main`

---

## Current state in one paragraph

NetworkDecoder is a macOS-only Tauri 2 desktop app that captures
live network traffic or imports PCAP files and decodes packets
layer-by-layer from Ethernet through HTTP / DNS / TLS. Three
viewing modes: **Wireshark-style packet list** (familiar),
**per-connection swimlane timeline** (novel; visualizes connection
duration and parallelism), and **protocol card summaries** (high-
level digest). Rust does the heavy packet engine work (parser
modules + ring buffer with baseline tests); React + TypeScript
handles the UI. Per memory: Phases 0-4 complete. README status
badge says "Work in Progress — PCAP export and live-capture UI in
progress" — same stale-badge pattern as APIReverse. Canonical
commit cadence (v1.0.0 bump + Cargo.lock + .dmg build deps + CSP
+ baseline Rust tests) is the v1 release closeout, not in-flight.
Operator-side work remaining: Apple Developer ID signing +
notarization + privileged-network-access UX (ChmodBPF / TCC) +
DMG distribution.

For full detail see `README.md` on `origin/main`.

---

## Why "Release Frozen" — second confirmation of Tauri 2 v1.0 signature

The cadence pattern observed in APIReverse repeats:

| Signal | APIReverse | **NetworkDecoder** |
|---|---|---|
| Tauri 2 + Rust + React | ✓ | ✓ |
| v1.0.0 version bump | `aa5c068` | `0c1d906` |
| Cargo.lock for v1.0.0 | `a253deb` | `f430505` |
| .dmg distribution build deps | `995bb8a` | `458bc46` |
| Baseline Rust tests | `838df63` | `2fd9f74` |
| CSP on Tauri webview | `a4328ff` | `58edd7f` |
| Full Tauri icon set | `ae15099` | (implicit in Phase 0-4 commit) |
| Stale "WIP" README badge | ✓ | ✓ |
| OSS scaffolding wave | ✓ | ✓ |
| Extension sub-shape | ✓ (alternate capture) | None — pure Tauri |

**Conclusion: the Tauri 2 v1.0 release closeout signature is
stable.** Future Tauri 2 apps in the portfolio (Interruption
Resume Studio, LifeCadenceLedger, Pulse Orbit, ReturnRadar,
thought-trails per memory) can be classified by this signature on
inspection.

NetworkDecoder is **distinguished from APIReverse by NOT having an
extension sub-shape** — pure Tauri DMG, no browser-extension
alternate capture surface. This shows the signing cluster's
"hybrid signing+extension" sub-shape (introduced in APIReverse) is
**optional**, not a cluster-wide trait.

---

## Cluster taxonomy update

| Cluster | Count | Sub-shapes / notes |
|---|---|---|
| **Signing (Apple desktop)** | **24** | (no formal sub-shapes; APIReverse is the only hybrid-extension variant) |
| iOS App Store | 5 | local-first (4) / cloud-backed (1) |
| Static-host (web) | 3 sub-shapes | … |
| Self-hosted service | 1 | (n/a) |
| PyPI distribution | 2 | Release Frozen / Active |
| Local-first pipeline | 1 | (n/a) |
| Operator-tool / dogfood | 1 | (n/a) |
| Chrome MV3 extension | 2 | vanilla / React + AI-API |

Signing cluster is at 24 with the v1.0 signature stable. Remaining
Tauri 2 candidates (~6 per memory) likely batch here on inspection.

---

## Unblock trigger (operator)

When ready to ship publicly:

1. **Apple Developer ID + notarization credentials wired.** Standard
   signing cluster prerequisite.
2. **macOS privileged network access UX — load-bearing.** Packet
   capture on macOS requires one of:
   - **ChmodBPF helper** (the Wireshark approach — install a small
     setuid helper that grants packet capture access to the user).
     Requires admin password on install. Industry standard.
   - **Sudo wrapper** (run the capture engine as root). Operationally
     ugly; security review will flag.
   - **TCC entitlement** (com.apple.security.network.client +
     com.apple.security.network.server + custom entitlements). May
     not fully unlock pcap-level access; depends on macOS version.
   Decide before signing. ChmodBPF helper is the recommended path;
   document the install flow in onboarding.
3. **PCAP file format support** — verify export / import handles
   both standard pcap and pcapng formats. Wireshark interop matters
   for credibility.
4. **TLS decryption posture** — does NetworkDecoder decrypt TLS at
   all? If it imports SSLKEYLOGFILE-style key logs from a browser,
   document this. If it doesn't decrypt TLS, document that too —
   users will ask.
5. **macOS 13+ minimum** — README states this; verify the
   xcodeproj / Tauri config matches.
6. **Privacy posture** — packet capture sees everything the user's
   machine transmits. Document: nothing leaves the user's machine
   (local-only), no telemetry, no analytics. Strong privacy
   statement justified.
7. **Verify signed/notarized DMG** opens cleanly with no Gatekeeper
   warnings.
8. **Cut v1.0.0 release tag.**

Estimated operator time once Apple credentials exist: ~4-5 hours
(ChmodBPF helper or equivalent privileged-access UX is the
dominant cost; signing + notarization is mechanical).

---

## Portfolio operating system instructions

| Aspect | Posture |
|---|---|
| Portfolio status | `Release Frozen` |
| Distribution channel | **DMG via Apple Developer ID + notarization** |
| Current version | **v1.0.0** |
| Platform | macOS 13+ only (per README) |
| Review cadence | Suspend overdue counting |
| Resurface conditions | (a) Apple signing credentials wired, (b) ChmodBPF / privileged-access UX finalized, (c) PCAP export / live-capture UI polish (README flagged as "in progress" — but commits show Phase 0-4 done; resolve doc/code drift), or (d) v1.1 scope (more protocol decoders, Linux/Windows port) |
| Co-batch with | Signing cluster: … APIReverse / **NetworkDecoder** — **now 24 repos** |
| Special concern | **macOS privileged packet capture UX.** ChmodBPF helper install flow needs explicit user consent + admin password explanation. This is the dominant ship-readiness path. |
| Special concern | **TLS decryption posture must be documented.** Users will ask whether the tool decrypts HTTPS (it doesn't, based on the description — it parses raw packets). Set expectations clearly. |
| Special concern | **PCAP / pcapng interop.** Wireshark compatibility is the credibility benchmark for any packet decoder. Verify import/export with current Wireshark stable. |
| Special concern | **Privacy statement.** Packet capture inherently sees everything. Strong "local-only, no telemetry" statement is justified and trust-building. |
| Special concern | **README "WIP" badge is stale.** Refresh in v1.1 polish (same as APIReverse). |

---

## Why this row stabilizes the Tauri 2 v1.0 signature

APIReverse (R12.5) was the first Tauri 2 app audited with the
v1.0.0 release closeout signature (`aa5c068 bump to 1.0.0` +
Cargo.lock + .dmg deps + tests + CSP + icon set). NetworkDecoder is
the second app to follow the **exact same release closeout
pattern** with the same 5-6 commits in the same order:

1. Phase 0-4 feat (sometimes monolithic, sometimes split)
2. Stale "WIP" README badge persists from pre-v1.0
3. CSP hardened
4. v1.0.0 version bump
5. Cargo.lock updated for v1.0.0
6. Baseline Rust tests for the core engine
7. .dmg distribution build deps

This signature is now reliable enough to **classify remaining Tauri
2 apps by quick scan** rather than per-app investigation:

- If the repo shows this commit pattern → Release Frozen signing
  cluster member, operator-blocked on signing + sometimes a
  domain-specific UX path (CA for APIReverse, ChmodBPF for
  NetworkDecoder, accessibility/screen-recording for GlassLayer).
- If the repo shows scaffolding cadence only (no v1.0.0 bump) →
  Active or scaffold-stop.

This is the same kind of cluster maturation that the iOS App Store
cluster reached at 5 members.

---

## Reactivation procedure (for the next code session)

1. Verify `git branch -vv` shows `main` tracking `origin/main`.
   Already correct as of this disposition pass.
2. Review the local stash (`r13-networkdecoder-stash`) — contains
   modifications to `CLAUDE.md` and `package-lock.json` plus
   untracked `.claude/`, `.codex/`, `AGENTS.md`, `pnpm-lock.yaml`.
   **`pnpm-lock.yaml` is untracked but `package-lock.json` is
   modified** — operator may be migrating from npm to pnpm. Decide
   before committing further.
3. **Reconcile README "WIP" badge** with v1.0.0 reality. Either:
   - Refresh README to reflect v1.0 release state, or
   - Document precisely what's not in v1.0 (PCAP export? live-
     capture UI polish?) so the badge is honest.
4. Re-run `cargo test` to confirm baseline Rust tests still pass.
5. Re-run `pnpm tauri build` (or npm equivalent) to confirm
   toolchain.
6. **Manually verify packet capture** — needs admin / ChmodBPF.
   Don't ship without testing on a clean macOS user account.
7. **Test PCAP import** against a Wireshark-generated sample to
   verify interop.

---

## Last known reference

| Field | Value |
|---|---|
| `origin/main` tip | `458bc46` chore: update build dependencies for .dmg distribution |
| Last substantive commit | `2fd9f74` test: add baseline Rust tests for parser modules and ring buffer |
| Default branch | `main` |
| Build system | **Tauri 2 + Rust + React + TypeScript** |
| Version | **v1.0.0** (bumped + Cargo.lock updated + .dmg deps + baseline tests + CSP) |
| Phases shipped | 0-4 in single `f00362d` feat commit + v1.0 release closeout cadence |
| Platform | macOS 13+ only |
| Capture model | Live network capture (requires ChmodBPF / privileged access) + PCAP file import |
| Decoders | Ethernet → IP → TCP/UDP → HTTP / DNS / TLS (parse, not decrypt) |
| Viewing modes | Wireshark-style packet list + per-connection swimlane timeline + protocol card summaries |
| Release scaffolding | **`.dmg` build deps + Cargo.lock at 1.0.0 + baseline Rust tests + CSP + Tauri icon set + CHANGELOG + SECURITY.md** |
| Blocker | Apple signing + ChmodBPF helper UX + README/code drift reconciliation (operator-only) |
| Migration state | **No `legacy-origin` remote** — clean |
| Distinguishing feature | **24th signing cluster member. Confirms the Tauri 2 v1.0 release closeout signature is stable** across two apps (APIReverse + NetworkDecoder). Remaining Tauri 2 candidates can be classified by quick scan. |
