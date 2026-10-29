# Meridian Protocol

> High-performance, anti-detection secure proxy protocol  
> Inspired by Shadowsocks, Hysteria2, VLESS, and REALITY

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/peterxulove/meridian)](https://github.com/peterxulove/meridian/releases)
[![Platform](https://img.shields.io/badge/Platform-macOS%20%7C%20Linux-lightgrey)](https://github.com/peterxulove/meridian/releases)
[![Architecture](https://img.shields.io/badge/Arch-ARM64%20%7C%20AMD64-orange)](https://github.com/peterxulove/meridian/releases)

[中文 README](README.md)

---

## Table of Contents

- [Introduction](#introduction)
- [Changelog](#changelog)
- [Protocol Architecture](#protocol-architecture)
- [Features](#features)
- [Quick Start](#quick-start)
- [LAN Proxy Usage](#lan-proxy-usage)
- [Configuration](#configuration)
- [Security Mechanism](#security-mechanism)
- [Build](#build)
- [Download Prebuilt Binaries](#download-prebuilt-binaries)
- [Development](#development)

---

## Introduction

Meridian is a custom secure proxy protocol designed to deliver **undetectable encrypted communication** under hostile network conditions.

| Goal | Metric |
|------|--------|
| Anti-detection | Traffic indistinguishable from standard HTTPS/HTTP3 |
| Low latency | Handshake < 50ms, 0-RTT session resumption supported |
| High throughput | Theoretical 95%+ of link bandwidth |
| Robustness | Works across NAT, firewalls, and congested networks |
| Forward secrecy | Independent ephemeral keys per connection |
| Memory usage | < 512KB per connection on the server side |

---

## Changelog

### v1.6.9 (2026-10-30)

#### 🐛 Fix: three problems that all look like "playback interrupted"

1. **Happy Eyeballs was lost (regression from v1.6.8).** Caching DNS meant
   resolving first and dialling addresses in order, so a host that resolves to
   a blackholed IPv6 waited the full 10 s timeout before IPv4 was even tried,
   then failed overall. `speedtest.tele2.net` reproduces it on the server: IPv6
   connect times out, IPv4 is fine, and through the tunnel it became "hang for
   10 s, then error". Addresses are now raced in parallel (IPv4 first, 200 ms
   stagger), so a blackholed address costs 200 ms instead of everything.
2. **Flow control reset a stream after 60 s without credit.** A player stops
   reading when its buffer is full; pausing for a minute made the server reset
   the stream, which shows up as an interruption with nothing in the logs.
   Raised to 10 minutes, and resets now log their reason (`downlink stalled` /
   `uplink stalled`).
3. **A lane was force-closed 5 minutes after its lifetime.** When
   `session_lifetime` expired the lane stopped taking new streams but was
   closed after at most 5 minutes regardless, cutting whatever was playing on
   it — with four lanes that is an interruption roughly every 15 minutes. It
   now waits for idle, with a 30 minute hard cap and a log line when it fires.

#### 🔍 Diagnostics

Flow-control stalls, buffer overflows and forced lane closes now log
explicitly, so a future interruption can be attributed to the protocol or to
the upstream instead of guessed at.

### v1.6.8 (2026-10-30)

#### 🚀 Faster playback start: early data + server-side DNS cache

Measured against an 85 ms path, a new connection used to cost:

| Stage | Before | Why |
|-------|--------|-----|
| SOCKS CONNECT → tunnel confirmation | 126 ms | the client waited for the server's dial before replying |
| TLS handshake | 129 ms | one round trip, as expected |
| First byte | 125 ms | one round trip, as expected |

Two changes:

- **Early data (handshake version 3)**: the server registers the stream (queue
  and flow window) as soon as it parses CONNECT and dials asynchronously; the
  client no longer waits for `CONNECT SUCCESS`, so the local proxy answers the
  application immediately and its first bytes (usually the TLS ClientHello)
  travel in parallel with the dial. One round trip saved per new connection
  (~90 ms on an 85 ms path). A failed dial is reported as `CONNECT failed` +
  `RESET`, which the application sees as a mid-transfer close.
- **Server-side DNS cache (60 s TTL, concurrent lookups collapsed)**: a player
  opens several connections to `rr*.googlevideo.com` hosts it has not used
  yet, and each one used to pay a cold lookup (measured 130–160 ms) on the
  server. Now a host is resolved once a minute, and a failed dial invalidates
  the entry immediately.

Compatibility: version 3 is only sent to clients advertising `0x08 FLOW`; old
clients read it as ">= 2" and never pipeline; a new client talking to a
version 2 server falls back to waiting for the confirmation. All three
combinations were tested.

Local 8-way concurrency (4 full speed + 4 rate-limited): 8/8 checksums matched,
zero `stalled` events.

### v1.6.7 (2026-10-29)

#### 🐛 Fix: `transport: QUIC` still opened a plaintext TCP tunnel port

The server's `Start()` switch had no `QUIC` case, so a QUIC-only config fell
into `default` and opened a **plaintext TCP tunnel listener** next to the
UDP/QUIC one:

- Any scanner connecting to that port was treated as a tunnel handshake — a
  clear DPI fingerprint that a QUIC-only server would never produce.
- It left an unauthenticated cleartext entry point in a deployment that asked
  for QUIC only.

`QUIC` now binds UDP only. `QUIC+WebSocket`, `WebSocket` and `HTTP-POST` are
unchanged; `default` (a config with no `transport` key) keeps the legacy
behaviour.

Verified: with `transport: QUIC` only a UDP socket is bound, `nc -z` on the TCP
port fails, and an 8 MB end-to-end transfer matches checksums.

#### 🔧 Deploy script: `optimize` no longer overrides the transport

`./deploy.sh optimize` used to write `QUIC+WebSocket` for servers and
`WebSocket` for clients unconditionally, so every tuning run quietly moved a
QUIC deployment back to the TCP path. It now only writes a default when the
`transport` key is missing, and preserves an explicit choice. (Script change
only — it ships on `main`, no new binary.)

### v1.6.6 (2026-10-29)

#### 🐛 Fix: slow-consumer false positive truncated streams

Production logs after v1.6.5 showed `stream N consumer stalled, resetting`, which surfaced as occasional video errors and truncated downloads. The stall test counted **frames**, not bytes: the queue was sized `window / 60 KiB`, i.e. 25 slots for a 1 MiB window, while DATA frames on a fast link are commonly 1–2 KiB. A ~35 KB burst therefore looked "stalled" and reset the stream long before the 1 MiB window could ever apply backpressure.

- The threshold is now `stream_window + 4 × 60 KiB` **bytes**. Flow control already caps in-flight bytes at the window, so only a consumer that truly stopped reading can reach it.
- The frame channel is a fixed 1024-slot hand-off buffer and no longer carries backpressure, so bursts of small frames cannot reset a healthy stream.
- The server applies the same byte accounting on the write-to-target direction.
- A reset still affects only its own stream; the shared read loop never blocks on one slow consumer.

Verified locally (hybrid listener, `stream_window: 262144`): four full-speed plus four rate-limited 20 MB downloads, three runs — **24/24 checksums matched**, zero `stalled` events.

No wire change; interoperates with v1.6.5 and v1.6.4.

### v1.6.5 (2026-10-29)

#### 🚀 Per-stream ACK flow control (wire v2)

A saturated WebSocket lane used to queue small responses behind bulk data — measured 1.3 s median / 2.2 s p90 TTFB for a new request while four bulk streams ran. Each stream is now credit-windowed in both directions:

- A sender may have at most `stream_window` unacknowledged bytes in flight; the receiver returns cumulative `ACK` frames (one per `window/8` bytes consumed, bounded to 16–256 KiB).
- Queueing delay is bounded by roughly `window / link rate` (1 MiB at 150 Mbps ≈ 55 ms) while per-stream throughput stays `window / RTT`.
- ACKs are cumulative and clamped to bytes actually sent, so duplicates or reordering cannot over-credit a stream; a stream with no credit for 60 s is reset.
- **Backward compatible**: support is advertised with the `0x08` ClientHello flag and confirmed by version 2 in ServerHello. An older server ignores the bit and answers version 1, so both sides fall back to the unlimited behaviour instead of stalling.

#### 🐛 Fixes

- Fixed a race where `RESET` could win over the last queued frame and silently truncate the tail of a stream (observed as a missing ~20 KB under parallel load).

### v1.6.4 (2026-10-29)

#### 🔧 Config keys that finally do something

`stream_window`, `max_concurrent_streams` and `session_lifetime` were parsed but never read. All three are wired up now:

- **`stream_window`**: converts a byte budget into per-stream downlink queue depth (`window / 60 KiB`, clamped to 64–1024 frames). Same maths on both ends, default 8 MiB. (Redefined as an in-flight byte window in v1.6.5; local buffering is byte-accounted since v1.6.6.)
- **`max_concurrent_streams`**: per-tunnel stream cap. The client retries a saturated lane on another one; the server answers `server busy` instead of letting a single client exhaust its file descriptors. The local proxy listener is sized as `max_concurrent_streams × tunnel_connections`, bounded to 512–4096.
- **`session_lifetime`**: a lane that reaches its lifetime drains — it stops taking new streams, closes once the remaining ones finish (or after a 5 minute grace), and reconnects, refreshing the outer TCP/TLS connection. `0` disables recycling.

#### 🚀 Deployment

- New `./deploy.sh transport client|server [quic|websocket|hybrid|http-post]` (also menu item 9): changes only transport-specific keys, keeps password, SPKI, certificates and listen port, and rolls back if the service fails to start.
- `./deploy.sh optimize` now also writes `stream_window: 1048576` and `max_concurrent_streams: 512`.
- Default release version is `v1.6.4`.

### v1.6.0 (2026-10-21)

#### 🔒 Security Fixes

- **Password auth on the TCP tunnel**: the TCP path never checked the password (only Hysteria's UDP path did), which made the server an open proxy. ClientHello now carries a `0x0007 AUTH` extension and the server verifies an HMAC-SHA256 tag bound to timestamp + client random + ECDHE, with replay protection and a 120s window.
- **Control-frame type fix**: `Encode()` always wrote `TypeDATA`, so `PING`/`PONG`/`RESET` leaked into the `Flags` field and the peer never saw a typed control frame. Added `EncodeType()`.

#### ✨ New Features

- **HTTP-POST server implementation**: the transport previously had only a client, so `transport: "HTTP-POST"` never worked server-side. Sessions are now reconstructed from many short requests (`Mir-Session` header, downlink on the response body, `Mir-Poll` long-poll, idle reaping).
- **Keepalive actually works**: the client sends PING every `keepalive_interval`, the server answers with PONG, the client logs and skips them.
- **Padding / jitter / direction balancing wired up**: these config options used to be dead code. Both ends now honour them; a zero-value `PaddingConfig` (missing `padding_mode`) is no longer misread as "padding enabled", which silently broke interop.
- **Real TLS fingerprints**: `ApplyFingerprint()` now genuinely rewrites the `*tls.Config` instead of being a no-op; a server with no configured cert now generates an ECDSA P-256 self-signed certificate instead of silently degrading.

#### 🐛 Bug Fixes

- **WebSocket ALPN mismatch**: the client offered `meridian-1`/`h3` while the server's plain `http.Server` had no matching NextProtos, so the handshake failed with `tls: no application protocol`.
- **Removed UDP dead code**: `handlePacket`/`doHandshake`/`forwardFrame` were unreachable with an unfinished handshake TODO (the UDP socket is owned by the Hysteria library). Deleted, with a note explaining why.

#### 🐛 Bug fixes picked up during end-to-end verification

- **Direction balancing silently killed the tunnel**: `DummyFrame()` returned 14 raw header bytes with no ciphertext and no AEAD tag. The peer's decryption necessarily failed, and the decoder advanced the nonce counter even on failure, so *every* subsequent frame in that direction was rejected too. Dummy frames are now encrypted normally via `(*Encoder).DummyFrame()` as KEEPALIVE frames, which the peer recognises and skips.
- **Decryption failure consumed a nonce**: `Decoder.Decode` incremented its counter before authentication, so one bad frame permanently desynchronised that direction.
- **HTTP-POST read deadlock**: `Read` called `Write` while holding the transport lock, self-deadlocking on `sync.Mutex`. Replaced with a dedicated `pollOnce()` — this is why that transport was entirely unusable.

#### 🧪 Tests

- `pkg/mtp/handshake_test.go` (auth positive/negative, replay, expiry, malformed extensions)
- `pkg/mfp/frames_test.go` (padding round-trip, jitter bounds, direction balance, key rotation, control frame types)
- `pkg/transport/httppost_transport_test.go` and `httppost_e2e_test.go` (session reuse, pull-mode round-trip)

#### 🔧 Build & Release

- **Version is actually injected**: both binaries used to hardcode `v1.0.0`/`v1.0.1`, while the workflow's `-X main.Version` was a no-op because no such variable existed. `Version`/`BuildTime` are now real injectable variables defaulting to `dev`.
- **`build.sh` takes a version argument**: no longer pinned to `v1.3.0`. It defaults to the current git tag, or accepts `./build.sh v1.6.0`, and regenerates `SHA256SUMS`.
- **`SHA256SUMS` self-reference fixed**: the checksum file used to include itself (hashing an empty file), so `shasum -c` always failed. It now excludes itself.
- **`deploy.sh` version override**: the `MERIDIAN_VERSION` environment variable selects the download version, defaulting to `v1.6.0`.

### v1.5.0 (2026-06-03)

#### ✨ New Features

- **Windows Platform Support**: Rewrote signal handling logic; both client and server now compile and run flawlessly on Windows.
- **WebSocket Transport Backend**: Integrated WebSocket support. The server can tunnel traffic over WSS, and the client can fallback to WebSocket to bypass UDP blocking.
- **0-RTT Session Resumption**: Added an in-memory `SessionStore` to the transport layer. Reconnecting clients can now reuse previously negotiated keys to skip expensive ECDHE calculations.
- **Periodic Key Rotation (PFS)**: Both ends of the encrypted tunnel now automatically rotate traffic keys via HKDF every 64MB or 5 minutes to ensure long-term post-compromise security.
- **HTTP Proxy Protocol Support**: The client can now act as a forward HTTP/HTTPS proxy by configuring `proxy_protocol: "http"`.
### v1.3.5.1 (2026-06-03)

#### 🐛 Bug Fixes

- **Fixed QUIC transport name mismatch**: Config value `transport: "QUIC"` did not match the internal transport identifier `"Hysteria"`, causing the client to incorrectly fall back to a TCP connection with `deadline exceeded` timeouts. The transport name is now unified to `"QUIC"` while remaining backward-compatible with `"Hysteria"`.
- **Fixed server-side handshake stream read EOF**: The server used `conn.Read()` to read the ClientHello, which does not guarantee a complete read on QUIC/TCP streams. When insufficient data was received, the server prematurely closed the connection, causing the client to receive an `EOF` error. Changed to `io.ReadAtLeast()` to ensure at least 136 bytes are read before processing the handshake.

#### 📦 Build

- Rebuilt all platform binaries (Linux / macOS / Windows, amd64 / arm64)
- Updated SHA256SUMS checksum file

---

### v1.3.5 (2026-06-01)

- Fixed `TransportQUIC` undefined error in tests
- Updated GitHub Actions workflow to Go 1.25
- Rebuilt all platform binaries

### v1.3.2 (2026-06-01)

- Fixed high latency and data corruption issues in multiplexer
- Tuned QUIC receive window sizes for high throughput

### v1.3.1 (2026-06-01)

- Downgraded Go toolchain to 1.23.0 to fix Linux/ARM64 FIPS CPU init panic

### v1.3.0 (2026-06-01)

- Implemented QUIC transport layer (based on Hysteria v2)
- Enhanced SOCKS5 proxy robustness and added global debug mode

### v1.0.2 (2026-06-01)

- Full SOCKS5 proxy server (RFC 1928 + RFC 1929)
- LAN-wide proxy service (default listen `0.0.0.0:1080`)
- Fixed `reality_spki` / `server_spki` YAML unmarshalling error

### v1.0.1

- Config SPKI hex parsing fix

### v1.0.0

- Initial Meridian Protocol implementation
- X25519 ECDHE key exchange + ChaCha20-Poly1305 encryption
- MFP frame protocol + MTP handshake protocol
- End-to-end integration tests

---

## Protocol Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Application Layer (SOCKS5 Proxy / Relay)               │
├─────────────────────────────────────────────────────────┤
│  Meridian Frame Protocol (MFP)                          │
│  ┌────────┐ ┌─────────┐ ┌───────┐ ┌────────────────┐  │
│  │ Stream │ │  Mux    │ │ Queue │ │ Flow Control   │  │
│  └────────┘ └─────────┘ └───────┘ └────────────────┘  │
├─────────────────────────────────────────────────────────┤
│  Meridian Transport Protocol (MTP) — Handshake+Session  │
├─────────────────────────────────────────────────────────┤
│  QUIC (RFC 9000)  or  WebSocket (HTTP Upgrade)          │
├─────────────────────────────────────────────────────────┤
│  TCP / UDP (OS network stack)                           │
└─────────────────────────────────────────────────────────┘
```

### Transport Modes

| Transport | Best For | Notes |
|-----------|----------|-------|
| **QUIC** (default) | Open or semi-open networks | Best performance, multiplexed streams |
| **WebSocket** | UDP/QUIC blocked networks | Disguised as standard WSS traffic |
| **HTTP-POST** | Deep packet inspection environments | Mimics cloud storage file uploads |

---

## Features

### 🔐 Cryptography

- **Key exchange**: X25519 ephemeral ECDHE (Perfect Forward Secrecy)
- **Encryption**: ChaCha20-Poly1305 (default) / AES-256-GCM / AES-128-GCM
- **Key derivation**: HKDF-SHA256 with independent uplink/downlink nonce seeds
- **Nonce generation**: Counter-based unique nonce per packet — prevents reuse attacks
- **Authentication**: HMAC-SHA256 + handshake hash to prevent MITM

### 🛡️ Anti-Detection

- **TLS fingerprint spoofing**: Emulates real ClientHello of Chrome 120 / Firefox 121 / curl 8.4
- **SNI spoofing (REALITY)**: Points SNI to high-traffic legitimate domains (e.g. google.com)
- **Traffic padding**: Fixed or random padding to defeat traffic analysis
- **Timing jitter**: Configurable jitter (default 0–30ms) to prevent timing fingerprinting
- **Direction balancing**: Bidirectional traffic shaping to defeat asymmetric flow analysis
- **SPKI pinning**: Client verifies server certificate by SHA-256 public key hash — no CA trust chain required

### 🌐 SOCKS5 Proxy (New in v1.0.2)

- **RFC 1928** full implementation: IPv4, IPv6, and domain name address types
- **RFC 1929** username/password auth: auto-enabled when credentials are set in config
- **LAN-wide service**: Default listen `0.0.0.0:1080` — phones, tablets, and other PCs can connect
- **Live statistics**: Prints active connections and traffic every 60 seconds
- **Access log**: `[timestamp] [source IP:port] → target:port`

### 📦 Frame Protocol (MFP)

- 14-byte fixed frame header: type, stream ID, sequence number, flags, extension
- Frame types: DATA / ACK / PING / PONG / FLOW / RESET / KEEPALIVE
- ChaCha20-Poly1305 AEAD encryption with 16-byte authentication tag
- Built-in frame pool to reduce GC pressure

---

## Quick Start

### Download Prebuilt Binaries

Download from the [Releases page](https://github.com/peterxulove/meridian/releases).

| Platform | Architecture | Filename |
|----------|-------------|----------|
| macOS | Apple Silicon (M1/M2/M3) | `meridian-*-darwin-arm64` |
| macOS | Intel | `meridian-*-darwin-amd64` |
| Linux | ARM64 (Raspberry Pi, ARM servers) | `meridian-*-linux-arm64` |
| Linux | x86_64 | `meridian-*-linux-amd64` |

### One-Click Deployment (Recommended, Linux & macOS)

A comprehensive one-click script `deploy.sh` is provided. It allows interactive installation, configuration, and automatic registration of the client and server as system services (`systemd` for Linux, `launchd` for macOS).

```bash
# 1. Make the script executable
chmod +x deploy.sh

# 2. Run the script to open the interactive menu
./deploy.sh
```

**Supported CLI parameters:**
* `./deploy.sh`: Open the interactive deployment menu.
* `./deploy.sh status`: Display status of installed Meridian services.
* `./deploy.sh update client`: update the client core only. Existing `client.yaml`, certificates and service definitions are preserved; the previous binary is restored automatically if startup fails.
* `./deploy.sh update server`: update the server core only while preserving its existing configuration.
* `./deploy.sh transport client|server`: switch transport interactively (QUIC / WebSocket / QUIC+WebSocket / HTTP-POST), or pass it directly, e.g. `./deploy.sh transport client websocket`.
* `./deploy.sh uninstall`: Quickly uninstall client or server components.

---

### Server Deployment (Manual, Linux)

```bash
# 1. Make executable
chmod +x meridian-server-linux-amd64

# 2. Generate a self-signed certificate (required for REALITY mode)
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
  -sha256 -days 3650 -nodes -subj "/CN=www.apple.com"

# 3. Extract SPKI hash (paste into client config as reality_spki)
openssl x509 -in cert.pem -pubkey -noout \
  | openssl pkey -pubin -outform DER 2>/dev/null \
  | sha256sum | cut -c1-64

# 4. Create config
cp server.example.yaml server.yaml
vim server.yaml   # Set password, cert paths

# 5. Start
./meridian-server-linux-amd64 -config server.yaml
```

### Client Usage (Your Machine / LAN Gateway)

```bash
# 1. Make executable
chmod +x meridian-client-darwin-arm64

# 2. Create config
cp client.example.yaml client.yaml
vim client.yaml   # Set server address, password, SPKI hash

# 3. Start (automatically opens SOCKS5 proxy on 0.0.0.0:1080)
./meridian-client-darwin-arm64 -config client.yaml
```

Expected startup log:
```text
Meridian Client v1.3.5
  Server:    1.2.3.4:443
  Transport: QUIC
  Cipher:    MERIDIAN-CHACHA
  SOCKS5:    0.0.0.0:1080
  [Tunnel] Connected to Meridian server at 1.2.3.4:443
  [SOCKS5] Listening on 0.0.0.0:1080 (serving LAN)
Client running (PID 12345). Press Ctrl+C to stop.
[2026-06-01 23:27:38] socks5: [192.168.1.5:54321] → www.google.com:443
[2026-06-01 23:27:39] socks5: [192.168.1.8:33210] → api.twitter.com:443
  [Stats] active=2 total=47 in=1024KB out=8192KB
```

### CLI Flags

```
meridian-server flags:
  -config string      Path to server config file (default: server.yaml)
  -listen string      Override listen address (e.g. 0.0.0.0:443)
  -fingerprints       List available TLS fingerprints and exit

meridian-client flags:
  -config string      Path to client config file (default: client.yaml)
  -listen string      Override SOCKS5 listen address (e.g. 0.0.0.0:1080)
  -fingerprints       List available TLS fingerprints and exit
```

---

## LAN Proxy Usage

Once the client is running, point any device on the same network to the client machine's IP with port `1080` as a SOCKS5 proxy.

### Browser (SwitchyOmega — Recommended)

1. Install [Proxy SwitchyOmega](https://chrome.google.com/webstore/detail/proxy-switchyomega/padekgcemlokbadohgkifijomclgjgif)
2. Create a new profile: Protocol `SOCKS5`, Server `<client machine IP>`, Port `1080`
3. Import GFWList rules for smart split routing (blocked sites go through proxy, domestic sites connect directly)

### macOS System Proxy

**System Settings → Network → Wi-Fi → Details → Proxies → SOCKS Proxy**

Enter: Server `<client machine IP>`, Port `1080`

### iOS / iPadOS

**Settings → Wi-Fi → Tap current network → Configure Proxy → Manual**

Enter: Server `<client machine IP>`, Port `1080`

### Android

**Wi-Fi → Long press → Modify network → Advanced → Proxy → Manual**

Enter: Hostname `<client machine IP>`, Port `1080`

### Terminal / Shell

```bash
# Temporarily enable proxy for current shell session
export https_proxy="socks5://<client-machine-ip>:1080"
export http_proxy="socks5://<client-machine-ip>:1080"

# Git — proxy only for GitHub
git config --global http.https://github.com.proxy socks5://<client-machine-ip>:1080
```

---

## Configuration

Meridian supports four transport modes depending on your network environment:
QUIC, WebSocket, the server-side `QUIC+WebSocket` hybrid listener (both
protocols on one port), and HTTP-POST.

Switch without editing YAML by hand:

```bash
sudo ./deploy.sh transport server           # interactive
sudo ./deploy.sh transport client websocket # or explicit
```

Only transport-specific fields (`transport` / `wss_path` / `mirror_path`) are
touched; password, SPKI, certificates and listen port are preserved, and the
change is rolled back if the service fails to restart.

### Performance and connection parameters

| Key | Meaning | Default | Range |
|-----|---------|---------|-------|
| `tunnel_connections` | Independent outer tunnels per client; each has its own handshake and keys, streams are spread by active load | `4` (deploy script) | 1–16 |
| `stream_window` | Per-stream **in-flight** byte window (ACK flow control); queueing delay ≈ window / link rate | `1048576` (1 MiB) | 256 KiB–16 MiB |
| `max_concurrent_streams` | Stream cap **per tunnel**; the client retries another lane, the server answers `server busy` | `512` | 16–4096 |
| `session_lifetime` | Outer connection lifetime; the lane drains and reconnects at expiry, `0` disables | `1h` | 5m–24h |
| `timing_jitter_ms` | Random delay applied to small frames only | `0` | 0–100 |
| `up_mbps` / `down_mbps` | Fixed QUIC bandwidth hint; `0` selects adaptive BBR | `0` | 0 or link rate |

The local proxy listener is sized as `max_concurrent_streams ×
tunnel_connections` (clamped to 512–4096), so multiple lanes are not throttled
by a single lane's budget.

---

### 1. QUIC (REALITY) Mode — Recommended

#### 🔹 Server (`server.quic.yaml`)
```yaml
listen_addr: "0.0.0.0:443"
transport: "QUIC"
cipher_suite: 1                    # 1=ChaCha20, 2=AES256, 3=AES128
password: "your-strong-random-password-here"

# ─── REALITY camouflage ───
reality_mode: true
reality_enabled: true
server_cert: "cert.pem"
server_key: "key.pem"
reality_spki: "804d9c7922d9c491aefbe7f2da4930bfae498cda692994ea9a9fefb0f2ea99cb"
reality_short_id: 1002
reality_max_time: 0

# ─── Anti-detection ───
fingerprint: "chrome_win"          # chrome_win / firefox_mac / curl_linux
padding_mode: "random"             # none / fixed / random
base_payload_size: 1400
max_payload_size: 1452
timing_jitter_ms: 30.0

# ─── Connection limits ───
max_clients: 1000
stream_window: 1048576
max_concurrent_streams: 512
keepalive_interval: "30s"
handshake_timeout: "10s"

# ─── Fallback backend (anti-probing) ───
destinations:
  - name: "direct"
    addr: "127.0.0.1:8080"         # Unauthenticated probes are forwarded here
    protocol: "direct"
    rule: "all"
    priority: 0
```

#### 🔹 Client (`client.quic.yaml`)
```yaml
server_addr: "your-server-ip:443"
transport: "QUIC"
cipher_suite: 1
password: "your-strong-random-password-here"

# ─── REALITY ───
reality_mode: true
sni_spoof: "www.apple.com"         # Must match the CN in server certificate
reality_spki: "804d9c7922d9c491aefbe7f2da4930bfae498cda692994ea9a9fefb0f2ea99cb"
reality_short_id: 1002
reality_max_time: 0

# ─── Anti-detection ───
fingerprint: "chrome_win"
padding_mode: "random"
base_payload_size: 1400
max_payload_size: 1452
direction_balance: true
timing_jitter_ms: 30.0

# ─── Connection ───
keepalive_interval: "30s"
handshake_timeout: "10s"
stream_window: 1048576
max_concurrent_streams: 512
session_lifetime: "1h"
dial_timeout: "15s"

# ─── Local SOCKS5 proxy ───
# 0.0.0.0 = all LAN devices can connect
# 127.0.0.1 = this machine only
listen_addr: "0.0.0.0:1080"
proxy_protocol: "socks5"
```

---

### 2. WebSocket (WSS) Mode

#### 🔹 Server (`server.ws.yaml`)
```yaml
listen_addr: "127.0.0.1:8080"     # Recommend reverse-proxying via Nginx/Caddy on port 443
transport: "WebSocket"
cipher_suite: 1
password: "your-strong-random-password-here"
wss_path: "/v2/connection"
fingerprint: "firefox_mac"
padding_mode: "random"
timing_jitter_ms: 15.0
destinations:
  - name: "direct"
    addr: "127.0.0.1:8080"
    protocol: "direct"
    rule: "all"
```

#### 🔹 Client (`client.ws.yaml`)
```yaml
server_addr: "your-server-domain.com:443"
transport: "WebSocket"
cipher_suite: 1
password: "your-strong-random-password-here"
wss_path: "/v2/connection"
reality_mode: false
sni_spoof: "your-server-domain.com"
fingerprint: "firefox_mac"
padding_mode: "random"
listen_addr: "0.0.0.0:1080"
proxy_protocol: "socks5"
```

---

### 3. HTTP-POST Mode

#### 🔹 Server (`server.http.yaml`)
```yaml
listen_addr: "0.0.0.0:80"
transport: "HTTP-POST"
cipher_suite: 2
password: "your-strong-random-password-here"
mirror_path: "/api/v1/storage/upload"   # upload path; must match on both ends
destinations:
  - name: "direct"
    addr: "127.0.0.1:8080"
    protocol: "direct"
    rule: "all"
```

> ⚠️ **Padding must match on both ends**
> `padding_mode` changes the wire format (padded frames carry a 2-byte length prefix). A mismatch leaves the peer unable to strip the prefix.
>
> ⚠️ **HTTP-POST is pull-based**
> Downlink bytes can only ride back inside a request response, so an idle client sends empty `Mir-Poll` uploads to poll. Latency is therefore higher than QUIC/WebSocket — use it only in hostile environments.

#### 🔹 Client (`client.http.yaml`)
```yaml
server_addr: "your-server-ip:80"
transport: "HTTP-POST"
cipher_suite: 2
password: "your-strong-random-password-here"
upload_url: "http://your-server-ip/api/v1/storage/upload"
mirror_boundary: "----WebKitFormBoundaryT8z736aFmE1yB"
mirror_path: "/api/v1/storage/upload"
keepalive_interval: "5s"
listen_addr: "0.0.0.0:1080"
proxy_protocol: "socks5"
```

---

> 💡 **Generating a self-signed certificate and extracting SPKI hash**
>
> ```bash
> # Generate private key and certificate (CN must match client's sni_spoof)
> openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
>   -sha256 -days 3650 -nodes -subj "/CN=www.apple.com"
>
> # Extract SPKI hash (paste into reality_spki in both configs)
> openssl x509 -in cert.pem -pubkey -noout \
>   | openssl pkey -pubin -outform DER 2>/dev/null \
>   | sha256sum | cut -c1-64
> ```

---

## Security Mechanism

### Handshake Flow

```
Client                              Server
  │── ClientHello ──────────────────► │
  │   [magic][version][flags][MTU]    │
  │   [client_random 32B]             │
  │   [ECDHE public key 32B]          │
  │   [handshake hash 32B]            │
  │   [session ID 16B][cipher][ext]   │
  │                                    │
  │ ◄─────────────── ServerHello ─────│
  │   [server_random][ECDHE pubkey]   │
  │   [cipher suite][cert hash]       │
  │                                    │
  │── ClientKeyConfirm ──────────────► │
  │ ◄─────────────── HandshakeDone ───│
  │                                    │
  │══════════ Encrypted Data ══════════│
```

### Key Derivation

```
master_secret = HKDF(shared_ecdhe, client_random || server_random, "meridian-master")

keys = HKDF(master_secret, "meridian-keys"):
  [0:32]   → traffic_enc_key     (ChaCha20 encryption key)
  [32:64]  → traffic_mac_key     (HMAC verification key)
  [64:80]  → uplink_nonce_seed   (client→server nonce seed)
  [80:96]  → downlink_nonce_seed (server→client nonce seed)
  [96:128] → init_key            (handshake initialization key)

nonce = SHA256(direction_seed || counter_uint64)[0:12]
```

---

## Build

### Requirements

- Go 1.22+
- Network access (to download dependencies)

### Local Build

```bash
# Clone repository
git clone https://github.com/peterxulove/meridian.git
cd meridian

# Download dependencies
go mod tidy

# Build for current platform
go build -o meridian-server ./cmd/meridian-server/
go build -o meridian-client ./cmd/meridian-client/

# Run tests (11 integration tests)
go test ./test/integration/ -v
```

### Cross-Compilation

```bash
# macOS ARM64 (Apple Silicon)
GOOS=darwin  GOARCH=arm64 go build -ldflags="-s -w" -o dist/meridian-server-darwin-arm64 ./cmd/meridian-server/
GOOS=darwin  GOARCH=arm64 go build -ldflags="-s -w" -o dist/meridian-client-darwin-arm64 ./cmd/meridian-client/

# Linux ARM64 (Raspberry Pi / ARM servers)
GOOS=linux   GOARCH=arm64 go build -ldflags="-s -w" -o dist/meridian-server-linux-arm64  ./cmd/meridian-server/
GOOS=linux   GOARCH=arm64 go build -ldflags="-s -w" -o dist/meridian-client-linux-arm64  ./cmd/meridian-client/

# macOS x86_64
GOOS=darwin  GOARCH=amd64 go build -ldflags="-s -w" -o dist/meridian-server-darwin-amd64 ./cmd/meridian-server/
GOOS=darwin  GOARCH=amd64 go build -ldflags="-s -w" -o dist/meridian-client-darwin-amd64 ./cmd/meridian-client/

# Linux x86_64
GOOS=linux   GOARCH=amd64 go build -ldflags="-s -w" -o dist/meridian-server-linux-amd64  ./cmd/meridian-server/
GOOS=linux   GOARCH=amd64 go build -ldflags="-s -w" -o dist/meridian-client-linux-amd64  ./cmd/meridian-client/
```

---

## Download Prebuilt Binaries

Download the latest binaries from [GitHub Releases](https://github.com/peterxulove/meridian/releases).

Each release includes:
- `meridian-server-darwin-arm64` — macOS Apple Silicon server
- `meridian-client-darwin-arm64` — macOS Apple Silicon client
- `meridian-server-darwin-amd64` — macOS Intel server
- `meridian-client-darwin-amd64` — macOS Intel client
- `meridian-server-linux-arm64`  — Linux ARM64 server (static binary)
- `meridian-client-linux-arm64`  — Linux ARM64 client (static binary)
- `meridian-server-linux-amd64`  — Linux x86_64 server (static binary)
- `meridian-client-linux-amd64`  — Linux x86_64 client (static binary)
- `SHA256SUMS` — SHA-256 checksums for all files

---

## Development

### Project Structure

```
meridian/
├── cmd/
│   ├── meridian-client/    # Client CLI entrypoint
│   │   ├── main.go         # Main program, Client struct
│   │   ├── tunnel.go       # QUIC/TCP secure tunnel (MTP handshake + MFP multiplexing)
│   │   └── socks5.go       # Full SOCKS5 proxy server (RFC 1928/1929)
│   └── meridian-server/    # Server CLI entrypoint
│       ├── main.go
│       └── server.go
├── pkg/
│   ├── crypto/             # Cryptographic primitives (X25519, ChaCha20, HKDF)
│   ├── mfp/                # Meridian Frame Protocol (encode/decode/encrypt)
│   ├── mtp/                # Meridian Transport Protocol (handshake)
│   ├── transport/          # Transport adapters (QUIC/WebSocket)
│   ├── config/             # Configuration file loading
│   └── anti/               # Anti-detection (TLS fingerprints)
├── test/
│   └── integration/        # End-to-end integration tests (11 tests, all pass)
├── configs/                # Example configuration files
├── dist/                   # Prebuilt binaries (CI artifacts)
├── docs/                   # Protocol specification
├── .github/
│   └── workflows/
│       └── release.yml     # GitHub Actions auto-build and release
├── go.mod
└── go.sum
```

### Testing

```bash
# Run all integration tests (includes UDP end-to-end handshake test)
go test ./test/integration/ -v -timeout 30s

# Code linting
go vet ./...
```

### Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -m 'feat: add some feature'`
4. Push the branch: `git push origin feature/my-feature`
5. Open a Pull Request

---

## Roadmap

- [x] X25519 ECDHE key exchange
- [x] ChaCha20-Poly1305 / AES-GCM encryption
- [x] HKDF-SHA256 key derivation
- [x] MFP frame protocol encode/decode
- [x] ClientHello build and parse
- [x] Server handshake reception (UDP is owned by Hysteria v2; MTP handshake runs on its stream)
- [x] **Full SOCKS5 proxy server (RFC 1928 + RFC 1929)** ✅ v1.0.2
- [x] **LAN-wide proxy service (0.0.0.0 listen)** ✅ v1.0.2
- [x] **Config SPKI hex parsing fix** ✅ v1.0.1
- [x] **QUIC transport layer (Hysteria v2)** ✅ v1.3.0
- [x] **ServerHello full reply** ✅ v1.3.0
- [x] **Data frame forwarding through Meridian encrypted tunnel** ✅ v1.3.0
- [x] **QUIC transport connection and handshake fixes** ✅ v1.3.5.1
- [x] CLI flags support
- [x] Graceful signal shutdown
- [x] GitHub Actions automated release
- [x] WebSocket transport backend ✅ v1.5.0
- [x] 0-RTT session resumption ✅ v1.5.0
- [x] Periodic key rotation ✅ v1.5.0
- [x] Windows platform support ✅ v1.5.0
- [x] HTTP proxy protocol support ✅ v1.5.0
- [x] **Password auth on the TCP tunnel** ✅ v1.6.0
- [x] **HTTP-POST transport server** ✅ v1.6.0
- [x] **Direction balancing / nonce desync fixes** ✅ v1.6.0
- [x] **Version injected at build time** ✅ v1.6.0

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## References

- [Meridian Protocol Specification v1.0](docs/Meridian-Protocol-Spec.md)
- [RFC 1928 — SOCKS Protocol Version 5](https://www.rfc-editor.org/rfc/rfc1928)
- [RFC 1929 — Username/Password Authentication for SOCKS5](https://www.rfc-editor.org/rfc/rfc1929)
- [RFC 9000 — QUIC Protocol](https://www.rfc-editor.org/rfc/rfc9000)
- [ChaCha20-Poly1305 RFC 8439](https://www.rfc-editor.org/rfc/rfc8439)
- [X25519 Elliptic Curve Diffie-Hellman RFC 7748](https://www.rfc-editor.org/rfc/rfc7748)
