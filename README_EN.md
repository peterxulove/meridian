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

### Server Deployment (Linux)

```bash
# 1. Make executable
chmod +x meridian-server-linux-amd64

# 2. Generate a self-signed certificate (required for REALITY mode)
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
  -sha256 -days 3650 -nodes -subj "/CN=www.apple.com"

# 3. Extract SPKI hash (paste into client config as reality_spki)
openssl x509 -in cert.pem -pubkey -noout \
  | openssl pkey -pubout -outform DER 2>/dev/null \
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

Meridian supports three transport modes depending on your network environment.

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
max_concurrent_streams: 100
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
destinations:
  - name: "direct"
    addr: "127.0.0.1:8080"
    protocol: "direct"
    rule: "all"
```

#### 🔹 Client (`client.http.yaml`)
```yaml
server_addr: "your-server-ip:80"
transport: "HTTP-POST"
cipher_suite: 2
password: "your-strong-random-password-here"
upload_url: "http://your-server-ip/api/v1/storage/upload"
mirror_boundary: "----WebKitFormBoundaryT8z736aFmE1yB"
mirror_path: "/api/v1/storage/upload"
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
>   | openssl pkey -pubout -outform DER 2>/dev/null \
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
- [x] UDP server handshake reception
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
