# Meridian Protocol — Implementation

A high-efficiency, anti-detection secure communication protocol combining the best of Shadowsocks, Hysteria/Hysteria2, VLESS, and REALITY.

## Quick Start

```bash
# Build
cd meridian
go build -o meridian-server ./cmd/meridian-server
go build -o meridian-client ./cmd/meridian-client

# Run server
./meridian-server --config configs/server.example.yaml

# Run client (in another terminal)
./meridian-client --config configs/client.example.yaml
```

## Architecture

```
┌──────────────┐     QUIC      ┌──────────────┐
│   Client     │  ◄──────────► │    Server     │
│              │               │               │
│  MFP Layer   │  Frames       │  MFP Layer    │
│  (multiplex) │ ◄──────────► │  (multiplex)  │
│              │               │               │
│  MTP Layer   │  Handshake    │  MTP Layer    │
│  (auth + kex)│ ◄──────────► │  (auth + kex) │
│              │               │               │
│  Transport   │  QUIC/WS/HTTP│  Transport    │
│  (QUIC/WS)   │ ◄──────────► │  (QUIC/WS)    │
│              │               │               │
│  Anti-       │  Padding      │  Padding      │
│  Detection   │ ◄──────────► │  Control      │
└──────────────┘               └──────────────┘
```

## Protocol Layers

### 1. MTP — Meridian Transport Protocol (Handshake)

The handshake negotiates encryption parameters and establishes shared secrets.

**Full Handshake (3 messages):**
```
Client                          Server
  |--- ClientHello ------------->|
  |<-- ServerHello + KeyConfirm --|
  |--- ClientKeyConfirm ---------->|
  |<-- HandshakeDone -------------|
```

**Wire Format (ClientHello):**
```
0xDeadBeEF  (4 bytes — magic number)
0x01        (1 byte — version)
0x00        (1 byte — flags)
[0x0002]    (2 bytes — max MTU)
[32 bytes   (client random)]
[32 bytes   (client X25519 public key)]
[32 bytes   (handshake hash)]
[16 bytes   (session ID)]
[cipher list (variable)]
[extensions (variable)]
[4 bytes    (hash tag)]
```

**Negotiated Cipher Suites:**

| ID | Name           | AEAD              | KDF       | Auth     |
|----|----------------|-------------------|-----------|----------|
| 1  | MERIDIAN-CHACHA | ChaCha20-Poly1305 | Argon2id  | HMAC-256 |
| 2  | MERIDIAN-AES256 | AES-256-GCM       | HKDF-SHA256| HMAC-256 |
| 3  | MERIDIAN-AES128 | AES-128-GCM       | HKDF-SHA256| HMAC-256 |
| 4  | MERIDIAN-ARIA   | ARIA-256-GCM      | Argon2id  | HMAC-256 |
| 5  | MERIDIAN-SM4    | SM4-GCM           | SM3-KDF   | SM3-HMAC |

### 2. MFP — Meridian Frame Protocol (Data)

Data frames are encrypted and multiplexed over streams.

**Frame Header (14 bytes):**
```
[Type:1B] [Length:2B] [StreamID:4B] [Flags:1B] [Seq:4B] [Ext:2B]
```

**Frame Types:**

| ID  | Name       | Purpose |
|-----|------------|---------|
| 0x00| DATA       | Payload |
| 0x01| ACK        | Flow control |
| 0x02| CONGEST    | Congestion signal |
| 0x03| PING       | Keepalive |
| 0x04| PONG       | Ping response |
| 0x05| BOUNDARY   | Server push |
| 0x06| ERROR      | Error report |
| 0x07| FLOW       | Bandwidth adjustment |
| 0x08| RESET      | Stream reset |
| 0xFF| KEEPALIVE  | Padding placeholder |

**Encrypted Frame:**
```
[14-byte unencrypted header]
[N-byte encrypted payload]
[16-byte AEAD auth tag]
```

Total per frame: 14 + payload + 16 bytes.

### 3. Transport Options

| Transport | When to Use | Latency | Stealth |
|-----------|------------|---------|---------|
| **QUIC** (default) | Normal networks | ⭐ Best | High |
| **WebSocket** | UDP blocked | Good | High |
| **HTTP-POST** | Aggressive DPI | Fair | Very High |

### 4. Anti-Detection System

| Technique | Description | Impact |
|-----------|-------------|--------|
| **SNI Spoofing (REALITY)** | Pretend to visit google.com, bing.com, etc. | ⭐ Best |
| **TLS Fingerprint** | Emulate Chrome 120 / Firefox 121 / curl | High |
| **Traffic Padding** | Fixed/random size padding eliminates size analysis | High |
| **Directional Balancing** | Fills asymmetric traffic with dummy packets | Medium |
| **Timing Jitter** | Randomizes send timing (0-50ms) | Medium |
| **Connection Rotation** | Simulates real browser connection patterns | Medium |

## Configuration

### Server Config (server.example.yaml)

```yaml
listen_addr: "0.0.0.0:443"
transport: "QUIC"
cipher_suite: 1
password: "your-strong-password"

# REALITY mode (anti-detection)
reality_mode: true
server_cert: "cert.pem"
server_key: "key.pem"
reality_spki: "hex-hash-of-server-public-key"
reality_short_id: 0

# Anti-detection
fingerprint: "chrome_win"
padding_mode: "random"
base_payload_size: 1400
timing_jitter_ms: 30.0

# Upstream destinations
destinations:
  - name: "direct"
    addr: "127.0.0.1:8080"
    protocol: "direct"
    rule: "all"
```

### Client Config (client.example.yaml)

```yaml
server_addr: "server.example.com:443"
transport: "QUIC"
cipher_suite: 1
password: "your-strong-password"

# REALITY mode (must match server settings)
sni_spoof: "www.google.com"
reality_mode: true
reality_spki: "same-hex-hash-as-server"
reality_short_id: 0

# Anti-detection (must match server)
fingerprint: "chrome_win"
padding_mode: "random"
base_payload_size: 1400

# Local proxy
listen_addr: "127.0.0.1:1080"
proxy_protocol: "socks5"
```

## Security

### Threat Model

| Threat | Mitigation |
|--------|-----------|
| Passive eavesdropping | AEAD encryption (AES-GCM / ChaCha20-Poly1305) |
| Active MITM | ECDHE + SPKI hash verification |
| DPI detection | Traffic normalization, SNI spoofing, fingerprint randomization |
| Traffic analysis | Padding, timing jitter, direction balancing |
| Session key compromise | Forward secrecy (per-session ECDHE) + automatic key renewal |

### Key Derivation

```
master_secret = HKDF-SHA256(
    hash = SHA256(client_ECDHE || server_ECDHE),
    info = client_random || server_random
)

traffic_enc_key = HKDF(master_secret, "meridian-keys")[0:32]
traffic_mac_key = HKDF(master_secret, "meridian-keys")[32:64]
nonce_seed_up   = HKDF(master_secret, "meridian-keys")[64:80]
nonce_seed_dn   = HKDF(master_secret, "meridian-keys")[80:96]
init_key        = HKDF(master_secret, "meridian-keys")[96:128]

nonce = SHA256(init_key || counter)[0:12]
```

## Project Structure

```
meridian/
├── go.mod
├── configs/
│   ├── server.example.yaml    # Server example (REALITY mode)
│   ├── client.example.yaml    # Client example (REALITY mode)
│   ├── server.standalone.yaml  # Server (no REALITY, dev)
│   └── client.standalone.yaml  # Client (no REALITY, dev)
├── cmd/
│   ├── meridian-server/
│   │   ├── main.go            # Server CLI entrypoint
│   │   └── server.go          # Server implementation
│   └── meridian-client/
│       └── main.go            # Client CLI + implementation
├── pkg/
│   ├── config/
│   │   └── config.go          # Configuration model
│   ├── crypto/
│   │   └── crypto.go          # Encryption, KDF, X25519
│   ├── mtp/
│   │   └── handshake.go       # Meridian Transport Protocol
│   ├── mfp/
│   │   └── frames.go          # Meridian Frame Protocol
│   ├── transport/
│   │   ├── quic_transport.go  # QUIC transport adapter
│   │   └── websocket_transport.go  # WebSocket adapter
│   └── anti/
│       └── fingerprint.go     # TLS fingerprint management
```

## Usage

### Server

```bash
# Start with config file
./meridian-server --config configs/server.example.yaml

# Override listen address
./meridian-server --config configs/server.yaml --listen "0.0.0.0:8443"

# Show available TLS fingerprints
./meridian-server --fingerprints

# Print default config with comments
./meridian-server --print-config
```

### Client

```bash
# Start with config file
./meridian-client --config configs/client.example.yaml

# Override listen address
./meridian-client --config configs/client.yaml --listen "127.0.0.1:1081"

# Show available TLS fingerprints
./meridian-client --fingerprints

# Print default config with comments
./meridian-client --print-config
```

### System Proxy Setup

After starting the client, configure your system or browser to use:
- **SOCKS5**: `127.0.0.1:1080`
- **HTTP**: `127.0.0.1:1080`

Firefox: Settings → General → Network Settings → Manual proxy config → SOCKS v5 → 127.0.0.1:1080 → "Proxy DNS when using SOCKS v5"

Chrome: Use a proxy extension or launch with:
```bash
google-chrome --proxy-server="socks5://127.0.0.1:1080"
```

### Testing with curl

```bash
# Test via SOCKS proxy (using proxychains)
proxychains4 curl https://www.example.com

# Or set environment variables
export ALL_PROXY=socks5://127.0.0.1:1080
curl https://www.example.com
```

## Build

```bash
# Prerequisites: Go 1.22+
go version

# Build server
go build -o meridian-server ./cmd/meridian-server

# Build client
go build -o meridian-client ./cmd/meridian-client

# Run tests
go test ./...
```

## License

Internal use. Not for redistribution.
