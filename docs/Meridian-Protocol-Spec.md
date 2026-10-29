# Meridian Protocol Specification v1.4

> A hybrid high-efficiency, anti-detection secure communication protocol.
> Combines strengths of Shadowsocks, Hysteria/Hysteria2, VLESS, and REALITY.

Revision history:

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-06 | Initial specification |
| 1.1 | 2026-10-29 | Documented `QUIC+WebSocket` listener, multi-lane transport, real `stream_window` / `max_concurrent_streams` semantics, and session-lifetime draining |
| 1.2 | 2026-10-29 | Per-stream ACK flow control (version 2 wire); `stream_window` is now a real in-flight byte window |
| 1.3 | 2026-10-29 | Local per-stream buffer is bounded in bytes, not frames; stall detection no longer truncates healthy streams |
| 1.4 | 2026-10-29 | `QUIC` transport on the server binds UDP only; the legacy plaintext TCP listener is no longer opened |

---

## 1. Design Goals

| Goal | Target |
|------|--------|
| **Anti-detection** | Indistinguishable from normal HTTPS/HTTP3 traffic |
| **Low latency** | Sub-50ms handshake, 0-RTT resume |
| **High throughput** | Full link capacity, no self-imposed bottleneck |
| **Robustness** | Works across NATs, firewalls, congested networks |
| **Forward secrecy** | Ephemeral key exchange on every connection |
| **Post-compromise security** | Periodic key re-keying from application layer |
| **Low memory** | < 512KB per connection (server) |

---

## 2. Protocol Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Application Layer (proxy / relay)                      │
├─────────────────────────────────────────────────────────┤
│  Meridian Frame Protocol (MFP)                          │
│  ┌──────┐ ┌───────┐ ┌───────┐ ┌──────────────────┐    │
│  │ Stream│ │ Muxer │ │ Queue │ │ Flow Control     │    │
│  └──────┘ └───────┘ └───────┘ └──────────────────┘    │
├─────────────────────────────────────────────────────────┤
│  Meridian Transport Protocol (MTP) - Handshake + Ctx    │
├─────────────────────────────────────────────────────────┤
│  QUIC (RFC 9000) or WebSocket (Upgrade)                │
├─────────────────────────────────────────────────────────┤
│  TCP / UDP (OS)                                       │
└─────────────────────────────────────────────────────────┘
```

### 2.1 Transport Options

| Transport | When to use | Notes |
|-----------|-------------|-------|
| **QUIC (default)** | Open/semi-open networks | Best performance, multiplexed streams |
| **WebSocket** | Network blocks UDP/QUIC | Fingerprints as standard WSS |
| **QUIC+WebSocket (server)** | Mixed client fleet | UDP QUIC and TCP/WSS listeners share one port |
| **HTTP-POST** | Aggressive DPI environments | Mimics cloud storage upload |

The server-side `QUIC+WebSocket` transport is a listener configuration, not a
separate wire protocol: a client still speaks either QUIC or WebSocket, and the
server accepts both on the same `listen_addr`. This lets a deployment migrate
clients one at a time without changing the port.

A server configured for `QUIC` MUST bind UDP only. It MUST NOT also open a
plaintext TCP listener on `listen_addr`: an unauthenticated TCP port that
answers arbitrary connections with tunnel framing is trivially fingerprintable
and defeats the anti-detection goal. (Before v1.6.7 the `QUIC` value fell
through to the legacy raw-TCP path and opened both.)

Clients MAY open several independent outer connections ("lanes") to the same
server — see §6.4. Each lane carries its own handshake, session ID and key
schedule; streams are distributed across lanes by active load.

---

## 3. Handshake (Meridian Transport Protocol)

### 3.1 Overview

The handshake negotiates parameters, performs ECDHE key exchange, and optionally resuming session.

**Full Handshake (3-RTT max, typically 2):**
```
Client                          Server
  |--- ClientHello ------------->|
  |<-- ServerHello + KeyConfirm --|
  |--- ClientKeyConfirm ---------->|
  |<-- HandshakeDone -------------|
```

**0-RTT Resume:**
```
Client                          Server
  |--- ClientHello (0-RTT) ---->|
  |<-- ServerHello + KeyConfirm --|
  |--- 0-RTT Data -------------->|
  |<-- 0-RTT Response ----------->|
  |--- HandshakeConfirm -------->|
  |<-- HandshakeDone -------------|
```

### 3.2 ClientHello

```
Offset  Size    Name            Description
0       4       MAGIC           0xDE 0xAD 0xBE 0xEF (Meridian magic)
4       1       VERSION         0x01 (current spec)
5       1       FLAGS           Bitmask:
                              bit 0: 0 = full, 1 = resume
                              bit 1: 0 = QUIC, 1 = WebSocket
                              bit 2: 0 = no padding, 1 = padding mode
                              bit 3-7: reserved (must be 0)
6       2       CLIENT_MTU      Max payload per packet (network byte order)
8       32      CLIENT_RANDOM   Cryptographic random (32 bytes)
40      32      CLIENT_ECDHE  Client's X25519 public key
72      32      CLIENT_HASH   SHA256(CIPHERS || CLIENT_RANDOM || CLIENT_ECDHE)
104     16      CLIENT_ID     Session ID (for resume, random if fresh)
120     variable CIPHERS      Cipher suite preference list (see §3.3)
N       variable EXTENSIONS   Optional extensions (see §3.4)
N+4     4       HASH_TAG      SHA256(packed ClientHello)[0:4]
```

### 3.3 Cipher Suite Negotiation

Each cipher suite entry:
```
Offset  Size    Name            Description
0       2       CIPHER_ID       16-bit identifier (see table)
2       2       AEAD_ID         AEAD algorithm ID
4       2       KDF_ID          Key derivation function ID
6       2       AUTH_ID         Authentication method ID
```

**Negotiated Cipher Suite Registry:**

| ID  | Name           | AEAD              | KDF       | Auth     |
|-----|----------------|-------------------|-----------|----------|
| 0x01 | MERIDIAN-CHACHA | ChaCha20-Poly1305 | Argon2id  | HMAC-256 |
| 0x02 | MERIDIAN-AES256 | AES-256-GCM       | HKDF-SHA256| HMAC-256 |
| 0x03 | MERIDIAN-AES128 | AES-128-GCM       | HKDF-SHA256| HMAC-256 |
| 0x04 | MERIDIAN-ARIA   | ARIA-256-GCM      | Argon2id  | HMAC-256 |
| 0x05 | MERIDIAN-SM4    | SM4-GCM           | SM3-KDF   | SM3-HMAC |

*Best: 0x01 (portable, fast) or 0x02 (hardware accel).*

### 3.4 Extensions

```
Extension:
  2 bytes: EXT_ID
  2 bytes: EXT_LENGTH
  N bytes: EXT_DATA

Registered extensions:
  0x0001: REALITY_MODE
    2 bytes: SNI_LENGTH
    N bytes: Spoofed SNI (e.g., "www.google.com")
    2 bytes: DEST_PORT
    2 bytes: SPKI_HASH [32 bytes] (server's public key hash; client verifies)
    4 bytes: MAX_TIME [uint32, seconds since unix epoch] (connection valid until)
    4 bytes: SHORT_ID [uint32] (REALITY short ID)

  0x0002: TRAFFIC_PROFILE
    1 byte: MODE (0 = normal, 1 = fixed-size padded, 2 = randomized size)
    4 bytes: BASE_SIZE [uint32, network order]
    2 bytes: VARIANCE [uint16, max deviation]

  0x0003: SERVER_PUSH
    4 bytes: PUSH_INTERVAL [uint32, seconds]
    4 bytes: PUSH_SIZE [uint32, bytes]

  0x0004: FINGERPRINT
    32 bytes: Target TLS fingerprint (SHA256 of ClientHello bytes)

  0x0005: DOMAIN_FRONTING
    2 bytes: HOST_LENGTH
    N bytes: Fronting host
    2 bytes: PATH_LENGTH
    N bytes: Target path

  0x0006: BANDWIDTH_CONFIG
    8 bytes: UPLOAD_BPS [uint64]
    8 bytes: DOWNLOAD_BPS [uint64]
    2 bytes: ADJUST_INTERVAL [uint16, seconds]

  0x0007: AUTH (password authentication)
    8 bytes: TIMESTAMP [uint64, unix seconds, network order]
    32 bytes: AUTH_TAG [HMAC-SHA256, see below]

    AUTH_TAG = HMAC-SHA256(
      key  = password,
      data = TIMESTAMP || CLIENT_RANDOM(32) || CLIENT_ECDHE(32)
    )

    Binding the tag to the client random and the ECDHE public key prevents an
    attacker from replaying a captured tag on a different session. The server
    rejects tags whose timestamp is older than 120 seconds (or in the future by
    more than 120 seconds), and compares the tag in constant time.

    When no password is configured the server skips this check entirely, which
    keeps passwordless deployments working.
```

### 3.5 ServerHello

```
Offset  Size    Name                Description
0       4       MAGIC               0xDE 0xAD 0xBE 0xEF
4       1       VERSION             0x01
5       1       STATUS              0 = accept, 1 = reject, 2 = retry
6       32      SERVER_RANDOM       32 cryptographic random bytes
38      32      SERVER_ECDHE        Server's X25519 public key
70      32      SERVER_HASH         SHA256(CIPHERS || CLIENT_RANDOM || CLIENT_ECDHE)
102     2       NEGOTIATED_CIPHER   Selected cipher suite ID
104     32      SERVER_CERT_HASH    SHA256 of DER-encoded certificate (REALITY mode)
136     16      SERVER_ID           Session ID (match client's for resume)
152     4       SESSION_LIFETIME    Session lifetime in seconds
156     variable SERVER_EXTENSIONS  Server extensions
N       4       HASH_TAG            SHA256(packed ServerHello)[0:4]
```

### 3.6 Key Derivation

After ECDHE, derive keys using the negotiated KDF:

```
master_secret = KDF(HKDF/Argon2) (
  hash = SHA256(CLIENT_ECDHE || SERVER_ECDHE),
  client_random || server_random
)

keys = KDF(master_secret, "meridian-keys", nonce_counter)
  traffic_enc_key     = keys[0:32]
  traffic_mac_key     = keys[32:64]
  uplink_nonce_seed   = keys[64:80]
  downlink_nonce_seed = keys[80:96]
  init_key            = keys[96:128]  // first packet only
```

The nonce for each packet:
```
nonce = HMAC-SHA256(init_key, counter)[0:12]  // 12-byte nonce for AEAD
```

Counter is a 64-bit monotonically increasing value per direction (separate counters for uplink/downlink).

### 3.7 Server Hash Verification

Both client and server compute:
```
hash = SHA256(cipher_list_bytes || client_random || client_ecdh_public ||
              server_random || server_ecdh_public)
```

If hashes don't match, abort. This prevents MITM who can't forge ECDHE keys.

---

## 4. Meridian Frame Protocol (MFP)

### 4.1 Frame Header (14 bytes, unencrypted)

```
Offset  Size    Name            Description
0       1       TYPE            Frame type (see §4.2)
1       2       PAYLOAD_LENGTH  Length of encrypted payload (network byte order)
3       4       STREAM_ID       Stream identifier (0 = control, 1-2^31-1 = data)
7       1       FLAGS           Bitmask:
                              bit 0: 1 = last fragment
                              bit 1: 1 = compressed (ZSTD)
                              bit 2: 1 = padded (see §4.3)
                              bits 3-7: reserved
8       4       SEQUENCE        32-bit sequence number (per stream, wraps)
12      2       EXTENDED        16-bit extension type (0 = none)
14                    -- header end --
```

### 4.2 Frame Types

| ID  | Name       | Direction    | Description |
|-----|------------|-------------|-------------|
| 0x00| DATA       | Both        | Application payload |
| 0x01| ACK        | Both        | Flow control acknowledgment |
| 0x02| CONGESTION | Both        | Congestion signal (like Hysteria) |
| 0x03| PING       | Both        | Keepalive / round-trip timing |
| 0x04| PONG       | Server->C   | Ping response |
| 0x05| BOUNDARY   | Server->C   | Server push / notification |
| 0x06| ERROR      | Both        | Error with 2-byte code |
| 0x07| FLOW       | Both        | Bandwidth adjustment |
| 0x08| RESET      | Both        | Stream reset |
| 0xFF| KEEPALIVE  | Both        | Null frame (padding placeholder) |

KEEPALIVE doubles as the direction-balancing dummy frame. It is a normal
authenticated frame with an empty payload: an unencrypted, tag-less header is
*not* a legal dummy frame, because the receiver cannot authenticate it.

### 4.2.1 Typed control frames

`Type` and `Flags` are separate header fields and must not be conflated.
PING / PONG / RESET are control frames carried on stream 0 (the control
stream) and are encoded with an explicit type; a DATA frame's `Flags` field
carries per-stream semantics instead:

| Flags | Meaning for DATA frames |
|-------|-------------------------|
| 0x00  | stream payload          |
| 0x01  | CONNECT accepted        |
| 0x08  | CONNECT failed (payload is the error string) |

`0x08` covers both hard failures (dial error) and the retryable
`server busy: stream limit reached`, which a client answers by moving the
stream to another lane rather than surfacing an error to the application.

An implementation that writes a control type into `Flags` silently turns the
frame into an ordinary DATA frame, and the peer will never dispatch it to the
keepalive or stream-teardown handler.

### 4.3 Frame Format (after header)

```
[MFP Header: 14 bytes]
[ENCRYPTED PAYLOAD (variable length)]
  AEAD(CIPHER, traffic_enc_key, nonce, unencrypted_header || payload)

  AuthTag = AEAD_TAG (16 bytes for AEAD-256)
  Total encrypted block = payload + 16
```

#### Nonce counter semantics

Each direction derives its nonce from a per-direction seed and a monotonically
increasing counter. The counter must advance **only** when a frame is
successfully authenticated:

```
nonce = SHA256(seed || counter)[:12]
plaintext, ok = AEAD_Decrypt(key, nonce, frame[14:])
if !ok { discard frame; do NOT increment counter }
counter++
```

Advancing the counter on failure is fatal: a single unauthenticated frame
(truncated packet, an unencrypted dummy, a replayed record) permanently
desynchronises the direction, and every later legitimate frame is then tried
with a wrong nonce and rejected in turn. Since the transport is reliable and
ordered, a failed frame always means loss of sync, so the correct response is to
drop the frame and preserve the counter.

### 4.4 Payload Padding (anti-volume analysis)

When padding mode is enabled (ClientHello flag bit 2):

```
actual_payload   = [2-byte actual length, network order] || application_data
padding_bytes    = random bytes (0 to max_pad_size)
padded_payload   = actual_payload || padding_bytes
```

The 2-byte length prefix lets the receiver recover the real payload without any
out-of-band framing. Both ends must agree on the padding mode: a sender that
pads while the receiver does not strip the prefix silently corrupts the stream,
and vice versa.

- **Normal mode**: payload = actual_data, variable size
- **Fixed mode**: all payloads are EXACTLY `BASE_SIZE` bytes (0 padding removed, overflows split)
- **Random mode**: payload = actual_data || random_padding, total ∈ [BASE_SIZE - VARIANCE, BASE_SIZE + VARIANCE]

Default: BASE_SIZE = 1400 (typical MTU-headers), MODE = random.

---

## 5. Anti-Detection Mechanisms

### 5.1 Traffic Pattern Obfuscation

**Problem:** Censorship systems use timing, size, and direction analysis to detect VPN traffic.

**Solutions:**

1. **Packet Size Normalization**
   - All encrypted frames are padded to uniform sizes
   - Breaks volume-based signature matching
   - Configurable base size (default 1400)

2. **Timing Randomization**
   - Packets sent at pseudo-random intervals (jitter 0-50ms)
   - Prevents timing-based profiling
   - No effect on actual throughput (buffered send)

3. **Direction Balancing**
   - Fake "dummy" frames sent in one direction when traffic is asymmetric
   - Makes upload-heavy and download-heavy connections look similar
   - Ratio can be configured (default 1:1)

4. **Connection Lifetime Variation**
   - Connections opened/closed at random intervals
   - Simulates real user browsing patterns
   - Long-lived background connections get periodic dummy traffic

### 5.2 TLS Fingerprint Randomization (REALITY integration)

Three predefined TLS fingerprints to emulate:

```json
{
  "chrome_win": {
    "fingerprint": "TLS fingerprint of Chrome 120 on Windows 11",
    "ClientHello": "exact bytes of real Chrome 120 ClientHello"
  },
  "firefox_mac": {
    "fingerprint": "TLS fingerprint of Firefox 121 on macOS",
    "ClientHello": "exact bytes of real Firefox 121 ClientHello"
  },
  "curl_linux": {
    "fingerprint": "TLS fingerprint of curl 8.4 on Ubuntu",
    "ClientHello": "exact bytes of real curl 8.4 ClientHello"
  }
}
```

Client specifies target fingerprint in ClientHello. Server must support it.

### 5.3 SNI Spoofing (REALITY)

Client spoofs SNI to point to a legitimate, high-traffic website:

```
Recommended targets:
  - www.google.com          (high traffic, unlikely to block)
  - www.microsoft.com       (enterprise traffic)
  - cdn.cloudflare.com      (already uses CDN)
  - api.github.com          (API traffic)
  - www.bilibili.com        (if targeting China)
```

The server's REALITY mode intercepts connections to the spoofed SNI and proxies them to the actual destination. The server certificate's SHA256 hash (SPKI) is known to the client beforehand - no CA trust required.

### 5.4 HTTP/3 Mirror Mode

When QUIC is blocked but HTTP/3 is allowed, the protocol can mirror HTTP/3 semantics:

```
actual HTTP/3 HEADERS frame  = Meridian control frames
actual HTTP/3 DATA frame      = Meridian DATA frames (encrypted)
actual HTTP/3 SETTINGS        = Meridian handshake (obfuscated)
```

Connection appears as normal H3 traffic to DPI systems.

### 5.5 WebSocket Secure (WSS) Fallback

When QUIC is completely blocked:

```
WebSocket Upgrade Request (looks like standard WSS):
  GET /ws/ HTTP/1.1
  Host: target.example.com
  Sec-WebSocket-Version: 13
  Sec-WebSocket-Key: <random 16-byte>
  Upgrade: websocket
  Connection: Upgrade
  [Padding to look like normal browser WebSocket]
```

After upgrade, Meridian frames are base64-encoded and wrapped as WebSocket binary frames (opcode 0x02).

### 5.6 HTTP-POST Cloud Mirror Mode

When even WebSocket is suspicious:

```
POST /upload HTTP/1.1
Host: storage.cloud-provider.com
Content-Type: multipart/form-data
Content-Length: NNNN

--boundary
Content-Disposition: form-data; name="file"; filename="upload.tmp"
Content-Type: application/octet-stream

[encrypted Meridian frames as binary data]
--boundary--
```

Traffic looks like a cloud storage upload. Repeated POSTs mimic normal cloud backup behavior.

#### Session binding

HTTP is request/response, so a long-lived tunnel has to be rebuilt from many
short requests. The server allocates a session id on the first upload and
returns it in the `Mir-Session` header; every later upload carries that header
so it joins the same tunnel instead of opening a new one.

```
Client                                    Server
  |-- POST /upload (no Mir-Session) ------->|   allocate session, queue uplink
  |<-- 200 OK, Mir-Session: <id> -----------|
  |-- POST /upload, Mir-Session: <id> ----->|   feed uplink, drain downlink
  |<-- 200 OK [downlink bytes] --------------|
  |-- POST /upload, Mir-Poll: 1 ----------->|   long-poll for downlink
  |<-- 200 OK [downlink bytes or empty] ----|
  |-- DELETE /upload, Mir-Session: <id> --->|   release session
```

- The response body carries whatever downlink bytes are pending, so an upload
  doubles as a poll for downlink data.
- A request with `Mir-Poll: 1` and no payload long-polls (bounded, default
  2s) instead of returning empty immediately, which keeps the client's polling
  rate low without adding latency to real traffic.
- Sessions idle for more than 5 minutes are reaped.

Because `Read` on the client polls by issuing an upload, the poll path must not
re-enter the code that takes the transport lock while it is already held.

---

## 6. Flow Control & Congestion

### 6.1 Congestion Control (Hysteria-inspired)

Two modes:

1. **QUIC-mode**: Uses QUIC's built-in congestion control (BBRv2 or Cubic)
2. **UDP/TCP-mode**: Implements a congestion signal protocol:

```
CONGESTION frame:
  1 byte:  TYPE (0x02)
  2 bytes: LENGTH (2)
  4 bytes: STREAM_ID (0)
  1 byte:  FLAGS
  4 bytes: BANDWIDTH_BPS [uint32, bits per second, network order]
  2 bytes: RETRY_INTERVAL [uint16, milliseconds]

Server sends CONGESTION frames to inform client of current bottleneck.
Client adapts sending rate accordingly.
```

### 6.2 Flow Control (Stream-level)

Every stream is credit-windowed in each direction. A sender may have at most
`stream_window` unacknowledged bytes in flight; the receiver returns credit
with cumulative `ACK` frames as its application consumes data.

```
ACK frame (type 0x01, stream id = the data stream):
  8 bytes: CUMULATIVE_CONSUMED [uint64, big endian]
```

Rules:

- The sender reserves credit before writing a DATA frame and refunds it if the
  write fails. When the window is exhausted it blocks until an ACK arrives.
- The receiver emits one ACK per `window / 8` bytes consumed (bounded to
  16–256 KiB), so the reverse direction carries a negligible amount of
  overhead while credit is refilled promptly.
- ACK counts are cumulative and are clamped to the bytes actually sent, so a
  duplicated, reordered or forged ACK cannot over-credit a stream.
- A sender that sees no credit for 60 seconds treats the stream as stalled,
  resets it, and lets the application reconnect.

Why this exists: without a window, one bulk stream fills the shared socket
buffer and every later frame — including the first response of a newly opened
stream — queues behind it. Measured on a saturated 4-lane WebSocket tunnel,
that produced ~1.3 s median / ~2.2 s p90 time-to-first-byte for small
requests. Bounding in-flight bytes per stream limits queueing delay to roughly
`stream_window / link rate` (1 MiB at 150 Mbps ≈ 55 ms) while leaving
per-stream throughput at `window / RTT`.

### 6.2.1 Capability negotiation and fallback

Flow control is advertised with the `0x08 FLOW` bit in the ClientHello flags
byte rather than a protocol version bump, so peers that predate it keep
working:

- The client sets `FlagFlow` and still sends `CurrentVer` (1).
- A server that understands it answers with version **2** in ServerHello byte
  4 and enables windowing in both directions.
- A server that does not understand it ignores the unknown bit, answers
  version 1, and the session runs without a window — no ACK frames, receive
  queue backpressure only.
- An older client never sets the bit, so a new server keeps the same
  unlimited behaviour for it and answers version 1.

Both ends MUST NOT send ACK frames unless the session negotiated version 2.

The `0x02 CONGESTION` and `0x07 FLOW` frame types remain reserved.

### 6.2.2 Concurrent stream cap

`max_concurrent_streams` caps how many streams one lane may carry at once
(default 512, clamped to 16–4096):

- The client checks the cap when opening a stream and returns a retryable
  "lane saturated" condition, so the dial is re-attempted on the least loaded
  lane.
- The server checks the cap when it receives `CONNECT` and answers
  `0x08 CONNECT failed` with `server busy: stream limit reached` when the lane
  is full. It never silently drops the request.

The local proxy listener is sized as `max_concurrent_streams ×
tunnel_connections`, clamped to 512–4096, so a multi-lane client is not
throttled by a single lane's budget.

### 6.2.3 Local buffering and stall detection

Each stream keeps a hand-off queue between the tunnel read loop and the
application socket. An implementation MUST bound that queue in **bytes**, not
in frames:

- The threshold is `stream_window + 4 × 60 KiB`.
- Because flow control already caps in-flight bytes at `stream_window`, a
  healthy stream can never reach the threshold: reaching it proves the local
  consumer stopped reading.
- Only then is the stream reset (`RESET`), and only that stream — the shared
  read loop never blocks on a single slow consumer, so one stalled download
  cannot add latency to every other stream.

Counting frames instead of bytes is a defect: a burst of small frames (an
ordinary side effect of TCP segmentation on a fast link) can fill a
frame-counted queue while holding only tens of kilobytes, resetting streams
that were never stalled. That produced truncated downloads and video
playback retries in v1.6.5.

### 6.3 Keepalive & Heartbeat

Ping/Pong frames with timestamp:

```
PING frame:
  1 byte:  TYPE (0x03)
  2 bytes: LENGTH (12)
  4 bytes: STREAM_ID (0)
  1 byte:  FLAGS
  4 bytes: SEQUENCE
  8 bytes: TIMESTAMP [uint64, milliseconds, network order]

PONG frame mirrors PING with received timestamp.
RTT = server_timestamp - client_timestamp (one-way) * 2 (approximate)
```

Default ping interval: 30 seconds. Timeout: 3 consecutive missed pongs = dead connection.

### 6.4 Session Lifetime and Lane Draining

`session_lifetime` (default `1h`, `0` disables) bounds how long an outer
connection may live, so a single long-lived TCP/TLS session does not become a
stable fingerprint. The lifecycle is:

1. A lane whose age reaches `session_lifetime` enters the **draining** state.
   It stays connected but receives no new streams.
   Lane `n` of `N` uses `session_lifetime × (1 + n/20)` (up to +15%) so lanes
   opened together do not all drain at the same instant.
2. Existing streams keep running until they finish, or until the drain grace
   period expires: `clamp(session_lifetime / 10, 30s, 5min)`.
3. The lane is closed and reconnected with a fresh TLS/QUIC handshake. The
   session ID is intentionally reused so session resumption still works; only
   the outer connection is refreshed.

Lane state is local to the client — nothing is signalled on the wire, so a
server does not need to support draining to interoperate.

### 6.5 Multi-lane Stream Distribution

`tunnel_connections` (1–16) is the number of independent outer connections a
client maintains. Each lane is a full Meridian tunnel (own handshake, session
ID and keys), and the client assigns each new stream to the lane with the
lowest active stream count, skipping lanes that are closed or draining. If the
chosen lane fails while dialling, the remaining lanes are tried once before the
proxy reports a failure.

This exists because a single outer TCP/QUIC flow is BDP-limited: on a ~55ms RTT
path one flow plateaus around 150 Mbps regardless of available bandwidth, while
four WebSocket lanes reach 500–600 Mbps aggregate. Lanes are independent, so
their throughput adds up; per-stream throughput is still bounded by the lane it
lands on.

---

## 7. Security Properties

### 7.1 Encryption

| Parameter | Value |
|-----------|-------|
| **AEAD** | ChaCha20-Poly1305 (default) or AES-256-GCM |
| **Key Length** | 256 bits (AEAD key + MAC key) |
| **Nonce** | 12 bytes, derived from session key + counter |
| **Auth Tag** | 16 bytes (AEAD tag) |

### 7.2 Key Exchange

- **Algorithm**: X25519 (ECDH over Curve25519)
- **Type**: Ephemeral (perfect forward secrecy)
- **Handshake Hash**: SHA-256 for verification

### 7.3 Authentication

- **Primary**: X.509 certificate (standard TLS) or SPKI hash (REALITY)
- **Session**: 16-byte session token (for resume)
- **Channel Integrity**: SHA-256 hash of handshake transcript

### 7.4 Forward Secrecy

Every connection uses a new X25519 key pair. Compromising the server's long-term key does NOT allow decryption of past sessions.

### 7.5 Post-Compromise Security (Renewal)

Sessions periodically re-key from application data:

```
Every 64MB of transferred data, or every 5 minutes:
  1. Generate new session keys from current traffic
  2. Discard old keys
  3. Continue transparently
```

This ensures that even if a session key is compromised, the damage is limited to at most 5 minutes or 64MB of traffic.

---

## 8. Server Push & Notifications

### 8.1 PUSH BOUNDARY Frame

Server can push data to clients without explicit request:

```
BOUNDARY frame:
  1 byte:  TYPE (0x05)
  2 bytes: LENGTH (4 + push_data_length)
  4 bytes: STREAM_ID (0 for broadcast, >0 for specific stream)
  1 byte:  FLAGS (0x01 = last fragment)
  4 bytes: SEQUENCE
  2 bytes: EXTENDED
  N bytes: PUSH_DATA (encrypted payload)
```

Use cases:
- Server-initiated config updates
- Push notification payloads
- Live data streams (e.g., market data)
- Critical alerts

### 8.2 Multi-cast Groups

Clients can join push groups (identified by 32-byte group ID). Server broadcasts to all members of a group simultaneously.

---

## 9. Protocol Implementation Guidelines

### 9.1 Recommended Defaults

```go
type DefaultConfig struct {
    Transport            TransportType = "QUIC"
    CipherSuite          CipherID    = 0x0001  // CHACHA20
    PaddingMode          PaddingMode   = "random"
    BasePayloadSize     uint32       = 1400
    MaxPayloadSize      uint32       = 1452  // typical UDP MTU
    KeepaliveInterval   float32      = 30  // seconds
    HandshakeTimeout    float32      = 10  // seconds
    StreamWindow        uint64       = 1048576  // 1MB in-flight window per stream
    MaxConcurrentStreams uint32      = 512      // per lane
    TunnelConnections   int          = 4        // independent outer connections
    SessionLifetime     uint32       = 3600  // 1 hour
    RenewalInterval     float32      = 300  // 5 minutes
    RenewalDataLimit    uint64       = 67108864  // 64MB
}
```

`StreamWindow` is clamped to 256 KiB–16 MiB, `MaxConcurrentStreams` to 16–4096,
`TunnelConnections` to 1–16, and `SessionLifetime` to 5 minutes–24 hours (or `0`
to disable recycling).

### 9.2 Performance Benchmarks (Reference)

| Metric | Value |
|--------|-------|
| Handshake (full) | ~80ms (single RTT) |
| Handshake (0-RTT resume) | ~30ms |
| Overhead (encrypted frame) | 30 bytes (14 header + 16 auth tag) |
| Max throughput (1Gbps link) | ~950Mbps (theoretical, with padding) |
| Latency (local, no padding) | ~12μs per 1KB frame |
| Server memory per conn | ~384KB |

### 9.3 Interoperability Notes

- Compatible with standard QUIC implementations (boring QUIC, masque, quic-go)
- WebSocket fallback requires standard RFC 6455 WebSocket library
- REALITY integration requires XTLS REALITY-compatible backend
- Certificate-based mode is compatible with standard mTLS deployments

---

## 10. Migration Path from Existing Protocols

### 10.1 Shadowsocks → Meridian

| SS Concept | Meridian Equivalent |
|-----------|-------------------|
| Cipher | AEAD (Chacha20-Poly1305 / AES-GCM) |
| Auth | HMAC-SHA256 in frame header |
| TCP stream | QUIC streams or WebSocket frames |
| UDP relay | MFP BOUNDARY frames over QUIC |

### 10.2 Hysteria → Meridian

| Hysteria Concept | Meridian Equivalent |
|-----------------|-------------------|
| QUIC transport | QUIC (same transport layer) |
| Custom congestion | CONGESTION frames (same semantics) |
| Request/Response | MFP DATA + ACK (same model) |
| Server push | BOUNDARY frames |
| Auth token | Session token + ClientHello hash |

### 10.3 VLESS → Meridian

| VLESS Concept | Meridian Equivalent |
|----------------|-------------------|
| VMess UUID | Client ID (32-byte session ID) |
| Auth ID + Sort ID | ClientHello hash verification |
| obfs (WebSocket) | WebSocket transport mode |
| obfs HTTP | HTTP-POST mirror mode |
| Header → stream | MFP stream multiplexing |

### 10.4 REALITY → Meridian

| REALITY Concept | Meridian Equivalent |
|----------------|-------------------|
| SNI spoofing | REALITY_MODE extension |
| SPKI hash verification | Server cert hash in ServerHello |
| Short ID | ClientHello SHORT_ID |
| Max time validity | Session lifetime |
| TLS fingerprint | FINGERPRINT extension |
| Reverse proxy | Server mode configuration |

---

## 11. Wire Format Summary

### ClientHello (minimum ~150 bytes)

```
0xDeadBeEF  (4 bytes magic)
0x01        (1 byte version)
0x00        (1 byte flags)
[0x0002]    (2 bytes client MTU)
[32 bytes client random]
[32 bytes client ECDHE public key]
[32 bytes client hash = SHA256(ciphers || client_random || client_ecdh)]
[16 bytes client session ID]
[cipher list (variable)]
[extensions (variable)]
[4 bytes hash tag = SHA256(message)[0:4]]
```

### ServerHello (minimum ~200 bytes)

```
0xDeadBeEF  (4 bytes magic)
0x01        (1 byte version)
[0x00]      (1 byte status)
[32 bytes server random]
[32 bytes server ECDHE public key]
[32 bytes server hash = SHA256(ciphers || client_random || client_ecdh || server_random || server_ecdh)]
[2 bytes negotiated cipher suite]
[32 bytes server certificate hash (or 0s)]
[16 bytes server session ID]
[4 bytes session lifetime]
[server extensions (variable)]
[4 bytes hash tag]
```

### Data Frame (minimum 44 bytes)

```
[14 bytes MFP header]
[N bytes encrypted payload]
[16 bytes AEAD auth tag]
```

### Max packet size: 1452 bytes (typical UDP-safe MTU)
### Min packet size: 44 bytes (empty payload, no padding)

---

## 12. Security Considerations

### 12.1 Threat Model

| Threat | Mitigation |
|--------|-----------|
| Passive eavesdropping | AEAD encryption (AES-GCM / ChaCha20-Poly1305) |
| Active MITM | ECDHE key verification + certificate/SPKI check |
| DPI detection | Traffic normalization, SNI spoofing, fingerprint randomization |
| Traffic analysis | Padding, timing randomization, direction balancing |
| Replayed connection | Session ID + nonce counter + timestamp |
| Server key compromise | Forward secrecy (per-session ECDHE) |
| Long-term session compromise | Automatic key renewal (time + data limits) |

### 12.2 Known Limitations

1. **Padding overhead**: Fixed-size padding reduces throughput by 5-30% depending on configuration. Trade-off between stealth and performance.

2. **WebSocket fallback**: Higher overhead (WebSocket header 6-14 bytes per frame), cannot exploit QUIC's multiplexing.

3. **QUIC fingerprinting**: Some firewalls detect QUIC by connection pattern. The WebSocket/HTTP-POST fallbacks mitigate this.

4. **Memory usage**: Each encrypted connection requires key material, buffer pools, and stream state (~384KB baseline).

### 12.3 Recommendations

1. **Default to QUIC + CHACHA20 + REALITY** for best performance-security balance
2. **Use SNI spoofing to high-traffic domains** to avoid being singled out
3. **Enable random padding mode** when facing active DPI
4. **Rotate fingerprints periodically** (every ~24 hours) to avoid long-term profiling
5. **Keep connections alive** for ~30 minutes before rotating (simulates real usage)
6. **Use realistic payload sizes** (80% of traffic should be 200-1500 bytes)

---

## 13. Glossary

| Term | Definition |
|------|-----------|
| **MFP** | Meridian Frame Protocol - application-level protocol |
| **MTP** | Meridian Transport Protocol - handshake layer |
| **AEAD** | Authenticated Encryption with Associated Data |
| **SPKI** | Subject Public Key Info - fingerprint of server's public key |
| **SNI** | Server Name Indication - TLS extension for host routing |
| **REALITY** | Transport agnostic TLS fingerprint + SNI spoofing mode |
| **DPI** | Deep Packet Inspection |
| **ECDHE** | Elliptic Curve Diffie-Hellman Ephemeral |
| **X25519** | Elligator 2 key agreement over Curve25519 |
| **0-RTT** | Zero Round Trip Time - resume handshake in 1 message |
| **HOL** | Head-of-Line blocking |
| **BBR** | Bottleneck Bandwidth and Round-trip time |

---

*Document Version: 1.0*
*Last Updated: 2026-06-01*
*Authors: Meridian Protocol Design Team*
