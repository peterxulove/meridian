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

### v1.6.18 (2026-10-30)

#### ⏱ First-byte watchdog: a silent server no longer hangs forever

Router 110's 10809 broke last night with a signature nothing like 111's: four lanes handshook successfully and never logged a disconnect, the SOCKS handshake succeeded, the request bytes went into the tunnel, and then nothing came back. `total` sat at 4, not one `dial_other` event, and it did not recover in eight minutes — a restart fixed it.

The cause is early data: `DialStream` returns immediately when `tc.earlyData` is set instead of waiting on `confirmChan`. That saves a round trip (the first frame of a video notices), and the price is that a server which never answers becomes an infinite wait — no timeout, no counter, no log line. That server (132.226.1.144) was answering keepalives the whole time, so the client saw nothing wrong.

- **First-byte watchdog**: armed when the CONNECT is sent (`first_byte_timeout`, default 10s) and disarmed by anything the server says about that stream — CONNECT SUCCESS, data, reset. If nothing arrives, the stream is reset and the application gets the error; `stream_silent` joins the per-minute summary.
- **Three in a row rebuild the lane** (`first_byte_failures`, default 3): one slow target does not count, but three separate dials with no answer mean the server stopped serving. Logged as `3 streams in a row went unanswered within 10s, server is not serving; reconnecting`.
- **One burst counts once**: dial order decides — streams already in flight when the previous silence was counted belong to the same incident, so a browser opening five sockets to a dead host is one failure and will not tear down a lane that is serving everything else. Any response clears the streak immediately.
- `first_byte_timeout: 0` disables the watchdog; `first_byte_failures: 0` resets streams but never rebuilds the lane.

Verified by freezing the server with `SIGSTOP` — socket open, kernel still acknowledging, nothing ever answered, exactly the 10809 state:

- Three requests failed after **4s** each (test config `first_byte_timeout: 4s`) instead of sitting until the application's 45s timeout; the fourth failed in 0s while the lane was being rebuilt.
- The log showed `3 streams in a row went unanswered within 4s, server is not serving; reconnecting`, then `QUIC disconnected after 16s, reconnecting`, then a fresh handshake.
- After `SIGCONT`: 200 within 5s and stable for the following 30s.
- 7 unit tests plus `go test -race ./...` clean.

No wire change; the server does not need to be updated.

### v1.6.17 (2026-10-30)

#### 🔁 A lane now hands over instead of stepping aside

At 21:03 every request through router 111's 10808 returned `dial … failed: tunnel not connected or unavailable`; `failed` climbed from 0 to 1780 and it stayed that way until the process was restarted. The log showed all four lanes printing `session lifetime reached, draining` at 20:53, 20:56, 20:59 and 21:02 — and not one reconnect afterwards.

The network was fine. A lane that reached its lifetime drained in place: stop taking streams, close once the ones already running finish. But every drain was still carrying long-lived streams (Telegram-style connections that never end), so `ActiveLoad()` never reached zero and no lane ever closed. Four lanes three minutes apart meant all four were draining at once, `pickTunnel` had nothing to hand a request to, and the proxy was a black hole — for as long as `drainGrace(1h)`, i.e. up to half an hour.

- **Successor first**: a lane reaching its lifetime gets a replacement connection built on the same transport and published, and only then is the old one retired in the background. New streams go to the successor immediately; the old connection keeps serving what it already carries. Same ordering as a transport switch and as the QUIC fallback.
- **A failed handover never strands the lane**: if the successor cannot connect, the current connection keeps serving and the handover is retried in 5s; the failure still counts towards `quic_fallback_*`.
- **Retired connections are no longer cut on a timer**: at the end of the grace the deadline is re-armed if any stream moved a byte in the last two minutes (`retired lane still moving N/M streams, holding it for another 30m0s`), and a lane whose streams have all gone quiet is closed.
- **Last resort**: if every lane happens to be retired, `pickTunnel` serves the least loaded retired lane instead of answering `tunnel not connected`, logging `[Proxy] no fresh lane, serving on retired lane …` at most once a minute.

No wire change; the server does not need to be updated.

Verified with `session_lifetime: 5m`, two lanes, one 6KB/s download per lane so
each lane is still carrying a live stream when it rotates, probing every 4s for
8 minutes:

- **Before**: lanes printed `draining (1 active)` at 21:30:29 and 21:30:44, then
  every request returned `tunnel not connected or unavailable` until 21:32:47 —
  90 of 120 probes succeeded, 30 failed, a black hole of 2m18s. Same shape as
  the router 111 incident.
- **After**: the successor handshake lands in the same second as the rotation
  (`rotating (draining 1 active)` immediately followed by `handshake successful
  over QUIC`), 120/120 probes succeeded across both rotations.
- `go test -race ./...` clean.

### v1.6.16 (2026-10-30)

#### 🛬 When QUIC cannot get through, use WSS: fall back after repeated failures

At 19:22:40 router 111 dropped four QUIC lanes at once, every one of them with
`timeout: no recent network activity`; 159 connections failed inside a minute
and it healed itself 60 seconds later. Router 110 had zero failures in the same
window — the server was fine, that path simply dropped UDP for a while. The old
loop retried QUIC every five seconds: it kept sending into the one path that
could not work, while a WebSocket listener on the same port sat there unused.

- **Failure streak**: a failed handshake counts once; so does a connection that
  dies inside `quic_fallback_min_uptime` (15s default) — **a handshake that
  immediately dies is exactly what a blocked UDP path looks like**, so it must
  not reset the streak.
- **Three failures in a row** (`quic_fallback_failures`) park that lane on
  WebSocket for `quic_fallback_hold` (10 minutes).
- **The hold doubles per trip** (10m → 20m → 40m → 1h cap) and is forgotten as
  soon as a QUIC connection survives the min uptime. A path blocked all evening
  is not re-probed every ten minutes, and a restored one is picked up at once.
- **Probing never cuts a playing stream**: the replacement is connected on the
  new transport before the old lane is retired, the same order the daily
  schedule uses.
- **Per lane**: four lanes decide independently, so they stagger instead of
  turning around in the same second.
- `quic_fallback_failures: 0` disables the fallback and restores "retry QUIC
  forever".

```
[19:38:34] [Tunnel 1/1] QUIC connect failed: tunnel: Hysteria client creation failed: connect error: timeout: no recent network activity, retrying in 5s
[19:38:54] [Tunnel 1/1] QUIC failed 3 times in a row, falling back to WebSocket for 1m0s
[19:38:54] [Tunnel] handshake successful over WebSocket, cipher MERIDIAN-CHACHA
[19:39:59] [Tunnel 1/1] switch to QUIC failed: … no recent network activity, staying on WebSocket
[19:40:19] [Tunnel 1/1] QUIC still unreachable after 3 tries, staying on WebSocket for 2m0s
```

Verification:

- Nine new unit tests (threshold, hold expiry, doubling and cap, a healthy
  connection clearing the streak, a short-lived connection counting as a
  failure, WebSocket failures ignored, `0` disabling it, HTTP-POST untouched)
  plus one for the config normaliser; `go test -race ./...` is green.
- **E2E A — UDP blocked** (server offering WebSocket only, nothing listening on
  UDP): after three QUIC failures, one every ~10s, the lane fell back at
  `19:38:54`, the WebSocket handshake succeeded **in the same second** and a
  SOCKS request returned 200. When the one-minute hold expired it probed QUIC
  three more times, failed, doubled the hold to two minutes, and curl kept
  returning 200 throughout.
- **E2E B — QUIC healthy** (hybrid server): both the pre-change and post-change
  clients connected over QUIC immediately, 12/12 requests returned 200, and the
  `connect failed` count stayed at zero.
- **E2E C — replaying the 111 incident** (QUIC connected, then the UDP listener
  is replaced by a WebSocket-only server): `19:47:42 QUIC disconnected after
  40s` → three failures → fell back at `19:48:07`, 200 in the same second. The
  old build would have retried QUIC until the path came back.

No wire-format change; the server does not need an update.

### v1.6.15 (2026-10-30)

#### 🎬 Stop killing streams on a timer: reclaim under pressure, drain by liveness

v1.6.14 reclaimed a stream after 10 minutes without a byte. The trouble is that
**a paused video, a keep-alive socket the browser still intends to use, and a
connection the application forgot are identical from the byte stream**. The
instance on router 111 reclaimed 12 streams in 1.5 hours, every one of them
between 10m01s and 10m30s, and in the same window logged
`drain grace expired with 1 active, closing` — a retired lane whose grace ran
out took a playing stream with it. Both look like "playback interrupted" to the
viewer, and both belong to the same family as the three causes fixed in v1.6.9
(the Happy Eyeballs regression, the 60 second flow stall, the 5 minute lane
close), just with different triggers.

- **Reclamation is gated on lane pressure**: it starts at 80% of the lane's
  stream cap. While there is room, nothing is evicted — ordinary browsing and a
  paused video are never touched by a timer. When the lane does fill, the oldest
  streams go, so a forgotten connection is still cleaned out.
- **Threshold 10 → 30 minutes**, as a ceiling on how long a leak can hide
  rather than a schedule that kills idle streams.
- **A draining lane is checked for life before its grace expires**: if any
  stream moved a byte in the last two minutes the deadline is pushed forward,
  and only a lane whose streams have all gone silent is closed. Rotation still
  happens for idle lanes; a playing video is never cut.
- Reclamation logs now name the **target address** and the lane occupancy, so
  "is the client killing my video?" is answerable from the log.

```
[Summary] last 60s: conns=0 events=16 stream_idle=16 | stream_idle: tunnel: stream 16 (127.0.0.1:8081) idle for 55s, reclaimed (lane was 16/16 in use)
```

Verification:

- Four new unit tests: no reclamation without pressure, age-based reclamation on
  a full lane, target address in the summary line, `ActiveWithin` liveness.
- Local end to end (same server, `stream_idle_timeout: 30s`): a lane with room
  for 512 and one silent stream → **untouched after 120s**; a lane capped at 16
  with 16 silent streams → **16/16 reclaimed within 55s**.
- Drain: one lane, `session_lifetime: 5m`, a slow source emitting 64 bytes every
  5 seconds. The lane starts draining at its lifetime, and when the grace
  expires five minutes later it logs
  `drain extended: 1/1 streams alive, next check in 5m0s` instead of closing;
  the reader pulled **11342 bytes over 801 seconds without one break**.

No wire-format change; the server does not need an update.

### v1.6.14 (2026-10-30)

#### 🩺 Make a freeze leave evidence: file logging, per-minute summaries, half-dead stream reclamation

This started from the freeze on router 111: the SOCKS layer reported
`failed=617` out of `total=1585` (~39%), but the window that would explain it
had already been evicted — one line per failed connection cleared out logd's
64 KiB ring.

Four changes:

- **Log to a rotated file** (`log_file` / `log_rotate_size` /
  `log_rotate_keep`). Stdout stays, so `logread` still works; the file is what
  survives a storm. 4 MiB × (1+3) by default, rotating on line boundaries so a
  line is never split across two files.
- **Failures become one summary line per minute**, counted by reason
  (`dial_timeout` / `dial_refused` / `dial_dns` / `dial_reset` /
  `dial_lane_full` / `limit_dropped` / `negotiate` / `stream_idle` …) with a
  single sample kept per reason:

```
[Summary] last 60s: conns=0 events=1 stream_idle=1 | stream_idle: tunnel: stream 65 idle for 39s, reclaimed
[Summary] last 60s: conns=319 events=612 dial_timeout=590 limit_dropped=22 | dial_timeout: socks5: [192.168.1.111:36890] dial www.gstatic.com:443 failed: tunnel: dial timeout …
```

​       `conns=` also replaces the per-connection flood as evidence of a
connection storm, which is why `log_verbose` defaults to off.
- **Reclaim half-dead streams** (`stream_idle_timeout`, 10 minutes in this release; 30 minutes and pressure-gated from v1.6.15).
  When a player drops a connection without closing the socket, the stream keeps
  its slot and its window forever; enough of them and the tunnel looks
  connected while applications cannot connect at all. A stream with no bytes in
  either direction past the threshold is reset on the wire.
- **`deploy.sh` no longer drops the transport schedule.** It rewrites
  `client.yaml` wholesale and the template had no `transport_schedule`, so a
  re-deploy silently turned "QUIC at night" into "WebSocket around the clock".
  The template now carries a commented example, and an existing
  `transport_schedule` / `schedule_timezone` is appended back with a
  `Transport schedule preserved:` line.
- **Timestamps follow a configured zone** (`log_timezone`, defaulting to
  `schedule_timezone`). Router 110's system zone turned out to be UTC while 111
  was UTC+8, so the same incident sat 8 hours apart in the two logs.
- **Cap concurrent dials per lane** (`max_pending_dials`, default 64). A storm
  no longer hands hundreds of simultaneous dials to the server to time out
  together: the excess queue behind a slot, bounded by the caller's deadline.

Local verification (`stream_idle_timeout: 5s` clamped up to the 30s floor,
reaper every 30s):

- One silent connection against a black-hole target **was reclaimed after 39s**,
  and the next summary reported `stream_idle=1`.
- 60 concurrent connections to the same target with `max_pending_dials: 2`
  (deliberately tiny): **60/60 succeeded**, none failed because of queueing.
- The file matched stdout, and after rotation `client.log` / `.1` / `.2` were
  all under the limit and ended on a newline.

No wire-format change: the server does not need to be updated.

### v1.6.13 (2026-10-30)

#### 🩹 Fallback fixes: preserve Host, bound every phase, pin HTTP/1.1

Two problems showed up as soon as `fallback_url` met a real server:

- The proxy rewrote `Host` to the target address (`127.0.0.1`), which landed on the cover site's default server block and got closed with 444 — the probe saw a 502. Host is now rewritten only for domain targets; an address target (the loopback case) keeps the virtual host the probe asked for.
- HTTPS fallback hung: after negotiating h2 the exchange stalled and the probe stayed connected. The cover hop is now pinned to HTTP/1.1, with 5s dial, 5s handshake and 8s response-header deadlines, so a dead cover site returns 502 instead of pinning a connection.

### v1.6.12 (2026-10-30)

#### 🪪 Closing the handshake surface: no self-named ALPN, no self-signed cert, no 404

Identification cost is concentrated in the fields nobody needs to decrypt, so
this release only touches those:

- **The client offers browser ALPN values only**: `h3` over QUIC, `h2` + `http/1.1` over WSS. The WSS ClientHello used to carry `meridian-1` in cleartext, which names the protocol to every observer. The server keeps accepting `meridian-1` for old clients — its choice lives in the encrypted ServerHello, so it exposes nothing — which allows a fleet-wide upgrade without a flag day.
- **The certificate must come from a CA**: `deploy.sh` now installs from acme.sh when `MERIDIAN_DOMAIN` is set (with the renewal reload hook), or takes `MERIDIAN_CERT`/`MERIDIAN_KEY`. A self-signed pair is generated only with explicit consent, and is now 90 days with a SAN. The server prints the certificate CN and expiry at start-up and warns on self-signed or near-expiry.
- **Unauthenticated requests get the cover site**: `fallback_url` / `fallback_sni` reverse-proxy everything that is not a tunnel upgrade (including a plain GET on `/ws/`), so a probe gets the cover site's status, headers and body instead of Go's `404 page not found` or the upgrader's 400.

Also fixed a silent downgrade: with `reality_mode: true` and no `reality_spki`,
the client used to skip certificate verification entirely. No pin now means
normal CA verification, so deleting one line no longer disables authentication.

Specification is now v1.8 (§5.7, handshake surface).

### v1.6.11 (2026-10-30)

#### 🕘 The schedule no longer trusts the system timezone

`transport_schedule` can now pin the zone its windows are evaluated in:

```yaml
transport: "WebSocket"
transport_schedule:
  - transport: "QUIC"
    from: "19:00"
    to: "03:00"
schedule_timezone: "UTC+8"     # IANA names such as Asia/Shanghai also work
```

- This fixes a bug seen in the field: when the file behind `/etc/localtime` is unreadable, `date` prints only `CST-8` with no time of day and Go's `time.Local` silently falls back to UTC. A client that should have used WebSocket at 10:59 decided it was 02:59 and dialled QUIC.
- Fixed offsets accept `UTC+8`, `UTC+08:00`, `+08:00`, `-0700`, `GMT+5:30`. A typo is a start-up error instead of a silent shift to UTC.
- The start-up banner now prints the zone, the current time and the chosen transport, so the decision is verifiable at a glance.

### v1.6.10 (2026-10-30)

#### 🕒 Time-based transport switching: WebSocket by day, QUIC at night

The client can now follow a daily schedule in **local time**:

```yaml
transport: "WebSocket"        # used outside every window
transport_schedule:
  - transport: "QUIC"         # 19:00-03:00
    from: "19:00"
    to: "03:00"
```

- The first matching window wins, otherwise `transport` is used. Windows may
  wrap around midnight.
- A switch builds the replacement connection on the new transport and installs
  it **before** retiring the old one, so new connections use the new transport
  immediately while existing streams finish on the old one (up to five more
  minutes). There is never a moment without a usable lane.
- Malformed entries (bad times, a client-unsupported transport such as
  `QUIC+WebSocket`, identical from/to) fail at start-up instead of silently
  keeping the wrong transport for a day.
- The banner prints the schedule and each switch logs
  `Schedule switched WebSocket -> QUIC`.

Verified locally with a window starting one minute ahead (two lanes): WSS →
QUIC → WSS, 25 probes at 5 s intervals during the switches, no failures.

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

QUIC runs on UDP, the first thing an unfriendly path drops, and it fails in a way indistinguishable from "the server is down": the handshake times out, or an established association dies with `timeout: no recent network activity`. By default the client parks a lane on WebSocket — same port, same handshake — after three consecutive QUIC failures, then probes QUIC again ten minutes later. See `quic_fallback_*`.

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
| `stream_idle_timeout` | A stream with **no byte in either direction** for this long becomes a reclamation candidate; it is only actually reclaimed when the lane is at 80% of `max_concurrent_streams` (RESET, slot freed); `0` disables | `30m` | 0 or ≥30s |
| `max_pending_dials` | Concurrent dials awaiting the server, **per lane**; the rest queue instead of failing; `0` disables | `64` | 0–4096 |
| `quic_fallback_failures` | Consecutive QUIC failures that park the lane on WebSocket; `0` retries QUIC forever | `3` | 0–20 |
| `quic_fallback_hold` | How long a parked lane stays on WebSocket before probing QUIC again; doubles per trip, capped at 1h | `10m` | 30s–6h |
| `quic_fallback_min_uptime` | Uptime that makes a QUIC connection count as healthy; anything shorter is another failure | `15s` | 5s–10m |

The local proxy listener is sized as `max_concurrent_streams ×
tunnel_connections` (clamped to 512–4096), so multiple lanes are not throttled
by a single lane's budget.

### Logging and diagnosis

By default the client only writes to stdout, which procd/systemd forwards to
the system log. A router's logd ring holds only tens of KiB, so **one burst of
errors overwrites the window that explains it**. Enable the file sink when you
expect to dig through an incident:

```yaml
log_file: "/var/log/meridian-client.log"   # stdout keeps working
log_rotate_size: 4194304                   # 4 MiB per file
log_rotate_keep: 3                         # keep .1 .. .3
log_verbose: false                         # true logs one line per connection
# log_timezone: "UTC+8"                    # clock for timestamps; defaults to schedule_timezone
```

Three shapes of line:

```
[2026-10-30 16:51:28] [Tunnel] handshake successful over QUIC, cipher MERIDIAN-CHACHA   # event
[2026-10-30 16:52:28]   [Stats] active=1 total=65 failed=0 in=4KB out=7KB               # running totals
[2026-10-30 16:52:28] [Summary] last 60s: conns=65 events=0                             # per-minute summary
```

Timestamps follow `schedule_timezone` (then the system zone): two routers do not
necessarily agree on `/etc/localtime` — measured 110 in UTC and 111 in UTC+8, so
the same incident was 8 hours apart in the two logs.

`conns=` is how many proxied connections were opened in that minute (a restart
storm is obvious), `events=` counts failures and reclaims by reason, and the
`|` part shows one sample for the three busiest reasons. Read it in this order:
whether `conns=` spiked, then the ratio of `dial_timeout` (upstream is slow) to
`limit_dropped` (local slots are exhausted); `stream_idle` counts reclaimed
half-dead streams.


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
