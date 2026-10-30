# Meridian 协议

> 高性能、抗检测的安全代理协议实现  
> 融合 Shadowsocks、Hysteria2、VLESS 和 REALITY 的设计精华

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/peterxulove/meridian)](https://github.com/peterxulove/meridian/releases)
[![Platform](https://img.shields.io/badge/Platform-macOS%20%7C%20Linux-lightgrey)](https://github.com/peterxulove/meridian/releases)
[![Architecture](https://img.shields.io/badge/Arch-ARM64%20%7C%20AMD64-orange)](https://github.com/peterxulove/meridian/releases)

[English README](README_EN.md)

---

## 目录

- [简介](#简介)
- [更新日志](#更新日志)
- [协议架构](#协议架构)
- [功能特性](#功能特性)
- [快速开始](#快速开始)
- [使用方式（局域网代理）](#使用方式局域网代理)
- [配置说明](#配置说明)
- [安全机制](#安全机制)
- [编译构建](#编译构建)
- [下载预编译版本](#下载预编译版本)
- [开发说明](#开发说明)

---

## 简介

Meridian 是一个自定义安全代理协议，设计目标是在恶劣的网络环境下实现**不可检测的加密通信**。

| 目标 | 指标 |
|------|------|
| 抗检测 | 流量与正常 HTTPS/HTTP3 无法区分 |
| 低延迟 | 握手延迟 < 50ms，支持 0-RTT 会话恢复 |
| 高吞吐 | 理论吞吐达链路带宽 95%+ |
| 健壮性 | 跨 NAT、防火墙、拥塞网络正常工作 |
| 前向保密 | 每次连接使用独立的临时密钥 |
| 内存占用 | 服务端每连接 < 512KB |

---

## 多节点与多实例

一台机器可以跑多个服务端，一个客户端也可以同时连多台服务器。每个实例只是
一份配置加一个服务单元，没有共享状态。

服务端（systemd）：

```
/etc/meridian/server.yaml                       listen_addr: "0.0.0.0:19443"
/etc/systemd/system/meridian-server.service     /usr/local/bin/meridian-server -config ...
```

客户端第二实例（OpenWrt / procd）：

```
/etc/meridian/client2.yaml      listen_addr: "0.0.0.0:10809"，server_addr 指向另一台服务器
/etc/init.d/meridian-client2    /usr/sbin/meridian-client -config /etc/meridian/client2.yaml
```

启用：`/etc/init.d/meridian-client2 enable && /etc/init.d/meridian-client2 start`。

三点注意：监听端口必须互不相同；每个进程各自生成 session ID，互不干扰；
`sni_spoof`、`transport_schedule` 都是逐实例配置，所以可以让一个实例白天走
WSS、另一个常驻 QUIC。

---

## 更新日志

### v1.6.17（2026-10-30）

#### 🔁 lane 到期改为“接班”，不是“让位”

21:03 起 111 的 10808 全挂：每个请求都是 `dial … failed: tunnel not connected or unavailable`，`failed` 从 0 涨到 1780，直到手动重启才恢复。日志里四条 lane 分别在 20:53、20:56、20:59、21:02 打出 `session lifetime reached, draining`，然后**一条都没有重连过**。

原因不是网络：lane 到期后原地排空——停止接收新流，等自己手上的流跑完再关。可每一轮排空都还在扛着长连接（Telegram 这类连接不会自己结束），`ActiveLoad()` 永远不归零，于是一条都关不掉。四条 lane 相差 3 分钟依次到期，**全部进入排空状态**，`pickTunnel` 找不到任何可用 lane，整个代理对外就是一个黑洞；`drainGrace(1h)` 是 30 分钟，所以这个状态最长可以持续半小时。

- **先建后拆**：lane 到期时先在同一 transport 上建好接替连接、放进 `tunnels[lane]`，再把旧连接交给后台退休。新流立刻有新家，旧流继续在旧连接上跑完——和时段切换、QUIC 回落同一套顺序。
- **接班失败不裸奔**：接替连接建不起来就继续用当前这条服务，5 秒后重试，失败照常计入 QUIC 连败。
- **退休连接不再按点砍**：宽限期到点时若仍有流在最近 2 分钟内动过字节，就顺延一个宽限期（日志 `retired lane still moving N/M streams, holding it for another 30m0s`），彻底安静的才关。
- **兜底**：万一所有 lane 都处于退休状态，`pickTunnel` 改用负载最低的那条退休 lane 服务，而不是回 `tunnel not connected`（每分钟最多一行 `[Proxy] no fresh lane, serving on retired lane …`）。

日志（正常轮换 / 旧行为的黑洞）：

```
[Tunnel 1/4] session lifetime reached, rotating (draining 17 active)
[Tunnel 1/4] retired lane still moving 1/17 streams, holding it for another 30m0s
[Tunnel 1/4] retired lane had 0 stalled streams at grace expiry, closing
```

验证（`session_lifetime: 5m`、2 条 lane，每条 lane 上挂一个 6KB/s 的慢下载，轮换时两条 lane 各有 1 条活跃流，每 4 秒探一次，共 8 分钟）：

- **旧版**：`21:30:29` 与 `21:30:44` 两条 lane 依次 `draining (1 active)`，此后请求全部 `tunnel not connected or unavailable`，直到 `21:32:47` 才恢复 —— 120 次探测里 90 次 200、**30 次失败，黑洞 2 分 18 秒**。和 111 现场一致。
- **新版**：同一秒建好接替连接（`rotating (draining 1 active)` 紧跟一条 `handshake successful over QUIC`），**120/120 全 200**，两条 lane 各轮换一次，没有任何一次请求被拒。
- 单测 `go test -race ./...` 全绿。

这一版不改线路协议，服务端不用动。

### v1.6.16（2026-10-30）

#### 🛬 QUIC 走不通就换 WSS：连续失败自动回落

111 在 19:22:40 有四条 QUIC lane 同时断开，全是 `timeout: no recent network activity`，一分钟内 159 条连接失败，60 秒后自愈；同一时段 110 一次失败都没有——不是服务端挂了，是那条路径那一刻把 UDP 丢了。旧逻辑只会每 5 秒重试 QUIC：路径不通就一直重试同一条走不通的路，而同端口的 WebSocket 明明就在那儿，客户端自己不会拐过去。

- **连败计数**：握手失败算一次；连上后活不过 `quic_fallback_min_uptime`（默认 15 秒）也算一次——**握手成功但立刻死，正是被挡住的 UDP 路径的样子**，不能让它把连败清零。
- **连续 3 次失败**（`quic_fallback_failures`）→ 这条 lane 换到 WebSocket，保持 `quic_fallback_hold`（默认 10 分钟）。
- **保持期按次翻倍**（10m → 20m → 40m → 1h 封顶），一旦有 QUIC 连接活过 min uptime 就全部清零。被挡一晚上的路径不会每十分钟被打扰一次，恢复正常后第一次成功就忘掉前嫌。
- **探测不打断在播的流**：到期后先在新 transport 上建好连接、再退役旧的，和时段切换同一套顺序，视频不会因为一次失败的探测被切。
- **分 lane 独立**：四条 lane 各自判断，天然错开，不会同一秒集体掉头。
- `quic_fallback_failures: 0` 关掉回落，回到“永远重试 QUIC”的老行为。

日志：

```
[19:38:34] [Tunnel 1/1] QUIC connect failed: tunnel: Hysteria client creation failed: connect error: timeout: no recent network activity, retrying in 5s
[19:38:54] [Tunnel 1/1] QUIC failed 3 times in a row, falling back to WebSocket for 1m0s
[19:38:54] [Tunnel] handshake successful over WebSocket, cipher MERIDIAN-CHACHA
[19:39:59] [Tunnel 1/1] switch to QUIC failed: … no recent network activity, staying on WebSocket
[19:40:19] [Tunnel 1/1] QUIC still unreachable after 3 tries, staying on WebSocket for 2m0s
```

验证：

- 单测 9 条（连败阈值、保持期到期、翻倍与封顶、长连接清零连败、短命连接记失败、WSS 失败不触发、`0` 关闭、HTTP-POST 不受影响）+ 配置归一化 1 条；`go test -race ./...` 全绿。
- **e2e A｜模拟 UDP 被丢**（服务端只开 WSS，UDP 端口无监听）：3 次 QUIC 失败（每次约 10 秒）后 `19:38:54` 回落，**同一秒** WebSocket 握手成功，SOCKS 请求 200；1 分钟保持期到点后重探 3 次仍失败，保持期翻倍到 2 分钟，整个探测过程中 curl 一直 200。
- **e2e B｜QUIC 正常**（混合模式服务端）：改动前后两个客户端都**秒连 QUIC**，12 次请求全 200，`connect failed` 计数为 0，没有任何误判。
- **e2e C｜复现 111**（QUIC 已连上 → 撤掉 UDP 换成纯 WSS 服务端）：`19:47:42 QUIC disconnected after 40s` → 3 次失败 → `19:48:07` 回落，同一秒 200。旧版本在这个场景会一直重试 QUIC 直到路径恢复。

这一版不改线路协议，服务端不用动。

### v1.6.15（2026-10-30）

#### 🎬 不再按时间杀流：回收看压力，排空看活跃

v1.6.14 的僵尸流回收是“10 分钟没有字节就 RESET”。问题在于**暂停的视频、浏览器留着的 keep-alive、被应用丢弃的连接，从字节流上看完全一样**。111 上的实例跑了 1.5 小时回收了 12 条，时间全部卡在 10m01s–10m30s；同一时段还有一次 `drain grace expired with 1 active, closing`——排空的 lane 宽限到点，把还在播的流一起关了。这两个在播放器侧都表现为“播放中断”，和 v1.6.9 修掉的那三条（Happy Eyeballs 回归、流控 60 秒静默重置、lane 5 分钟硬关）是同一类症状、不同的触发点。

- **回收改成压力触发**：lane 达到 80% 并发上限才动手，房间够住就不赶人。正常浏览、暂停的视频都不会被定时器碰到；真挤了才按年龄淘汰，被丢弃的连接照样清得出去。
- **阈值 10 分钟 → 30 分钟**：作为“最多能瞒多久”的上限，而不是“到点就杀”的日程表。
- **排空宽限到点先判活**：两分钟内还有字节在动就续一期，只有全部流静默才关。轮换对空闲 lane 照常生效，在播的视频不会被切。
- 附带：回收日志补上**目标地址**与当时的 lane 占用，下次能直接区分 googlevideo 和死连接。

```
[Summary] last 60s: conns=0 events=16 stream_idle=16 | stream_idle: tunnel: stream 16 (127.0.0.1:8081) idle for 55s, reclaimed (lane was 16/16 in use)
```

验证：

- 单测 4 条：无压力不回收、满容量按年龄回收、汇总行带目标地址、`ActiveWithin` 判活。
- 本地 e2e（同一套服务端、`stream_idle_timeout: 30s`）：容量 512 + 1 条静默流 → **120 秒没被回收**；容量 16 + 16 条静默流 → **55 秒内 16/16 回收**。
- 排空续期：单 lane、`session_lifetime: 5m`、慢速源每 5 秒 64 字节。寿命到点进入 draining（`1 active`），5 分钟后宽限到点打出 `drain extended: 1/1 streams alive, next check in 5m0s` 而不是强制关闭；读端连续读了 **801 秒 / 11342 字节，一次没断**。

这一版不改线路协议，服务端不用动。

### v1.6.14（2026-10-30）

#### 🩺 让“卡死”留下证据：日志落盘、分钟级汇总、僵尸流回收

起因是 111 上那次卡死：SOCKS 层 `failed=617`（`total=1585`，约 39% 失败），可翻日志时 13:00–13:54 的现场**已经被自己挤掉了**——每连接一行的错误日志把 64KB 的 logd 环形缓冲冲干净了。

四项改动：

- **日志同时落盘并按大小轮转**（`log_file` / `log_rotate_size` / `log_rotate_keep`）。stdout 保留，`logread` 照旧可用；文件是时间长度的载体。默认 4 MiB ×（1+3）份，按行边界轮转，不会把一行拆到两个文件。
- **失败日志改成每分钟一行汇总**。改成按原因计数（`dial_timeout` / `dial_refused` / `dial_dns` / `dial_reset` / `dial_lane_full` / `limit_dropped` / `negotiate` / `stream_idle` …），每个原因只保留最后一条样本：

```
[Summary] last 60s: conns=0 events=1 stream_idle=1 | stream_idle: tunnel: stream 65 idle for 39s, reclaimed
[Summary] last 60s: conns=319 events=612 dial_timeout=590 limit_dropped=22 | dial_timeout: socks5: [192.168.1.111:36890] dial www.gstatic.com:443 failed: tunnel: dial timeout …
```

​       每分钟的 `conns=` 也顺便替代了“每连接一行”的连接风暴证据，所以 `log_verbose` 默认关闭。
- **僵尸流回收**（`stream_idle_timeout`，本版默认 10 分钟，v1.6.15 起改为 30 分钟且只在 lane 接近满时回收）。播放器丢弃连接但不关 socket 时，这条流会一直占着名额和窗口；攒够就表现为“隧道连着、应用全连不上”。超过阈值没有字节流动就回收，并给服务端发 RESET 关掉目标连接。
- **单 lane 建连并发上限**（`max_pending_dials`，默认 64）。连接风暴时不再把几百个 dial 一起丢给服务端等超时：超出的排队（受调用方自己的 deadline 约束），前面的先跑完。
- **时间戳统一到配置时区**（`log_timezone`，缺省跟随 `schedule_timezone`）。实测 110 的系统时区是 UTC、111 是 UTC+8，同一次事故两边的日志差 8 小时；现在两台机器的日志时间可以直接对齐。
- **`deploy.sh` 不再吞掉时段表**。它生成 `client.yaml` 是整份覆盖，而模板里没有 `transport_schedule`：重跑一次部署，"晚上走 QUIC"就悄悄变成"24 小时 WebSocket"，还没有任何提示。现在模板里带注释示例，并且已有的 `transport_schedule` / `schedule_timezone` 会在重写后原样追加回去，同时打印一行 `Transport schedule preserved:`。

本地实测（`stream_idle_timeout: 5s` 被抬到 30s 下限，reaper 每 30s 扫一次）：

- 黑洞目标上挂一条静默连接，**39 秒后被回收**，下一分钟汇总打出 `stream_idle=1`。
- 60 个并发连接打同一目标（`max_pending_dials: 2`，故意压到极小）：**60/60 成功**，没有一条因为排队而失败。
- 日志文件与 stdout 内容一致，轮转后 `client.log` / `.1` / `.2` 均不超过上限且都以换行结尾。

这一版不改线路协议，服务端不用动。

### v1.6.13（2026-10-30）

#### 🩹 修回源：保留 Host、加上超时、TLS 回源固定 HTTP/1.1

v1.6.12 的 `fallback_url` 有两个实测问题，都是回源方式引起的：

- 回源时把 `Host` 改成了目标地址（`127.0.0.1`），命中伪装站点的默认 server 块，直接 444 关闭 → 探测拿到 502。现在只有在回源目标是**域名**时才改写 Host；目标是 IP（回环）时保留探测者原本的虚拟主机名。
- HTTPS 回源会卡住（协商 h2 后停留在预交换），探测方一直挂着连接。现在回源固定 HTTP/1.1，并给拨号、TLS 握手、响应头分别加了 5s/5s/8s 上限，伪装站点挂掉最多 502，不会挂住连接。

### v1.6.12（2026-10-30）

#### 🪪 握手面收敛：不再自报协议、不再自签证书、不再回 404

这一版只改“不加密就能读到的字段”，因为识别的成本几乎全在这三处：

- **客户端 ALPN 只发浏览器会发的值**：QUIC 发 `h3`，WSS 发 `h2` + `http/1.1`。之前 WSS 的 ClientHello 里明文写着 `meridian-1`，等于把协议名挂在门口。服务端仍保留 `meridian-1` 作为兼容项——服务端的 ALPN 选择在加密的 ServerHello 里，不暴露，这样新旧客户端可以共存升级。
- **证书必须是 CA 签发的**：`deploy.sh` 支持 `MERIDIAN_DOMAIN`（走 acme.sh 安装证书并注册续期重启）或 `MERIDIAN_CERT`/`MERIDIAN_KEY` 直接给一对证书；只有在显式同意（`MERIDIAN_ALLOW_SELF_SIGNED=1` 或交互确认）时才生成自签证书，且改成 90 天、带 SAN。服务器启动时会打印证书 CN 和到期日，自签或 14 天内到期会打 WARN。
- **未认证请求回落到真站点**：新增 `fallback_url` / `fallback_sni`，非隧道升级的请求（包括直接 GET `/ws/`）全部反向代理到伪装站点，返回它的状态码、头与正文，而不是 Go 的 `404 page not found` 或升级器的 400。

另外修掉一个静默降级：`reality_mode: true` 但没配 `reality_spki` 时，客户端原本会跳过证书校验。现在没有钉扎就正常走 CA 校验，删一行配置不再等于关掉认证。

协议规范升到 v1.8（§5.7 握手面要求）。

### v1.6.11（2026-10-30）

#### 🕘 时段表不再依赖系统时区

`transport_schedule` 现在可以显式指定判断窗口所用的时区：

```yaml
transport: "WebSocket"
transport_schedule:
  - transport: "QUIC"
    from: "19:00"
    to: "03:00"
schedule_timezone: "UTC+8"     # 也支持 Asia/Shanghai 这类 IANA 名称
```

- 修的是实测踩到的坑：路由器上 `/etc/localtime` 指向的文件不可读时，`date` 只输出 `CST-8`、没有时分，Go 的 `time.Local` 会静默退回 UTC。结果本该 10:59 走 WebSocket，却被判成 02:59 走了 QUIC。
- 固定偏移支持 `UTC+8`、`UTC+08:00`、`+08:00`、`-0700`、`GMT+5:30`；写错直接启动失败，不会悄悄退化成 UTC。
- 启动横幅新增一行，直接打印判定时区、当前时间和当前选中的传输，一眼就能确认：

```
  Schedule:  now 10:59 UTC+8 (UTC+08:00) => WebSocket
```

### v1.6.10（2026-10-30）

#### 🕒 按时间切换传输：白天 WebSocket，晚上 QUIC

客户端新增每日时段表，按**本机本地时间**自动切换外层传输：

```yaml
transport: "WebSocket"        # 时段外使用（默认白天）
transport_schedule:
  - transport: "QUIC"         # 19:00-03:00 使用
    from: "19:00"
    to: "03:00"
```

- 首个命中的时段生效，未命中则用 `transport`；时段支持跨零点（`19:00` → `03:00`）。
- 切换时**先在新传输上建好连接并接入调度，再退旧连接**：新连接立刻走新传输，旧连接上的存量流继续跑完（最多再保留 5 分钟）。因此切换点不会出现“无 lane 可用”的空窗。
- 格式错误（时间非法、`transport` 写了 `QUIC+WebSocket` 这类客户端不支持的值、起止相同）直接启动失败，避免打错字后一整天用错传输。
- 启动横幅会打印时段表，运行时会打印 `Schedule switched WebSocket -> QUIC`。

本地实测（把窗口设成一分钟后，2 条 lane）：WSS → QUIC → WSS 两次切换，期间每 5 秒一次探测共 25 次全部成功，无一次失败。

### v1.6.9（2026-10-30）

#### 🐛 修复：三处会表现为“播放中断”的问题

1. **拨号丢了 Happy Eyeballs（v1.6.8 引入的回归）**。为做 DNS 缓存改成先解析再按顺序拨号，结果是：域名解析出 IPv6 但该地址是黑洞时，要等满 10 秒超时才轮到 IPv4，随后整体超时失败。实测 `speedtest.tele2.net` 在服务器上 IPv6 connect 直接超时、IPv4 正常，走隧道就变成“卡 10 秒后报错”。现在按 200ms 间隔**并行赛跑**各地址（IPv4 优先），黑洞地址只损失 200ms。
2. **流控 60 秒无信用就重置**。播放器缓冲满了会停止读取，暂停超过 60 秒后服务端就把这条流重置了——日志里看不到任何报错，用户看到的就是“中断”。改为 10 分钟，并且**重置时会打印原因**（`downlink stalled` / `uplink stalled`）。
3. **lane 到寿命 5 分钟硬关**。`session_lifetime` 到期后该 lane 停止接新流，但最多 5 分钟就强制关闭，正在这条 lane 上播放的视频会被直接掐断；4 条 lane 轮转意味着大约每 15 分钟就断一次。现在改为等到空闲再关，硬上限 30 分钟，强制关闭时也会打印日志。

#### 🔍 新增诊断日志

流控卡死、缓冲溢出、lane 强制关闭现在都会明确打印，下次再出现“中断”可以直接从日志定位是协议侧还是上游。

### v1.6.8（2026-10-30）

#### 🚀 起播更快：早发数据 + 服务端 DNS 缓存

YouTube 起播慢于 anytls 的原因量化如下（到服务器 RTT 85ms）：

| 阶段 | 优化前 | 说明 |
|------|--------|------|
| SOCKS CONNECT → 隧道确认 | 126ms | 要等服务器拨号完成才回 OK，多花整整 1 个 RTT |
| TLS 握手 | 129ms | 正常 1 RTT |
| 首字节 | 125ms | 正常 1 RTT |

两条改动：

- **早发数据（握手版本 3）**：服务端解析到 CONNECT 就先把流建好（队列 + 流控窗口），拨号异步进行；客户端不再等 `CONNECT SUCCESS`，本地代理立刻回成功，应用的首个字节（通常是 TLS ClientHello）与拨号并行。每条新连接省下 1 个 RTT（85ms 链路上约 90ms）。拨号失败时回 `CONNECT failed` + `RESET`，应用按“连接中途断开”处理。
- **服务端 DNS 缓存（60s TTL，并发查询合并）**：播放器会同时连多个没用过的 `rr*.googlevideo.com`，原先每条连接都要在服务器上做一次冷解析（实测 130–160ms）。缓存后同一主机一分钟内只查一次；拨号失败会立即失效该条目。

兼容性：版本 3 只发给声明了 `0x08 FLOW` 的客户端；旧客户端读作“≥2”，照常工作且不会早发；新客户端遇到版本 2 的旧服务端会自动退回“等确认”模式。三种组合均已实测。

本地 8 路并发（4 全速 + 4 限速）校验 8/8 一致、0 次 stalled。

### v1.6.7（2026-10-29）

#### 🐛 修复：`transport: QUIC` 仍会开一个裸 TCP 隧道端口

服务端 `Start()` 的 `switch` 里没有 `QUIC` 分支，纯 QUIC 配置落进了 `default`，于是除了 UDP/QUIC 监听外，还在同一端口开了一个**无 TLS 的裸 TCP 隧道监听**：

- 任何扫描器连上来都会被当成隧道握手处理，行为与正常 QUIC-only 服务器明显不同，是典型的 DPI 指纹特征；
- 等于在“只用 QUIC”的部署里留了一个明文入口。

现在 `QUIC` 只绑 UDP。`QUIC+WebSocket` 混合监听和 `WebSocket` / `HTTP-POST` 不受影响；`default`（未配置 transport 的老配置）仍保留旧的裸 TCP 行为。

实测：`transport: QUIC` 启动后 `lsof -i :<port>` 只有一条 UDP 记录，`nc -z` 连 TCP 直接失败，端到端 8MB 传输校验一致。

#### 🔧 部署脚本：`optimize` 不再覆盖传输协议

`./deploy.sh optimize` 以前无条件把服务端写成 `QUIC+WebSocket`、客户端写成 `WebSocket`，于是每次调优都会把 QUIC 部署悄悄改回 TCP 路径。现在只有配置里缺少 `transport` 键时才写入默认值，已有选择一律保留（脚本改动随 `main` 分发，无需新版本二进制）。

### v1.6.6（2026-10-29）

#### 🐛 修复：慢消费者误判导致流被截断

v1.6.5 上线后生产日志出现 `stream N consumer stalled, resetting`，表现为视频偶尔报错、大文件下载被截断。根因是**按帧数**判定卡死：队列深度按 `窗口 / 60KiB` 换算，1 MiB 窗口只有 25 帧，而链路上常见的 DATA 帧只有 1–2 KiB，于是缓冲到 ~35KB 就被判为“消费者卡死”并重置，而 1 MiB 的流控窗口根本没机会起作用。

- 队列改为**按字节**判定：阈值 `stream_window + 4 × 60 KiB`。流控已经把在途字节限制在窗口内，因此只有应用真正停止读取才会达到阈值。
- 帧通道改为固定 1024 槽的纯交接缓冲，不再承担背压职责，小帧突发不会再触发重置。
- 服务端（写目标方向）同步改为字节判定，两端语义一致。
- 重置仍然只影响单条流，共享读循环不会被慢消费者阻塞，因此“一条卡住的下载拖慢所有流”不会复现。

实测（本地混合监听，`stream_window: 262144`）：4 路全速 + 4 路限速并发下载 20MB，连续三轮 **24/24 校验一致**，`stalled` 计数为 0。

协议无线上变更，与 v1.6.5 / v1.6.4 互通。

### v1.6.5（2026-10-29）

#### 🚀 每流 ACK 流控（协议 v2）

WSS 多隧道在高负载下会把小请求堵在大流后面（实测 4 路持续大流量时，新连接 TTFB 中位数 1.3s、p90 2.2s）。根因是整条 lane 共享一个 TCP 缓冲区，谁都能把几 MB 塞进去。本版加入真正的每流窗口：

- 发送方每条流最多 `stream_window` 字节未确认在途，接收方按消费量回 `ACK`（累计字节数），阈值 `窗口/8`（16–256 KiB）。
- 窗口耗尽即阻塞，因此排队时延被限制在约 `窗口 / 链路速率`（1 MiB @ 150 Mbps ≈ 55 ms），而单流吞吐仍为 `窗口 / RTT`。
- ACK 累计且钳制在已发送字节内，重复/乱序/伪造都不会超额放行；60 秒拿不到信用则判定该流僵死并重置。
- **向后兼容**：能力用 ClientHello 的标志位（0x08）声明，服务端支持时在 ServerHello 回版本 2；旧服务端会忽略该位并回版本 1，双方自动退回无窗口模式，不会卡死。

#### 🐛 修复

- 修复流结束时 `RESET` 与队列中最后一帧竞争导致的**尾部数据丢失**（并发压测中偶发少 20KB）。

### v1.6.4（2026-10-29）

#### 🔧 配置项真正生效

此前 `stream_window`、`max_concurrent_streams`、`session_lifetime` 只被解析、从未被代码读取，改了不起作用。本版全部接通：

- **`stream_window`**：按字节预算决定单条流的下行缓冲帧数（`窗口 / 60KiB`，限制在 64–1024 帧）。客户端与服务端使用同一套换算，默认 8 MiB。（v1.6.5 起改为每流在途字节窗口，v1.6.6 起本地缓冲也按字节判定，见上。）
- **`max_concurrent_streams`**：**每条隧道**的并发流上限。客户端超限时把连接切到其他 lane 重试，服务端超限时返回 `server busy`，避免单客户端耗尽文件描述符。本地代理监听器的总并发由 `max_concurrent_streams × tunnel_connections` 推导，并限制在 512–4096。
- **`session_lifetime`**：每条外层连接到达寿命后进入 draining 状态，不再接收新流；存量流结束后（或超过 5 分钟宽限期）自动断开重连，定期刷新外层 TCP/TLS 连接指纹。设为 `0` 关闭。

#### 🚀 部署

- 新增 `./deploy.sh transport client|server [quic|websocket|hybrid|http-post]`，交互菜单第 9 项同样可用：只改传输相关配置，保留密码、SPKI、证书与本地端口，重启失败自动回滚。
- `./deploy.sh optimize` 现在同时写入 `stream_window: 1048576` 与 `max_concurrent_streams: 512`。
- 默认发布版本更新为 `v1.6.4`。

### v1.6.3（2026-10-29）

#### 🚀 高吞吐

- **多隧道并行**：新增 `tunnel_connections`。此前所有 SOCKS 流都复用一条外层 TCP/QUIC 流，单流 BDP 会把整条代理限制在约 150–250 Mbps；现在按负载把用户流分配到多条独立隧道，实测 111 → Oracle 8 路并发从约 200 Mbps 提升到约 576 Mbps。
- **QUIC + WebSocket 混合监听**：服务端新增 `transport: "QUIC+WebSocket"`，同一端口同时提供 UDP QUIC 和 TCP/WSS，老客户端无需立即切换。
- **WebSocket 热路径优化**：改为流式读取 WebSocket message，去掉每帧整块分配与复制；读写缓冲提升到 64KB。
- **大帧填充修正**：随机填充不再给每个 32KB 数据帧额外加上 1400 字节，只保留小帧填充和最多 52 字节随机尾部。
- **批量数据不再逐帧 sleep**：`timing_jitter_ms` 只作用于小帧，避免上行被每帧最多 30ms 的延迟串行化。
- **带宽默认值改为自动**：`up_mbps`/`down_mbps` 默认 `0`，QUIC 使用自适应 BBR；固定填 1000 会触发 Brutal 过冲，实测反而更慢。

#### 🔧 部署

- `deploy.sh update` 改为强制从 GitHub Release 安装指定版本，避免当前目录里的旧 `dist/` 二进制把客户端降级。
- 新增 `./deploy.sh optimize client|server`：保留密码、SPKI、地址和本地端口，只切换高吞吐传输与并行参数。
- 默认发布版本更新为 `v1.6.3`，`deploy.sh version` 可查看已安装核心版本。

### v1.6.0（2026-10-21）

#### 🔒 安全修复

- **TCP 隧道密码认证**：此前 TCP 隧道路径不校验密码（只有 Hysteria 的 UDP 路径校验），服务端实际是一个开放代理。现在 ClientHello 新增 `0x0007 AUTH` 扩展，服务端校验 HMAC-SHA256 标签（绑定 timestamp + clientRandom + ECDHE，防重放，120 秒窗口）。
- **控制帧类型修复**：`Encode()` 恒定写入 `TypeDATA`，导致 `PING`/`PONG`/`RESET` 被写进 `Flags` 字段而类型丢失。新增 `EncodeType()`，控制帧现在能正确被对端识别。

#### ✨ 新增功能

- **HTTP-POST 传输服务端实现**：此前只有客户端，`transport: "HTTP-POST"` 在服务端无法工作。现已补齐会话化的服务端（`Mir-Session` 头绑定会话、响应体承载下行、`Mir-Poll` 长轮询、空闲会话回收）。
- **keepalive 真正生效**：客户端按 `keepalive_interval` 发 PING，服务端回 PONG，客户端记录并跳过。
- **Padding/Jitter/方向均衡接线**：此前配置项是死代码，完全不生效。现在两端按配置接线；同时修复零值 `PaddingConfig`（`mode` 缺省）被误判为启用填充并破坏互通的问题。
- **真实 TLS 指纹**：`ApplyFingerprint()` 现在真正改写 `*tls.Config`（此前配置项空转）；无证书时改为生成 ECDSA P-256 自签证书而非静默降级。

#### 🐛 Bug 修复

- **方向均衡会静默摧毁隧道（v1.6.0 修复）**：`DummyFrame()` 返回的是 14 字节裸头部（无密文、无 AEAD tag）。对端解密必然失败，且旧代码在失败时仍推进 nonce 计数器，导致该方向后续帧**全部**认证失败。现在 dummy 帧经 `(*Encoder).DummyFrame()` 正常加密成 KEEPALIVE 帧，对端识别后跳过。
- **解密失败仍消耗 nonce**：`Decoder.Decode` 在认证失败时已 `Count++`，任何一帧失败即让该方向永久失步。
- **WebSocket ALPN 不匹配**：客户端发 `meridian-1/h3`，服务端标准 `http.Server` 无对应 NextProtos，握手失败（`tls: no application protocol`）。
- **HTTP-POST 读取死锁**：`Read` 持锁调用 `Write` 导致 `sync.Mutex` 自死锁。改为独立的 `pollOnce()`（此 bug 是该传输完全不可用的直接原因）。
- **删除 UDP 死代码**：`handlePacket`/`doHandshake`/`forwardFrame` 无人调用且握手是未完成 TODO（UDP socket 由 Hysteria 库独占），已删除并留下说明。

#### 🧪 测试

- 新增 `pkg/mtp/handshake_test.go`（认证正反例、重放、过期、畸形扩展）
- 新增 `pkg/mfp/frames_test.go`（padding 往返、抖动边界、方向均衡、密钥轮换、控制帧类型）
- 新增 `pkg/transport/httppost_transport_test.go` 与 `httppost_e2e_test.go`（会话复用、pull 模式往返）

#### 🔧 构建与发布

- **版本号真正注入**：此前两端把版本写死为 `v1.0.0`/`v1.0.1`，workflow 里的 `-X main.Version` 因没有对应变量而完全空转。现在 `Version`/`BuildTime` 是可注入变量，默认 `dev`。
- **`build.sh` 参数化**：版本不再硬编码为 `v1.3.0`，默认取当前 git tag，也可 `./build.sh v1.6.0` 指定；同时生成 `SHA256SUMS`。
- **`SHA256SUMS` 自引用修复**：此前把 `SHA256SUMS` 自身也纳入校验（对空文件取哈希），导致 `shasum -c` 必然失败。现在生成时排除自身。
- **`deploy.sh` 版本可覆盖**：`MERIDIAN_VERSION` 环境变量可指定下载版本。

### v1.5.0（2026-06-03）

#### ✨ 新增功能

- **Windows 平台支持**：重写信号处理逻辑，现在能在 Windows 上顺利编译并运行客户端和服务端。
- **WebSocket 传输层**：集成了 WebSocket，服务端支持 WSS 隧道，客户端支持回退到 WebSocket 绕过 UDP 封锁。
- **0-RTT 会话恢复**：在传输层新增基于内存的 `SessionStore`，客户端重连时可复用之前协商好的密钥对。
- **密钥定期轮换 (PFS)**：传输隧道两端每传输 64MB 或 5 分钟自动通过 HKDF 轮换流量密钥，保障长期安全。
- **HTTP 代理协议支持**：客户端可通过配置 `proxy_protocol: "http"` 提供正向 HTTP/HTTPS 代理。

### v1.3.5.1（2026-06-03）

#### 🐛 Bug 修复

- **修复 QUIC 传输协议名称不匹配问题**：配置文件中 `transport: "QUIC"` 无法正确匹配内部传输标识 `"Hysteria"`，导致客户端错误回退到 TCP 连接并出现 `deadline exceeded` 超时。现已统一传输名称为 `"QUIC"`，同时向后兼容 `"Hysteria"`。
- **修复服务端握手流式读取 EOF 错误**：服务端使用 `conn.Read()` 读取 ClientHello，在 QUIC/TCP 流式传输中无法保证一次读取完整包，导致数据不足时服务端提前关闭连接，客户端收到 `EOF` 错误。已改用 `io.ReadAtLeast()` 确保至少读取 136 字节后再处理握手。

#### 📦 构建

- 重新编译全平台二进制文件（Linux / macOS / Windows，amd64 / arm64）
- 更新 SHA256SUMS 校验文件

---

### v1.3.5（2026-06-01）

- 修复测试中 `TransportQUIC` 未定义错误
- 更新 GitHub Actions 工作流至 Go 1.25
- 重新编译全平台二进制文件

### v1.3.2（2026-06-01）

- 修复高延迟和数据损坏问题
- QUIC 接收窗口调优

### v1.3.1（2026-06-01）

- 降级 Go Toolchain 至 1.23.0，修复 Linux/ARM64 FIPS CPU 初始化崩溃

### v1.3.0（2026-06-01）

- 实现 QUIC 传输层（基于 Hysteria v2）
- SOCKS5 代理健壮性增强和全局调试模式

### v1.0.2（2026-06-01）

- 完整 SOCKS5 代理服务器（RFC 1928 + RFC 1929）
- 局域网代理服务（默认监听 `0.0.0.0:1080`）
- 修复 `reality_spki` / `server_spki` YAML 反序列化错误

### v1.0.1

- 配置文件 SPKI 十六进制解析修复

### v1.0.0

- Meridian 协议初始实现
- X25519 ECDHE 密钥交换 + ChaCha20-Poly1305 加密
- MFP 帧协议 + MTP 握手协议
- 端到端集成测试

---

## 协议架构

```
┌─────────────────────────────────────────────────────────┐
│  应用层（SOCKS5 代理 / 中继）                            │
├─────────────────────────────────────────────────────────┤
│  Meridian 帧协议（MFP）                                   │
│  ┌──────┐ ┌───────┐ ┌───────┐ ┌──────────────────┐    │
│  │ 流   │ │ 复用  │ │ 队列  │ │ 流量控制          │    │
│  └──────┘ └───────┘ └───────┘ └──────────────────┘    │
├─────────────────────────────────────────────────────────┤
│  Meridian 传输协议（MTP）— 握手 + 会话                    │
├─────────────────────────────────────────────────────────┤
│  QUIC（RFC 9000）或 WebSocket（HTTP Upgrade）            │
├─────────────────────────────────────────────────────────┤
│  TCP / UDP（操作系统）                                    │
└─────────────────────────────────────────────────────────┘
```

### 传输模式

| 传输方式 | 适用场景 | 说明 |
|---------|---------|------|
| **QUIC+WebSocket**（服务端推荐） | 大多数环境 | 同一端口同时提供 UDP QUIC 与 TCP/WSS |
| **WebSocket**（高吞吐客户端推荐） | 500 Mbps 以上、UDP 受限 | 多隧道并行，伪装为标准 WSS 流量 |
| **QUIC** | 低延迟、UDP 质量好 | 单流受 BDP 限制，适合交互而非高速下载 |
| **HTTP-POST** | 强力 DPI 环境 | 模拟云存储上传行为 |

QUIC 走 UDP，是链路上最先被丢的东西，而它失败的样子和“服务端挂了”一模一样：握手超时，或者已建立的连接以 `timeout: no recent network activity` 断掉。客户端默认在连续 3 次 QUIC 失败后把这条 lane 换到 WebSocket（同端口、同握手），10 分钟后再探一次 QUIC，见 `quic_fallback_*`。

### 高吞吐部署（500 Mbps+）

单条 TCP/QUIC 流受带宽时延积限制，实测 111 → Oracle 单条约 196–250 Mbps；把所有用户流复用到一条外层隧道不会突破这个上限。高吞吐配置使用 4 条独立 WSS 隧道并按负载分配用户流：

```bash
# 服务端：保留现有密码/证书，只开启 TCP/WSS 混合监听
./deploy.sh optimize server

# 客户端：保留现有密码、SPKI、地址和本地端口，开启 4 条 WebSocket 隧道
./deploy.sh optimize client

# 更新核心（配置不变，强制使用最新 Release）
./deploy.sh update server
./deploy.sh update client
```

关键配置：

```yaml
# server.yaml
transport: "QUIC+WebSocket"
wss_path: "/ws/"

# client.yaml
transport: "WebSocket"
wss_path: "/ws/"
tunnel_connections: 4
timing_jitter_ms: 0.0
up_mbps: 0
down_mbps: 0
```

> 实测同一服务器、同一文件：单条 TCP/QUIC 隧道约 200 Mbps；4 条 TCP 隧道 8 路并发约 576 Mbps。线路本身没有 500 Mbps 问题时，瓶颈是单流而不是 Meridian 加解密。

---

## 功能特性

### 🔐 密码学

- **密钥交换**：X25519 临时 ECDHE（完美前向保密）
- **加密算法**：ChaCha20-Poly1305（默认）/ AES-256-GCM / AES-128-GCM
- **密钥派生**：HKDF-SHA256，独立的上行/下行随机种子
- **Nonce 生成**：基于计数器的唯一 Nonce，彻底防止重用攻击
- **身份验证**：HMAC-SHA256 + 握手哈希防 MITM

### 🛡️ 抗检测机制

- **TLS 指纹伪装**：模拟 Chrome 120 / Firefox 121 / curl 8.4 的真实 ClientHello
- **SNI 欺骗（REALITY）**：将 SNI 指向高流量合法网站（google.com 等）
- **流量填充**：固定大小 / 随机大小两种模式，对抗流量特征分析
- **时序随机化**：可配置抖动（默认 0-30ms），防时序指纹识别
- **方向均衡**：双向流量伪造，对抗非对称流量分析
- **SPKI 哈希验证**：无需 CA 信任链，直接验证服务端公钥指纹

### 🌐 SOCKS5 代理（v1.0.2 新增）

- **RFC 1928** 完整实现：支持 IPv4 / IPv6 / 域名三种地址类型
- **RFC 1929** 用户名密码认证：配置账号密码后自动启用
- **局域网服务**：默认监听 `0.0.0.0:1080`，手机、平板、其他电脑均可接入
- **实时统计**：每 60 秒打印连接数和流量数据
- **访问日志**：`[时间] [来源IP:端口] → 目标地址:端口`

### 📦 帧协议（MFP）

- 14 字节固定帧头：类型、流ID、序号、标志、扩展字段
- 支持 DATA / ACK / PING / PONG / FLOW / RESET / KEEPALIVE 等帧类型
- ChaCha20-Poly1305 AEAD 加密，16 字节认证标签
- 内置帧池（Frame Pool）减少 GC 压力

---

## 快速开始

### 下载预编译版本

前往 [Releases 页面](https://github.com/peterxulove/meridian/releases) 下载对应平台的二进制文件。

| 平台 | 架构 | 文件名 |
|------|------|--------|
| macOS | Apple Silicon (M1/M2/M3) | `meridian-*-darwin-arm64` |
| macOS | Intel | `meridian-*-darwin-amd64` |
| Linux | ARM64（树莓派、ARM 服务器） | `meridian-*-linux-arm64` |
| Linux | x86_64 | `meridian-*-linux-amd64` |

### 一键部署（推荐，支持 Linux & macOS）

项目提供了一键部署脚本 `deploy.sh`，可交互式地安装、配置并启动服务端与客户端，自动注册为系统服务（Linux 上使用 `systemd`，macOS 上使用 `launchd`）。

```bash
# 1. 赋予执行权限
chmod +x deploy.sh

# 2. 运行脚本进入交互式菜单
./deploy.sh
```

**支持的指令：**
* `./deploy.sh`：打开交互式部署主菜单。
* `./deploy.sh status`：查看目前所有 Meridian 服务运行状态。
* `./deploy.sh version`：查看配置目标版本与已安装核心版本。
* `./deploy.sh update client`：只更新客户端核心，保留现有 `client.yaml`、证书与服务定义；新核心启动失败会自动回滚。
* `./deploy.sh update server`：只更新服务端核心，保留现有 `server.yaml`、证书与服务定义。
* `./deploy.sh optimize client|server`：保留凭据，切换高吞吐传输与并行参数。
* `./deploy.sh transport client|server`：交互式切换传输协议（QUIC / WebSocket / QUIC+WebSocket / HTTP-POST）；也可直接跟参数，例如 `./deploy.sh transport client websocket`。
* `./deploy.sh uninstall`：快捷卸载已安装的客户端或服务端。

---

### 服务端部署（手动，Linux 服务器）

```bash
# 1. 下载并赋予执行权限
chmod +x meridian-server-linux-amd64

# 2. 生成自签证书（REALITY 模式必须）
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
  -sha256 -days 3650 -nodes -subj "/CN=www.apple.com"

# 3. 获取 SPKI 哈希（填入客户端配置）
openssl x509 -in cert.pem -pubkey -noout \
  | openssl pkey -pubin -outform DER 2>/dev/null \
  | sha256sum | cut -c1-64

# 4. 创建配置文件
cp server.example.yaml server.yaml
vim server.yaml   # 填入密码、证书路径

# 5. 启动服务端
./meridian-server-linux-amd64 -config server.yaml
```

### 客户端使用（本机 / 局域网网关）

```bash
# 1. 下载并赋予执行权限
chmod +x meridian-client-darwin-arm64

# 2. 创建配置文件
cp client.example.yaml client.yaml
vim client.yaml   # 填入服务器地址、密码、SPKI 哈希

# 3. 启动客户端（自动开启 SOCKS5 代理，监听 0.0.0.0:1080）
./meridian-client-darwin-arm64 -config client.yaml
```

启动后日志示例：
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

### CLI 参数

```
meridian-server 参数：
  -config string      配置文件路径（默认：server.yaml）
  -listen string      覆盖监听地址（例如：0.0.0.0:443）
  -fingerprints       列出所有可用 TLS 指纹并退出

meridian-client 参数：
  -config string      配置文件路径（默认：client.yaml）
  -listen string      覆盖 SOCKS5 监听地址（例如：0.0.0.0:1080）
  -fingerprints       列出所有可用 TLS 指纹并退出
```

---

## 使用方式（局域网代理）

客户端启动后，局域网内任意设备只需将 SOCKS5 代理指向**运行客户端的主机 IP + 1080 端口**即可科学上网。

### 电脑浏览器（推荐 SwitchyOmega）

1. 安装 [Proxy SwitchyOmega](https://chrome.google.com/webstore/detail/proxy-switchyomega/padekgcemlokbadohgkifijomclgjgif) 插件
2. 新建情景模式：协议 `SOCKS5`，服务器 `运行客户端的主机IP`，端口 `1080`
3. 导入 GFWList 规则实现智能分流（被墙走代理，国内直连）

### macOS 系统全局代理

**系统设置 → 网络 → Wi-Fi → 详细信息 → 代理 → SOCKS 代理**

填入：服务器 `主机IP`，端口 `1080`

### iOS / iPadOS

**设置 → Wi-Fi → 点击当前网络 → 配置代理 → 手动**

填入：服务器 `主机IP`，端口 `1080`

### Android

**Wi-Fi 长按 → 修改网络 → 高级选项 → 代理 → 手动**

填入：代理主机名 `主机IP`，代理端口 `1080`

### 终端 / 命令行

```bash
# 临时为当前终端会话启用代理
export https_proxy="socks5://主机IP:1080"
export http_proxy="socks5://主机IP:1080"

# Git 仅对 GitHub 设置代理
git config --global http.https://github.com.proxy socks5://主机IP:1080
```

---

## 配置说明

根据所部署的网络环境，Meridian 提供四种传输层配置方案：

1. **QUIC (Hysteria v2)**：UDP 单协议，延迟最低，链路干净时首选。
2. **WebSocket (WSS)**：TLS/TCP，配 4 条隧道时吞吐最高，UDP 被限速时首选。
3. **QUIC + WebSocket 混合模式**：服务端推荐，同一端口同时兼容 UDP QUIC 与 TCP/WSS，便于客户端逐个迁移。
4. **HTTP-POST 模式**：模拟大文件上传，极端环境下使用，速度最慢。

切换协议不必手改配置：

```bash
sudo ./deploy.sh transport server          # 交互式选择
sudo ./deploy.sh transport client websocket # 或直接指定
```

该命令只改传输相关字段（`transport` / `wss_path` / `mirror_path`），密码、SPKI、证书和本地端口保持不变，重启失败会自动回滚。

### 性能与连接参数

| 参数 | 作用 | 默认 | 取值范围 |
|------|------|------|----------|
| `tunnel_connections` | 客户端并行外层隧道数；每条隧道独立握手、独立密钥，按活跃流数分摊 | `4`（部署脚本生成） | 1–16 |
| `stream_window` | 单条流的**在途未确认字节上限**（每流 ACK 窗口）；排队时延 ≈ 窗口 / 链路速率 | `1048576`（1 MiB） | 256 KiB–16 MiB |
| `max_concurrent_streams` | **每条隧道**的并发流上限；超限时客户端换 lane 重试，服务端回 `server busy` | `512` | 16–4096 |
| `session_lifetime` | 外层连接寿命，到期后 drain（不再接新流）并重连；多 lane 自动错开 0–15%；`0` 关闭 | `1h` | 5m–24h |
| `timing_jitter_ms` | 小帧随机延迟；大帧不受影响 | `0` | 0–100 |
| `up_mbps` / `down_mbps` | QUIC 固定带宽提示；`0` 表示自适应 BBR | `0` | 0 或链路值 |
| `stream_idle_timeout` | 单条流**双向都无字节**多久后成为回收候选；只在 lane 达到 80% 并发上限时才真的回收（发 RESET 并释放名额）；`0` 关闭 | `30m` | 0 或 ≥30s |
| `max_pending_dials` | **每条 lane** 同时在建连的上限；超出的排队而不是直接失败；`0` 关闭 | `64` | 0–4096 |
| `quic_fallback_failures` | 连续多少次 QUIC 失败后把这条 lane 停到 WebSocket 上；`0` 表示永远重试 QUIC | `3` | 0–20 |
| `quic_fallback_hold` | 停到 WebSocket 后多久再探一次 QUIC；每次连续触发翻倍，上限 1h | `10m` | 30s–6h |
| `quic_fallback_min_uptime` | QUIC 连接活过多久才算“能用”（否则算一次失败，不让它清空连败计数） | `15s` | 5s–10m |

`stream_window` 现在同时决定吞吐与延迟：调大更抗抖动但排队更久，调小更跟手；单流吞吐上限约为 `窗口 / RTT`（1 MiB @ 55ms ≈ 145 Mbps）。`max_concurrent_streams` 是每隧道上限，客户端本地代理的总并发按 `max_concurrent_streams × tunnel_connections` 推导（限制在 512–4096）。

### 日志与排障

客户端默认只往 stdout 写，由 procd / systemd 收进日志系统。路由器上的 logd 环形缓冲只有几十 KB，**一次错误风暴就会把它自己覆盖掉**，所以现场排查建议打开文件日志：

```yaml
log_file: "/var/log/meridian-client.log"   # 同时仍写 stdout
log_rotate_size: 4194304                   # 4 MiB 一份
log_rotate_keep: 3                         # 保留 .1 .. .3
log_verbose: false                         # true 才打每连接一行
# log_timezone: "UTC+8"                    # 时间戳用哪个时钟；缺省跟随 schedule_timezone
```

日志行的三种形态：

```
[2026-10-30 16:51:28] [Tunnel] handshake successful over QUIC, cipher MERIDIAN-CHACHA   # 事件
[2026-10-30 16:52:28]   [Stats] active=1 total=65 failed=0 in=4KB out=7KB               # 每分钟累计
[2026-10-30 16:52:28] [Summary] last 60s: conns=65 events=0                             # 每分钟汇总
```

时间戳默认跟随 `schedule_timezone`（再退回系统时区）——两台路由的 `/etc/localtime` 未必一致，实测 110 用 UTC、111 用 UTC+8，同一次事故在日志里差 8 小时，对不上时间线。

`conns=` 是这一分钟新建的代理连接数（连接风暴一眼可见），`events=` 是按原因归类的失败/回收次数，`|` 后面是占比最高的三个原因各一条样本。排障顺序建议：先看 `conns=` 是否异常放大（重启后的连接风暴），再看 `dial_timeout` 与 `limit_dropped` 的比例（前者是上游慢，后者是本地名额打满），`stream_idle` 则是僵尸流回收的计数。


---

### 1. QUIC (REALITY) 模式（低延迟）

#### 🔹 服务端 (`server.quic.yaml`)
```yaml
listen_addr: "0.0.0.0:443"
transport: "QUIC"
cipher_suite: 1                    # 1=ChaCha20, 2=AES256, 3=AES128
password: "your-strong-random-password-here"

# ─── REALITY 伪装配置 ───
reality_mode: true
reality_enabled: true
server_cert: "cert.pem"
server_key: "key.pem"
reality_spki: "804d9c7922d9c491aefbe7f2da4930bfae498cda692994ea9a9fefb0f2ea99cb"
reality_short_id: 1002
reality_max_time: 0

# ─── 抗检测主动防御 ───
fingerprint: "chrome_win"          # chrome_win / firefox_mac / curl_linux
padding_mode: "random"             # none / fixed / random
base_payload_size: 1400
max_payload_size: 1452
timing_jitter_ms: 0.0
up_mbps: 0
down_mbps: 0

# ─── 连接与性能控制 ───
max_clients: 1000
stream_window: 1048576
max_concurrent_streams: 512
keepalive_interval: "30s"
handshake_timeout: "10s"

# ─── 后端（防探测回落） ───
destinations:
  - name: "direct"
    addr: "127.0.0.1:8080"         # 未授权探测流量回落到此处的普通 Web 服务
    protocol: "direct"
    rule: "all"
    priority: 0
```

#### 🔹 客户端 (`client.quic.yaml`)
```yaml
server_addr: "your-server-ip:443"
transport: "QUIC"
cipher_suite: 1
password: "your-strong-random-password-here"

# ─── REALITY 配置 ───
reality_mode: true
sni_spoof: "www.apple.com"         # 伪装的 SNI 域名（需与生成证书的 CN 一致）
reality_spki: "804d9c7922d9c491aefbe7f2da4930bfae498cda692994ea9a9fefb0f2ea99cb"
reality_short_id: 1002
reality_max_time: 0

# ─── 抗检测 ───
fingerprint: "chrome_win"
padding_mode: "random"
base_payload_size: 1400
max_payload_size: 1452
direction_balance: true
timing_jitter_ms: 0.0
up_mbps: 0
down_mbps: 0

# ─── 连接优化 ───
keepalive_interval: "30s"
handshake_timeout: "10s"
stream_window: 1048576
max_concurrent_streams: 512
session_lifetime: "1h"
dial_timeout: "15s"

# ─── 本地 SOCKS5 代理 ───
# 0.0.0.0 = 局域网所有设备均可连接
# 127.0.0.1 = 仅本机使用
listen_addr: "0.0.0.0:1080"
proxy_protocol: "socks5"
```

---

### 2. WebSocket (WSS) 模式

#### 🔹 服务端 (`server.ws.yaml`)
```yaml
listen_addr: "127.0.0.1:8080"     # 推荐配合 Nginx/Caddy 反代暴露 443
transport: "WebSocket"
cipher_suite: 1
password: "your-strong-random-password-here"
wss_path: "/v2/connection"
fingerprint: "firefox_mac"
padding_mode: "random"
timing_jitter_ms: 0.0
destinations:
  - name: "direct"
    addr: "127.0.0.1:8080"
    protocol: "direct"
    rule: "all"
```

#### 🔹 客户端 (`client.ws.yaml`)
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
timing_jitter_ms: 0.0
tunnel_connections: 4
listen_addr: "0.0.0.0:1080"
proxy_protocol: "socks5"
```

---

### 3. HTTP-POST 模式

#### 🔹 服务端 (`server.http.yaml`)
```yaml
listen_addr: "0.0.0.0:80"
transport: "HTTP-POST"
cipher_suite: 2
password: "your-strong-random-password-here"
mirror_path: "/api/v1/storage/upload"   # 客户端上传帧的路径，两端必须一致
destinations:
  - name: "direct"
    addr: "127.0.0.1:8080"
    protocol: "direct"
    rule: "all"
```

> ⚠️ **两端 padding 配置必须一致**
> `padding_mode` 会改变线上帧格式（填充后带 2 字节长度前缀）。两端不一致会导致对端无法解帧。
>
> ⚠️ **HTTP-POST 是 pull 模式**
> 下行数据只能搭在请求的响应里返回，空闲时客户端会发空上传（`Mir-Poll`）轮询。因此该模式的延迟高于 QUIC/WebSocket，仅在极端环境使用。

#### 🔹 客户端 (`client.http.yaml`)
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

> 💡 **生成自签证书并获取 SPKI 哈希**
>
> ```bash
> # 生成私钥与证书（CN 必须与客户端 sni_spoof 一致）
> openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
>   -sha256 -days 3650 -nodes -subj "/CN=www.apple.com"
>
> # 提取 SPKI 哈希（填入 reality_spki）
> openssl x509 -in cert.pem -pubkey -noout \
>   | openssl pkey -pubin -outform DER 2>/dev/null \
>   | sha256sum | cut -c1-64
> ```

---

## 安全机制

### 握手流程

```
客户端                              服务端
  │── ClientHello ──────────────────► │
  │   [魔数][版本][标志][MTU]         │
  │   [客户端随机数 32B]              │
  │   [ECDHE 公钥 32B]               │
  │   [握手哈希 32B]                  │
  │   [会话ID 16B][密码套件][扩展]    │
  │                                    │
  │ ◄─────────────── ServerHello ─────│
  │   [服务端随机数][ECDHE 公钥]      │
  │   [协商密码套件][证书哈希]        │
  │                                    │
  │── ClientKeyConfirm ──────────────► │
  │ ◄─────────────── HandshakeDone ───│
  │                                    │
  │════════════ 加密数据传输 ══════════│
```

### 密钥派生

```
master_secret = HKDF(shared_ecdhe, client_random || server_random, "meridian-master")

keys = HKDF(master_secret, "meridian-keys"):
  [0:32]   → traffic_enc_key     (ChaCha20 加密密钥)
  [32:64]  → traffic_mac_key     (HMAC 验证密钥)
  [64:80]  → uplink_nonce_seed   (上行 Nonce 种子)
  [80:96]  → downlink_nonce_seed (下行 Nonce 种子)
  [96:128] → init_key            (握手初始密钥)

nonce = SHA256(direction_seed || counter_uint64)[0:12]
```

---

## 编译构建

### 环境要求

- Go 1.22+
- 网络访问（用于下载依赖）

### 本地编译

```bash
# 克隆仓库
git clone https://github.com/peterxulove/meridian.git
cd meridian

# 下载依赖
go mod tidy

# 编译当前平台
go build -o meridian-server ./cmd/meridian-server/
go build -o meridian-client ./cmd/meridian-client/

# 运行测试（11 个集成测试）
go test ./test/integration/ -v
```

### 交叉编译

```bash
# macOS ARM64（Apple Silicon）
GOOS=darwin  GOARCH=arm64 go build -ldflags="-s -w" -o dist/meridian-server-darwin-arm64 ./cmd/meridian-server/
GOOS=darwin  GOARCH=arm64 go build -ldflags="-s -w" -o dist/meridian-client-darwin-arm64 ./cmd/meridian-client/

# Linux ARM64（树莓派 / ARM 服务器）
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

## 下载预编译版本

访问 [GitHub Releases](https://github.com/peterxulove/meridian/releases) 获取最新预编译二进制文件。

每个 Release 包含：
- `meridian-server-darwin-arm64` — macOS Apple Silicon 服务端
- `meridian-client-darwin-arm64` — macOS Apple Silicon 客户端
- `meridian-server-darwin-amd64` — macOS Intel 服务端
- `meridian-client-darwin-amd64` — macOS Intel 客户端
- `meridian-server-linux-arm64`  — Linux ARM64 服务端（静态链接）
- `meridian-client-linux-arm64`  — Linux ARM64 客户端（静态链接）
- `meridian-server-linux-amd64`  — Linux x86_64 服务端（静态链接）
- `meridian-client-linux-amd64`  — Linux x86_64 客户端（静态链接）
- `SHA256SUMS` — 所有文件的 SHA256 校验和

---

## 开发说明

### 项目结构

```
meridian/
├── cmd/
│   ├── meridian-client/    # 客户端 CLI 入口
│   │   ├── main.go         # 主程序、Client 结构
│   │   ├── tunnel.go       # QUIC/TCP 安全隧道（MTP 握手 + MFP 多路复用）
│   │   └── socks5.go       # 完整 SOCKS5 代理服务器（RFC 1928/1929）
│   └── meridian-server/    # 服务端 CLI 入口
│       ├── main.go
│       └── server.go
├── pkg/
│   ├── crypto/             # 密码学原语（X25519、ChaCha20、HKDF）
│   ├── mfp/                # Meridian 帧协议（编解码、加密）
│   ├── mtp/                # Meridian 传输协议（握手）
│   ├── transport/          # 传输层（QUIC/WebSocket 适配器）
│   ├── config/             # 配置文件加载
│   └── anti/               # 抗检测（TLS 指纹）
├── test/
│   └── integration/        # 端到端集成测试（11 个，全部通过）
├── configs/                # 示例配置文件
├── dist/                   # 预编译二进制（CI 构建产物）
├── docs/                   # 协议规格文档
├── .github/
│   └── workflows/
│       └── release.yml     # GitHub Actions 自动构建发布
├── go.mod
└── go.sum
```

### 测试

```bash
# 运行全部集成测试（含 UDP 握手端到端测试）
go test ./test/integration/ -v -timeout 30s

# 代码检查
go vet ./...
```

### 贡献指南

1. Fork 本仓库
2. 创建特性分支：`git checkout -b feature/my-feature`
3. 提交变更：`git commit -m 'feat: add some feature'`
4. 推送分支：`git push origin feature/my-feature`
5. 提交 Pull Request

---

## 路线图

- [x] X25519 ECDHE 密钥交换
- [x] ChaCha20-Poly1305 / AES-GCM 加密
- [x] HKDF-SHA256 密钥派生
- [x] MFP 帧协议编解码
- [x] ClientHello 构建与解析
- [x] 服务端握手接收（Hysteria v2 承载 UDP，MTP 握手在其流上完成）
- [x] **完整 SOCKS5 代理服务（RFC 1928 + RFC 1929）** ✅ v1.0.2
- [x] **局域网代理服务（0.0.0.0 监听）** ✅ v1.0.2
- [x] **配置文件 SPKI Hex 解析修复** ✅ v1.0.1
- [x] **QUIC 传输层（Hysteria v2）** ✅ v1.3.0
- [x] **ServerHello 完整回包** ✅ v1.3.0
- [x] **数据帧通过 Meridian 加密隧道转发** ✅ v1.3.0
- [x] **QUIC 传输连接和握手修复** ✅ v1.3.5.1
- [x] CLI 参数支持
- [x] 信号优雅退出
- [x] GitHub Actions 自动发布
- [x] WebSocket 传输后端 ✅ v1.5.0
- [x] 0-RTT 会话恢复 ✅ v1.5.0
- [x] 密钥定期轮换 ✅ v1.5.0
- [x] Windows 平台支持 ✅ v1.5.0
- [x] HTTP 代理协议支持 ✅ v1.5.0
- [x] **TCP 隧道密码认证** ✅ v1.6.0
- [x] **HTTP-POST 传输服务端** ✅ v1.6.0
- [x] **方向均衡 / Nonce 失步修复** ✅ v1.6.0
- [x] **版本号构建注入** ✅ v1.6.0
- [x] **多隧道并行 / QUIC+WebSocket 混合监听** ✅ v1.6.3
- [x] **`stream_window` / `max_concurrent_streams` / `session_lifetime` 真正生效** ✅ v1.6.4
- [x] **每流 ACK 流控（协议 v2，消除大流堵塞小流）** ✅ v1.6.5
- [x] **`deploy.sh transport` 协议切换菜单** ✅ v1.6.4

---

## 许可证

MIT License — 详见 [LICENSE](LICENSE) 文件

---

## 参考资料

- [Meridian Protocol Specification v1.0](docs/Meridian-Protocol-Spec.md)
- [RFC 1928 — SOCKS5 协议](https://www.rfc-editor.org/rfc/rfc1928)
- [RFC 1929 — SOCKS5 用户名/密码认证](https://www.rfc-editor.org/rfc/rfc1929)
- [RFC 9000 — QUIC 协议](https://www.rfc-editor.org/rfc/rfc9000)
- [ChaCha20-Poly1305 RFC 8439](https://www.rfc-editor.org/rfc/rfc8439)
- [X25519 椭圆曲线 Diffie-Hellman](https://www.rfc-editor.org/rfc/rfc7748)
