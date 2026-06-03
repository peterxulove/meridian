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

## 更新日志

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
| **QUIC**（默认） | 开放或半开放网络 | 最佳性能，多路复用流 |
| **WebSocket** | 网络封锁 UDP/QUIC | 伪装为标准 WSS 流量 |
| **HTTP-POST** | 强力 DPI 环境 | 模拟云存储上传行为 |

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

### 服务端部署（Linux 服务器）

```bash
# 1. 下载并赋予执行权限
chmod +x meridian-server-linux-amd64

# 2. 生成自签证书（REALITY 模式必须）
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
  -sha256 -days 3650 -nodes -subj "/CN=www.apple.com"

# 3. 获取 SPKI 哈希（填入客户端配置）
openssl x509 -in cert.pem -pubkey -noout \
  | openssl pkey -pubout -outform DER 2>/dev/null \
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

根据所部署的网络环境，Meridian 提供了三种传输层协议的配置方案：

1. **QUIC (REALITY) 模式**：基于 QUIC/UDP，性能最强，抗封锁效果最好，**推荐默认方案**。
2. **WebSocket (WSS) 模式**：基于 TCP/TLS，适合 UDP 受限环境。
3. **HTTP-POST 模式**：模拟大文件上传，极端环境下使用。

---

### 1. QUIC (REALITY) 模式（默认推荐）

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
timing_jitter_ms: 30.0

# ─── 连接与性能控制 ───
max_clients: 1000
stream_window: 1048576
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
timing_jitter_ms: 30.0

# ─── 连接优化 ───
keepalive_interval: "30s"
handshake_timeout: "10s"
stream_window: 1048576
max_concurrent_streams: 100
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
timing_jitter_ms: 15.0
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
destinations:
  - name: "direct"
    addr: "127.0.0.1:8080"
    protocol: "direct"
    rule: "all"
```

#### 🔹 客户端 (`client.http.yaml`)
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

> 💡 **生成自签证书并获取 SPKI 哈希**
>
> ```bash
> # 生成私钥与证书（CN 必须与客户端 sni_spoof 一致）
> openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
>   -sha256 -days 3650 -nodes -subj "/CN=www.apple.com"
>
> # 提取 SPKI 哈希（填入 reality_spki）
> openssl x509 -in cert.pem -pubkey -noout \
>   | openssl pkey -pubout -outform DER 2>/dev/null \
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
- [x] UDP 服务端握手接收
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
