# Meridian 协议

> 高性能、抗检测的安全代理协议实现
> 融合 Shadowsocks、Hysteria2、VLESS 和 REALITY 的设计精华

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-macOS%20%7C%20Linux-lightgrey)](https://github.com/peterxulove/meridian/releases)
[![Architecture](https://img.shields.io/badge/Arch-ARM64%20%7C%20AMD64-orange)](https://github.com/peterxulove/meridian/releases)

---

## 目录

- [简介](#简介)
- [协议架构](#协议架构)
- [功能特性](#功能特性)
- [快速开始](#快速开始)
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

## 协议架构

```
┌─────────────────────────────────────────────────────────┐
│  应用层（代理 / 中继）                                    │
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

### 服务端部署

```bash
# 1. 下载服务端
chmod +x meridian-server-linux-arm64

# 2. 复制配置文件
cp configs/server.example.yaml server.yaml

# 3. 编辑配置（修改密码、证书路径等）
vim server.yaml

# 4. 启动服务端
./meridian-server-linux-arm64 -config server.yaml
```

### 客户端使用

```bash
# 1. 下载客户端
chmod +x meridian-client-darwin-arm64

# 2. 复制配置文件
cp configs/client.example.yaml client.yaml

# 3. 编辑配置（填入服务器地址、密码等）
vim client.yaml

# 4. 启动客户端（本地监听 SOCKS5 代理 127.0.0.1:1080）
./meridian-client-darwin-arm64 -config client.yaml
```

### CLI 参数

```
meridian-server / meridian-client 通用参数：

  -config string
        配置文件路径（默认：server.yaml / client.yaml）
  -listen string
        覆盖监听地址（服务端示例：0.0.0.0:443，客户端示例：127.0.0.1:1080）
  -fingerprints
        列出所有可用的 TLS 指纹并退出
```

---

## 配置说明

根据所部署的网络环境，Meridian 提供了三种传输层协议的配置方案：

1. **QUIC (REALITY) 模式**：基于 QUIC/UDP，使用独创的 REALITY TLS 握手机制伪装正常流量，**性能最强，抗封锁效果最好，推荐作为默认方案**。
2. **WebSocket (WSS) 模式**：基于 TCP/TLS 升级协议，流量表现为标准的 WSS 通信，适合 UDP 受限或被 QoS 的环境。
3. **HTTP-POST 模式**：通过 HTTP/1.1 POST 大文件或持续视频上传的流量特征，实现业务级高隐蔽通信。

---

### 1. QUIC (REALITY) 模式（默认推荐）

使用真实的合法网站证书哈希和 TLS 伪装指纹，无需购买域名和配置公信力证书即可在客户端直接进行端到端强校验。

#### 🔹 服务端 (`server.quic.yaml`)
```yaml
# 监听端口（REALITY 推荐使用标准 443 端口以达到完美伪装）
listen_addr: "0.0.0.0:443"
transport: "QUIC"
cipher_suite: 1                    # 加密套件：1=ChaCha20, 2=AES256, 3=AES128
password: "your-strong-random-password-here"

# ─── REALITY 伪装配置 ───
reality_mode: true
reality_enabled: true
server_cert: "cert.pem"            # 服务端私有签名证书
server_key: "key.pem"              # 服务端私有签名私钥
# 预设的 SPKI 证书哈希，可替换为你自签证书的 SPKI 哈希
reality_spki: "804d9c7922d9c491aefbe7f2da4930bfae498cda692994ea9a9fefb0f2ea99cb"
reality_short_id: 1002             # 4字节随机正整数 ID 标识，防侦测攻击
reality_max_time: 0                # 时间戳校验最大容差秒数，0 表示不限制

# ─── 抗检测主动防御 ───
fingerprint: "chrome_win"          # 伪装客户端指纹类型：chrome_win / firefox_mac / curl_linux
padding_mode: "random"             # 数据帧填充策略：none / fixed / random
base_payload_size: 1400            # 数据帧基线载荷大小 (字节)
max_payload_size: 1452             # 最大数据帧大小 (字节)
timing_jitter_ms: 30.0             # 流量发送的时间轴随机扰动上限 (毫秒)

# ─── 连接与性能控制 ───
max_clients: 1000                  # 最大并发客户端会话数量
stream_window: 1048576             # 数据流窗口大小 (字节，1MB)
keepalive_interval: "30s"          # 存活心跳发送周期
handshake_timeout: "10s"           # 握手最大超时时间

# ─── 后端路由与转发（上游） ───
destinations:
  - name: "direct"
    addr: "127.0.0.1:8080"         # 服务端中转或直连后端的落地服务地址
    protocol: "direct"
    rule: "all"
    priority: 0
```

#### 🔹 客户端 (`client.quic.yaml`)
```yaml
# 服务端公网地址与监听端口
server_addr: "your-server-ip:443"
transport: "QUIC"
cipher_suite: 1                    # 必须与服务端配置相同
password: "your-strong-random-password-here"

# ─── REALITY 抗探测握手 ───
reality_mode: true
sni_spoof: "www.google.com"        # 伪装的目标 SNI 域名（建议选择免流或访问频次极高的域名）
# 填入服务端生成的 SPKI 哈希用于客户端主动强校验防 MITM 中间人探测
reality_spki: "804d9c7922d9c491aefbe7f2da4930bfae498cda692994ea9a9fefb0f2ea99cb"
reality_short_id: 1002             # 必须与服务端配置相同
reality_max_time: 0

# ─── 抗检测主动防御 ───
fingerprint: "chrome_win"
padding_mode: "random"
base_payload_size: 1400
max_payload_size: 1452
direction_balance: true            # 开启双向流量伪造平衡，对抗非对称流量分析
timing_jitter_ms: 30.0

# ─── 连接优化参数 ───
keepalive_interval: "30s"
handshake_timeout: "10s"
stream_window: 1048576
max_concurrent_streams: 100
session_lifetime: "1h"             # 临时密钥会话最大生命周期 (自动定期重协商)
dial_timeout: "15s"

# ─── 本地监听代理代理 ───
listen_addr: "127.0.0.1:1080"      # 本地暴露出的科学上网服务接口
proxy_protocol: "socks5"           # 支持 socks5 或 http
```

---

### 2. WebSocket (WSS) 模式

将加密流量包装在标准 HTTP WebSocket 升级链接内，可配合 Nginx / Caddy 等反向代理进行 HTTPS 流量伪装。

#### 🔹 服务端 (`server.ws.yaml`)
```yaml
listen_addr: "127.0.0.1:8080"      # 推荐监听在本地，用外部 Nginx 暴露 443 并配置 HTTPS TLS
transport: "WebSocket"
cipher_suite: 1
password: "your-strong-random-password-here"

# ─── WebSocket 参数 ───
wss_path: "/v2/connection"         # WebSocket 升级所用的指定伪装请求路径，防主动探测

# ─── 抗检测主动防御 ───
fingerprint: "firefox_mac"
padding_mode: "random"
timing_jitter_ms: 15.0

# ─── 后端路由与转发 ───
destinations:
  - name: "direct"
    addr: "127.0.0.1:8080"
    protocol: "direct"
    rule: "all"
```

#### 🔹 客户端 (`client.ws.yaml`)
```yaml
server_addr: "your-server-domain.com:443" # 如果使用反代，请指向反向代理的公网域名和 HTTPS 端口
transport: "WebSocket"
cipher_suite: 1
password: "your-strong-random-password-here"

# ─── WebSocket 升级配置 ───
wss_path: "/v2/connection"         # 必须与服务端配置完全相同

# ─── TLS 伪装指纹 ───
reality_mode: false                # WSS 模式不使用自签 REALITY 握手
sni_spoof: "your-server-domain.com"
fingerprint: "firefox_mac"
padding_mode: "random"
direction_balance: false

# ─── 本地监听代理代理 ───
listen_addr: "127.0.0.1:1080"
proxy_protocol: "socks5"
```

---

### 3. HTTP-POST 模式

采用完全合法的标准 HTTP/1.1 POST 大文件上传或媒体流传输行为欺骗检测引擎。

#### 🔹 服务端 (`server.http.yaml`)
```yaml
listen_addr: "0.0.0.0:80"          # 监听普通 HTTP 80 端口，模拟正常的免密明文或代理上传
transport: "HTTP-POST"
cipher_suite: 2                    # 推荐选用 AES-256-GCM 保护载荷
password: "your-strong-random-password-here"

# ─── 后端路由与转发 ───
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

# ─── HTTP-POST 镜像流量伪装 ───
upload_url: "http://your-server-ip/api/v1/storage/upload" # 客户端请求大文件上传的模拟完整 URL
mirror_boundary: "----WebKitFormBoundaryT8z736aFmE1yB"     # 伪装 MIME Web 浏览器文件上传分界线
mirror_path: "/api/v1/storage/upload"                     # 服务端镜像处理的 HTTP 请求资源路径

# ─── 本地监听代理代理 ───
listen_addr: "127.0.0.1:1080"
proxy_protocol: "socks5"
```

---

> 💡 **小贴士：如何生成专用的自签证书并获取 SPKI 哈希？**
>
> 1. **生成私钥与自签证书**：
>    ```bash
>    openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -sha256 -days 3650 -nodes -subj "/CN=www.google.com"
>    ```
> 2. **一键提取 SPKI 哈希**（将其填入服务端和客户端的 `reality_spki`）：
>    ```bash
>    openssl x509 -in cert.pem -pubkey -noout \
>      | openssl pkey -pubout -outform DER 2>/dev/null \
>      | sha256sum | cut -c1-64
>    ```

---

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
│   │   └── main.go
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
│   └── integration/        # 端到端集成测试
├── configs/                # 示例配置文件
├── dist/                   # 预编译二进制（CI 构建产物）
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
- [x] 本地 SOCKS5 代理监听
- [x] CLI 参数支持
- [x] 信号优雅退出
- [x] GitHub Actions 自动发布
- [ ] ServerHello 完整回包
- [ ] 完整 SOCKS5/HTTP 代理协议
- [ ] 数据帧转发
- [ ] WebSocket 传输后端
- [ ] 0-RTT 会话恢复
- [ ] 密钥定期轮换

---

## 许可证

MIT License — 详见 [LICENSE](LICENSE) 文件

---

## 参考资料

- [Meridian Protocol Specification v1.0](docs/Meridian-Protocol-Spec.md)
- [RFC 9000 — QUIC 协议](https://www.rfc-editor.org/rfc/rfc9000)
- [ChaCha20-Poly1305 RFC 8439](https://www.rfc-editor.org/rfc/rfc8439)
- [X25519 椭圆曲线 Diffie-Hellman](https://www.rfc-editor.org/rfc/rfc7748)
