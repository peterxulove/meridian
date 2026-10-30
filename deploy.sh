#!/bin/bash
# ==============================================================================
# Meridian One-Click Deployment Script (Linux & macOS)
# ==============================================================================
#
# Supports:
#   - OS: Linux (systemd) and macOS (launchd)
#   - Architectures: amd64 and arm64
#   - Roles: Server (with auto SSL & SPKI derivation) and Client (interactive config)
#   - Actions: Install, Update (binary only, keep config), Uninstall, Status
#

set -e

DEFAULT_RELEASE_VERSION="v1.6.13"

# Re-execute with bash if run with sh
if [ -z "$BASH_VERSION" ]; then
    exec bash "$0" "$@"
fi


# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0;64m' # No Color
NC='\033[0m'

# Check OS and Architecture
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
if [ -f "/etc/openwrt_release" ]; then
    OS="openwrt"
fi

ARCH="$(uname -m)"
if [ "$ARCH" = "x86_64" ]; then
    ARCH="amd64"
elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
    ARCH="arm64"
else
    echo -e "${RED}[Error] Unsupported architecture: $ARCH${NC}"
    exit 1
fi

# Determine Config and Install Directory Paths based on OS
if [ "$OS" = "linux" ]; then
    CONFIG_DIR="/etc/meridian"
    BIN_DIR="/usr/local/bin"
    # Detect sudo/root
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${YELLOW}[Warning] Please run with sudo or as root for full installation on Linux.${NC}"
        SUDO="sudo"
    else
        SUDO=""
    fi
elif [ "$OS" = "openwrt" ]; then
    CONFIG_DIR="/etc/meridian"
    BIN_DIR="/usr/sbin"
    SUDO=""
elif [ "$OS" = "darwin" ]; then
    CONFIG_DIR="$HOME/.meridian"
    BIN_DIR="/usr/local/bin"
    SUDO=""
else
    echo -e "${RED}[Error] Unsupported OS: $OS. This script supports Linux, OpenWrt/iStoreOS and macOS only.${NC}"
    exit 1
fi

print_banner() {
    echo -e "${CYAN}====================================================${NC}"
    echo -e "${CYAN}        __  ___           _     _ _                 ${NC}"
    echo -e "${CYAN}       /  |/  /__  _____ (_)___| (_)___ _____       ${NC}"
    echo -e "${CYAN}      / /|_/ / _ \\/ ___// / __  / / __ \`/ __ \\      ${NC}"
    echo -e "${CYAN}     / /  / /  __/ /   / / /_/ / / /_/ / / / /      ${NC}"
    echo -e "${CYAN}    /_/  /_/\\___/_/   /_/\\__,_/_/\\__,_/_/ /_/       ${NC}"
    echo -e "${CYAN}                                                    ${NC}"
    echo -e "${CYAN}    Meridian Secure Tunnel One-Click Deployment     ${NC}"
    echo -e "${CYAN}====================================================${NC}"
    echo -e "System Info: ${GREEN}$OS ($ARCH)${NC}"
    echo -e "Config Path: ${GREEN}$CONFIG_DIR${NC}"
    echo -e "Binary Path: ${GREEN}$BIN_DIR${NC}"
    echo -e "----------------------------------------------------"
}

# Helper to generate robust random passwords
generate_password() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 16
    elif [ -r /dev/urandom ]; then
        head -c 16 /dev/urandom | xxd -p | head -n 1
    else
        echo "meridian-default-super-secure-password"
    fi
}

# Helper to calculate SPKI Hash
calculate_spki_hex() {
    local cert_path="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        openssl x509 -in "$cert_path" -pubkey -noout | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | cut -c1-64
    elif command -v shasum >/dev/null 2>&1; then
        openssl x509 -in "$cert_path" -pubkey -noout | openssl pkey -pubin -outform DER 2>/dev/null | shasum -a 256 | cut -c1-64
    else
        openssl x509 -in "$cert_path" -pubkey -noout | openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256 | awk '{print $2}' | cut -c1-64
    fi
}

# Return the release version to install unless the caller overrides it.
release_version() {
    echo "${MERIDIAN_VERSION:-$DEFAULT_RELEASE_VERSION}"
}

# Download a release asset atomically. A failed/partial download must never
# replace a working binary.
download_binary() {
    local role="$1"
    local platform="$2"
    local target_bin="$3"
    local version
    version="$(release_version)"
    local asset_name="meridian-${role}-${platform}-${ARCH}"
    local download_url="https://github.com/peterxulove/meridian/releases/download/${version}/${asset_name}"
    local tmp_download="${target_bin}.download.$$"

    echo -e "Downloading ${version}: ${download_url}"
    if command -v curl >/dev/null 2>&1; then
        if ! $SUDO curl --fail --location --retry 3 --retry-all-errors \
            --connect-timeout 10 --max-time 180 \
            -o "$tmp_download" "$download_url"; then
            $SUDO rm -f "$tmp_download"
            return 1
        fi
    elif command -v wget >/dev/null 2>&1; then
        local attempt=1
        while [ "$attempt" -le 3 ]; do
            if $SUDO wget -O "$tmp_download" "$download_url"; then
                break
            fi
            $SUDO rm -f "$tmp_download"
            [ "$attempt" -eq 3 ] && return 1
            attempt=$((attempt + 1))
            sleep 2
        done
    else
        echo -e "${RED}[Error] Neither curl nor wget found. Cannot download binary.${NC}"
        return 1
    fi

    if [ ! -s "$tmp_download" ]; then
        $SUDO rm -f "$tmp_download"
        return 1
    fi
    $SUDO chmod +x "$tmp_download"
    $SUDO mv -f "$tmp_download" "$target_bin"
}

# Build or copy executable. source=release forces the signed GitHub release
# path, which prevents update_core from silently installing an older local
# dist/ binary.
install_binary() {
    local role="$1" # "server" or "client"
    local source="${2:-auto}"
    local bin_name="meridian-${role}"
    local target_bin="${BIN_DIR}/${bin_name}"
    
    echo -e "${BLUE}[1/4] Installing $bin_name binary...${NC}"
    
    $SUDO mkdir -p "$BIN_DIR"
    
    local platform="$OS"
    if [ "$OS" = "openwrt" ]; then
        platform="linux"
    fi
    
    if [ "$source" = "release" ]; then
        download_binary "$role" "$platform" "$target_bin" || {
            echo -e "${RED}[Error] Failed to download $(release_version) for ${platform}/${ARCH}.${NC}"
            return 1
        }
    # Check if we are running in the source repo and can build
    elif command -v go >/dev/null 2>&1 && [ -f "go.mod" ]; then
        echo -e "Go compiler found. Building from source..."
        go build -ldflags "-s -w" -o "$bin_name" "./cmd/meridian-${role}"
        $SUDO cp "$bin_name" "$target_bin"
        $SUDO chmod +x "$target_bin"
        rm -f "$bin_name"
    # Check if prebuilt exists in current directory as meridian-${role}-${platform}-${ARCH}
    elif [ -f "meridian-${role}-${platform}-${ARCH}" ]; then
        echo -e "Using prebuilt binary from current directory..."
        $SUDO cp "meridian-${role}-${platform}-${ARCH}" "$target_bin"
        $SUDO chmod +x "$target_bin"
    # Check if prebuilt exists in dist/
    elif [ -f "dist/meridian-${role}-${platform}-${ARCH}" ]; then
        echo -e "Using prebuilt binary from dist/ directory..."
        $SUDO cp "dist/meridian-${role}-${platform}-${ARCH}" "$target_bin"
        $SUDO chmod +x "$target_bin"
    # Check if local built exists in root
    elif [ -f "meridian-${role}" ]; then
        echo -e "Using local binary in root..."
        $SUDO cp "meridian-${role}" "$target_bin"
        $SUDO chmod +x "$target_bin"
    else
        echo -e "No local binary or Go compiler found. Attempting release download..."
        download_binary "$role" "$platform" "$target_bin" || {
            echo -e "${RED}[Error] Failed to download $(release_version) for ${platform}/${ARCH}.${NC}"
            return 1
        }
    fi
    
    echo -e "${GREEN}Binary installed to $target_bin${NC}"
    if "$target_bin" -version >/dev/null 2>&1; then
        echo -e "  Version: $("$target_bin" -version)"
    fi
}

# Config Server
configure_server() {
    echo -e "${BLUE}[2/4] Generating Server Configuration & Certificates...${NC}"
    $SUDO mkdir -p "$CONFIG_DIR"
    
    local cert_path="${CONFIG_DIR}/cert.pem"
    local key_path="${CONFIG_DIR}/key.pem"

    # Certificate resolution, best camouflage first:
    #   1. MERIDIAN_CERT / MERIDIAN_KEY  — a pair you already have
    #   2. MERIDIAN_DOMAIN               — install from acme.sh, renewals wired up
    #   3. self-signed                   — last resort, only with explicit consent
    #
    # A self-signed certificate is not a neutral default: issuer == subject is
    # the clearest "not a website" signal a passive observer can read, and it
    # makes every other anti-detection measure pointless. It used to be
    # generated silently, which is how a 10-year CN=www.apple.com ended up in
    # production.
    local cert_source=""
    if [ -n "${MERIDIAN_CERT:-}" ] && [ -n "${MERIDIAN_KEY:-}" ]; then
        $SUDO install -m 644 "$MERIDIAN_CERT" "$cert_path"
        $SUDO install -m 600 "$MERIDIAN_KEY" "$key_path"
        cert_source="provided pair"
    elif [ -n "${MERIDIAN_DOMAIN:-}" ]; then
        local acme_home="${MERIDIAN_ACME_HOME:-/root/.acme.sh}"
        local acme_sh="${acme_home}/acme.sh"
        if [ ! -x "$acme_sh" ]; then
            echo -e "${RED}[Error] MERIDIAN_DOMAIN is set but ${acme_sh} is not executable.${NC}"
            return 1
        fi
        local keylen_flag=""
        if [ -d "${acme_home}/${MERIDIAN_DOMAIN}_ecc" ]; then
            keylen_flag="--ecc"
        elif [ ! -d "${acme_home}/${MERIDIAN_DOMAIN}" ]; then
            echo -e "${RED}[Error] No acme.sh certificate for ${MERIDIAN_DOMAIN}.${NC}"
            echo -e "Issue one first, for example:"
            echo -e "  ${acme_sh} --issue -d ${MERIDIAN_DOMAIN} -w /var/www/html --keylength ec-256"
            return 1
        fi
        # --install-cert copies the pair and registers the reload command, so a
        # renewal restarts the tunnel without anyone remembering to do it.
        $SUDO "$acme_sh" --install-cert -d "$MERIDIAN_DOMAIN" $keylen_flag \
            --key-file "$key_path" \
            --fullchain-file "$cert_path" \
            --reloadcmd "systemctl restart meridian-server 2>/dev/null || true" >/dev/null
        cert_source="acme.sh (${MERIDIAN_DOMAIN})"
    elif [ ! -f "$cert_path" ] || [ ! -f "$key_path" ]; then
        if [ "${MERIDIAN_ALLOW_SELF_SIGNED:-0}" != "1" ]; then
            echo -e "${YELLOW}[Warning] No CA-issued certificate configured.${NC}"
            echo -e "  Set MERIDIAN_CERT/MERIDIAN_KEY, or MERIDIAN_DOMAIN with an acme.sh"
            echo -e "  issuance, to present a certificate a browser would accept."
            echo -e "  A self-signed certificate is a passive fingerprint and cannot be"
            echo -e "  hidden by any other setting."
            if [ -t 0 ]; then
                read -rp "  Continue with a self-signed certificate? [y/N]: " selfsigned_ok
                case "$selfsigned_ok" in
                    y|Y|yes|YES) ;;
                    *) echo -e "${RED}Aborted.${NC}"; return 1 ;;
                esac
            fi
        fi
        local cn="${MERIDIAN_SNI:-localhost}"
        echo -e "Generating self-signed SSL Certificate (CN=${cn}, 90 days)..."
        $SUDO openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
            -keyout "$key_path" \
            -out "$cert_path" \
            -subj "/CN=${cn}" \
            -addext "subjectAltName=DNS:${cn}" \
            -days 90 >/dev/null 2>&1
        $SUDO chmod 600 "$key_path"
        $SUDO chmod 644 "$cert_path"
        cert_source="self-signed (not recommended)"
    else
        cert_source="existing ${cert_path}"
    fi
    echo -e "  Certificate: ${cert_source}"
    
    # Calculate SPKI Hash
    local spki_hex
    spki_hex=$(calculate_spki_hex "$cert_path")
    
    # Generate Random Password
    local password
    password=$(generate_password)
    
    # Write server.yaml
    local server_yaml="${CONFIG_DIR}/server.yaml"
    cat <<EOF | $SUDO tee "$server_yaml" >/dev/null
# Meridian Server - Auto-generated configuration
listen_addr: "0.0.0.0:443"
transport: "QUIC+WebSocket"
cipher_suite: 1
password: "${password}"
wss_path: "/ws/"
# Everything that is not a tunnel upgrade is proxied here, so the port answers
# like a real site instead of returning Go's 404 to a prober.
fallback_url: "${MERIDIAN_FALLBACK_URL:-}"
fallback_sni: "${MERIDIAN_FALLBACK_SNI:-}"

# ─── REALITY Mode (anti-detection) ───
reality_mode: true
reality_enabled: true
server_cert: "${cert_path}"
server_key: "${key_path}"
server_spki: "${spki_hex}"
reality_short_id: 12345
reality_max_time: 0

# ─── Anti-Detection ───
fingerprint: "chrome_win"
padding_mode: "random"
base_payload_size: 1400
max_payload_size: 1452
timing_jitter_ms: 0.0
up_mbps: 0
down_mbps: 0

# ─── Connection Limits ───
max_clients: 1000
stream_window: 1048576
max_concurrent_streams: 512
keepalive_interval: "30s"
handshake_timeout: "10s"

# ─── Upstream Destinations ───
destinations:
  - name: "direct"
    addr: "127.0.0.1:8080"
    protocol: "direct"
    rule: "all"
    priority: 0
EOF
    
    $SUDO chmod 600 "$server_yaml"
    echo -e "${GREEN}Configuration generated: $server_yaml${NC}"
    
    # Store output values for the summary
    SERVER_PASS="$password"
    SERVER_SPKI="$spki_hex"
}

# Config Client
configure_client() {
    echo -e "${BLUE}[2/4] Configuring Client Settings...${NC}"
    $SUDO mkdir -p "$CONFIG_DIR"
    
    echo -e "Please enter the Meridian Server details:"
    read -rp "1. Server Address [IP:443 / Domain:443]: " client_server_addr
    if [ -z "$client_server_addr" ]; then
        echo -e "${RED}[Error] Server address cannot be empty.${NC}"
        exit 1
    fi
    
    read -rp "2. Connection Password: " client_password
    if [ -z "$client_password" ]; then
        echo -e "${RED}[Error] Password cannot be empty.${NC}"
        exit 1
    fi
    
    read -rp "3. SNI / cover domain (must match the server certificate) [default: www.apple.com]: " client_sni
    client_sni="${client_sni:-www.apple.com}"

    # An empty pin means "verify with the CA chain", which is what you want
    # with an ACME certificate: the pair is renewed every 60-90 days, and a
    # pinned leaf would break every client at each renewal.
    read -rp "4. Reality SPKI Hash (64 hex, empty = CA verification): " client_spki

    read -rp "5. Local Proxy Protocol (socks5 / http) [default: socks5]: " client_proto
    client_proto="${client_proto:-socks5}"

    read -rp "6. Local Listen Port [default: 1080]: " client_port
    client_port="${client_port:-1080}"

    read -rp "7. Tunnel connections for throughput (1-16) [default: 4]: " client_lanes
    client_lanes="${client_lanes:-4}"
    case "$client_lanes" in
        ''|*[!0-9]*) client_lanes=4 ;;
    esac
    if [ "$client_lanes" -lt 1 ]; then client_lanes=1; fi
    if [ "$client_lanes" -gt 16 ]; then client_lanes=16; fi
    
    local client_yaml="${CONFIG_DIR}/client.yaml"
    cat <<EOF | $SUDO tee "$client_yaml" >/dev/null
# Meridian Client - Auto-generated configuration
server_addr: "${client_server_addr}"
transport: "WebSocket"
cipher_suite: 1
password: "${client_password}"
wss_path: "/ws/"

# ─── REALITY Mode (anti-detection) ───
sni_spoof: "${client_sni}"
reality_mode: true
reality_short_id: 12345
reality_max_time: 0

# ─── Anti-Detection ───
fingerprint: "chrome_win"
padding_mode: "random"
base_payload_size: 1400
max_payload_size: 1452
direction_balance: false
timing_jitter_ms: 0.0

# ─── Connection ───
keepalive_interval: "30s"
handshake_timeout: "10s"
stream_window: 1048576
max_concurrent_streams: 512
tunnel_connections: ${client_lanes}
session_lifetime: "1h"
dial_timeout: "15s"

# 0 = adaptive BBR; set explicit Mbps only for a known QUIC link.
up_mbps: 0
down_mbps: 0

# ─── Local Proxy ───
listen_addr: "0.0.0.0:${client_port}"
proxy_protocol: "${client_proto}"
EOF

    if [ -n "$client_spki" ]; then
        printf 'reality_spki: "%s"\n' "$client_spki" | $SUDO tee -a "$client_yaml" >/dev/null
    fi

    $SUDO chmod 600 "$client_yaml"
    echo -e "${GREEN}Configuration generated: $client_yaml${NC}"
}

# Set a top-level scalar in a YAML file without touching passwords, SPKI,
# addresses or comments. Missing keys are appended.
set_yaml_key() {
    local file="$1"
    local key="$2"
    local value="$3"
    local tmp_file
    tmp_file="$(mktemp)"

    $SUDO awk -v key="$key" -v value="$value" '
        BEGIN { found = 0 }
        $0 ~ ("^" key ":") { print key ": " value; found = 1; next }
        { print }
        END { if (!found) print key ": " value }
    ' "$file" > "$tmp_file"
    $SUDO cp "$tmp_file" "$file"
    $SUDO chmod 600 "$file"
    rm -f "$tmp_file"
}

# Return true when a top-level key is already present in a YAML file.
yaml_has_key() {
    local file="$1"
    local key="$2"
    $SUDO grep -q "^${key}:" "$file" 2>/dev/null
}

# Restart the service after a configuration change and roll back to the given
# backup if it does not come up.
restart_or_rollback() {
    local role="$1"
    local config_file="$2"
    local backup_file="$3"

    echo -e "${BLUE}Restarting meridian-${role}...${NC}"
    if restart_service "$role"; then
        echo -e "${GREEN}Configuration applied.${NC}"
        return 0
    fi
    $SUDO cp -p "$backup_file" "$config_file"
    restart_service "$role" || true
    echo -e "${RED}[Error] The service did not restart. Configuration was rolled back.${NC}"
    return 1
}

# switch_transport [role] [quic|websocket|hybrid|http-post]
# Switches the wire protocol of an existing installation. Credentials, SPKI,
# certificates and proxy settings are preserved; only transport-specific keys
# are touched.
switch_transport() {
    local role="$1"
    local want="$2"
    local config_file="${CONFIG_DIR}/${role}.yaml"
    local backup_file="${config_file}.bak.$(date +%Y%m%d%H%M%S)-$$"
    local transport=""

    if [ ! -f "$config_file" ]; then
        echo -e "${RED}[Error] $config_file not found.${NC}"
        return 1
    fi

    if [ -z "$want" ]; then
        echo -e "Current transport: ${CYAN}$(grep -m1 '^transport:' "$config_file" | cut -d: -f2- | tr -d ' "')${NC}"
        echo -e "Select the transport for ${role}:"
        echo "  1) QUIC            - Hysteria v2 over UDP, best on clean links"
        echo "  2) WebSocket       - TLS over TCP, best throughput with 4 lanes"
        if [ "$role" = "server" ]; then
            echo "  3) QUIC+WebSocket  - UDP and TCP listeners share one port"
        fi
        echo "  4) HTTP-POST       - mirror mode, slowest but most camouflaged"
        read -rp "Choice [1-4]: " want
    fi

    case "$want" in
        1|quic|QUIC)                          transport="QUIC" ;;
        2|ws|wss|websocket|WebSocket)         transport="WebSocket" ;;
        3|hybrid|quic+websocket|QUIC+WebSocket) transport="QUIC+WebSocket" ;;
        4|http-post|httppost|HTTP-POST)       transport="HTTP-POST" ;;
        *) echo -e "${RED}Unknown transport: $want${NC}"; return 1 ;;
    esac

    if [ "$transport" = "QUIC+WebSocket" ] && [ "$role" != "server" ]; then
        echo -e "${RED}[Error] QUIC+WebSocket is a server-side listener; clients must pick QUIC or WebSocket.${NC}"
        return 1
    fi

    # The binary has to understand the new transport name before the config
    # starts pointing at it.
    if ! update_core "$role"; then
        echo -e "${RED}[Error] Core update failed; configuration was not changed.${NC}"
        return 1
    fi

    $SUDO cp -p "$config_file" "$backup_file"
    echo -e "Configuration backup: ${backup_file}"

    set_yaml_key "$config_file" "transport" "\"${transport}\""
    case "$transport" in
        "WebSocket")
            set_yaml_key "$config_file" "wss_path" '"/ws/"'
            if [ "$role" = "client" ] && ! yaml_has_key "$config_file" "tunnel_connections"; then
                set_yaml_key "$config_file" "tunnel_connections" "4"
            fi
            ;;
        "QUIC+WebSocket")
            set_yaml_key "$config_file" "wss_path" '"/ws/"'
            ;;
        "HTTP-POST")
            set_yaml_key "$config_file" "mirror_path" '"/upload"'
            ;;
    esac

    echo -e "Transport set to ${CYAN}${transport}${NC}"
    if [ "$role" = "server" ] && [ "$transport" = "WebSocket" ]; then
        echo -e "${YELLOW}Note: every client must also use WebSocket after this change.${NC}"
    fi
    restart_or_rollback "$role" "$config_file" "$backup_file"
}

# Switch an existing installation to the high-throughput transport while
# preserving all credentials and local proxy settings.
optimize_config() {
    local role="$1"
    local config_file="${CONFIG_DIR}/${role}.yaml"
    local backup_file="${config_file}.bak.$(date +%Y%m%d%H%M%S)-$$"

    if [ ! -f "$config_file" ]; then
        echo -e "${RED}[Error] $config_file not found.${NC}"
        return 1
    fi

    # Always install the release that understands the new transport names
    # before switching the configuration.
    if ! update_core "$role"; then
        echo -e "${RED}[Error] Core update failed; configuration was not changed.${NC}"
        return 1
    fi

    $SUDO cp -p "$config_file" "$backup_file"
    echo -e "Configuration backup: ${backup_file}"

    # Tuning must not silently rewrite the transport the operator chose:
    # `optimize` used to force QUIC+WebSocket on servers and WebSocket on
    # clients, so a QUIC-only deployment reverted on the next tune-up.
    local current_transport
    current_transport="$(grep -m1 '^transport:' "$config_file" | cut -d: -f2- | tr -d ' "')"
    if [ -z "$current_transport" ]; then
        if [ "$role" = "server" ]; then
            set_yaml_key "$config_file" "transport" '"QUIC+WebSocket"'
        else
            set_yaml_key "$config_file" "transport" '"WebSocket"'
        fi
        set_yaml_key "$config_file" "wss_path" '"/ws/"'
    fi
    if [ "$role" = "client" ] && ! yaml_has_key "$config_file" "tunnel_connections"; then
        set_yaml_key "$config_file" "tunnel_connections" "4"
    fi

    set_yaml_key "$config_file" "padding_mode" '"random"'
    set_yaml_key "$config_file" "base_payload_size" "1400"
    set_yaml_key "$config_file" "max_payload_size" "1452"
    set_yaml_key "$config_file" "timing_jitter_ms" "0.0"
    set_yaml_key "$config_file" "up_mbps" "0"
    set_yaml_key "$config_file" "down_mbps" "0"
    set_yaml_key "$config_file" "stream_window" "1048576"
    set_yaml_key "$config_file" "max_concurrent_streams" "512"

    restart_or_rollback "$role" "$config_file" "$backup_file"
}

# Start Service (Systemd / Launchd)
start_service() {
    local role="$1"
    local bin_name="meridian-${role}"
    
    echo -e "${BLUE}[3/4] Registering and starting system service...${NC}"
    
    if [ "$OS" = "linux" ]; then
        local service_file="/etc/systemd/system/${bin_name}.service"
        cat <<EOF | $SUDO tee "$service_file" >/dev/null
[Unit]
Description=Meridian $(echo "$role" | awk '{print toupper(substr($0,1,1))substr($0,2)}') Tunnel Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=${BIN_DIR}/${bin_name} -config ${CONFIG_DIR}/${role}.yaml
Restart=always
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
        
        $SUDO systemctl daemon-reload
        $SUDO systemctl enable "$bin_name"
        $SUDO systemctl start "$bin_name"
        echo -e "${GREEN}Systemd service registered: ${service_file}${NC}"
        echo -e "${GREEN}Service status:${NC}"
        $SUDO systemctl status "$bin_name" --no-pager -n 3
        
    elif [ "$OS" = "openwrt" ]; then
        local service_file="/etc/init.d/${bin_name}"
        cat <<EOF | $SUDO tee "$service_file" >/dev/null
#!/etc/rc.common

START=99
USE_PROCD=1

CONF_FILE="${CONFIG_DIR}/${role}.yaml"
BIN_FILE="${BIN_DIR}/${bin_name}"

start_service() {
    if [ ! -f "\$CONF_FILE" ]; then
        echo "Configuration file \$CONF_FILE not found."
        return 1
    fi

    procd_open_instance
    procd_set_param command "\$BIN_FILE" -config "\$CONF_FILE"
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_set_param respawn
    procd_close_instance
}
EOF
        $SUDO chmod +x "$service_file"
        $SUDO "$service_file" enable
        $SUDO "$service_file" start
        echo -e "${GREEN}OpenWrt init.d service registered: ${service_file}${NC}"
        echo -e "${GREEN}Service enabled and started.${NC}"

    elif [ "$OS" = "darwin" ]; then
        local plist_file="$HOME/Library/LaunchAgents/com.meridian.${role}.plist"
        cat <<EOF > "$plist_file"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.meridian.${role}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${BIN_DIR}/${bin_name}</string>
        <string>-config</string>
        <string>${CONFIG_DIR}/${role}.yaml</string>
    </array>
    <key>KeepAlive</key>
    <true/>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardOutPath</key>
    <string>${CONFIG_DIR}/${role}.log</string>
    <key>StandardErrorPath</key>
    <string>${CONFIG_DIR}/${role}.err</string>
</dict>
</plist>
EOF
        chmod 644 "$plist_file"
        
        # Load plist safely
        launchctl unload "$plist_file" >/dev/null 2>&1 || true
        launchctl load "$plist_file"
        
        echo -e "${GREEN}Launchd agent registered: ${plist_file}${NC}"
        echo -e "${GREEN}Service has been started.${NC}"
    fi
}

# Uninstall service, configs, and binaries
uninstall_service() {
    local role="$1"
    local bin_name="meridian-${role}"
    
    echo -e "${BLUE}Stopping and removing $bin_name...${NC}"
    
    if [ "$OS" = "linux" ]; then
        if [ -f "/etc/systemd/system/${bin_name}.service" ]; then
            $SUDO systemctl stop "$bin_name" || true
            $SUDO systemctl disable "$bin_name" || true
            $SUDO rm -f "/etc/systemd/system/${bin_name}.service"
            $SUDO systemctl daemon-reload
            echo -e "Removed systemd service."
        fi
    elif [ "$OS" = "openwrt" ]; then
        local service_file="/etc/init.d/${bin_name}"
        if [ -f "$service_file" ]; then
            $SUDO "$service_file" stop || true
            $SUDO "$service_file" disable || true
            $SUDO rm -f "$service_file"
            echo -e "Removed OpenWrt init.d service."
        fi
    elif [ "$OS" = "darwin" ]; then
        local plist_file="$HOME/Library/LaunchAgents/com.meridian.${role}.plist"
        if [ -f "$plist_file" ]; then
            launchctl unload "$plist_file" || true
            rm -f "$plist_file"
            echo -e "Removed launchd plist."
        fi
    fi
    
    # Remove binary
    if [ -f "${BIN_DIR}/${bin_name}" ]; then
        $SUDO rm -f "${BIN_DIR}/${bin_name}"
        echo -e "Removed binary."
    fi
    
    # Prompt to remove configs
    if [ -d "$CONFIG_DIR" ]; then
        read -rp "Do you want to delete all configuration files in $CONFIG_DIR? [y/N]: " del_configs
        if [ "$del_configs" = "y" ] || [ "$del_configs" = "Y" ]; then
            $SUDO rm -rf "$CONFIG_DIR"
            echo -e "Deleted configurations folder."
        fi
    fi
    
    echo -e "${GREEN}Uninstallation of Meridian $role completed successfully!${NC}"
}

# Restart an already-installed service without touching its config.
restart_service() {
    local role="$1"
    local bin_name="meridian-${role}"

    if [ "$OS" = "linux" ]; then
        $SUDO systemctl restart "$bin_name"
        sleep 2
        $SUDO systemctl is-active --quiet "$bin_name"
    elif [ "$OS" = "openwrt" ]; then
        local service_file="/etc/init.d/${bin_name}"
        [ -x "$service_file" ] || return 1
        $SUDO "$service_file" restart >/dev/null 2>&1 || return 1
        sleep 2
        pgrep -f "${BIN_DIR}/${bin_name}" >/dev/null 2>&1
    elif [ "$OS" = "darwin" ]; then
        local plist_file="$HOME/Library/LaunchAgents/com.meridian.${role}.plist"
        [ -f "$plist_file" ] || return 1
        launchctl unload "$plist_file" >/dev/null 2>&1 || true
        launchctl load "$plist_file" >/dev/null 2>&1 || return 1
        sleep 1
        launchctl list | grep -q "com.meridian.${role}"
    else
        return 1
    fi
}

# Update the core binary only. The existing YAML config, certificates and
# service definition are left exactly as they are; if the new binary fails to
# come up, the previous binary is restored automatically.
update_core() {
    local role="$1"
    local bin_name="meridian-${role}"
    local target_bin="${BIN_DIR}/${bin_name}"
    local config_file="${CONFIG_DIR}/${role}.yaml"
    local backup_bin="${target_bin}.bak"

    echo -e "${BLUE}Updating $bin_name (configuration will NOT be changed)...${NC}"

    if [ ! -f "$config_file" ]; then
        echo -e "${RED}[Error] $config_file not found. Use the install option first.${NC}"
        return 1
    fi
    if [ ! -f "$target_bin" ]; then
        echo -e "${RED}[Error] $target_bin not found. Use the install option first.${NC}"
        return 1
    fi

    $SUDO cp -p "$target_bin" "$backup_bin"
    echo -e "Previous binary saved to ${backup_bin}"

    # install_binary only writes ${BIN_DIR}/${bin_name}; it never touches
    # ${CONFIG_DIR}, so client.yaml and any certificates stay untouched.
    if ! install_binary "$role" release; then
        echo -e "${RED}[Error] Failed to install the new binary. Restoring previous version...${NC}"
        $SUDO mv -f "$backup_bin" "$target_bin"
        return 1
    fi

    echo -e "${BLUE}Restarting ${bin_name}...${NC}"
    if restart_service "$role"; then
        $SUDO rm -f "$backup_bin"
        echo -e "${GREEN}Update complete.${NC}"
        echo -e "  Binary: ${target_bin}"
        echo -e "  Config: ${config_file} ${GREEN}(unchanged)${NC}"
        if [ "$role" = "client" ]; then
            print_client_summary
        else
            echo -e "  Service: restarted successfully."
        fi
        return 0
    fi

    echo -e "${RED}[Error] The new binary did not start. Rolling back...${NC}"
    $SUDO mv -f "$backup_bin" "$target_bin"
    restart_service "$role" || true
    echo -e "${YELLOW}Rolled back to the previous ${bin_name} binary.${NC}"
    return 1
}

print_server_summary() {
    # Try to grab local public IP or local network IP
    local ip="YOUR_SERVER_IP"
    if command -v curl >/dev/null 2>&1; then
        ip=$(curl -s https://api.ipify.org || ip route get 1 | awk '{print $NF;exit}' 2>/dev/null || hostname)
    fi

    echo -e "\n${GREEN}====================================================${NC}"
    echo -e "${GREEN}      Meridian Server Deployed Successfully!       ${NC}"
    echo -e "${GREEN}====================================================${NC}"
    echo -e "Server configuration generated at: ${YELLOW}${CONFIG_DIR}/server.yaml${NC}"
    echo -e "\nUse the following details to configure your client:"
    echo -e "----------------------------------------------------"
    echo -e "Server Address:   ${CYAN}${ip}:443${NC}"
    echo -e "Password:         ${CYAN}${SERVER_PASS}${NC}"
    echo -e "Reality SPKI:     ${CYAN}${SERVER_SPKI}${NC}"
    echo -e "----------------------------------------------------"
    echo -e "You can copy-paste the above details when running the client deployment option."
    echo -e "====================================================\n"
}

print_client_summary() {
    echo -e "\n${GREEN}====================================================${NC}"
    echo -e "${GREEN}      Meridian Client Deployed Successfully!       ${NC}"
    echo -e "${GREEN}====================================================${NC}"
    echo -e "Client configuration generated at: ${YELLOW}${CONFIG_DIR}/client.yaml${NC}"
    echo -e "Your local socks5/http proxy is active."
    echo -e "To check client logs:"
    if [ "$OS" = "linux" ]; then
        echo -e "${CYAN}journalctl -u meridian-client -f${NC}"
    elif [ "$OS" = "openwrt" ]; then
        echo -e "${CYAN}logread -f | grep meridian-client${NC}"
    elif [ "$OS" = "darwin" ]; then
        echo -e "${CYAN}tail -f ${CONFIG_DIR}/client.log${NC}"
    fi
    echo -e "====================================================\n"
}

# Command line interface parsing
ACTION="${1:-}"

print_banner

case "$ACTION" in
    update)
        role="${2:-}"
        if [ -z "$role" ]; then
            echo -e "Select what to update (config files are preserved):"
            echo "1. Client core only"
            echo "2. Server core only"
            read -rp "Choice [1-2]: " upd_choice
            case "$upd_choice" in
                1) role="client" ;;
                2) role="server" ;;
                *) echo "Invalid choice"; exit 1 ;;
            esac
        fi
        case "$role" in
            client|server) update_core "$role" ;;
            *) echo -e "${RED}Usage: $0 update [client|server]${NC}"; exit 1 ;;
        esac
        ;;
    uninstall)
        echo -e "Select role to uninstall:"
        echo "1. Server"
        echo "2. Client"
        read -rp "Choice [1-2]: " choice
        case "$choice" in
            1) uninstall_service "server" ;;
            2) uninstall_service "client" ;;
            *) echo "Invalid choice"; exit 1 ;;
        esac
        ;;
    status)
        if [ "$OS" = "linux" ]; then
            echo -e "${BLUE}--- Server Status ---${NC}"
            systemctl status meridian-server --no-pager || echo "Server service not installed."
            echo -e "\n${BLUE}--- Client Status ---${NC}"
            systemctl status meridian-client --no-pager || echo "Client service not installed."
        elif [ "$OS" = "openwrt" ]; then
            echo -e "${BLUE}--- Server Status ---${NC}"
            if [ -f "/etc/init.d/meridian-server" ]; then
                /etc/init.d/meridian-server status || logread | grep meridian-server | tail -n 5
            else
                echo "Server service not installed."
            fi
            echo -e "\n${BLUE}--- Client Status ---${NC}"
            if [ -f "/etc/init.d/meridian-client" ]; then
                /etc/init.d/meridian-client status || logread | grep meridian-client | tail -n 5
            else
                echo "Client service not installed."
            fi
        elif [ "$OS" = "darwin" ]; then
            echo -e "${BLUE}--- Launchd Services ---${NC}"
            launchctl list | grep meridian || echo "No active meridian agents found."
        fi
        ;;
    version)
        echo -e "Configured release: $(release_version)"
        for role in client server; do
            bin="${BIN_DIR}/meridian-${role}"
            if [ -x "$bin" ]; then
                echo "Installed ${role}: $("$bin" -version 2>/dev/null || echo unknown)"
            else
                echo "Installed ${role}: not installed"
            fi
        done
        ;;
    optimize)
        role="${2:-}"
        if [ -z "$role" ]; then
            echo -e "Usage: $0 optimize [client|server]"
            exit 1
        fi
        case "$role" in
            client|server) optimize_config "$role" ;;
            *) echo -e "${RED}Usage: $0 optimize [client|server]${NC}"; exit 1 ;;
        esac
        ;;
    transport)
        role="${2:-}"
        if [ -z "$role" ]; then
            echo -e "Usage: $0 transport [client|server] [quic|websocket|hybrid|http-post]"
            exit 1
        fi
        case "$role" in
            client|server) switch_transport "$role" "${3:-}" ;;
            *) echo -e "${RED}Usage: $0 transport [client|server] [quic|websocket|hybrid|http-post]${NC}"; exit 1 ;;
        esac
        ;;
    *)
        # Interactive Menu
        echo "What would you like to deploy?"
        echo "1. Install Meridian Server"
        echo "2. Install Meridian Client"
        echo "3. Uninstall Meridian (Server/Client)"
        echo "4. Show Service Status"
        echo "5. Update Client Core (keep config)"
        echo "6. Update Server Core (keep config)"
        echo "7. Exit"
        echo "8. Enable high-throughput transport (keep credentials)"
        echo "9. Switch transport protocol (QUIC / WebSocket / Hybrid / HTTP-POST)"
        read -rp "Choice [1-9]: " choice
        
        case "$choice" in
            1)
                install_binary "server"
                configure_server
                start_service "server"
                print_server_summary
                ;;
            2)
                install_binary "client"
                configure_client
                start_service "client"
                print_client_summary
                ;;
            3)
                echo -e "Select role to uninstall:"
                echo "1. Server"
                echo "2. Client"
                read -rp "Choice [1-2]: " un_choice
                case "$un_choice" in
                    1) uninstall_service "server" ;;
                    2) uninstall_service "client" ;;
                    *) echo "Invalid choice"; exit 1 ;;
                esac
                ;;
            4)
                # Show status
                if [ "$OS" = "linux" ]; then
                    echo -e "${BLUE}--- Server Status ---${NC}"
                    systemctl status meridian-server --no-pager -n 5 || echo "Server service not running/installed."
                    echo -e "\n${BLUE}--- Client Status ---${NC}"
                    systemctl status meridian-client --no-pager -n 5 || echo "Client service not running/installed."
                elif [ "$OS" = "openwrt" ]; then
                    echo -e "${BLUE}--- Server Status ---${NC}"
                    if [ -f "/etc/init.d/meridian-server" ]; then
                        /etc/init.d/meridian-server status || logread | grep meridian-server | tail -n 5
                    else
                        echo "Server service not running/installed."
                    fi
                    echo -e "\n${BLUE}--- Client Status ---${NC}"
                    if [ -f "/etc/init.d/meridian-client" ]; then
                        /etc/init.d/meridian-client status || logread | grep meridian-client | tail -n 5
                    else
                        echo "Client service not running/installed."
                    fi
                elif [ "$OS" = "darwin" ]; then
                    echo -e "${BLUE}--- Active Launchd Services ---${NC}"
                    launchctl list | grep meridian || echo "No active meridian agents found."
                fi
                ;;
            5)
                update_core "client"
                ;;
            6)
                update_core "server"
                ;;
            7)
                echo "Goodbye."
                exit 0
                ;;
            8)
                echo -e "Select role to optimize:"
                echo "1. Server"
                echo "2. Client"
                read -rp "Choice [1-2]: " opt_choice
                case "$opt_choice" in
                    1) optimize_config "server" ;;
                    2) optimize_config "client" ;;
                    *) echo "Invalid choice"; exit 1 ;;
                esac
                ;;
            9)
                echo -e "Select role to reconfigure:"
                echo "1. Server"
                echo "2. Client"
                read -rp "Choice [1-2]: " tr_choice
                case "$tr_choice" in
                    1) switch_transport "server" "" ;;
                    2) switch_transport "client" "" ;;
                    *) echo "Invalid choice"; exit 1 ;;
                esac
                ;;
            *)
                echo -e "${RED}Invalid choice.${NC}"
                exit 1
                ;;
        esac
        ;;
esac
