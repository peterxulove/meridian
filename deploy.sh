#!/bin/bash
# ==============================================================================
# Meridian One-Click Deployment Script (Linux & macOS)
# ==============================================================================
#
# Supports:
#   - OS: Linux (systemd) and macOS (launchd)
#   - Architectures: amd64 and arm64
#   - Roles: Server (with auto SSL & SPKI derivation) and Client (interactive config)
#   - Actions: Install, Uninstall, Status
#

set -e

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
elif [ "$OS" = "darwin" ]; then
    CONFIG_DIR="$HOME/.meridian"
    BIN_DIR="/usr/local/bin"
    SUDO=""
else
    echo -e "${RED}[Error] Unsupported OS: $OS. This script supports Linux and macOS only.${NC}"
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
        openssl x509 -in "$cert_path" -pubkey -noout | openssl pkey -pubout -outform DER 2>/dev/null | sha256sum | cut -c1-64
    elif command -v shasum >/dev/null 2>&1; then
        openssl x509 -in "$cert_path" -pubkey -noout | openssl pkey -pubout -outform DER 2>/dev/null | shasum -a 256 | cut -c1-64
    else
        openssl x509 -in "$cert_path" -pubkey -noout | openssl pkey -pubout -outform DER 2>/dev/null | openssl dgst -sha256 | awk '{print $2}' | cut -c1-64
    fi
}

# Build or copy executable
install_binary() {
    local role="$1" # "server" or "client"
    local bin_name="meridian-${role}"
    local target_bin="${BIN_DIR}/${bin_name}"
    
    echo -e "${BLUE}[1/4] Installing $bin_name binary...${NC}"
    
    $SUDO mkdir -p "$BIN_DIR"
    
    # Check if we are running in the source repo and can build
    if command -v go >/dev/null 2>&1 && [ -f "go.mod" ]; then
        echo -e "Go compiler found. Building from source..."
        go build -ldflags "-s -w" -o "$bin_name" "./cmd/meridian-${role}"
        $SUDO cp "$bin_name" "$target_bin"
        $SUDO chmod +x "$target_bin"
        rm -f "$bin_name"
    # Check if prebuilt exists in current directory as meridian-${role}-${OS}-${ARCH}
    elif [ -f "meridian-${role}-${OS}-${ARCH}" ]; then
        echo -e "Using prebuilt binary from current directory..."
        $SUDO cp "meridian-${role}-${OS}-${ARCH}" "$target_bin"
        $SUDO chmod +x "$target_bin"
    # Check if prebuilt exists in dist/
    elif [ -f "dist/meridian-${role}-${OS}-${ARCH}" ]; then
        echo -e "Using prebuilt binary from dist/ directory..."
        $SUDO cp "dist/meridian-${role}-${OS}-${ARCH}" "$target_bin"
        $SUDO chmod +x "$target_bin"
    # Check if local built exists in root
    elif [ -f "meridian-${role}" ]; then
        echo -e "Using local binary in root..."
        $SUDO cp "meridian-${role}" "$target_bin"
        $SUDO chmod +x "$target_bin"
    else
        # Try to download from GitHub releases
        local version="v1.5.0"
        local asset_name="meridian-${role}-${OS}-${ARCH}"
        if [ "$OS" = "windows" ]; then
            asset_name+=".exe"
        fi
        local download_url="https://github.com/peterxulove/meridian/releases/download/${version}/${asset_name}"
        
        echo -e "No local binary or Go compiler found. Attempting to download ${version} from GitHub..."
        echo -e "Download URL: ${download_url}"
        
        if command -v curl >/dev/null 2>&1; then
            $SUDO curl -L -o "$target_bin" "$download_url"
        elif command -v wget >/dev/null 2>&1; then
            $SUDO wget -O "$target_bin" "$download_url"
        else
            echo -e "${RED}[Error] Neither curl nor wget found. Cannot download binary.${NC}"
            echo -e "Please install Go, curl, wget, or compile/place binaries manually."
            exit 1
        fi
        
        $SUDO chmod +x "$target_bin"
    fi
    
    echo -e "${GREEN}Binary installed to $target_bin${NC}"
}

# Config Server
configure_server() {
    echo -e "${BLUE}[2/4] Generating Server Configuration & Certificates...${NC}"
    $SUDO mkdir -p "$CONFIG_DIR"
    
    local cert_path="${CONFIG_DIR}/cert.pem"
    local key_path="${CONFIG_DIR}/key.pem"
    
    # Generate self-signed certificate if not exists
    if [ ! -f "$cert_path" ] || [ ! -f "$key_path" ]; then
        echo -e "Generating self-signed SSL Certificate for REALITY mode..."
        $SUDO openssl req -x509 -newkey rsa:2048 -nodes \
            -keyout "$key_path" \
            -out "$cert_path" \
            -subj "/CN=www.google.com" \
            -days 3650 >/dev/null 2>&1
        $SUDO chmod 600 "$key_path"
        $SUDO chmod 644 "$cert_path"
    fi
    
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
transport: "QUIC"
cipher_suite: 1
password: "${password}"

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
timing_jitter_ms: 30.0

# ─── Connection Limits ───
max_clients: 1000
stream_window: 1048576
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
    
    read -rp "3. Reality SPKI Hash (64 hex characters): " client_spki
    if [ -z "$client_spki" ]; then
        echo -e "${RED}[Error] SPKI hash cannot be empty.${NC}"
        exit 1
    fi
    
    read -rp "4. Local Proxy Protocol (socks5 / http) [default: socks5]: " client_proto
    client_proto="${client_proto:-socks5}"
    
    read -rp "5. Local Listen Port [default: 1080]: " client_port
    client_port="${client_port:-1080}"
    
    local client_yaml="${CONFIG_DIR}/client.yaml"
    cat <<EOF | $SUDO tee "$client_yaml" >/dev/null
# Meridian Client - Auto-generated configuration
server_addr: "${client_server_addr}"
transport: "QUIC"
cipher_suite: 1
password: "${client_password}"

# ─── REALITY Mode (anti-detection) ───
sni_spoof: "www.google.com"
reality_mode: true
reality_spki: "${client_spki}"
reality_short_id: 12345
reality_max_time: 0

# ─── Anti-Detection ───
fingerprint: "chrome_win"
padding_mode: "random"
base_payload_size: 1400
max_payload_size: 1452
direction_balance: false
timing_jitter_ms: 30.0

# ─── Connection ───
keepalive_interval: "30s"
handshake_timeout: "10s"
stream_window: 1048576
max_concurrent_streams: 100
session_lifetime: "1h"
dial_timeout: "15s"

# ─── Local Proxy ───
listen_addr: "0.0.0.0:${client_port}"
proxy_protocol: "${client_proto}"
EOF
    
    $SUDO chmod 600 "$client_yaml"
    echo -e "${GREEN}Configuration generated: $client_yaml${NC}"
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
    elif [ "$OS" = "darwin" ]; then
        echo -e "${CYAN}tail -f ${CONFIG_DIR}/client.log${NC}"
    fi
    echo -e "====================================================\n"
}

# Command line interface parsing
ACTION="${1:-}"

print_banner

case "$ACTION" in
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
        elif [ "$OS" = "darwin" ]; then
            echo -e "${BLUE}--- Launchd Services ---${NC}"
            launchctl list | grep meridian || echo "No active meridian agents found."
        fi
        ;;
    *)
        # Interactive Menu
        echo "What would you like to deploy?"
        echo "1. Install Meridian Server"
        echo "2. Install Meridian Client"
        echo "3. Uninstall Meridian (Server/Client)"
        echo "4. Show Service Status"
        echo "5. Exit"
        read -rp "Choice [1-5]: " choice
        
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
                elif [ "$OS" = "darwin" ]; then
                    echo -e "${BLUE}--- Active Launchd Services ---${NC}"
                    launchctl list | grep meridian || echo "No active meridian agents found."
                fi
                ;;
            5)
                echo "Goodbye."
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid choice.${NC}"
                exit 1
                ;;
        esac
        ;;
esac
