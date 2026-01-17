#!/bin/bash
#
# WireGuard Auto-Setup Script
# Automatically installs and configures WireGuard VPN with zero human intervention
# Sends client configuration to a Discord webhook
#
# Usage: sudo ./wireguard-autosetup.sh <DISCORD_WEBHOOK_URL> [CLIENT_NAME]
#

set -e

# ============ Configuration ============
DISCORD_WEBHOOK="${1:-}"
CLIENT_NAME="${2:-client1}"
WG_INTERFACE="wg0"
WG_PORT="51820"
WG_NETWORK="10.66.66.0/24"
WG_SERVER_IP="10.66.66.1"
WG_CLIENT_IP="10.66.66.2"
WG_DNS="1.1.1.1, 8.8.8.8"
WG_DIR="/etc/wireguard"
# =======================================

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

# Validate Discord webhook URL
check_webhook() {
    if [[ -z "$DISCORD_WEBHOOK" ]]; then
        log_error "Discord webhook URL is required"
        echo "Usage: $0 <DISCORD_WEBHOOK_URL> [CLIENT_NAME]"
        exit 1
    fi
    
    if [[ ! "$DISCORD_WEBHOOK" =~ ^https://discord(app)?\.com/api/webhooks/ ]]; then
        log_error "Invalid Discord webhook URL format"
        exit 1
    fi
}

# Detect package manager and install WireGuard
install_wireguard() {
    log_info "Detecting package manager and installing WireGuard..."
    
    if command -v apt-get &> /dev/null; then
        # Debian/Ubuntu
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq wireguard wireguard-tools qrencode curl iptables
    elif command -v dnf &> /dev/null; then
        # Fedora/RHEL 8+
        dnf install -y -q wireguard-tools qrencode curl iptables
    elif command -v yum &> /dev/null; then
        # CentOS/RHEL 7
        yum install -y -q epel-release elrepo-release
        yum install -y -q kmod-wireguard wireguard-tools qrencode curl iptables
    elif command -v pacman &> /dev/null; then
        # Arch Linux
        pacman -Sy --noconfirm wireguard-tools qrencode curl iptables
    elif command -v apk &> /dev/null; then
        # Alpine Linux
        apk add --no-cache wireguard-tools qrencode curl iptables
    else
        log_error "Unsupported distribution. Please install WireGuard manually."
        exit 1
    fi
    
    log_info "WireGuard installed successfully"
}

# Detect public IP address
get_public_ip() {
    local ip=""
    
    # Try multiple services
    for service in "ifconfig.me" "ipinfo.io/ip" "icanhazip.com" "ipecho.net/plain"; do
        ip=$(curl -s --max-time 5 "$service" 2>/dev/null | tr -d '[:space:]')
        if [[ -n "$ip" && "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "$ip"
            return 0
        fi
    done
    
    # Fallback: try to get from default route interface
    ip=$(ip -4 addr show scope global | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
    if [[ -n "$ip" ]]; then
        echo "$ip"
        return 0
    fi
    
    log_error "Could not detect public IP address"
    exit 1
}

# Detect main network interface
get_main_interface() {
    local iface=""
    
    # Get interface of default route
    iface=$(ip route show default | awk '/default/ {print $5}' | head -1)
    
    if [[ -z "$iface" ]]; then
        # Fallback: get first non-loopback interface
        iface=$(ip -o link show | awk -F': ' '{print $2}' | grep -v lo | head -1)
    fi
    
    if [[ -z "$iface" ]]; then
        log_error "Could not detect main network interface"
        exit 1
    fi
    
    echo "$iface"
}

# Generate WireGuard keys
generate_keys() {
    log_info "Generating WireGuard keys..."
    
    mkdir -p "$WG_DIR"
    chmod 700 "$WG_DIR"
    
    # Generate server keys
    wg genkey | tee "$WG_DIR/server_private.key" | wg pubkey > "$WG_DIR/server_public.key"
    chmod 600 "$WG_DIR/server_private.key"
    
    # Generate client keys
    wg genkey | tee "$WG_DIR/${CLIENT_NAME}_private.key" | wg pubkey > "$WG_DIR/${CLIENT_NAME}_public.key"
    chmod 600 "$WG_DIR/${CLIENT_NAME}_private.key"
    
    # Generate preshared key for additional security
    wg genpsk > "$WG_DIR/${CLIENT_NAME}_preshared.key"
    chmod 600 "$WG_DIR/${CLIENT_NAME}_preshared.key"
    
    log_info "Keys generated successfully"
}

# Enable IP forwarding
enable_forwarding() {
    log_info "Enabling IP forwarding..."
    
    # Enable immediately
    sysctl -w net.ipv4.ip_forward=1 > /dev/null
    sysctl -w net.ipv6.conf.all.forwarding=1 > /dev/null 2>&1 || true
    
    # Make persistent
    if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf 2>/dev/null; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    fi
    
    log_info "IP forwarding enabled"
}

# Create server configuration
create_server_config() {
    log_info "Creating server configuration..."
    
    local server_private=$(cat "$WG_DIR/server_private.key")
    local client_public=$(cat "$WG_DIR/${CLIENT_NAME}_public.key")
    local preshared=$(cat "$WG_DIR/${CLIENT_NAME}_preshared.key")
    local main_iface=$(get_main_interface)
    
    cat > "$WG_DIR/${WG_INTERFACE}.conf" << EOF
# WireGuard Server Configuration
# Generated on $(date)

[Interface]
Address = ${WG_SERVER_IP}/24
ListenPort = ${WG_PORT}
PrivateKey = ${server_private}

# NAT and firewall rules
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o ${main_iface} -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o ${main_iface} -j MASQUERADE

# Client: ${CLIENT_NAME}
[Peer]
PublicKey = ${client_public}
PresharedKey = ${preshared}
AllowedIPs = ${WG_CLIENT_IP}/32
EOF

    chmod 600 "$WG_DIR/${WG_INTERFACE}.conf"
    log_info "Server configuration created"
}

# Create client configuration
create_client_config() {
    log_info "Creating client configuration..."
    
    local server_public=$(cat "$WG_DIR/server_public.key")
    local client_private=$(cat "$WG_DIR/${CLIENT_NAME}_private.key")
    local preshared=$(cat "$WG_DIR/${CLIENT_NAME}_preshared.key")
    local public_ip=$(get_public_ip)
    
    cat > "$WG_DIR/${CLIENT_NAME}.conf" << EOF
# WireGuard Client Configuration
# Generated on $(date)
# Server: ${public_ip}

[Interface]
Address = ${WG_CLIENT_IP}/24
PrivateKey = ${client_private}
DNS = ${WG_DNS}

[Peer]
PublicKey = ${server_public}
PresharedKey = ${preshared}
Endpoint = ${public_ip}:${WG_PORT}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF

    chmod 600 "$WG_DIR/${CLIENT_NAME}.conf"
    log_info "Client configuration created at $WG_DIR/${CLIENT_NAME}.conf"
}

# Start WireGuard service
start_wireguard() {
    log_info "Starting WireGuard..."
    
    # Enable and start the service
    systemctl enable wg-quick@${WG_INTERFACE} 2>/dev/null || true
    systemctl start wg-quick@${WG_INTERFACE} 2>/dev/null || wg-quick up ${WG_INTERFACE}
    
    # Verify it's running
    if wg show ${WG_INTERFACE} &> /dev/null; then
        log_info "WireGuard is running"
    else
        log_error "Failed to start WireGuard"
        exit 1
    fi
}

# Configure firewall
configure_firewall() {
    log_info "Configuring firewall..."
    
    # Allow WireGuard port via iptables
    iptables -A INPUT -p udp --dport ${WG_PORT} -j ACCEPT 2>/dev/null || true
    iptables -A INPUT -p tcp --dport ${WG_PORT} -j ACCEPT 2>/dev/null || true
    
    # Save iptables rules if possible
    if command -v iptables-save &> /dev/null; then
        if [[ -d /etc/iptables ]]; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        elif [[ -f /etc/sysconfig/iptables ]]; then
            iptables-save > /etc/sysconfig/iptables 2>/dev/null || true
        fi
    fi
    
    # Also configure UFW if available
    if command -v ufw &> /dev/null; then
        ufw allow ${WG_PORT}/udp > /dev/null 2>&1 || true
        ufw allow ${WG_PORT}/tcp > /dev/null 2>&1 || true
    fi
    
    # Also configure firewalld if available
    if command -v firewall-cmd &> /dev/null; then
        firewall-cmd --permanent --add-port=${WG_PORT}/udp > /dev/null 2>&1 || true
        firewall-cmd --permanent --add-port=${WG_PORT}/tcp > /dev/null 2>&1 || true
        firewall-cmd --reload > /dev/null 2>&1 || true
    fi
    
    log_info "Firewall configured"
}

# Send configuration to Discord
send_to_discord() {
    log_info "Sending configuration to Discord..."
    
    local public_ip=$(get_public_ip)
    local config_content=$(cat "$WG_DIR/${CLIENT_NAME}.conf")
    
    # Create a summary message
    local summary="**🔐 WireGuard VPN Configuration**

**Server:** \`${public_ip}\`
**Port:** \`${WG_PORT}/UDP\`
**Client Name:** \`${CLIENT_NAME}\`
**Client IP:** \`${WG_CLIENT_IP}\`
**Generated:** $(date -u '+%Y-%m-%d %H:%M:%S UTC')

⚠️ **Security Notice:** This config contains private keys. Delete this message after saving the configuration."

    # Send summary message
    curl -s -X POST "$DISCORD_WEBHOOK" \
        -H "Content-Type: application/json" \
        -d "{\"content\": \"${summary}\"}" > /dev/null

    # Send config file
    curl -s -X POST "$DISCORD_WEBHOOK" \
        -F "file=@$WG_DIR/${CLIENT_NAME}.conf;filename=${CLIENT_NAME}.conf" \
        -F "payload_json={\"content\": \"📄 **Client Configuration File** - Import this into your WireGuard client:\"}" > /dev/null

    # Generate and send QR code if qrencode is available
    if command -v qrencode &> /dev/null; then
        local qr_file="/tmp/${CLIENT_NAME}_qr.png"
        qrencode -t PNG -o "$qr_file" < "$WG_DIR/${CLIENT_NAME}.conf"
        
        curl -s -X POST "$DISCORD_WEBHOOK" \
            -F "file=@${qr_file};filename=${CLIENT_NAME}_qr.png" \
            -F "payload_json={\"content\": \"📱 **QR Code** - Scan with WireGuard mobile app:\"}" > /dev/null
        
        rm -f "$qr_file"
    fi
    
    log_info "Configuration sent to Discord"
}

# Display summary
display_summary() {
    local public_ip=$(get_public_ip)
    
    echo ""
    echo "=============================================="
    echo -e "${GREEN}WireGuard Setup Complete!${NC}"
    echo "=============================================="
    echo "Server Public IP: $public_ip"
    echo "WireGuard Port:   $WG_PORT/UDP"
    echo "Server VPN IP:    $WG_SERVER_IP"
    echo "Client VPN IP:    $WG_CLIENT_IP"
    echo "Client Name:      $CLIENT_NAME"
    echo ""
    echo "Config Files:"
    echo "  Server: $WG_DIR/${WG_INTERFACE}.conf"
    echo "  Client: $WG_DIR/${CLIENT_NAME}.conf"
    echo ""
    echo "Service Status:"
    wg show ${WG_INTERFACE} 2>/dev/null || echo "  Run 'wg show' to check status"
    echo "=============================================="
}

# ============ Main ============
main() {
    echo ""
    echo "========================================"
    echo "   WireGuard Auto-Setup Script"
    echo "========================================"
    echo ""
    
    check_root
    check_webhook
    
    log_info "Starting WireGuard setup..."
    log_info "Client name: $CLIENT_NAME"
    
    install_wireguard
    generate_keys
    enable_forwarding
    create_server_config
    create_client_config
    configure_firewall
    start_wireguard
    send_to_discord
    display_summary
    
    log_info "Setup complete! Check Discord for your client configuration."
}

main "$@"
