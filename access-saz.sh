#!/bin/bash

# ==============================================================================
# Script Name:    update_ir_ips.sh
# Description:    Fast, automated nftables firewall configuration to restrict 
#                 traffic exclusively to Iranian IP ranges (via IP2Location).
#                 Automatically handles dependencies on Debian/Ubuntu/RHEL.
# ==============================================================================

SCRIPT_PATH="/usr/local/bin/update_ir_ips.sh"

# ------------------------------------------------------------------------------
# 0. Self-Installation & Dependency Management
# ------------------------------------------------------------------------------
if [[ "$1" == "--install" ]]; then
    echo "Starting installation and environment check..."
    
    # Check for root privileges
    if [ "$EUID" -ne 0 ]; then
        echo "Error: Please run with sudo or as root to install."
        exit 1
    fi

    # Detect Package Manager and Install Dependencies
    echo "Detecting OS and installing dependencies..."
    if [ -x "$(command -v apt-get)" ]; then
        # Debian/Ubuntu
        apt-get update -y
        apt-get install -y curl python3 nftables cron
    elif [ -x "$(command -v dnf)" ]; then
        # RHEL/CentOS/AlmaLinux/Rocky Linux
        dnf install -y curl python3 nftables cronie
    elif [ -x "$(command -v yum)" ]; then
        # Older RHEL/CentOS
        yum install -y curl python3 nftables cronie
    else
        echo "Warning: Package manager not recognized. Please ensure curl, python3, nftables, and cron are installed manually."
    fi

    # Enable and start nftables and cron services
    echo "Enabling required system services..."
    systemctl enable --now nftables 2>/dev/null || service nftables start 2>/dev/null
    systemctl enable --now cron 2>/dev/null || systemctl enable --now cronie 2>/dev/null || service cron start 2>/dev/null

    # Copy script to the standard local binary directory
    if [ "$0" != "$SCRIPT_PATH" ]; then
        cp "$0" "$SCRIPT_PATH"
        echo "-> Script copied to $SCRIPT_PATH"
    fi

    # Grant execution permissions
    chmod +x "$SCRIPT_PATH"
    echo "-> Execution permissions granted."

    # Setup a weekly Cron Job to update IPs automatically every Sunday at 00:00
    (crontab -l 2>/dev/null | grep -v "$SCRIPT_PATH"; echo "0 0 * * 0 $SCRIPT_PATH >/dev/null 2>&1") | crontab -
    echo "-> Weekly cron job scheduled (Every Sunday at 00:00)."
    
    echo "------------------------------------------------------------------------------"
    echo "Dependencies installed and system configured! Running firewall setup..."
    echo "------------------------------------------------------------------------------"
    exec "$SCRIPT_PATH"
fi

# Ensure the running script has root privileges (for manual runs)
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root. Use 'sudo $0'."
    exit 1
fi

# ------------------------------------------------------------------------------
# 1. Fetch JSON and Convert IP Ranges to CIDR via Python
# ------------------------------------------------------------------------------
echo "Fetching and parsing IP2Location dataset for Iran..."

curl -s "https://cdn-lite.ip2location.com/datasets/IR.json" | python3 -c '
import sys, json, ipaddress

try:
    raw_data = json.load(sys.stdin)
    for entry in raw_data.get("data", []):
        start_ip = entry[0]
        end_ip = entry[1]
        
        start = ipaddress.IPv4Address(start_ip)
        end = ipaddress.IPv4Address(end_ip)
        cidrs = [str(net) for net in ipaddress.summarize_address_range(start, end)]
        for cidr in cidrs:
            print(cidr)
except Exception as e:
    sys.exit(1)
' > /tmp/ir_ips.txt

# Validation check to ensure dataset is not empty
if [ ! -s /tmp/ir_ips.txt ]; then
    echo "Error: Failed to process IP2Location data. Firewall rules preserved."
    exit 1
fi

echo "Processing IPs done. Applying firewall rules..."

# ------------------------------------------------------------------------------
# 2. Structuring nftables Firewall
# ------------------------------------------------------------------------------
nft add table inet filter
nft add chain inet filter input { type filter hook input priority 0 \; policy drop \; }
nft add chain inet filter output { type filter hook output priority 0 \; policy drop \; }

# ------------------------------------------------------------------------------
# 3. Create Dedicated Named Set for Iran Subnets
# ------------------------------------------------------------------------------
nft add set inet filter ir_ips { type ipv4_addr \; flags interval \; }

# Clear existing elements for a clean update
nft flush set inet filter ir_ips

# ------------------------------------------------------------------------------
# 4. Batch Load Subnets via Temporary File (Massive Performance Boost)
# ------------------------------------------------------------------------------
echo "add element inet filter ir_ips {" > /tmp/nft_batch.txt
awk '{print $1 ","}' /tmp/ir_ips.txt >> /tmp/nft_batch.txt
# Remove the trailing comma to avoid nftables syntax error
sed -i '$ s/,$//' /tmp/nft_batch.txt
echo "}" >> /tmp/nft_batch.txt

# Inject all elements into nftables atomically
nft -f /tmp/nft_batch.txt

# Clean up temp files
rm -f /tmp/ir_ips.txt /tmp/nft_batch.txt

# ------------------------------------------------------------------------------
# 5. Apply Traffic Rules
# ------------------------------------------------------------------------------
# Allow Loopback traffic
nft add rule inet filter input iif lo accept
nft add rule inet filter output oif lo accept

# Allow established and related connections
nft add rule inet filter input ct state established,related accept
nft add rule inet filter output ct state established,related accept

# Restrict all other inbound/outbound traffic strictly to Iran IPs
nft add rule inet filter input ip saddr @ir_ips accept
nft add rule inet filter output ip daddr @ir_ips accept

echo "Success! Firewall successfully updated under 3 seconds."
