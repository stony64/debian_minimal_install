#!/bin/bash

####################################################
# Debian Container Install Script by Stony64
# Version: 0.5.0
# Initial Release: 09/2024
####################################################

# Exit on errors, unset variables, and pipeline failures
set -euo pipefail

# Clear the screen for clarity
clear

# Ensure script is run as root
if [[ "$(id -u)" -ne 0 ]]; then
    echo "Error: This script must be run as root."
    exit 1
fi

# Variables
CT_HOSTNAME=""                              # Container name (will be prompted)
CT_ID=$(pvesh get /cluster/nextid)          # Get next available container ID
ROOT_PASSWORD=""                            # Root password (will be prompted)
TEMPLATE_NAME="debian-12-standard_12.2-1_amd64.tar.zst"
TEMPLATE_PATH="/var/lib/vz/template/cache"  # Path to the Proxmox container template
STORAGE="VM_CON_1TB"                        # Storage allocation for the container
DISK_SIZE="8"                               # Disk size in GB
RAM="512"                                   # RAM size in MB
SWAP="512"                                  # Swap size in MB
CPU_CORES="1"                               # Number of CPU cores
NET="vmbr0"                                 # Network bridge

# Network settings
BASE_CT_IPV4="192.168.10."                   # Base IPv4 subnet for containers
BASE_CT_IPV6="fd00:1234:abcd:10::"           # Base IPv6 subnet for containers
CT_GATEWAY_IPV4="192.168.10.1"               # IPv4 Gateway for the containers
CT_GATEWAY_IPV6="fd00:1234:abcd:10:3ea6:2fff:fe65:8fa7" # IPv6 Gateway

# Check if the template is already downloaded, if not download it
if ! pveam list local | grep -q "$TEMPLATE_NAME"; then
    echo "Template not found locally. Downloading..."
    pveam download local "$TEMPLATE_NAME" || { echo "Failed to download template"; exit 1; }
fi

# Function to prompt user for input with validation
prompt_input() {
    local prompt_message="$1"
    local variable_name="$2"

    # Continuously prompt user until a valid input is given
    while true; do
        read -r -p "$prompt_message" input
        if [[ -n "$input" ]]; then
            declare -g "$variable_name"="$input"  # Dynamically set the global variable
            break
        else
            echo "Warning: Input cannot be empty. Please try again."
        fi
    done
}

# Collect necessary user inputs such as IP addresses and hostname
collect_user_inputs() {
    local last_octet
    # Validate IPv4 last octet input (must be between 1 and 254)
    while ! [[ $last_octet =~ ^[0-9]+$ ]] || ((last_octet < 1 || last_octet > 254)); do
        read -r -p "Enter the last octet of the IPv4 address (e.g., x for 192.168.10.x): " last_octet
    done

    # Collect hostname and root password inputs
    prompt_input "Enter the new hostname for the container: " "CT_HOSTNAME"
    prompt_input "Enter root-password for the container: " "ROOT_PASSWORD"

    # Set full IPv4 and IPv6 addresses using the last octet provided
    IPV4="${BASE_CT_IPV4}${last_octet}"
    IPV6="${BASE_CT_IPV6}${last_octet}"
}

# Start collecting user inputs
collect_user_inputs

# Create the LXC container with the specified IPv4 and IPv6 addresses
echo "Creating container $CT_ID with IPv4: $IPV4 and IPv6: $IPV6"
pct create "$CT_ID" "$TEMPLATE_PATH/$TEMPLATE_NAME" \
    --hostname "$CT_HOSTNAME" \
    --password "$ROOT_PASSWORD" \
    --cores "$CPU_CORES" \
    --memory "$RAM" \
    --swap "$SWAP" \
    --net0 name="eth0",bridge="$NET",ip="$IPV4/24",gw="$CT_GATEWAY_IPV4",ip6="$IPV6/64",gw6="$CT_GATEWAY_IPV6" \
    --rootfs "$STORAGE:$DISK_SIZE" \
    --features "mount=nfs;cifs,nesting=1" \
    --onboot "1" \
    --start 1

# Wait for 5 seconds to ensure the container starts
echo "Waiting 5 seconds for the container to start..."
sleep 5

# Check the container status and proceed with further configuration if successful
if pct status "$CT_ID" | grep -q 'running'; then
    echo "Container $CT_ID created and started successfully."
    echo "Enabling root login via SSH..."

    # Modify SSH config to allow root login and restart SSH service
    pct exec "$CT_ID" -- sed -i 's/^#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
    pct exec "$CT_ID" -- systemctl restart ssh

    echo "Root login via SSH has been enabled."

    # Download the install script into the container and make it executable
    echo "Downloading and setting up installation script..."
    pct exec "$CT_ID" -- mkdir -p /opt/scripts/install
    pct exec "$CT_ID" -- wget -O /opt/scripts/install/ct_debian_minimal_install.sh https://raw.githubusercontent.com/stony64/debian_minimal_install/main/ct_debian_minimal_install.sh
    pct exec "$CT_ID" -- chmod +x /opt/scripts/install/ct_debian_minimal_install.sh

    echo "Installation script downloaded and made executable."
else
    echo "Error: Container $CT_ID was not started successfully."
    exit 1
fi
