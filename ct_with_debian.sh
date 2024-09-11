#!/bin/bash

####################################################
# Debian Container Install Script by Stony64
# Version: 0.4.0
# Initial Release: 09/2024
####################################################

# Exit on errors, unset variables, and pipeline failures
set -euo pipefail

# Clear the screen
clear

# Check if the script is run with root privileges
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root."
    exit 1
fi

# Variables
CT_HOSTNAME=""          # Container name
CT_ID=$(pvesh get /cluster/nextid)  # Get the next available container ID
ROOT_PASSWORD=""        # Root password
TEMPLATE="debian-12-standard_12.2-1_amd64.tar.zst"
TEMPLATE_FULL_NAME="/var/lib/vz/template/cache/$TEMPLATE"  # Path to the template
STORAGE="VM_CON_1TB"    # Storage for the container
DISK_SIZE="8"           # Disk size in GB
RAM="512"               # RAM size in MB
SWAP="512"              # Swap size in MB
CPU_CORES="1"           # Number of CPU cores
NET="vmbr0"             # Network bridge

# Network settings
BASE_CT_IPV4="192.168.10."
BASE_CT_IPV6="fd00:1234:abcd:10::"
CT_GATEWAY_IPV4="192.168.10.1"
CT_GATEWAY_IPV6="fd00:1234:abcd:10::1"

# Check if the template is already downloaded
if ! pveam list local | grep -q "$TEMPLATE"; then
    echo "Template not found locally. Downloading..."
    pveam download local "$TEMPLATE" || { echo "Failed to download template"; exit 1; }
fi

# Function to prompt user for input
prompt_input() {
    local prompt_message=$1
    local variable_name=$2
    read -rp "$prompt_message" $variable_name
}

# Collect user input for the last octet of IPv4 and the corresponding IPv6 address
collect_user_inputs() {
    prompt_input "Enter the new hostname for the container: " CT_HOSTNAME

    prompt_input "Enter root-password for the container: " ROOT_PASSWORD

    prompt_input "Enter the last octet of the IPv4 address (e.g., x for 192.168.10.x): " last_octet

    # Validate last octet
    while ! [[ "$last_octet" =~ ^[0-9]+$ ]] || ((last_octet < 1 || last_octet > 254)); do
        echo "Invalid last octet. Please enter a number between 1 and 254."
        prompt_input "Enter the last octet of the IPv4 address (e.g., x for 192.168.10.x): " last_octet
    done

    # Check if last_octet is non-empty
    if [[ -z "$last_octet" ]]; then
        echo "Error: Last octet is null or empty."
        exit 1
    fi

    # Construct IPv4 and IPv6 addresses
    ipv4="${BASE_CT_IPV4}${last_octet}"
    ipv6="${BASE_CT_IPV6}${last_octet}"

    echo "IPv4 address set to: $ipv4"
    echo "IPv6 address set to: $ipv6"
}

# Run the function to collect user inputs
collect_user_inputs

# Verify hostname and addresses
if [[ -z "$CT_HOSTNAME" ]]; then
    echo "Error: Hostname is null or empty. Aborting."
    exit 1
fi

if [[ -z "$ipv4" || -z "$ipv6" ]]; then
    echo "Error: IPv4 or IPv6 address is null or empty. Aborting."
    exit 1
fi

# Create the LXC container with IPv4 and IPv6 addresses
echo "Creating container $CT_ID with IPv4: $ipv4 and IPv6: $ipv6"
pct create "$CT_ID" "$TEMPLATE_FULL_NAME" \
    --hostname "$CT_HOSTNAME" \
    --password "$ROOT_PASSWORD" \
    --cores "$CPU_CORES" \
    --memory "$RAM" \
    --swap "$SWAP" \
    --net0 name=eth0,bridge="$NET",ip="$ipv4/24",gw="$CT_GATEWAY_IPV4",ip6="$ipv6/64",gw6="$CT_GATEWAY_IPV6" \
    --rootfs "$STORAGE:$DISK_SIZE" \
    --features "mount=nfs;cifs,nesting=1" \
    --onboot "1" \
    --start 1

# Check if the container was created successfully
if pct status "$CT_ID" | grep -q 'running'; then
    echo "Container $CT_ID created and started successfully."
else
    echo "Error: Container $CT_ID was not started successfully."
    exit 1
fi
