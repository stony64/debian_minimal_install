#!/bin/bash

####################################################
# Debian Container Install Script by Stony64
# Initial Release: 09/2024
####################################################

# Exit on errors, unset variables, and pipeline failures
# ------------------------------------------------------------------
# This causes the script to terminate if any command in the pipeline
# fails. Additionally, it will log an error and exit with a status code
# of 1 if any command raises an error.
#
set -euo pipefail
trap 'log_error "Script terminated unexpectedly."; exit 1;' ERR

# Clear the screen to make the output more readable
clear

# Ensure script is run as root
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root."
    exit 1
fi

# Constants (readonly)
# ----------------------

# Name of the script
readonly SCRIPT_NAME="$(basename "$0")"
# Directory where the script is located
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Version of the script
readonly SCRIPT_VERSION="0.7.0"
# Log file for the script
readonly LOG_FILE="/var/log/${SCRIPT_NAME}.log"

# Container settings
# -------------------
#
# These variables are used to configure the container creation
#
readonly templateName="debian-12-standard_12.2-1_amd64.tar.zst" # Name of the template
readonly templatePath="/var/lib/vz/template/cache"              # Path to the template
readonly storage="VM_CON_1TB"                                   # Storage name
readonly baseCtIpv4="192.168.10."                               # Base IPv4 address
readonly baseCtIpv6="fd00:1234:abcd:10::"                       # Base IPv6 address
readonly ctGatewayIpv4="192.168.10.1"                           # Gateway IPv4 address
readonly ctGatewayIpv6="fd00:1234:abcd:10:3ea6:2fff:fe65:8fa7"  # Gateway IPv6 address

# Variables for container configuration
ctHostname=""                                # Container name (will be prompted)
ctId=$(pvesh get /cluster/nextid)            # Get next available container ID
rootPassword=""                              # Root password (will be prompted)
diskSize="8"                                 # Disk size in GB
ram="512"                                    # RAM size in MB
swap="512"                                   # Swap size in MB
cpuCores="1"                                 # Number of CPU cores
netBridge="vmbr0"                            # Network bridge
ipv4=""                                      # Full IPv4 address
ipv6=""                                      # Full IPv6 address

# Set colors for output
# ----------------------
#
# These are used for logging output
#
readonly RED='\e[0;31m'     # Red color
readonly GREEN='\e[0;32m'   # Green color
readonly YELLOW='\e[0;33m'  # Yellow color
readonly CYAN='\e[0;36m'    # Cyan color
readonly NC='\e[0m'         # No Color (reset)

# Command-line options for help and version
#
# Check if any command-line options were provided
#
if [[ -n "${1:-}" ]]; then
    case "$1" in
        -h)
            # Print help message
            echo "Usage: $SCRIPT_NAME [-h] [-v]"
            echo "  -h  Display this help message"
            echo "  -v  Display script version"
            exit 0
            ;;
        -v)
            # Print version number
            echo "$SCRIPT_NAME"
            echo "version $SCRIPT_VERSION"
            exit 0
            ;;
        *)
            # Print error for invalid option
            echo "Invalid option: $1" >&2
            echo "Usage: $SCRIPT_NAME [-h] [-v]" >&2
            exit 1
            ;;
    esac
fi

# Function to rotate log files if they exceed a certain size
#
# This function will rotate the log file if it exceeds the specified size
# by renaming the old log file to a numbered backup, and then creating a
# new empty log file.
#
# Parameters:
#   - max_size: maximum log file size in bytes (default: 100KB)
#   - backup_count: number of backup log files to keep (default: 3)
#
rotate_logs() {
    local log_file="$LOG_FILE"
    local max_size=102400  # Maximum log file size in bytes (e.g., 100KB)
    local backup_count=3   # Number of backup log files to keep

    # Check if the log file exists and is larger than the maximum size
    if [[ -f "$log_file" && $(stat -c%s "$log_file") -ge $max_size ]]; then
        log_info "Log file exceeds max size of $((max_size / 1024))KB. Rotating logs..."

        # Rotate logs by renaming old logs and removing the oldest backup if necessary
        for ((i=backup_count - 1; i>=1; i--)); do
            if [[ -f "$log_file.$i" ]]; then
                mv "$log_file.$i" "$log_file.$((i + 1))"
            fi
        done
        
        # Rename the current log to the first backup
        mv "$log_file" "$log_file.1"

        # Create a new empty log file
        : > "$log_file"
        log_info "Log rotation complete."
    fi
}

# Logs a message with a color and timestamp
#
# Parameters:
#   logLevel: a string with the log level (e.g., "INFO", "ERROR", etc.)
#   logColor: a string with the color code for the log level (e.g., "$CYAN", "$RED", etc.)
#   logMessage: the message to log
#
log_message() {
    local logLevel="$1"
    local logColor="$2"
    local logMessage="$3"
    local logTimestamp
    logTimestamp="$(date '+%Y-%m-%d %H:%M:%S')"

    printf '%b[%s] %s: %s%b\n' "$logColor" "$logTimestamp" "$logLevel" "$logMessage" "$NC" | tee -a "$LOG_FILE"
}

# Convenience functions for logging messages at different levels
log_info()      { log_message "INFO" "$CYAN" "$1"; }
log_error()     { log_message "ERROR" "$RED" "$1"; }
log_success()   { log_message "SUCCESS" "$GREEN" "$1"; }
log_warning()   { log_message "WARNING" "$YELLOW" "$1"; }

# Prompts the user for input with validation.
#
# Parameters:
#   promptMessage: a string with the message to display to the user
#   variableName: a string with the name of the global variable to set
#   validation: a string with a regular expression to validate the input
#
prompt_input() {
    local promptMessage="$1"
    local variableName="$2"
    local validation="$3"

    while true; do
        read -r -p "$promptMessage" input

        # Check if the input is empty
        if [[ -z "$input" ]]; then
            log_warning "Input cannot be empty. Please try again."

        # Check if the input matches the validation regex
        elif [[ -n "$validation" ]] && ! [[ "$input" =~ $validation ]]; then
            log_warning "Invalid input format. Please try again."

        # If the input is valid, set the global variable and break out of the loop
        else
            declare -g "$variableName"="$input"
            break
        fi
    done
}

# Confirms user inputs before proceeding with the script
#
# This function loops until the user confirms the inputs or decides to re-enter
# the inputs.
#
confirm_inputs() {
    local confirmation

    while true; do
        log_info "Summary of inputs:"
        log_info "CT-Hostname: $ctHostname"
        log_info "Root-Password: $rootPassword"

        prompt_input "Are these details correct? (y/n): " "confirmation" '^[yYnN]$'
        if [[ $confirmation =~ ^[yY]$ ]]; then
            # User confirmed the inputs; break out of the loop
            break
        elif [[ $confirmation =~ ^[nN]$ ]]; then
            # User wants to re-enter the inputs; call the input collection function
            collect_user_inputs
        else
            # User entered an invalid choice; display an error message
            log_warning "Invalid choice. Please enter 'y' or 'n'."
        fi
    done
}

# Collects user inputs for the container creation
#
# This function prompts the user for necessary inputs such as the hostname,
# root password, and last octet of the IP address. It also validates the
# inputs and sets the full IPv4 and IPv6 addresses using the last octet
# provided.
#
# The inputs are validated as follows:
# - Hostname: Alphanumeric characters and hyphens are allowed.
# - Root password: Minimum 8 characters are required.
# - Last octet of the IPv4 address: Must be between 1 and 254.
#
collect_user_inputs() {
    local lastOctet
    prompt_input "Enter the new hostname for the container (alphanumeric and hyphens allowed): " "ctHostname" '^[a-zA-Z0-9-]+$'
    prompt_input "Enter root-password for the container (min. 8 characters): " "rootPassword" '.{8,}'

    # Validate IPv4 last octet input (must be between 1 and 254)
    prompt_input "Enter the last octet of the IPv4 address (e.g., x for 192.168.10.x): " "lastOctet" '^[1-9][0-9]?$|^1[0-9]{2}$|^2[0-4][0-9]$|^25[0-4]$'

    confirm_inputs

    # Set full IPv4 and IPv6 addresses using the last octet provided
    ipv4="${baseCtIpv4}${lastOctet}"
    ipv6="${baseCtIpv6}${lastOctet}"

    log_info "IPv4 Address set to: $ipv4"
    log_info "IPv6 Address set to: $ipv6"
}

# Create the LXC container with the specified IPv4 and IPv6 addresses
#
create_lxc_container() {
    log_info "Creating container $ctId with IPv4: $ipv4 and IPv6: $ipv6"
    if pct create "$ctId" "$templatePath/$templateName" \
        --hostname "$ctHostname" \
        --password "$rootPassword" \
        --cores "$cpuCores" \
        --memory "$ram" \
        --swap "$swap" \
        --net0 name="eth0",bridge="$netBridge",ip="$ipv4/24",gw="$ctGatewayIpv4",ip6="$ipv6/64",gw6="$ctGatewayIpv6" \
        --rootfs "$storage:$diskSize" \
        --features "mount=nfs;cifs,nesting=1" \
        --onboot "1" \
        --start 1; then
        log_success "Container $ctId created successfully."
    else
        log_error "Failed to create container $ctId."
        exit 1
    fi
}

# Check the container status and proceed with further configuration if successful
# @param {string} ctId - The ID of the container to check
# @returns {boolean} true if the container is running, false otherwise
#
setTempSsh() {
    log_info "Waiting 10 seconds for the container to start..."
    sleep 10

    # Check if the container is running
    local containerStatus
    containerStatus=$(pct status "$ctId")

    # If the container is running, enable root login via SSH
    if [[ $containerStatus =~ 'running' ]]; then
        log_success "Container $ctId is running."
        log_info "Enabling root login via SSH..."

        # Modify SSH config to allow root login and restart SSH service
        if pct exec "$ctId" -- sed -i 's/^#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
           pct exec "$ctId" -- systemctl restart ssh; then
            log_success "Root login via SSH has been enabled."
        else
            log_error "Failed to enable root login via SSH."
            exit 1
        fi
    else
        log_error "Container $ctId was not started successfully."
        exit 1
    fi
}

# Downloads the installation script from the GitHub repository and sets it up in
# the container.
#
downloadCTInstallScript() {
    # Download the script from the GitHub repository
    log_info "Downloading and setting up installation script..."
    if pct exec "$ctId" -- mkdir -p /opt/scripts/install && \
       pct exec "$ctId" -- wget -O /opt/scripts/install/ct_debian_minimal_install.sh https://raw.githubusercontent.com/stony64/debian_minimal_install/main/ct_debian_minimal_install.sh; then
        # Make the script executable
        if pct exec "$ctId" -- chmod +x /opt/scripts/install/ct_debian_minimal_install.sh; then
            log_success "Installation script downloaded and made executable."
        else
            log_error "Failed to set permissions for the installation script."
            exit 1
        fi
    else
        log_error "Failed to download the installation script."
        exit 1
    fi
}

# Main script logic
# This function is the main entry point for the script. It calls other functions to
# perform the necessary steps to set up the LXC container.
# 1. Rotate log files to prevent them from growing too large.
# 2. Collect user inputs for the LXC container setup.
# 3. Create the LXC container with the specified parameters.
# 4. Set up temporary SSH access to the container.
# 5. Download the installation script from the GitHub repository and set it up in
#    the container.
#
main() {
    rotate_logs
    collect_user_inputs
    create_lxc_container
    setTempSsh
    downloadCTInstallScript
}

# Runs the main function of the script
#
# This will execute the main function and its called functions
# in the correct order.
#
main
