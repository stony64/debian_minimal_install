#!/bin/bash

####################################################
#
# Raspberry-Pihole Install Script by Stony64
# Initial July 2024
#
####################################################

# Exit on errors, unset variables, and pipeline failures
set -euo pipefail

# Clear the screen
clear

# Constants for URLs and file paths
LOGFILE="/var/log/raspberry_pihole_install.log"

# Define colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to initialize log
initialize_log() {
    echo -e "\n\n#### Installation Start ####\n" >>"$LOGFILE"
}

# Function to print log messages
log() {
    local message="$1"
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo -e "\n${CYAN}$timestamp | $message${NC}\n"
    echo "$timestamp | $message" >>"$LOGFILE"
}

# Function to print error messages
error() {
    local message="ERROR: $1"
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo -e "\n${RED}$timestamp | $message${NC}\n" >&2
    echo "$timestamp | $message" >>"$LOGFILE"
}

# Function to print success messages
success() {
    local message="SUCCESS: $1"
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo -e "\n${GREEN}$timestamp | $message${NC}\n"
    echo "$timestamp | $message" >>"$LOGFILE"
}

# Function to print warning messages
warning() {
    local message="WARNING: $1"
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo -e "\n${YELLOW}$timestamp | $message${NC}\n"
    echo "$timestamp | $message" >>"$LOGFILE"
}

# Function to update the system
update_system() {
    log "Updating system..."
    if apt update -y && apt upgrade -y && apt full-upgrade -y; then
        sync
        success "System update completed successfully."
    else
        error "Failed to update system."
        return 1
    fi
}

# Function to install required packages
install_required_packages() {
    log "Installing required packages..."
    if apt install -y net-tools curl git htop btop bash-completion haveged gnupg2 man-db tldr dnsutils; then
        success "Required packages installed."
    else
        error "Failed to install required packages."
        return 1
    fi
}

# Function to install required software
install_required_software() {
    log "Installing required software..."
    if apt install -y chrony fake-hwclock watchdog; then
        success "Required software installed."
    else
        error "Failed to install required software."
        return 1
    fi
}

# Function to edit chrony.conf
edit_chrony() {
    log "Edit chrony.conf..."
    local chrony_config_file="/etc/chrony/chrony.conf"
    local backup_chrony_config_file="/etc/chrony.conf.ori"

    cp "$chrony_config_file" "$backup_chrony_config_file" && success "Backup of $chrony_config_file created successfully." || warning "Failed to create backup for $chrony_config_file."

    # Comment out the line starting with "pool" and add the new server
    sed -i '/^pool/{s/^/# /; n; s/.*/server 192.168.10.1 iburst/}' "$chrony_config_file"

    systemctl restart chronyd || {
        error "Failed to restart chronyd service"
        return 1
    }

    success "Changes have been applied. The chrony.conf file has been updated."
}

# Function to edit watchdog.conf
edit_watchdog() {
    log "Edit watchdog.conf..."
    local watchdog_config_file="/etc/watchdog.conf"
    local backup_watchdog_config_file="/etc/watchdog.conf.ori"

    cp "$watchdog_config_file" "$backup_watchdog_config_file" && success "Backup of $watchdog_config_file created successfully." || warning "Failed to create backup for $watchdog_config_file."
    truncate -s 0 "$watchdog_config_file" || {
        error "Failed to truncate $watchdog_config_file"
        return 1
    }

    cat <<EOL >>"$watchdog_config_file"
watchdog-device     = /dev/watchdog
watchdog-timeout    = 15
log-dir        = /var/log/watchdog
realtime        = yes
priority        = 1
max-load-1      = 24
EOL

    systemctl restart watchdog || {
        echo "Failed to restart watchdog service."
        return 1
    }

    success "Changes have been applied. The watchdog.conf file has been updated."
}

# Function to check network status
# Source: https://blog.doenselmann.com/raspberry-pi-fuer-dauereinsatz-optimieren/
edit_check_network() {
    log "Install Network_Check...."
    local script_path="/opt/scripts"
    local network_service_file="/opt/scripts/network_status.sh"
    local network_status_service="/etc/systemd/system/network_status.service"
    local network_status_timer="/etc/systemd/system/network_status.timer"

    mkdir -p "$script_path" || {
        error "Failed to create directory $script_path"
        return 1
    }

    cat <<EOL >"$network_service_file"


# global variables
gateway="192.168.10.1"
interface="eth0"

# Ping gateway for network status test
ping -c4 \$gateway > /dev/null

# if gateway is not reachable, restart the network interface 
if [ $? != 0 ] 
then
  ifdown \$interface
  sleep 3
  ifup --force \$interface
fi
EOL

    cat <<EOL >"network_status_service"
[Unit]
Description=Check Network Status

[Service]
Type=simple
ExecStart=/opt/scripts/network_status.sh 
EOL

    cat <<EOL >"network_status_timer"
[Unit]
Description=Runs Check Network Status every 20 minutes

[Timer]
OnBootSec=10min
OnUnitActiveSec=20min
Unit= network_status.service

[Install]
WantedBy=multi-user.target
EOL

    chmod +x "$network_service_file"

    systemctl enable network_status.timer
    systemctl start network_status.timer

    success "Network_Check succesfully installed."
}

# Function to clean up variables and system
clean_system() {
    log "Resetting variables and cleaning up system..."

    apt autoremove -y
    apt autoclean
    apt clean
    sync

    success "System cleaned up."
}

# Function to prompt for system reboot
reboot_system() {
    while true; do
        read -p "Do you want to reboot the system now? (y/n): " choice
        case "$choice" in
        j | J | y | Y)
            log "Rebooting system..."
            reboot
            break
            ;;
        n | N)
            log "Please remember to reboot the system later."
            break
            ;;
        *)
            warning "Please respond with yes (y) or no (n)."
            ;;
        esac
    done
}

# Main part of the script
main() {
    initialize_log

    update_system || {
        error "Error system_update."
        return 1
    }

    install_required_package || {
        error "Error install required packages."
        return 1
    }

    install_required_software || {
        error "Error install requiered software."
        return 1
    }

    edit_chrony || {
        error "Error edit Chrony config file."
        return 1
    }

    edit_watchdog || {
        error "Error install watchdog."
        return 1
    }

    edit_check_network || {
        error "Error edit_check_network."
        return 1
    }

    clean_system
    reboot_system
}

# Start the script
main
