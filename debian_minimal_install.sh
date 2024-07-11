#!/bin/bash

####################################################
#
# Debian Install Script by Stony64
# Initial July 2024
#
####################################################

# Exit on errors
set -euo pipefail

# Clear the screen
clear

# Constants for URLs and file paths
DOTFILES_URL="https://raw.githubusercontent.com/stony64/dotfiles/main"
HOSTFILES=(".bashrc" ".bash_aliases" ".bash_functions" ".nanorc")
BACKUP_DIR_NANO="/root/.nano/backups"
LOGFILE="/var/log/debian_install_script.log"

# Initialize user inputs
NEW_USERNAME=""
NEW_HOSTNAME=""
IPV4=""
IPV6=""
SSH_PORT=""
NETMASK_IPV4="255.255.255.0"
NETMASK_IPV6="64"
GATEWAY_IPV4="192.168.10.1"
GATEWAY_IPV6="fd00::1"
NEW_LOCALES="de_DE.UTF-8"

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
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo -e "\n${CYAN}$timestamp | $message${NC}\n"
    echo "$timestamp | $message" >>"$LOGFILE"
}

# Function to print error messages
error() {
    local message="ERROR: $1"
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo -e "\n${RED}$timestamp | $message${NC}\n" >&2
    echo "$timestamp | $message" >>"$LOGFILE"
}

# Function to print success messages
success() {
    local message="SUCCESS: $1"
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo -e "\n${GREEN}$timestamp | $message${NC}\n"
    echo "$timestamp | $message" >>"$LOGFILE"
}

# Function to print warning messages
warning() {
    local message="WARNING: $1"
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo -e "\n${YELLOW}$timestamp | $message${NC}\n"
    echo "$timestamp | $message" >>"$LOGFILE"
}

# Function to prompt and validate user input
prompt_input() {
    local prompt="$1"
    local var_name="$2"
    local value=""
    while true; do
        read -p "$prompt" value
        if [ -n "$value" ]; then
            eval "$var_name='$value'"
            break
        else
            warning "Input cannot be empty. Please try again."
        fi
    done
}

# Function to validate IP addresses
validate_ip() {
    local ip="$1"
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        return 0
    else
        return 1
    fi
}

# Function to validate SSH port
validate_port() {
    local port="$1"
    if [[ "$port" =~ ^[0-9]{1,5}$ ]] && [ "$port" -le 65535 ]; then
        return 0
    else
        return 1
    fi
}

# Function to confirm user inputs
confirm_inputs() {
    while true; do
        log "Summary of inputs:"
        log "Username: $NEW_USERNAME"
        log "Hostname: $NEW_HOSTNAME"
        log "IPv4: $IPV4"
        log "IPv6: $IPV6"
        log "SSH Port: $SSH_PORT"

        read -p "Are these details correct? (y/n): " choice
        case "$choice" in
        y | Y) break ;;
        n | N) collect_user_inputs ;;
        *) warning "Invalid choice. Please enter 'y' or 'n'." ;;
        esac
    done
}

# Function to collect user inputs with validation
collect_user_inputs() {
    prompt_input "Enter the new username: " NEW_USERNAME
    prompt_input "Enter the new hostname: " NEW_HOSTNAME
    while true; do
        prompt_input "Enter the new IPv4 address: " IPV4
        if validate_ip "$IPV4"; then
            break
        else
            warning "Invalid IPv4 address. Please try again."
        fi
    done
    while true; do
        prompt_input "Enter the new IPv6 address: " IPV6
        if [[ "$IPV6" =~ ^([a-fA-F0-9:]+:+)+[a-fA-F0-9]+$ ]]; then
            break
        else
            warning "Invalid IPv6 address. Please try again."
        fi
    done
    while true; do
        prompt_input "Enter the new SSH port: " SSH_PORT
        if validate_port "$SSH_PORT"; then
            break
        else
            warning "Invalid SSH port. Please try again."
        fi
    done

    confirm_inputs
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
    if apt install -y mc console-setup keyboard-configuration locales sudo; then
        success "Required packages installed."
    else
        error "Failed to install required packages."
        return 1
    fi
}

# Function to set system locales
setup_locales() {
    log "Setting locales to German..."
    locales=("de_DE.UTF-8 UTF-8" "en_GB.UTF-8 UTF-8" "en_US.UTF-8 UTF-8")

    for locale in "${locales[@]}"; do
        grep -q "^${locale%% *}" /etc/locale.gen || echo "$locale" >>/etc/locale.gen
    done

    locale-gen
    update-locale LANG="$NEW_LOCALES"
    success "Locales set successfully!"
}

# Function to set German keyboard layout
setup_keyboard() {
    log "Setting German keyboard layout..."
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layoutcode string de"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layout string German"
    dpkg-reconfigure -f noninteractive keyboard-configuration
    success "German keyboard layout set successfully."
}

# Function to configure console-setup
setup_console() {
    log "Setting console-setup configuration..."
    debconf-set-selections <<<"console-setup console-setup/charmap47 select UTF-8"
    debconf-set-selections <<<"console-setup console-setup/codesetcode47 select # Latin1 and Latin5 - western Europe and Turkic languages"
    debconf-set-selections <<<"console-setup console-setup/fontface47 select Fixed"
    debconf-set-selections <<<"console-setup console-setup/fontsize-text47 select 8x18"
    dpkg-reconfigure -f noninteractive console-setup
    success "Console-setup configuration set successfully."
}

# Function to set hostname with validation
setup_hostname() {
    local new_hostname="$1"
    if [ -z "$new_hostname" ]; then
        error "Hostname is empty. This function requires a valid hostname."
        return 1
    fi

    local hostname_pattern='^[a-zA-Z0-9-]+$'
    if ! [[ "$new_hostname" =~ $hostname_pattern ]]; then
        error "Invalid hostname. Only alphanumeric characters and hyphens are allowed."
        return 1
    fi

    log "Changing hostname to $new_hostname"
    hostnamectl set-hostname "$new_hostname"
    success "Hostname set successfully to $new_hostname."
}

# Function to configure network interfaces
setup_network_interfaces() {
    local interfaces_file="/etc/network/interfaces"
    local backup_file="/etc/network/interfaces.bak"

    cp "$interfaces_file" "$backup_file" && success "Backup of $interfaces_file created successfully." || warning "Failed to create backup for $interfaces_file."
    truncate -s 0 "$interfaces_file" || {
        error "Failed to truncate $interfaces_file"
        return 1
    }

    cat <<EOL >>"$interfaces_file"
auto lo
iface lo inet loopback
iface lo inet6 loopback
EOL

    if [ -n "$IPV4" ]; then
        cat <<EOL >>"$interfaces_file"

auto eth0
iface eth0 inet static
        address $IPV4/24
        netmask $NETMASK_IPV4
        gateway $GATEWAY_IPV4
EOL
    fi

    if [ -n "$IPV6" ]; then
        cat <<EOL >>"$interfaces_file"

iface eth0 inet6 static
        address $IPV6/64
        netmask $NETMASK_IPV6
        gateway $GATEWAY_IPV6
EOL
    fi

    success "Network configuration updated successfully."
}

# Function to create sudo user with sudo privileges
create_sudo_user() {
    log "Creating new user and setting sudo privileges..."

    if id "$NEW_USERNAME" &>/dev/null; then
        warning "User '$NEW_USERNAME' already exists."
        read -p "Do you want to delete the user and recreate? (y/n): " choice
        case "$choice" in
        j | J | y | Y)
            visudo -c /etc/sudoers || {
                error "Syntax check failed for sudoers file"
                return 1
            }
            sed -i "/^$NEW_USERNAME/d" /etc/sudoers
            rm -f "/etc/sudoers.d/$NEW_USERNAME"
            sudo userdel -r "$NEW_USERNAME"
            log "User '$NEW_USERNAME' deleted."
            ;;
        *)
            warning "User not recreated."
            return
            ;;
        esac
    fi

    adduser --gecos "" "$NEW_USERNAME"
    usermod -aG sudo "$NEW_USERNAME"
    echo "$NEW_USERNAME ALL=(ALL:ALL) NOPASSWD:ALL" | tee "/etc/sudoers.d/$NEW_USERNAME" >/dev/null
    visudo -c /etc/sudoers.d/"$NEW_USERNAME" || {
        error "Syntax check failed for sudoers file for $NEW_USERNAME"
        return 1
    }

    success "User $NEW_USERNAME created successfully with sudo privileges and added to /etc/sudoers.d/."
}

# Function to setup SSH access
setup_ssh_access() {
    log "Setting up SSH access..."
    get_ssh_key || {
        error "Failed to get SSH key."
        return 1
    }
    success "SSH access set up successfully."
}

# Function to get SSH key and save to authorized_keys
get_ssh_key() {
    log "Please paste your SSH key (*.pub) here:"
    read -r ssh_key

    local authorized_keys_file="/home/$NEW_USERNAME/.ssh/authorized_keys"
    if [ ! -f "$authorized_keys_file" ]; then
        log "Creating .ssh directory and authorized_keys file..."
        mkdir -p "/home/$NEW_USERNAME/.ssh" || {
            error "Failed to create directory"
            return 1
        }
        touch "$authorized_keys_file" || {
            error "Failed to create authorized_keys file"
            return 1
        }
        chmod 700 "/home/$NEW_USERNAME/.ssh"
        chmod 600 "$authorized_keys_file"
        chown -R "$NEW_USERNAME:$NEW_USERNAME" "/home/$NEW_USERNAME/.ssh"
    fi

    if grep -q "$ssh_key" "$authorized_keys_file"; then
        warning "SSH key already exists in authorized_keys file."
    else
        echo "$ssh_key" >>"$authorized_keys_file"
        success "SSH key added successfully to authorized_keys file for $NEW_USERNAME."
    fi
}

# Function to create advanced SSH configuration file
create_advanced_ssh_config() {
    log "Creating advanced SSH configuration file..."
    SSH_CONFIG_DIR="/etc/ssh/sshd_config.d"
    SSH_CONFIG_FILE="$SSH_CONFIG_DIR/$NEW_HOSTNAME.conf"

    if [ ! -d "$SSH_CONFIG_DIR" ]; then
        mkdir -p "$SSH_CONFIG_DIR" || {
            error "Failed to create directory $SSH_CONFIG_DIR."
            return 1
        }
    fi

    cat <<EOL >"$SSH_CONFIG_FILE"
Port $SSH_PORT
Protocol 2
PermitRootLogin prohibit-password
PasswordAuthentication no
ChallengeResponseAuthentication no
GSSAPIAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
UsePAM yes
MaxAuthTries 3
ClientAliveInterval 600
ClientAliveCountMax 2
LogLevel VERBOSE
AllowUsers $NEW_USERNAME
AllowTcpForwarding no
X11Forwarding no
PermitTunnel no
AllowAgentForwarding no
AllowStreamLocalForwarding no
EOL

    chown root:root "$SSH_CONFIG_FILE"
    chmod 644 "$SSH_CONFIG_FILE"

    if systemctl restart sshd.service; then
        success "SSH configuration updated successfully and SSH service restarted."
    else
        error "Failed to restart SSH service. Please check SSH configuration manually."
        return 1
    fi
}

 # Function to create backup directory for nano
create_backup_directory_nano() {
    mkdir -p "$BACKUP_DIR_NANO" && success "Directory $BACKUP_DIR_NANO created successfully for root." || warning "Directory $BACKUP_DIR_NANO already exists for root."
    
    local user_backup_dir="/home/$NEW_USERNAME/.nano/backups"
    mkdir -p "$user_backup_dir" && success "Directory $user_backup_dir created successfully for $NEW_USERNAME." || warning "Directory $user_backup_dir already exists for $NEW_USERNAME."
    chown -R "$NEW_USERNAME:$NEW_USERNAME" "/home/$NEW_USERNAME/.nano"
}

# Function to download and backup host files
download_and_backup_hostfiles() {
    local temp_dir="/tmp/hostfiles"
    log "Downloading and backing up host files..."

    mkdir -p "$temp_dir" || {
        error "Failed to create temporary directory $temp_dir."
        return 1
    }

    pushd "$temp_dir" >/dev/null || {
        error "Failed to change directory to $temp_dir."
        return 1
    }

    for file in "${HOSTFILES[@]}"; do
        if wget -q "$DOTFILES_URL/$file"; then
            log "Successfully downloaded $file."
            # Backup and copy for root
            if [ -f "/root/$file" ]; then
                cp "/root/$file" "/root/$file.bak" && rm "/root/$file" || warning "Failed to backup /root/$file."
            fi
            cp "$file" "/root/" || warning "Failed to copy $file to /root/."

            # Backup and copy for new user
            local user_home="/home/$NEW_USERNAME"
            if [ -d "$user_home" ]; then
                if [ -f "$user_home/$file" ]; then
                    cp "$user_home/$file" "$user_home/$file.bak" && rm "$user_home/$file" || warning "Failed to backup $user_home/$file."
                fi
                cp "$file" "$user_home/" || warning "Failed to copy $file to $user_home/."
                chown "$NEW_USERNAME:$NEW_USERNAME" "$user_home/$file"
            else
                warning "Home directory for $NEW_USERNAME does not exist."
            fi
        else
            warning "Failed to download $file."
        fi
    done

    popd >/dev/null || {
        error "Failed to change back to original directory."
        return 1
    }

    rm -rf "$temp_dir" || warning "Failed to delete temporary directory $temp_dir."

    success "Download and backup of host files completed."
}

# Function to clean up variables and system
clean_system() {
    log "Resetting variables and cleaning up system..."

    unset NEW_USERNAME
    unset NEW_HOSTNAME
    unset IPV4
    unset IPV6
    unset SSH_PORT
    unset NETMASK_IPV4
    unset NETMASK_IPV6
    unset GATEWAY_IPV4
    unset GATEWAY_IPV6
    unset NEW_LOCALES

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

    collect_user_inputs || {
        error "Error in user inputs."
        return 1
    }
    update_system || {
        error "Failed to update system."
        return 1
    }
    install_required_packages || {
        error "Failed to install required packages."
        return 1
    }
    setup_locales || {
        error "Failed to setup locales."
        return 1
    }
    setup_keyboard || {
        error "Failed to setup keyboard layout."
        return 1
    }
    setup_console || {
        error "Failed to setup console configuration."
        return 1
    }
    setup_hostname "$NEW_HOSTNAME" || {
        error "Failed to setup hostname."
        return 1
    }
    setup_network_interfaces || {
        error "Failed to setup network interfaces."
        return 1
    }
    create_sudo_user || {
        error "Failed to create sudo user."
        return 1
    }
    setup_ssh_access || {
        error "Failed to setup SSH access."
        return 1
    }
    create_advanced_ssh_config || {
        error "Failed to create advanced SSH configuration."
        return 1
    }
    create_backup_directory_nano || {
        warning "Failed to create backup directory for nano."
    }
     download_and_backup_hostfiles || {
        warning "Failed to download and backup host configuration files."
    }
    clean_system
    reboot_system
}

# Start the script
main
