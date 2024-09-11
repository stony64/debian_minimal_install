#!/bin/bash

####################################################
# Debian CT Install Script by Stony64
# Version: 0.3.0
# Initial Release: 09/2024
####################################################

# Exit on errors, unset variables, and pipeline failures
set -euo pipefail
trap 'log_error "Script terminated unexpectedly."; exit 1;' ERR

# Clear the screen
clear

# Check if the script is run with root privileges
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root."
    exit 1
fi

# Constants
readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_VERSION="0.3.0"  # Updated version
readonly LOG_FILE="/var/log/${SCRIPT_NAME}.log"
readonly DOTFILES_URL="https://raw.githubusercontent.com/stony64/dotfiles/main"
readonly HOSTFILES=(.bashrc .bash_aliases .bash_functions .nanorc)

# Set colors for output
readonly RED='\e[0;31m'
readonly GREEN='\e[0;32m'
readonly YELLOW='\e[0;33m'
readonly CYAN='\e[0;36m'
readonly NC='\e[0m' # No Color

# Initialize user inputs
declare newUsername shPort
declare newLocales="de_DE.UTF-8"

# Check if any command-line options were provided
if [[ -n "${1:-}" ]]; then
    case "$1" in
        -h)
            echo "Usage: $SCRIPT_NAME [-h] [-v]"
            echo "  -h  Display this help message"
            echo "  -v  Display script version"
            exit 0
            ;;
        -v)
            echo "$SCRIPT_NAME"
            echo "version $SCRIPT_VERSION"
            exit 0
            ;;
        *)
            echo "Invalid option: $1" >&2
            echo "Usage: $SCRIPT_NAME [-h] [-v]" >&2
            exit 1
            ;;
    esac
fi

log_message() {
    # Logs messages with color and to the log file
    local logLevel="$1"
    local logColor="$2"
    local logMessage="$3"
    local logTimestamp
    logTimestamp="$(date '+%Y-%m-%d %H:%M:%S')"

    # Ensure color codes are interpreted
    printf '%b[%s] %s: %s%b\n' "$logColor" "$logTimestamp" "$logLevel" "$logMessage" "$NC" | tee -a "$LOG_FILE"
}

log_info() { log_message "INFO" "$CYAN" "$1"; }
log_error() { log_message "ERROR" "$RED" "$1"; }
log_success() { log_message "SUCCESS" "$GREEN" "$1"; }
log_warning() { log_message "WARNING" "$YELLOW" "$1"; }

prompt_input() {
    # Prompts for user input and validates it
    local prompt="$1"
    local varName="$2"

    while true; do
        read -r -p "$prompt" input
        if [[ -n "$input" ]]; then
            declare -g "$varName"="$input"
            break
        else
            log_warning "Input cannot be empty. Please try again."
        fi
    done
}

confirm_inputs() {
    # Confirms the user inputs before proceeding
    while true; do
        log_info "Summary of inputs:"
        log_info "Username: $newUsername"
        log_info "SSH Port: $shPort"

        read -r -p "Are these details correct? (y/n): " choice
        case "$choice" in
            y | Y) break ;;
            n | N) collect_user_inputs ;;
            *) log_warning "Invalid choice. Please enter 'y' or 'n'." ;;
        esac
    done
}

collect_user_inputs() {
    # Collects and validates user inputs
    prompt_input "Enter the new username: " newUsername

    while true; do
        prompt_input "Enter the new SSH port (1-65535): " shPort
        if [[ "$shPort" =~ ^[0-9]{1,5}$ ]] && (( shPort >= 1 && shPort <= 65535 )); then
            break
        else
            log_warning "Invalid SSH port. Please enter a port number between 1 and 65535."
        fi
    done

    confirm_inputs
}

setAptSource() {
    # Sets the APT sources list
    local aptSourceListFile="/etc/apt/sources.list"
    local aptSourceListBackupFile="/etc/apt/sources.list.bak"

    cp "$aptSourceListFile" "$aptSourceListBackupFile" && log_success "Backup of $aptSourceListFile created successfully." || log_warning "Failed to create backup for $aptSourceListFile."
    
    cat <<EOL >"$aptSourceListFile"
deb http://deb.debian.org/debian bookworm main contrib non-free non-free-firmware
deb http://deb.debian.org/debian bookworm-updates main contrib non-free non-free-firmware
deb http://security.debian.org/debian-security bookworm-security main contrib non-free non-free-firmware
# Backports are _not_ enabled by default.
# Enable them by uncommenting the following line:
# deb http://deb.debian.org/debian bookworm-backports main non-free-firmware
EOL
}

updateSystem() {
    # Updates the system packages
    log_info "Updating system..."
    if apt update -y && apt upgrade -y && apt full-upgrade -y; then
        sync
        log_success "System update completed successfully."
    else
        log_error "Failed to update system."
        return 1
    fi
}

installRequiredPackages() {
    # Installs required packages
    log_info "Installing required packages..."
    if apt install -y mc console-setup keyboard-configuration locales sudo curl; then
        log_success "Required packages installed."
    else
        log_error "Failed to install required packages."
        return 1
    fi
}

setupLocales() {
    # Sets up system locales
    log_info "Setting locales to German..."
    local locales=("de_DE.UTF-8 UTF-8" "en_GB.UTF-8 UTF-8" "en_US.UTF-8 UTF-8")

    for locale in "${locales[@]}"; do
        grep -q "^${locale%% *}" /etc/locale.gen || echo "$locale" >>/etc/locale.gen
    done

    locale-gen
    update-locale LANG="$newLocales"
    log_success "Locales set successfully!"
}

setKeyboardLayout() {
    # Configures German keyboard layout
    local layout="German"
    local variant=""

    log_info "Configuring keyboard layout to $layout..."

    if debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layout select $layout" &&
       debconf-set-selections <<<"keyboard-configuration keyboard-configuration/variant select $variant" &&
       dpkg-reconfigure -f noninteractive keyboard-configuration; then
       log_success "Keyboard layout set to $layout successfully."
    else
        log_error "Failed to set keyboard layout to $layout."
        return 1
    fi
}

setupConsole() {
    # Configures console setup
    local charmap="UTF-8"
    local codeset="Latin1 and Latin5 - western Europe and Turkic languages"
    local fontface="Fixed"
    local fontsize="8x18"

    log_info "Setting console-setup configuration..."

    debconf-set-selections <<<"console-setup console-setup/charmap select $charmap"
    debconf-set-selections <<<"console-setup console-setup/codeset select $codeset"
    debconf-set-selections <<<"console-setup console-setup/fontface select $fontface"
    debconf-set-selections <<<"console-setup console-setup/fontsize select $fontsize"

    dpkg-reconfigure -f noninteractive console-setup
    log_success "Console-setup configuration set successfully."
}

setupSsh() {
    # Configures the SSH service
    log_info "Configuring SSH service..."

    local sshConfigFile="/etc/ssh/sshd_config"
    local sshConfigBackupFile="/etc/ssh/sshd_config.bak"

    systemctl stop ssh.service

    cp "$sshConfigFile" "$sshConfigBackupFile" && log_success "Backup of $sshConfigFile created successfully." || log_warning "Failed to create backup for $sshConfigFile."

    sed -i 's/^#Port 22/Port '"$shPort"'/g' "$sshConfigFile" || {
        log_error "Failed to set SSH port in $sshConfigFile"
        return 1
    }
   
    log_success "SSH service configured successfully on port $shPort."
}

create_advanced_ssh_config() {
    # Function to create advanced SSH configuration file
    log_info "Creating advanced SSH configuration file..."

    # Define the directory and file path for the SSH configuration
    local SSH_CONFIG_DIR="/etc/ssh/sshd_config.d"
    local SSH_CONFIG_FILE="$SSH_CONFIG_DIR/$newUsername.conf"

    # Check if the directory exists; if not, create it
    if [ ! -d "$SSH_CONFIG_DIR" ]; then
        mkdir -p "$SSH_CONFIG_DIR" || {
            log_error "Failed to create directory $SSH_CONFIG_DIR."
            return 1
        }
    fi

    # Create the SSH configuration file with advanced settings
    cat <<EOL >"$SSH_CONFIG_FILE"
Port $shPort                               # Define the port SSH will listen on
Protocol 2                                  # Use SSH Protocol 2
PermitRootLogin prohibit-password           # Disallow root login with password, but allow key-based login
PasswordAuthentication no                   # Disable password authentication
ChallengeResponseAuthentication no          # Disable challenge-response authentication
GSSAPIAuthentication no                     # Disable GSSAPI authentication
PubkeyAuthentication yes                    # Enable public key authentication
AuthorizedKeysFile .ssh/authorized_keys     # Location of the authorized keys file
UsePAM yes                                  # Enable Pluggable Authentication Modules
MaxAuthTries 3                              # Maximum number of authentication attempts
ClientAliveInterval 600                     # Interval in seconds to send keep-alive messages
ClientAliveCountMax 2                       # Number of keep-alive messages before disconnecting
LogLevel VERBOSE                            # Set logging level to verbose for detailed logs
AllowUsers root, $newUsername                     # Allow only specified user to connect
AllowTcpForwarding no                       # Disable TCP forwarding
X11Forwarding no                            # Disable X11 forwarding
PermitTunnel no                             # Disable tunneling
AllowAgentForwarding no                     # Disable agent forwarding
AllowStreamLocalForwarding no               # Disable stream local forwarding
EOL

    # Set appropriate permissions for the SSH configuration file
    chown root:root "$SSH_CONFIG_FILE"
    chmod 644 "$SSH_CONFIG_FILE"

    # Restart the SSH service to apply new configuration
    if systemctl start ssh.service; then
       systemctl reload ssh.service
        log_success "SSH configuration updated successfully and SSH service started."
    else
        log_error "Failed to start SSH service. Please check SSH configuration manually."
        return 1
    fi
}

setupNewUser() {
    # Sets up a new user with the provided username
    local -r username="$newUsername"
    local -r homeDir="/home/$username"
    local -r sshDir="$homeDir/.ssh"

    # Checks if the user already exists
    if id "$username" &>/dev/null; then
        log_warning "User $username already exists."
        
        # Provides the user with the option to delete and recreate the existing user
        read -p "Do you want to delete and recreate the user? (y/n): " choice
        case "$choice" in
            y | Y)
                # Check sudoers file for syntax errors
                visudo -c /etc/sudoers || {
                    log_error "Syntax check of the sudoers file failed."
                    return 1
                }

                # Remove sudo privileges for the user
                sed -i "/^$username/d" /etc/sudoers
                rm -f "/etc/sudoers.d/$username"

                # Delete the user and their home directory
                sudo userdel -r "$username"
                log_success "User '$username' deleted."
                ;;
            *)
                log_warning "User was not recreated."
                return
                ;;
        esac
    fi

    log_info "Creating new user account: $username"

    # Create the new user with a home directory and bash as the default shell
    useradd -m -s /bin/bash "$username"

    # Set the password for the new user
    log_info "Setting password for user $username:"
    passwd "$username"

    # Create the SSH directory and set permissions
    mkdir -p "$sshDir"
    chown -R "$username:$username" "$sshDir"
    chmod 700 "$sshDir"

    # Grant sudo privileges to the new user
    usermod -aG sudo "$username"
    echo "$username ALL=(ALL:ALL) ALL" | tee "/etc/sudoers.d/$username" >/dev/null
    visudo -c /etc/sudoers.d/"$username" || {
        log_error "Syntax check failed for sudoers file for $username"
        return 1
    }

    # Add the public SSH key
    log_info "Enter the contents of your public key file (.pub):"
    read -r publicKey
    echo "$publicKey" | tee "$sshDir/authorized_keys" >/dev/null
    chmod 600 "$sshDir/authorized_keys"

    # Add the public root key
    echo "$publicKey" | tee "/root/.ssh/authorized_keys" >/dev/null
    chmod 600 "/root/.ssh/authorized_keys"

    # Copy dotfiles
    for file in "${HOSTFILES[@]}"; do
        curl -o "$homeDir/$file" "$DOTFILES_URL/$file" || {
            log_error "Failed to download $file for $homeDir."
            return 1
        }
        chown "$username:$username" "$homeDir/$file"
    done

    for file in "${HOSTFILES[@]}"; do
        curl -o "/root/$file" "$DOTFILES_URL/$file" || {
            log_error "Failed to download $file for /root."
            return 1
        }
        chown "root:root" "/root/$file"
    done

    log_success "User $username created successfully with sudo privileges and added to /etc/sudoers.d/. Dotfiles installed."
}

clean_system() {
    # Resets variables and cleans up the system
    log_info "Resetting variables and cleaning up system..."

    # Reset variables
    unset newUsername
    unset shPort
    unset newLocales

    # Clean up system
    apt autoremove -y
    apt autoclean
    apt clean
    sync

    log_success "System cleaned up."
}

reboot_system() {
    while true; do
        read -p "Do you want to reboot the system now? (y/n): " choice
        case "$choice" in
            j | J | y | Y)
                log_info "Rebooting system..."
                reboot
                break
                ;;
            n | N)
                log_info "Please remember to reboot the system later."
                break
                ;;
            *)
                log_warning "Please respond with yes (y) or no (n)."
                ;;
        esac
    done
}

main() {
    # Main installation process
    collect_user_inputs
    setAptSource
    updateSystem
    installRequiredPackages
    setupLocales
    setupConsole
    setupSsh
    create_advanced_ssh_config
    setupNewUser
    clean_system

    log_info "Installation complete."

    reboot_system
}

main
