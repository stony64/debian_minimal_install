#!/bin/bash

####################################################
# Debian CT Install Script by Stony64
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

# Constants
# ------------------------------------------------------------------
# These are constant values used throughout the script. They are
# readonly, meaning they cannot be changed after they are set.
#
readonly SCRIPT_NAME="$(basename "$0")"                             # Name of the script
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)" # Directory where the script is located
readonly SCRIPT_VERSION="0.6.0"                                     # Version of the script
readonly LOG_FILE="/var/log/${SCRIPT_NAME}.log"                     # Log file for the script
readonly DOTFILES_URL="https://raw.githubusercontent.com/stony64/dotfiles/main" # URL of the dotfiles repository
readonly HOSTFILES=(.bashrc .bash_aliases .bash_functions .nanorc)  # List of host files to copy from the dotfiles repository

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

# Initialize variables for user inputs
# ------------------------------------------------------------------
# These variables will be set by the user via prompts. They are
# declared here so that they can be accessed in any function.
#
declare newUsername                 # The username to create for the new user
declare shPort                      # The port number for SSH access
declare newLocales="de_DE.UTF-8"    # The locales to set for the system

# Command-line options for help and version
#
# Check if any command-line options were provided
#
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
# Confirms user inputs before proceeding
#
# This function loops until the user confirms the inputs or decides to re-enter
# the inputs.
#
confirm_inputs() {
    while true; do
        log_info "Summary of inputs:"
        log_info "Container-Hostname: $ctHostname"
        log_info "RootPassword: $rootPassword"
        log_info "Last Octet: $lastOctet"

        read -r -p "Are these details correct? (y/n): " choice
        case "$choice" in
            y | Y) break ;;
            n | N) collect_user_inputs ;;
            *) log_warning "Invalid choice. Please enter 'y' or 'n'." ;;
        esac
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

# Set APT source list for the system
#
# This function will set the APT source list for the system by
# backing up the current list and creating a new one with the
# specified contents.
#
setAptSource() {
    local aptSourceListFile="/etc/apt/sources.list"
    local aptSourceListBackupFile="/etc/apt/sources.list.bak"
    log_info "Backing up and setting APT source list..."

    # Backup the current APT source list
    cp "$aptSourceListFile" "$aptSourceListBackupFile" && log_success "Backup of $aptSourceListFile created successfully." || log_warning "Failed to create backup for $aptSourceListFile."

    # Create a new APT source list with the specified contents
    cat <<EOL >"$aptSourceListFile"
# Debian bookworm main repository
deb http://deb.debian.org/debian bookworm main contrib non-free non-free-firmware

# Debian bookworm-updates repository
deb http://deb.debian.org/debian bookworm-updates main contrib non-free non-free-firmware

# Debian security repository
deb http://security.debian.org/debian-security bookworm-security main contrib non-free non-free-firmware

# Backports are _not_ enabled by default.
# Enable them by uncommenting the following line:
# deb http://deb.debian.org/debian bookworm-backports main non-free-firmware
EOL
}

# Update system packages
#
# This function will update the system packages using apt.
#
# The apt update command will update the package list, apt upgrade will
# upgrade all packages that can be upgraded without changing the install
# status of any package, and apt full-upgrade will perform the same as
# apt upgrade but will also intelligently handle the upgrade of the most
# important packages at the expense of potential changes on the system.
#
updateSystem() {
    log_info "Updating system..."
    if apt update -y && apt upgrade -y && apt full-upgrade -y; then
        sync
        log_success "System update completed successfully."
    else
        log_error "Failed to update system."
        return 1
    fi
}

# Installs required packages
#
# Installs the following packages:
# - mc: a text-based file manager
# - console-setup: for setting up the console font and keymap
# - keyboard-configuration: for setting up the keyboard layout
# - locales: for setting up the system locales
# - sudo: for allowing regular users to run commands as root
# - curl: for downloading files over HTTP
#
installRequiredPackages() {
    log_info "Installing required packages..."
    if apt install -y mc console-setup keyboard-configuration locales sudo curl; then
        log_success "Required packages installed."
    else
        log_error "Failed to install required packages."
        return 1
    fi
}

# Set the system locales
#
setupLocales() {
    local locales=("de_DE.UTF-8 UTF-8" "en_GB.UTF-8 UTF-8" "en_US.UTF-8 UTF-8")

    log_info "Setting locales to German..."
    # Add the required locales to /etc/locale.gen if they are not already present
    for locale in "${locales[@]}"; do
        grep -q "^${locale%% *}" /etc/locale.gen || echo "$locale" >>/etc/locale.gen
    done

    # Generate the locales
    locale-gen

    # Update the LANG environment variable for the system
    update-locale LANG="$newLocales"

    log_success "Locales set successfully!"
}

# Set up console and keyboard configurations
#
# This function sets the console character map to UTF-8 and the keyboard layout to
# German. It also sets the font face to Fixed and the font size to 8x18.
#
setupConsoleAndKeyboard() {
    log_info "Setting console and keyboard configuration..."

    # Set console character map
    debconf-set-selections <<<"console-setup console-setup/charmap select UTF-8" &&
    # Set console codeset to Latin1 and Latin5 (western Europe and Turkic languages)
    debconf-set-selections <<<"console-setup console-setup/codeset select Latin1 and Latin5 - western Europe and Turkic languages" &&
    # Set console font face to Fixed
    debconf-set-selections <<<"console-setup console-setup/fontface select Fixed" &&
    # Set console font size to 8x18
    debconf-set-selections <<<"console-setup console-setup/fontsize select 8x18"

    # Set keyboard layout to German
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layout select German" &&
    # Set keyboard variant to none
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/variant select " &&
    
    # Apply changes for console and keyboard settings
    dpkg-reconfigure -f noninteractive console-setup &&
    dpkg-reconfigure -f noninteractive keyboard-configuration &&
    
    log_success "Console and keyboard configuration set successfully." || log_error "Failed to set console or keyboard configuration."
}

# Configures the SSH service with advanced options
#
# This function configures the SSH service to listen on the specified port,
# disables password authentication, and enables public key authentication.
#
setupSsh() {
    log_info "Configuring SSH service..."
    local sshConfigFile="/etc/ssh/sshd_config"
    local sshConfigBackupFile="/etc/ssh/sshd_config.bak"
    systemctl stop ssh.service
    cp "$sshConfigFile" "$sshConfigBackupFile" && log_success "Backup of $sshConfigFile created successfully." || log_warning "Failed to create backup for $sshConfigFile."
    sed -i 's/^#Port 22/Port '"$shPort"'/g' "$sshConfigFile" || log_error "Failed to set SSH port in $sshConfigFile"
    log_success "SSH service configured successfully on port $shPort."
}

# Creates an advanced SSH configuration file with the specified username and
# SSH port
#
# The file is created in the /etc/ssh/sshd_config.d directory and is named
# after the username.
#
# The configuration file sets the specified SSH port, disables password
# authentication, and enables public key authentication. It also sets the
# maximum number of authentication attempts, sets the interval between client
# alive messages, and sets the log level to AUTH. Additionally, it allows only
# the specified user and group to connect.
#
create_advanced_ssh_config() {
    log_info "Creating advanced SSH configuration file..."

    # Define the directory and file path for the SSH configuration
    local SSH_CONFIG_DIR="/etc/ssh/sshd_config.d"
    local SSH_CONFIG_FILE="$SSH_CONFIG_DIR/$newUsername.conf"

    # Create the SSH configuration directory if it doesn't exist
    mkdir -p "$SSH_CONFIG_DIR" || log_error "Failed to create directory $SSH_CONFIG_DIR."

    # Create the SSH configuration file
    cat <<EOL >"$SSH_CONFIG_FILE"
Port $SSH_PORT                          # Use the specified SSH port
Protocol 2                              # Use SSH protocol 2
PermitRootLogin no                      # Disable root login
PasswordAuthentication no               # Disable password authentication
ChallengeResponseAuthentication no      # Disable challenge-response authentication
KbdInteractiveAuthentication no         # Disable keyboard-interactive authentication
GSSAPIAuthentication no                 # Disable GSSAPI authentication
PubkeyAuthentication yes                # Enable public-key authentication
AuthorizedKeysFile .ssh/authorized_keys # Use the specified authorized keys file
UsePAM yes                              # Disable PAM authentication
MaxAuthTries 3                          # Set the maximum number of authentication attempts
ClientAliveInterval 600                 # Set the interval between client alive messages
ClientAliveCountMax 2                   # Set the number of allowed client alive messages
LogLevel AUTH                           # Set the log level to AUTH
AllowUsers root, $NEW_USERNAME          # Allow the specified user to connect
AllowGroups sshusers                    # Allow the specified group to connect
AllowTcpForwarding no                   # Disable TCP forwarding
X11Forwarding no                        # Disable X11 forwarding
PermitTunnel no                         # Disable tunneling
AllowAgentForwarding no                 # Disable agent forwarding
AllowStreamLocalForwarding no           # Disable stream local forwarding
Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr         # Set the ciphers to use
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com                # Set the MACs to use
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256 # Set the key exchange algorithms to use
HostbasedAuthentication no              # Disable host-based authentication
RhostsRSAAuthentication no              # Disable RhostsRSA authentication
Match User root                         # Disable TCP forwarding and X11 forwarding for the root user. 
    AllowTcpForwarding no
    X11Forwarding no
EOL

    # Set the appropriate permissions for the SSH configuration file
    chown root:root "$SSH_CONFIG_FILE"
    chmod 644 "$SSH_CONFIG_FILE"

    # Reload the SSH service and start it
    systemctl start ssh.service && systemctl reload ssh.service && log_success "SSH configuration updated and SSH service started." || log_error "Failed to start SSH service."
}

<<<<<<<<<<<<<<  ✨ Codeium Command 🌟  >>>>>>>>>>>>>>>>
# Creates a new user with sudo privileges.
# This function creates a new user and grants them sudo privileges.
# Parameters:
#   $newUsername: The username for the new user.
#
setupNewUser() {
    log_info "Creating new user account: $newUsername"
    useradd -m -s /bin/bash "$newUsername" && passwd "$newUsername"
    usermod -aG sudo "$newUsername"
    echo "$newUsername ALL=(ALL:ALL) ALL" > "/etc/sudoers.d/$newUsername"
    log_success "User $newUsername created and granted sudo privileges."
}

# Clean up the system and reset variables
# This function cleans up the system by removing unneeded packages and
# resetting the variables that were used in the script.
#
clean_system() {
    log_info "Cleaning up system..."
    apt autoremove -y && apt autoclean && apt clean && sync
    unset newUsername shPort newLocales
    log_success "System cleaned up."
}

# Reboot the system if the user chooses to
#
# This function prompts the user to decide if they want to reboot the system
# after the script has finished running. If the user chooses to reboot, the
# system will be rebooted. If the user chooses not to reboot, the script will
# exit.
#
reboot_system() {
    while true; do
        read -p "Do you want to reboot the system now? (y/n): " choice
        case "$choice" in
            y | Y) log_info "Rebooting system..." && reboot ;;
            n | N) log_info "Please remember to reboot the system later." && break ;;
            *) log_warning "Please respond with yes (y) or no (n)." ;;
        esac
    done
}

# Main function to orchestrate the script flow
#
# This function will call the functions to
# - Collect user inputs
# - Set up the APT source
# - Update the system
# - Install required packages
# - Set up the console and keyboard settings
# - Set up SSH
# - Create an advanced SSH configuration file
# - Set up a new user
# - Clean up the system
# - Reboot the system
#
main() {
    collect_user_inputs
    setAptSource
    updateSystem
    installRequiredPackages
    setupConsoleAndKeyboard
    setupSsh
    create_advanced_ssh_config
    setupNewUser
    clean_system
    log_info "Installation complete."
    reboot_system
}

# Runs the main function of the script
#
# This will execute the main function and its called functions
# in the correct order.
#
main
