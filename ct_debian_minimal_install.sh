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
readonly SCRIPT_NAME="$(basename "$0")"                                         # Name of the script
readonly SCRIPT_VERSION="0.8.5"                                                 # Version of the script
readonly LOG_FILE="/var/log/${SCRIPT_NAME}.log"                                 # Log file for the script
readonly DOTFILES_URL="https://raw.githubusercontent.com/stony64/dotfiles/main" # URL of the dotfiles repository
readonly HOSTFILES=(.bashrc .bash_aliases .bash_functions .nanorc)              # List of host files to copy from the dotfiles repository

# User inputs
# ------------------------------------------------------------------
# These variables are used to store user inputs provided by
# the user during the script execution. They are declared here
# so that they can be accessed in any function.
#
newUsername=""              # The username to create for the new user
sshPort=""                  # The port number for SSH access
confirmation=""             # Confirmation variable
newLocales="de_DE.UTF-8"    # locales to Enable

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

# Process command-line options
#
# The script accepts the following options:
#   -h: Print help message and exit
#   -v: Print version number and exit
#
# All other options are invalid and will cause the script to exit with an error
# message.
#
if [[ -n "${1:-}" ]]; then
    case "$1" in
        -h)
            echo "Usage: $SCRIPT_NAME [-h] [-v]"
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
    local validation="${3:-}"

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
    while true; do
        log_info "Summary of inputs:"
        log_info "Username: $newUsername"
        log_info "SSH Port: $sshPort"

        prompt_input "Are these details correct? (y/n): " "confirmation" '^[yYnN]$'
        if [[ $confirmation =~ ^[yY]$ ]]; then
            break
        elif [[ $confirmation =~ ^[nN]$ ]]; then
            collect_user_inputs
        else
            log_warning "Invalid choice. Please enter 'y' or 'n'."
        fi
    done
}

# Collects necessary inputs from the user
#
# This function is responsible for asking the user for necessary inputs and
# setting the global variables with the collected values.
#
collect_user_inputs() {
    # Prompt the user for the new username, the username should be alphanumeric and must be at least one character long.
    prompt_input "Enter the new Username (alphanumeric): " "newUsername"

    # Prompt the user for the new SSH port, the port should be a number between 1 and 65535.
    prompt_input "Enter the new SSH port (1-65535): " "sshPort" '^[1-9][0-9]{0,4}$'

    # Confirm the inputs, Loop until the user confirms the inputs or decides to re-enter the inputs.
    confirm_inputs
}

# Sets the APT source list for the system.
#
# Backs up the original source list file and then overwrites the file with the
# contents of the file.
#
setAptSource() {
    local aptSourceListFile="/etc/apt/sources.list"
    local aptSourceListBackupFile="/etc/apt/sources.list.bak"
    log_info "Backing up and setting APT source list..."

    cp "$aptSourceListFile" "$aptSourceListBackupFile" && log_success "Backup created." || log_warning "Backup failed."
    
    cat <<EOL >"$aptSourceListFile"
deb http://deb.debian.org/debian bookworm main contrib non-free non-free-firmware
deb http://deb.debian.org/debian bookworm-updates main contrib non-free non-free-firmware
deb http://security.debian.org/debian-security bookworm-security main contrib non-free non-free-firmware
# Backports are _not_ enabled by default.
# Enable them by uncommenting the following line:
# deb https://deb.debian.org/debian bookworm-backports main non-free-firmware
EOL
}

# Update the system packages
#
# This function updates the system using the APT package manager.
#
updateSystem() {
    log_info "Updating system..."
    if apt update -y && apt upgrade -y && apt full-upgrade -y; then
        log_success "System update completed."
    else
        log_error "System update failed."
        return 1
    fi
}

# Installs required packages
#
# Installs the following packages:
#   - mc: Midnight Commander (a file manager)
#   - console-setup: Console font and keymap setup
#   - keyboard-configuration: Keyboard configuration
#   - locales: System locales
#   - sudo: Superuser privileges management utility
#   - curl: Command-line tool for transferring data
#
installRequiredPackages() {
    log_info "Installing required packages..."
    if apt install -y mc console-setup keyboard-configuration locales sudo curl; then
        log_success "Packages installed."
    else
        log_error "Package installation failed."
        return 1
    fi
}

# Sets locales for the system
#
# This function sets the locales for the system, which control things like the
# character set, date format, and currency symbol.
#
# The locales are set to German, British English, and American English.
#
setupLocales() {
    local locales=("de_DE.UTF-8 UTF-8" "en_GB.UTF-8 UTF-8" "en_US.UTF-8 UTF-8")

    log_info "Setting locales to German..."
    for locale in "${locales[@]}"; do
        grep -q "^${locale%% *}" /etc/locale.gen || echo "$locale" >> /etc/locale.gen
    done

    locale-gen
    update-locale LANG="$newLocales"

    log_success "Locales set successfully!"
}

# Sets the console and keyboard configurations
#
# This function sets the console and keyboard configurations based on user input.
# The console font and keymap are set to UTF-8 and Latin1 and Latin5 - western Europe
# and Turkic languages, respectively. The console font size is set to 8x18.
# The keyboard configuration is set to German.
#

setupConsoleAndKeyboard() {
    log_info "Setting console and keyboard configuration..."

    # Set console font and keymap
    debconf-set-selections <<< "console-setup console-setup/charmap select UTF-8"
    debconf-set-selections <<< "console-setup console-setup/codeset select Latin1 and Latin5 - western Europe and Turkic languages"
    debconf-set-selections <<< "console-setup console-setup/fontface select Fixed"
    debconf-set-selections <<< "console-setup console-setup/fontsize select 8x18"

    # Set keyboard configuration
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layoutcode string de"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layout string German"

    # Reconfigure the console and keyboard
    dpkg-reconfigure -f noninteractive console-setup
    dpkg-reconfigure -f noninteractive keyboard-configuration

    log_success "Console and keyboard configuration set."
}

# Set up the SSH service and configure it with advanced settings
#
# This function will configure the SSH service to listen on a port specified
# by the user, and apply advanced settings to the SSH configuration file.
#
# Parameters:
#   - sshPort: the port number to set for the SSH service
#
setupSsh() {
    log_info "Configuring SSH service..."

    # Back up the SSH configuration file
    local sshConfigFile="/etc/ssh/sshd_config"
    cp "$sshConfigFile" "${sshConfigFile}.bak" && log_success "SSH config backed up."

    # Set the port number for the SSH service
    sed -i 's/^#Port 22/Port '"$sshPort"'/g' "$sshConfigFile"
    log_success "SSH service configured on port $sshPort."
}

# Create advanced SSH configuration file with restrictive settings
#
# This function will create an advanced SSH configuration file in the
# /etc/ssh/sshd_config.d directory. The file will have restrictive settings
# such as disabling password authentication, root login, etc. The function
# will also restart the SSH service to apply the new configuration.
#
# Returns 1 if the SSH service fails to start, 0 otherwise.
create_advanced_ssh_config() {
    local newHostname="$(hostname)"
    local SSH_CONFIG_DIR="/etc/ssh/sshd_config.d"
    local SSH_CONFIG_FILE="$SSH_CONFIG_DIR/$newHostname.conf"

    log_info "Creating advanced SSH configuration file..."

    # Check if the directory exists; if not, create it
    if [ ! -d "$SSH_CONFIG_DIR" ]; then
        mkdir -p "$SSH_CONFIG_DIR" || {
            log_error "Failed to create directory $SSH_CONFIG_DIR."
            return 1
        }
    fi

    # Create the SSH configuration file with advanced settings
    log_info "Creating SSH configuration file with advanced settings..."
    cat <<EOL >"$SSH_CONFIG_FILE"
# SSH configuration file with advanced settings
#
# This file is automatically generated by the ct_debian_minimal_install.sh script
#
Port $sshPort                                                                       # Port number to listen on
Protocol 2                                                                          # Only allow SSH protocol version 2
PermitRootLogin no                                                                  # Disable root login 
PasswordAuthentication no                                                           # Disable password authentication
ChallengeResponseAuthentication no                                                  # Disable challenge-response authentication
KbdInteractiveAuthentication no                                                     # Disable keyboard-interactive authentication
GSSAPIAuthentication no                                                             # Disable GSSAPI authentication
PubkeyAuthentication yes                                                            # Enable public key authentication
AuthorizedKeysFile .ssh/authorized_keys                                             # Set the location of the authorized keys file
UsePAM yes                                                                          # Enable PAM
MaxAuthTries 3                                                                      # Set the maximum number of authentication attempts
ClientAliveInterval 600                                                             # Set the client alive interval
ClientAliveCountMax 2                                                               # Set the maximum number of client alive messages
LogLevel VERBOSE                                                                    # Set the log level
AllowUsers $newUsername                                                             # Set the allowed users
AllowTcpForwarding no                                                               # Disable TCP forwarding
X11Forwarding no                                                                    # Disable X11 forwarding
PermitTunnel no                                                                     # Disable tunneling
AllowAgentForwarding no                                                             # Disable agent forwarding
AllowStreamLocalForwarding no                                                       # Disable stream local forwarding
Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr             # Set the ciphers
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com                    # Set the MACs
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256     # Set the key exchange algorithms
HostbasedAuthentication no                                                          # Disable host-based authentication
Match User root                                                                     # Disable root login for the root user
    AllowTcpForwarding no
    X11Forwarding no
EOL

    # Set appropriate permissions for the SSH configuration file
    log_info "Setting appropriate permissions for the SSH configuration file..."
    chown root:root "$SSH_CONFIG_FILE"
    chmod 644 "$SSH_CONFIG_FILE"

    # Restart the SSH service to apply new configuration
    log_info "Restarting the SSH service to apply new configuration..."
    # sometimes it fail with new port-settings
    apt purge openssh-server -y
    apt install openssh-server -y
    if systemctl start sshd.service; then
        systemctl reload sshd.service
        log_success "SSH configuration updated successfully and SSH service started."
    else
        log_error "Failed to start SSH service. Please check SSH configuration manually."
        return 1
    fi
}

# Creates a new user account with sudo privileges and sets up the SSH
# directory and authorized keys. If the user already exists, it will
# prompt the user whether to delete and recreate the user. The user will
# be prompted for the contents of their public key file (.pub) and their
# dotfiles from the GitHub repository. The dotfiles will be placed in the
# user's home directory and in the root directory.
#
setupNewUser() {
    local -r homeDir="/home/$newUsername"
    local -r sshDir="$homeDir/.ssh"

    if id "$newUsername" &>/dev/null; then
        log_warning "User $newUsername already exists."
        
        # Prompt the user to enter y or n to indicate whether to delete
        # and recreate the user.
        prompt_input "Do you want to delete and recreate the user? (y/n): " "choice" '^[yYnN]$'
        case "$choice" in
            y | Y)
                # Syntax check the sudoers file and remove the user's entry
                # from the sudoers file.
                visudo -c /etc/sudoers || {
                    log_error "Syntax check of the sudoers file failed."
                    return 1
                }

                sed -i "/^$newUsername/d" /etc/sudoers
                rm -f "/etc/sudoers.d/$newUsername"
                userdel -r "$newUsername"
                log_success "User '$newUsername' deleted."
                ;;
            *)
                log_warning "User was not recreated."
                return
                ;;
        esac
    fi

    # Create the user with a home directory and bash as the default shell
    useradd -m -s /bin/bash "$newUsername"
    # Set the password for the new user
    log_info "Password for new User $newUsername:"
    passwd "$newUsername"
    
    # Create the SSH directory and set permissions
    chmod 700 /home/$newUsername
    chown $newUsername:$newUsername /home/$newUsername

    mkdir -p "$sshDir"
    chmod 700 "$sshDir"
    chown -R "$newUsername:$newUsername" "$sshDir"
    
    # Add the user to the sudo group
    usermod -aG sudo "$newUsername"
    # Write the user's entry to the sudoers file
    echo "$newUsername ALL=(ALL:ALL) ALL" | tee "/etc/sudoers.d/$newUsername" >/dev/null
    # Syntax check the sudoers file for the new user
    visudo -c /etc/sudoers.d/"$newUsername" || {
        log_error "Syntax check failed for sudoers file for $newUsername"
        return 1
    }

    # Prompt the user for the contents of their public key file (.pub)
    prompt_input "Enter the contents of your public key file (.pub): " "publicKey"
    
    # Write the public key to the authorized_keys file and set permissions
    echo "$publicKey" | tee "$sshDir/authorized_keys" >/dev/null
    chmod 600 "$sshDir/authorized_keys"
    chown $newUsername:$newUsername "$sshDir"/authorized_keys

    # Get the user's dotfiles from the GitHub repository and place them in
    # the user's home directory and in the root directory
    for file in "${HOSTFILES[@]}"; do
        curl -o "$homeDir/$file" "$DOTFILES_URL/$file"
        chown "$newUsername:$newUsername" "$homeDir/$file"
    done

    for file in "${HOSTFILES[@]}"; do
        curl -o "/root/$file" "$DOTFILES_URL/$file"
        chown "root:root" "/root/$file"
    done

    log_success "User $newUsername created successfully with sudo privileges."
}

# Function to clean up variables and system
# ------------------------------------------------
# This function resets the script variables and cleans up the system.
#
clean_system() {
    log_info "Resetting variables and cleaning up system..."

    # Reset variables
    unset newUsername
    unset sshPort
    unset confirmation
    unset newLocales

    # Clean up system
    apt autoremove -y
    apt autoclean
    apt clean
    sync

    log_success "System cleaned up."
    return 0
}

# Function to prompt for system reboot
# ------------------------------------------------
# This function will prompt the user whether to reboot the system after the script
# has finished running. If the user responds with 'y', the system will be
# immediately rebooted. Otherwise, the user will be reminded to reboot the system
# later.
#
reboot_system() {
    # Prompt for user input
    prompt_input "Do you want to reboot the system now? (y/n): " "choice" '^[yYnN]$'

    # Handle the user's response
    case "$choice" in
        y | Y)
            log_info "Rebooting system..."
            reboot
            ;;
        n | N)
            log_info "Please remember to reboot the system later."
            ;;
        *)
            log_warning "Invalid choice. Please respond with 'y' or 'n'."
            ;;
    esac
}

# Main function to orchestrate script flow
# -----------------------------------------
# This function is the main entry point for the script. It calls other functions
# to perform the necessary steps to set up the LXC container.
#
# 1. Collect user inputs for the container creation
# 2. Set up the APT sources for the container
# 3. Update the system
# 4. Install required packages
# 5. Set up the console and keyboard
# 6. Set up SSH
# 7. Create advanced SSH configuration file
# 8. Set up the new user
# 9. Clean up the system
# 10. Reboot the system
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
    log_info "Script execution completed."
    clean_system
    reboot_system
}

# Run the script
main
