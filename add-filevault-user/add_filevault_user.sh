#!/bin/bash
# /usr/local/bin/add_filevault_user.sh
# This script runs at login to add Entra ID users to FileVault

CURRENT_USER=$(stat -f%Su /dev/console)
SCRIPT_LOG="/var/log/filevault_user_addition.log"

log_message() {
    echo "$(date): $1" >> "$SCRIPT_LOG"
}

# Check if user is already FileVault enabled
check_filevault_user() {
    local username="$1"
    fdesetup list | grep -q "^$username,"
    return $?
}

# Add user to FileVault using bootstrap token or admin credentials
add_user_to_filevault() {
    local username="$1"
    
    log_message "Attempting to add $username to FileVault"
    
    # Method 1: Try using bootstrap token (if available)
    if [[ -f "/var/db/BootstrapToken" ]]; then
        log_message "Using bootstrap token method"
        echo "$username" | fdesetup add -usertoadd "$username" -inputplist < /var/db/BootstrapToken
        if [[ $? -eq 0 ]]; then
            log_message "Successfully added $username using bootstrap token"
            return 0
        fi
    fi
    
    # Method 2: Use institutional recovery key
    if [[ -f "/usr/local/recovery_key.plist" ]]; then
        log_message "Using institutional recovery key method"
        fdesetup add -usertoadd "$username" -inputplist < /usr/local/recovery_key.plist
        if [[ $? -eq 0 ]]; then
            log_message "Successfully added $username using recovery key"
            return 0
        fi
    fi
    
    # Method 3: Prompt user for admin credentials (fallback)
    log_message "Prompting user for admin credentials"
    /usr/bin/osascript << EOF
display dialog "To enable FileVault unlock for your account, please enter admin credentials:" with title "FileVault Setup"
set adminUser to text returned of (display dialog "Username:" default answer "" with title "FileVault Setup")
set adminPass to text returned of (display dialog "Password:" default answer "" with hidden answer with title "FileVault Setup")
do shell script "echo '" & adminPass & "' | /usr/bin/fdesetup add -usertoadd $username -user " & adminUser & " -stdin"
EOF
    
    return $?
}

# Main execution
main() {
    # Skip if system user or already FileVault enabled
    if [[ "$CURRENT_USER" == "root" ]] || [[ "$CURRENT_USER" == "_mbsetupuser" ]]; then
        exit 0
    fi
    
    if check_filevault_user "$CURRENT_USER"; then
        log_message "$CURRENT_USER already has FileVault access"
        exit 0
    fi
    
    # Check if this is an Entra ID user (look for domain suffix or other identifier)
    if [[ "$CURRENT_USER" =~ @.*\.com$ ]] || id "$CURRENT_USER" | grep -q "your-domain"; then
        log_message "Detected Entra ID user: $CURRENT_USER"
        
        # Wait for user session to fully establish
        sleep 10
        
        add_user_to_filevault "$CURRENT_USER"
        
        if [[ $? -eq 0 ]]; then
            log_message "FileVault setup completed for $CURRENT_USER"
            # Optional: Show success notification
            /usr/bin/osascript -e 'display notification "FileVault has been enabled for your account" with title "Security Setup Complete"'
        else
            log_message "Failed to add $CURRENT_USER to FileVault"
        fi
    fi
}

main "$@"