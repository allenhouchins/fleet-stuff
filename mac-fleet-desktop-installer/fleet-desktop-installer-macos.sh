#!/bin/sh

# Fleet Reloader function that can be used across other scripts that 
# require the Fleet Agent to restart in order to pick up changes
fleet_reloader()
{
# Create the files we're going to use, set their permissions, and check to
# ensure existing, potentially malicious code isn't already at these paths

if [ -e "/private/tmp/fleetreloader.sh" ]; then
    echo "fleetreloader.sh already exists. Deleting it before continuing..."
    /bin/rm "/private/tmp/fleetreloader.sh"
else
    /usr/bin/touch /private/tmp/fleetreloader.sh
    /bin/chmod 744 /private/tmp/fleetreloader.sh
     echo "Created fleetreloader script"
fi

if [ -e "/private/tmp/com.fleetdm.reload.plist" ]; then
    echo "fleetreloader LaunchDaemon already exists. Deleting it before continuing..."
    /bin/rm "/private/tmp/com.fleetdm.reload.plist"
else
    /usr/bin/touch /private/tmp/com.fleetdm.reload.plist
    /bin/chmod 644 /private/tmp/com.fleetdm.reload.plist
    echo "Created fleetreloader LaunchDaemon"
fi


# Create the Fleet Agent Reloader Script
/bin/cat << 'EOF' > "/private/tmp/fleetreloader.sh"
#!/bin/sh
/bin/sleep 15
/bin/launchctl bootout system /Library/LaunchDaemons/com.fleetdm.orbit.plist
/bin/launchctl bootstrap system /Library/LaunchDaemons/com.fleetdm.orbit.plist
/bin/launchctl bootout system "/private/tmp/com.fleetdm.reload.plist" 
EOF

# Create the Fleet Agent Reloader daemon
/bin/cat << 'EOF' > "/private/tmp/com.fleetdm.reload.plist"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
    <dict>
        <key>Label</key>
        <string>com.fleetdm.reload</string>
        <key>ProgramArguments</key>
        <array>
            <string>/bin/sh</string>
            <string>/private/tmp/fleetreloader.sh</string>
        </array>
        <key>RunAtLoad</key>
        <true/>
        <key>StandardErrorPath</key>
        <string>/dev/null</string>
        <key>StandardOutPath</key>
        <string>/dev/null</string>
    </dict>
</plist>
EOF

# Load Fleet Agent Reloader plist
/bin/launchctl bootstrap system "/private/tmp/com.fleetdm.reload.plist"; 
}

### Start script ###
# Check if Fleet Agent is installed
if [ ! -f "/Library/LaunchDaemons/com.fleetdm.orbit.plist" ]; then
    echo "Fleet Agent is not installed."
    exit 1
else
    echo "Fleet Agent is installed. Continuing..."
fi

# Add Orbit Desktop Channel to Fleet Agent plist
/usr/bin/plutil -replace EnvironmentVariables.ORBIT_DESKTOP_CHANNEL -string "stable" /Library/LaunchDaemons/com.fleetdm.orbit.plist

# Enable Fleet Destop via Fleet Agent plist
/usr/bin/plutil -replace EnvironmentVariables.ORBIT_FLEET_DESKTOP -string "true" /Library/LaunchDaemons/com.fleetdm.orbit.plist

# Call Reloader function
fleet_reloader

echo "Fleet Desktop has been enabled. Please allow up to a minute for it to download and open on the device."

exit 0
