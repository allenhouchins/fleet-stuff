#!/bin/bash
set -e

#########################
# Determine the currently logged in user
#########################
if [ "$EUID" -eq 0 ]; then
    if [ -n "$SUDO_USER" ]; then
        CURRENT_USER="$SUDO_USER"
        echo "SUDO_USER is set: $CURRENT_USER"
    else
        # Try using logname
        CURRENT_USER=$(logname 2>/dev/null)
        if [ -n "$CURRENT_USER" ]; then
            echo "Using logname: $CURRENT_USER"
        else
            # Fallback: use the output of who (first non-root user)
            CURRENT_USER=$(who | awk '$1 != "root" {print $1; exit}')
            echo "Using who: $CURRENT_USER"
        fi
    fi

    if [ -z "$CURRENT_USER" ]; then
        echo "Could not determine the currently logged in user."
        exit 1
    fi
else
    CURRENT_USER=$(whoami)
fi

echo "Using user: $CURRENT_USER"

#########################
# Set up the DBus session address for the target user
#########################
USER_UID=$(id -u "$CURRENT_USER")
export DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$USER_UID/bus"

#########################
# Retrieve the dconf dump as the target user
#########################
if [ "$EUID" -eq 0 ]; then
    # Run dconf dump in the target user's context using sudo
    DCONF_DUMP=$(sudo -u "$CURRENT_USER" env DBUS_SESSION_BUS_ADDRESS="$DBUS_SESSION_BUS_ADDRESS" dconf dump /)
else
    DCONF_DUMP=$(dconf dump /)
fi

if [ -z "$DCONF_DUMP" ]; then
    echo "dconf dump returned nothing. Are you sure settings exist?"
    exit 1
fi

echo "dconf dump retrieved; processing..."

#########################
# Define the target directory and SQLite database variables
#########################
TARGET_DIR="/usr/local/bin/fleet"
if [ ! -d "$TARGET_DIR" ]; then
    echo "Directory $TARGET_DIR does not exist. Creating..."
    mkdir -p "$TARGET_DIR"
fi

DB_FILE="${TARGET_DIR}/dconf_settings.db"
TABLE_NAME="settings"

# (Re)create the SQLite database and table (dropping any existing version)
sqlite3 "$DB_FILE" <<EOF
DROP TABLE IF EXISTS $TABLE_NAME;
CREATE TABLE IF NOT EXISTS $TABLE_NAME (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT UNIQUE NOT NULL,
    value TEXT NOT NULL
);
EOF

#########################
# Process the dconf dump and build SQL statements
#########################
NAMESPACE=""
SQL_STATEMENTS="BEGIN TRANSACTION;
"

# Read the dump line by line
while IFS= read -r line; do
    # Trim leading and trailing whitespace
    trimmed_line=$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    
    # Skip empty lines
    if [[ -z "$trimmed_line" ]]; then
        continue
    fi

    # Detect a namespace (section header) e.g., [org/gnome/desktop/session]
    if [[ "$trimmed_line" == \[*\] ]]; then
        # Remove the leading '[' and trailing ']'
        NAMESPACE="${trimmed_line#[}"
        NAMESPACE="${NAMESPACE%]}"
        echo "Found namespace: $NAMESPACE"
        continue
    fi

    # Process lines with a key=value pair
    if [[ "$trimmed_line" == *"="* ]]; then
        # Extract key and value parts
        KEY="${trimmed_line%%=*}"
        VALUE="${trimmed_line#*=}"
        
        # Trim any extra whitespace from key and value
        KEY=$(echo "$KEY" | xargs)
        VALUE=$(echo "$VALUE" | xargs)
        
        # Construct the full key path (e.g., /org/gnome/desktop/session/idle-delay)
        FULL_KEY="/${NAMESPACE}/${KEY}"
        
        # Escape single quotes in the value for safe SQL insertion
        SAFE_VALUE=$(echo "$VALUE" | sed "s/'/''/g")
        
        echo "Inserting: $FULL_KEY = $SAFE_VALUE"
        
        SQL_STATEMENTS+="INSERT OR REPLACE INTO $TABLE_NAME (key, value) VALUES ('$FULL_KEY', '$SAFE_VALUE');"$'\n'
    fi
done <<< "$DCONF_DUMP"

SQL_STATEMENTS+="COMMIT;"

#########################
# Execute the SQL transaction
#########################
echo "Executing SQL transaction..."
echo "$SQL_STATEMENTS" | sqlite3 "$DB_FILE"

echo "dconf settings have been saved to $DB_FILE."
echo "Total entries inserted:"
sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM $TABLE_NAME;"
