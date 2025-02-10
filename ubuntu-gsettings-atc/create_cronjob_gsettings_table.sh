#!/bin/sh

# Define the path for the script that the cron job will execute
EXECUTABLE_SCRIPT_PATH="/usr/local/bin/fleet/create_gsettings_database.sh"

# Ensure the directory for the executable script exists
EXECUTABLE_DIR="/usr/local/bin/fleet"
if [ ! -d "$EXECUTABLE_DIR" ]; then
    echo "Directory $EXECUTABLE_DIR does not exist. Creating it now..."
    sudo mkdir -p "$EXECUTABLE_DIR"
    sudo chown $USER:$USER "$EXECUTABLE_DIR"  # Ensure the current user owns the directory
fi

# Check if sqlite3 is installed; if not, install it
if ! command -v sqlite3 > /dev/null 2>&1; then
    echo "sqlite3 could not be found. Installing it now..."
    sudo apt update && sudo apt install -y sqlite3
else
    echo "sqlite3 is already installed."
fi

# Write out the executable script that creates/updates the gsettings database
cat << 'EOF' > $EXECUTABLE_SCRIPT_PATH
#!/bin/sh

# If running as root, determine the current (non-root) user so that dconf dump returns that user’s settings.
if [ "$(id -u)" -eq 0 ]; then
    if [ -n "$SUDO_USER" ]; then
        CURRENT_USER="$SUDO_USER"
    else
        CURRENT_USER=$(logname 2>/dev/null)
    fi
else
    CURRENT_USER=$(whoami)
fi

echo "Using user: $CURRENT_USER for dconf dump."

# Get the UID for the target user and set up the DBus session bus address
USER_UID=$(id -u "$CURRENT_USER")
export DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$USER_UID/bus"

# Define the SQLite database and table name for gsettings (dconf) data
DB_DIR="/usr/local/bin/fleet"
DB_NAME="dconf_settings.db"
DB_PATH="$DB_DIR/$DB_NAME"
TABLE_NAME="settings"

# Ensure the database directory exists
if [ ! -d "$DB_DIR" ]; then
    echo "Directory $DB_DIR does not exist. Creating it now..."
    mkdir -p "$DB_DIR"
fi

# Retrieve the dconf dump as the target user. When running as root, we use sudo -u.
if [ "$(id -u)" -eq 0 ]; then
    DCONF_DUMP=$(sudo -u "$CURRENT_USER" env DBUS_SESSION_BUS_ADDRESS="$DBUS_SESSION_BUS_ADDRESS" dconf dump /)
else
    DCONF_DUMP=$(dconf dump /)
fi

if [ -z "$DCONF_DUMP" ]; then
    echo "dconf dump returned nothing. Exiting..."
    exit 1
fi

echo "dconf dump retrieved; processing..."

# Create (or drop & recreate) the SQLite table for storing settings
sqlite3 "$DB_PATH" <<SQL
DROP TABLE IF EXISTS $TABLE_NAME;
CREATE TABLE IF NOT EXISTS $TABLE_NAME (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT UNIQUE NOT NULL,
    value TEXT NOT NULL
);
SQL

# Clear any existing data in the table before inserting updated settings
sqlite3 "$DB_PATH" "DELETE FROM $TABLE_NAME;"

# Build SQL statements for inserting data using a transaction.
# We accumulate the SQL commands into a variable.
SQL_STATEMENTS="BEGIN TRANSACTION;
"
NAMESPACE=""

# Process the dconf dump line by line. The dump format has section headers like [org/gnome/desktop/session]
# followed by key=value pairs.
echo "$DCONF_DUMP" | while IFS= read -r line; do
    # Trim leading and trailing whitespace
    trimmed_line=$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    # Skip empty lines
    if [ -z "$trimmed_line" ]; then
        continue
    fi
    # If the line is a namespace header (e.g. [org/gnome/desktop/session])
    case "$trimmed_line" in
        \[*\])
            # Remove the brackets to extract the namespace
            NAMESPACE=$(echo "$trimmed_line" | sed 's/^\[\(.*\)\]$/\1/')
            echo "Found namespace: $NAMESPACE"
            ;;
        *=*)
            # Extract the key and value (everything before and after the first '=')
            KEY=$(echo "$trimmed_line" | cut -d'=' -f1 | xargs)
            VALUE=$(echo "$trimmed_line" | cut -d'=' -f2- | xargs)
            # Construct the full key path (e.g., /org/gnome/desktop/session/idle-delay)
            FULL_KEY="/${NAMESPACE}/${KEY}"
            # Escape any single quotes in the value for safe SQL insertion
            SAFE_VALUE=$(echo "$VALUE" | sed "s/'/''/g")
            SQL_STATEMENTS="$SQL_STATEMENTS
INSERT OR REPLACE INTO $TABLE_NAME (key, value) VALUES ('$FULL_KEY', '$SAFE_VALUE');"
            ;;
    esac
done

SQL_STATEMENTS="$SQL_STATEMENTS
COMMIT;"

# Execute the accumulated SQL transaction
echo "$SQL_STATEMENTS" | sqlite3 "$DB_PATH"

echo "dconf settings have been successfully inserted into the $DB_PATH database."
EOF

# Make the new gsettings (dconf) script executable
chmod 744 $EXECUTABLE_SCRIPT_PATH

# Run the script immediately
$EXECUTABLE_SCRIPT_PATH

# Create a cron job that runs every 6 hours to update the database
CRON_JOB="0 */6 * * * $EXECUTABLE_SCRIPT_PATH"
(crontab -l 2>/dev/null | grep -F "$EXECUTABLE_SCRIPT_PATH") || \
  (crontab -l 2>/dev/null; echo "$CRON_JOB") | crontab -
