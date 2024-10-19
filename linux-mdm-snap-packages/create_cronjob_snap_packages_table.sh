#!/bin/sh

# Create a script that will be executed by the cron job
EXECUTABLE_SCRIPT_PATH="/usr/local/bin/fleet/create_snap_database.sh"

cat << 'EOF' > $EXECUTABLE_SCRIPT_PATH
#!/bin/sh

# Define the SQLite database and table name
DB_DIR="/var/fleet"
DB_NAME="snap_list.db"
DB_PATH="$DB_DIR/$DB_NAME"
TABLE_NAME="snap_packages"

# Run the snap list command and store the output
SNAP_LIST=$(snap list)

# Check if sqlite3 is installed
if ! command -v sqlite3 &> /dev/null
then
    echo "sqlite3 could not be found. Please install it using 'sudo apt install sqlite3'."
    exit
fi

# Check if the /var/fleet directory exists, if not, create it
if [ ! -d "$DB_DIR" ]; then
    echo "Directory $DB_DIR does not exist. Creating it now..."
    sudo mkdir -p "$DB_DIR"
    sudo chown $USER:$USER "$DB_DIR"  # Ensure the current user owns the directory
fi

# Check if the database already exists
if [ -f "$DB_PATH" ]; then
    echo "Database $DB_PATH already exists."
else
    echo "Creating database at $DB_PATH..."
    # Create the SQLite database and table
    sqlite3 "$DB_PATH" <<EOF
CREATE TABLE IF NOT EXISTS $TABLE_NAME (
    name TEXT,
    version TEXT,
    rev TEXT,
    tracking TEXT,
    publisher TEXT,
    notes TEXT
);
EOF
fi

# Clear the existing data in the table before inserting new data
sqlite3 "$DB_PATH" <<EOF
DELETE FROM $TABLE_NAME;
EOF

# Parse the snap list output and insert into the SQLite database
# Skip the first two lines (header and separator)
echo "$SNAP_LIST" | tail -n +3 | while read -r line
do
    # Split the line into columns
    NAME=$(echo $line | awk '{print $1}')
    VERSION=$(echo $line | awk '{print $2}')
    REV=$(echo $line | awk '{print $3}')
    TRACKING=$(echo $line | awk '{print $4}')
    PUBLISHER=$(echo $line | awk '{print $5}')
    NOTES=$(echo $line | awk '{print $6}')

    # Insert data into the SQLite table
    sqlite3 "$DB_PATH" <<EOF
    INSERT INTO $TABLE_NAME (name, version, rev, tracking, publisher, notes)
    VALUES ('$NAME', '$VERSION', '$REV', '$TRACKING', '$PUBLISHER', '$NOTES');
EOF
done

echo "Snap list data has been successfully inserted into the $DB_PATH database."
EOF

# Make the script executable
chmod +x $EXECUTABLE_SCRIPT_PATH

# Create a cron job that runs every 6 hours
CRON_JOB="0 */6 * * * $EXECUTABLE_SCRIPT_PATH"

# Add the cron job to the crontab (if not already present)
(crontab -l; echo "$CRON_JOB") | sort -u | crontab -