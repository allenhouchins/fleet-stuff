#!/bin/bash

# Define the SQLite database and table name
DB_NAME="snap_list.db"
TABLE_NAME="snap_packages"

# Run the snap list command and store the output
SNAP_LIST=$(snap list)

# Check if sqlite3 is installed
if ! command -v sqlite3 &> /dev/null
then
    echo "sqlite3 could not be found. Please install it using 'sudo apt install sqlite3'."
    exit
fi

# Create the SQLite database and table if it doesn't exist
sqlite3 $DB_NAME <<EOF
CREATE TABLE IF NOT EXISTS $TABLE_NAME (
    name TEXT,
    version TEXT,
    rev TEXT,
    tracking TEXT,
    publisher TEXT,
    notes TEXT
);
EOF

# Clear the existing data in the table before inserting new data
sqlite3 $DB_NAME <<EOF
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
    sqlite3 $DB_NAME <<EOF
    INSERT INTO $TABLE_NAME (name, version, rev, tracking, publisher, notes)
    VALUES ('$NAME', '$VERSION', '$REV', '$TRACKING', '$PUBLISHER', '$NOTES');
EOF
done

echo "Snap list data has been successfully inserted into the $DB_NAME database."

