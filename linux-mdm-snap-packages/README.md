# atc_tables.json
This is for testing through osquery by running this command: osqueryi --verbose --config_path /path/to/atc_tables.json

# create_snap_database.sh
This script should be distributed to all Ubuntu hosts and run via a cronjob to populate the database periodically. This has only been tested on Ubuntu 24.04 Desktop. 

# fleet_agent_options
Copy this into a the agent options for a specific Team in Fleet. Settings > Teams > select the team > Agent options

# snap_packages.ext
This file can be used as a baseline to compile a new version of osquery that has this snap_packages table built in natively.

# fleet_output.png
This is what results should look like in Fleet UI.

# osquery_output.png
This is what results should look like when testing via osquery. 
