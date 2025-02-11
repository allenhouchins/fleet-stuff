# Overview
This folder contains all the pieces you need to query a custom table in Fleet (or osquery) called ```gsettings```. This should fill the gap until this feature is implemented: [https://github.com/fleetdm/fleet/issues/22658](https://github.com/fleetdm/fleet/issues/22823)

### atc_tables.json
This is for testing through osquery by running this command: ```osqueryi --verbose --config_path /path/to/atc_tables.json```

### create_gsettings_database.sh
This script should be deployed to all Ubuntu hosts and run as root via a cron job. It retrieves the currently logged‑in user's gsettings (dconf) settings and populates a SQLite database located at /usr/local/bin/fleet/dconf_settings.db.. ** This has only been tested on Ubuntu 24.04 Desktop. **

### create_cronjob_gsettings_database.sh
This script creates a cron job that runs create_gsettings_database.sh every 6 hours. To deploy via Fleet, upload this script and create a Policy with the following query: ```SELECT 1 FROM file WHERE path = "/usr/local/bin/fleet/dconf_settings.db";``` and set the script to run through Policy automation. ** This has only been tested on Ubuntu 24.04 Desktop. **

### fleet_agent_options
Copy this into the Agent options for a specific Team in Fleet. Settings > Teams > select the team > Agent options
