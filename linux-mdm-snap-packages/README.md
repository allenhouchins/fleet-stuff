# Overview
This folder contains all the pieces you need to query a custom table in Fleet (or osquery) called ```snap_packages```. Currently Fleet and osquery have a ```deb_packages``` table but this do not include packages installed via ```snap``` (ex: "Ubuntu Software" Snap Store). This should fill the gap until this feature is implemented: https://github.com/fleetdm/fleet/issues/22658

### atc_tables.json
This is for testing through osquery by running this command: ```osqueryi --verbose --config_path /path/to/atc_tables.json```

### create_snap_database.sh
This script should be distributed to all Ubuntu hosts and run as root via a cron job to populate the database periodically. ** This has only been tested on Ubuntu 24.04 Desktop. **

### create_cronjob_snap_packages_database.sh
This script will create a cron job that runs the create_snap_database.sh on a 6 hour interval. To deliver via Fleet, upload this script, create a Policy with the following query ```SELECT 1 FROM file WHERE path = "/usr/local/bin/fleet/snap_list.db";``` and set the script to run through Policy automation. ** This has only been tested on Ubuntu 24.04 Desktop. **

### fleet_agent_options
Copy this into the Agent options for a specific Team in Fleet. Settings > Teams > select the team > Agent options

### snap_packages.cpp
This file can be used as a baseline to compile a new version of osquery that has the ```snap_packages``` table built in natively.

### fleet_output.png
![alt text](https://github.com/allenhouchins/fleet-stuff/blob/main/linux-mdm-snap-packages/fleet_ouput.png "Fleet output")

### osquery_output.png
![alt text](https://github.com/allenhouchins/fleet-stuff/blob/main/linux-mdm-snap-packages/osquery_output.png "osquery output")
