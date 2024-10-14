# Overview
This folder contains all the pieces you need to query a custom table in Fleet (or osquery) called ```snap_packages```. Currently Fleet and osquery have a ```deb_packages``` and ```rpm_packages``` table but these do not include packages installed via snap. This should fill the gap until this feature is implemented: https://github.com/fleetdm/fleet/issues/22658

### atc_tables.json
This is for testing through osquery by running this command: ```osqueryi --verbose --config_path /path/to/atc_tables.json```

### create_snap_database.sh
This script should be distributed to all Ubuntu hosts and run via a cronjob to populate the database periodically. ** This has only been tested on Ubuntu 24.04 Desktop. **

### fleet_agent_options
Copy this into the Agent options for a specific Team in Fleet. Settings > Teams > select the team > Agent options

### snap_packages.ext
This file can be used as a baseline to compile a new version of osquery that has the ```snap_packages``` table built in natively.

### fleet_output.png
![alt text](https://github.com/allenhouchins/fleet-stuff/blob/main/linux-mdm-snap-packages/fleet_ouput.png "Fleet output")

### osquery_output.png
![alt text](https://github.com/allenhouchins/fleet-stuff/blob/main/linux-mdm-snap-packages/osquery_output.png "osquery output")
