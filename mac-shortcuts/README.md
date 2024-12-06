# Overview
This folder contains all the pieces you need to query a custom table in Fleet (or osquery) called ```shortcuts_app```. By configuring Fleet (or osquery) with the settings found here, you will be able to query the contents of Apple Shortcuts on macOS.

### atc_tables.json
This is for testing through osquery by running this command: ```osqueryi --verbose --config_path /path/to/atc_tables.json```


### fleet_agent_options
Copy this into the Agent options for a specific Team in Fleet. Settings > Teams > select the team > Agent options
