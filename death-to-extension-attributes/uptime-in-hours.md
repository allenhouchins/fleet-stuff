# Uptime in Hours

The purpose of this Extension Attribute is to retrieve the uptime in hours for a macOS device.
 
## Extension Attribute:
```
#!/bin/sh

DAYS="days,"
HRS=" hrs"

DAYScheck=$(uptime | awk {'print $4'})

if [ $DAYScheck = "$DAYS" ]; then

result=$(uptime | awk {'print $3.$4.$5'} | sed 's/,/ /g' | sed 's/d/ d/g')

        echo "<result>$result$HRS</result>"

        else

result=$(uptime | awk {'print $3'} | sed 's/,//g')

        echo "<result>$result$HRS</result>"
fi

exit
```
## Fleet query:
```SELECT hours FROM uptime;```

Compatible with: ✅ macOS ✅ Windows ✅ Linux 🚫 ChromeOS
