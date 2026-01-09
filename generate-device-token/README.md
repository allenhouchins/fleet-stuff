# Fleet Desktop Device Token Generation Script

This directory contains a bash script to generate and register a Fleet Desktop device token with your Fleet server. This script is useful when Fleet Desktop is not enabled, but you still need to generate the device token identifier file.

## Overview

The script:
1. Reads the Orbit node key from `secret-orbit-node-key.txt`
2. Generates a new UUID device token
3. Registers the token with Fleet via the API endpoint `POST /api/fleet/orbit/device_token`
4. Saves the token to the `identifier` file (used by Fleet Desktop)

## Prerequisites

- **Orbit must be enrolled** - The `secret-orbit-node-key.txt` file must exist in your Orbit root directory
- **Network access** to your Fleet server
- **Appropriate permissions** - May require `sudo` to read the node key file and write the identifier file
- **curl** - Required for making HTTP requests
- **uuidgen** - Required for UUID generation (or Linux kernel UUID support)

## Script

### `get_device_token.sh` (Bash)
- **Platform**: macOS, Linux
- **Requirements**: 
  - `curl` (for HTTP requests)
  - `uuidgen` (for UUID generation on macOS)
  - Linux kernel UUID support via `/proc/sys/kernel/random/uuid` (for Linux)
- **Permissions**: May require `sudo` to read node key and write identifier file

## Usage

### Bash Script

```bash
# Make executable (if not already)
chmod +x get_device_token.sh

# Run with Fleet URL
sudo ./get_device_token.sh https://fleet.example.com

# Or use environment variable
export FLEET_URL=https://fleet.example.com
sudo ./get_device_token.sh
```

## Environment Variables

The script supports the following environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `FLEET_URL` | Fleet server URL (required if not provided as argument) | None |
| `ORBIT_ROOT_DIR` | Custom Orbit root directory | `/opt/orbit` |
| `FLEET_CERTIFICATE` | Path to Fleet server certificate file (optional) | None |
| `FLEET_INSECURE` | Set to `"1"` to skip TLS verification (not recommended) | `"0"` |

### Examples with Environment Variables

```bash
export ORBIT_ROOT_DIR=/custom/path/to/orbit
export FLEET_CERTIFICATE=/path/to/cert.pem
export FLEET_URL=https://fleet.example.com
sudo ./get_device_token.sh
```

## Default File Locations

### Unix (macOS/Linux)
- Orbit root: `/opt/orbit`
- Node key file: `/opt/orbit/secret-orbit-node-key.txt`
- Token file: `/opt/orbit/identifier`

## How It Works

1. **Read Orbit Node Key**: The script reads the Orbit node key from `secret-orbit-node-key.txt`. This key is used to authenticate with Fleet. The script will attempt to read the file directly, and if that fails, it will try using `sudo`.

2. **Generate Device Token**: A new UUID (v4) is generated for the device token using one of the following methods:
   - `uuidgen` command (if available, typically on macOS)
   - Linux kernel UUID via `/proc/sys/kernel/random/uuid` (if available on Linux)
   - If neither is available, the script will exit with an error

3. **Register with Fleet**: The script makes a POST request to:
   ```
   POST {FLEET_URL}/api/fleet/orbit/device_token
   ```
   With the following JSON payload:
   ```json
   {
     "orbit_node_key": "...",
     "device_auth_token": "uuid-here"
   }
   ```

4. **Save Token**: If registration is successful, the token is saved to the `identifier` file with appropriate permissions (644 on Unix). The script will attempt to write directly, and if that fails, it will try using `sudo`.

## Troubleshooting

### Permission Denied Errors

**Unix systems:**
```bash
# The node key file is typically owned by root with restricted permissions
# Run the script with sudo:
sudo ./get_device_token.sh https://fleet.example.com
```

### Cannot Read Node Key File

**Error**: `Orbit node key file not found at /opt/orbit/secret-orbit-node-key.txt`

**Solution**: 
- Ensure Orbit is enrolled
- Check that the file exists: `ls -la /opt/orbit/secret-orbit-node-key.txt`
- If using a custom location, set `ORBIT_ROOT_DIR` environment variable

### Network/Connection Errors

**Error**: `Failed to connect to Fleet server`

**Solutions**:
- Verify the Fleet URL is correct and accessible
- Check firewall rules
- If using a self-signed certificate, set `FLEET_INSECURE=1` (not recommended for production)
- For custom certificates, use `FLEET_CERTIFICATE` environment variable

### UUID Generation Fails

**Error**: `Cannot generate UUID`

**Solutions**:
- **macOS**: `uuidgen` should be available by default. If not, install via Homebrew: `brew install ossp-uuid`
- **Linux**: Install `uuid-runtime` package:
  - Debian/Ubuntu: `sudo apt-get install uuid-runtime`
  - RHEL/CentOS: `sudo yum install util-linux` (uuidgen is part of util-linux)

### HTTP 401 Unauthorized

**Error**: `HTTP Status: 401`

**Solutions**:
- Verify the Orbit node key is valid
- Ensure Orbit is properly enrolled with Fleet
- Check that the node key file contains the correct key

### HTTP 400 Bad Request

**Error**: `HTTP Status: 400`

**Solutions**:
- Verify the device token format (should be a valid UUID)
- Check that the request payload is correctly formatted
- Ensure the Fleet server supports the device token endpoint

## API Endpoint Details

The script calls the following Fleet API endpoint:

- **Method**: `POST`
- **Path**: `/api/fleet/orbit/device_token`
- **Authentication**: Uses `orbit_node_key` in the request body
- **Request Body**:
  ```json
  {
    "orbit_node_key": "your-orbit-node-key",
    "device_auth_token": "generated-uuid"
  }
  ```
- **Response**: 
  - Success: `200 OK` with empty or minimal JSON response
  - Error: `400/401/500` with error details in JSON

## Security Notes

- The Orbit node key file (`secret-orbit-node-key.txt`) is typically protected (600 permissions on Unix)
- The device token file (`identifier`) is world-readable (644 permissions) so Fleet Desktop can access it
- Device tokens rotate every hour automatically when Fleet Desktop is enabled
- Never commit these files to version control

## Examples

### Basic Usage
```bash
sudo ./get_device_token.sh https://fleet.example.com
```

### With Custom Certificate
```bash
export FLEET_CERTIFICATE=/path/to/fleet-cert.pem
sudo ./get_device_token.sh https://fleet.example.com
```

### With Custom Orbit Directory
```bash
export ORBIT_ROOT_DIR=/var/lib/orbit
export FLEET_URL=https://fleet.example.com
sudo ./get_device_token.sh
```

### Testing with Insecure Mode (Not Recommended)
```bash
export FLEET_INSECURE=1
sudo ./get_device_token.sh https://fleet.example.com
```

## Related Files

- `secret-orbit-node-key.txt` - Orbit node key (read by script)
- `identifier` - Device token file (written by script)
- Fleet API documentation for `/api/fleet/orbit/device_token`

## Support

For issues or questions:
1. Check that Orbit is properly enrolled
2. Verify network connectivity to Fleet server
3. Ensure you have appropriate permissions
4. Review Fleet server logs for API errors
5. Check the Fleet documentation for device token requirements
