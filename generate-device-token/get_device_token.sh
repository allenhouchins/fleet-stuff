#!/bin/bash
# Script to generate and register a Fleet Desktop device token
# Works on macOS and Linux
#
# Usage:
#   ./get_device_token.sh [FLEET_URL]
#
# Environment variables:
#   ORBIT_ROOT_DIR - Orbit root directory (default: /opt/orbit)
#   FLEET_URL - Fleet server URL (required if not provided as argument)
#   FLEET_CERTIFICATE - Path to Fleet server certificate (optional)
#   FLEET_INSECURE - Set to "1" to skip TLS verification (optional)

set -e

# Default Orbit root directory
ORBIT_ROOT="${ORBIT_ROOT_DIR:-/opt/orbit}"
NODE_KEY_FILE="${ORBIT_ROOT}/secret-orbit-node-key.txt"
TOKEN_FILE="${ORBIT_ROOT}/identifier"

# Get Fleet URL from argument or environment variable
FLEET_URL="${1:-${FLEET_URL}}"

if [ -z "$FLEET_URL" ]; then
    echo "Error: Fleet URL is required" >&2
    echo "Usage: $0 [FLEET_URL]" >&2
    echo "Or set FLEET_URL environment variable" >&2
    exit 1
fi

# Ensure Fleet URL doesn't have trailing slash
FLEET_URL="${FLEET_URL%/}"

# Check if orbit node key file exists
if [ ! -f "$NODE_KEY_FILE" ]; then
    echo "Error: Orbit node key file not found at $NODE_KEY_FILE" >&2
    echo "Orbit must be enrolled first. The node key file should exist." >&2
    exit 1
fi

# Read the orbit node key (may require sudo if file is root-owned)
if [ -r "$NODE_KEY_FILE" ]; then
    ORBIT_NODE_KEY=$(cat "$NODE_KEY_FILE" | tr -d '\n\r ')
elif command -v sudo >/dev/null 2>&1; then
    # Try with sudo if file is not readable
    ORBIT_NODE_KEY=$(sudo cat "$NODE_KEY_FILE" 2>/dev/null | tr -d '\n\r ')
else
    echo "Error: Cannot read orbit node key file at $NODE_KEY_FILE" >&2
    echo "File may require root permissions. Please run with sudo or ensure file is readable." >&2
    exit 1
fi

if [ -z "$ORBIT_NODE_KEY" ]; then
    echo "Error: Orbit node key file is empty or could not be read" >&2
    echo "You may need to run this script with sudo: sudo $0 $@" >&2
    exit 1
fi

# Generate a new UUID for the device token
if command -v uuidgen >/dev/null 2>&1; then
    DEVICE_TOKEN=$(uuidgen)
elif [ -f /proc/sys/kernel/random/uuid ]; then
    # Linux kernel UUID
    DEVICE_TOKEN=$(cat /proc/sys/kernel/random/uuid)
else
    echo "Error: Cannot generate UUID. Please install uuidgen." >&2
    echo "On macOS: uuidgen should be available by default." >&2
    echo "On Linux: install uuid-runtime package." >&2
    exit 1
fi

# Check if curl is available
if ! command -v curl >/dev/null 2>&1; then
    echo "Error: curl is required but not found. Please install curl." >&2
    exit 1
fi

# Prepare JSON payload using a temporary file for better handling
TMP_JSON=$(mktemp)
trap "rm -f $TMP_JSON" EXIT

cat > "$TMP_JSON" <<EOF
{
  "orbit_node_key": "$ORBIT_NODE_KEY",
  "device_auth_token": "$DEVICE_TOKEN"
}
EOF

# Build curl command
CURL_ARGS=(-s -w "\n%{http_code}" -X POST)
CURL_ARGS+=(-H "Content-Type: application/json")

# Add TLS certificate if provided
if [ -n "$FLEET_CERTIFICATE" ]; then
    CURL_ARGS+=(--cacert "$FLEET_CERTIFICATE")
elif [ "${FLEET_INSECURE:-0}" = "1" ]; then
    CURL_ARGS+=(--insecure)
fi

# Add data and URL
CURL_ARGS+=(-d "@$TMP_JSON")
CURL_ARGS+=("${FLEET_URL}/api/fleet/orbit/device_token")

# Make the API request
RESPONSE=$(curl "${CURL_ARGS[@]}" 2>&1)

# Extract HTTP status code (last line)
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')

# Check if request was successful
if [ "$HTTP_CODE" != "200" ]; then
    echo "Error: Failed to register device token" >&2
    echo "HTTP Status: $HTTP_CODE" >&2
    echo "Response: $BODY" >&2
    exit 1
fi

# Check for error in response body
if echo "$BODY" | grep -q '"error"'; then
    echo "Error: Server returned an error" >&2
    echo "Response: $BODY" >&2
    exit 1
fi

# Save the token to the identifier file (may require sudo)
if [ -w "$ORBIT_ROOT" ] || [ -w "$(dirname "$TOKEN_FILE")" ] 2>/dev/null; then
    mkdir -p "$ORBIT_ROOT"
    echo -n "$DEVICE_TOKEN" > "$TOKEN_FILE"
    chmod 644 "$TOKEN_FILE"
else
    echo "Warning: Cannot write to $TOKEN_FILE directly. Attempting with sudo..." >&2
    if command -v sudo >/dev/null 2>&1; then
        sudo mkdir -p "$ORBIT_ROOT"
        echo -n "$DEVICE_TOKEN" | sudo tee "$TOKEN_FILE" > /dev/null
        sudo chmod 644 "$TOKEN_FILE"
    else
        echo "Error: Cannot write to $TOKEN_FILE. Please run this script with sudo:" >&2
        echo "  sudo $0 $@" >&2
        exit 1
    fi
fi

echo "Successfully generated and registered device token"
echo "Token saved to: $TOKEN_FILE"
echo "Device token: $DEVICE_TOKEN"

