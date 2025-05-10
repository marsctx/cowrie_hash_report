#!/bin/bash

# Capture the arguments
file_hash="$1"
log_file_path="$2"

# Execute the jq command to filter the log file
cat "$log_file_path" | jq --arg hash "$file_hash" 'select(.shasum == $hash) | [.src_ip, .timestamp, .session, .url]' | sed 's/"//g'
