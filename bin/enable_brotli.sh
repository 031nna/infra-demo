#!/bin/bash 
# enable_brotli.sh

# Read JSON from stdin
input=$(cat)
api_token=$(echo "$input" | jq -r '.api_token')
zone_id=$(echo "$input" | jq -r '.zone_id')  # You can pass ZONE_ID similarly through the query if needed

# Run the command to enable Brotli (your command might differ)
response=$(curl -s -X PATCH "https://api.cloudflare.com/client/v4/zones/$zone_id/settings/brotli" \
    -H "Authorization: Bearer $api_token" \
    -H "Content-Type: application/json" \
    --data '{"value":"on"}')

# Check if the response indicates success
if [[ $response == *"\"success\":true"* ]]; then
    echo '{"status":"enabled"}'
else
    echo '{"status":"failed"}'
fi
