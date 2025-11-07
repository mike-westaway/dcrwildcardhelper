#!/bin/bash

# Config
# This is the IMDS endpoint used by the System Managed Identity to get tokens
API_VERSION="2020-06-01"
RESOURCE="https://storage.azure.com/"
IDENTITY_ENDPOINT="${IDENTITY_ENDPOINT:-http://localhost:40342/metadata/identity/oauth2/token}"
ENDPOINT="${IDENTITY_ENDPOINT}?resource=${RESOURCE}&api-version=${API_VERSION}"

# Storage Variables
storage_account=$1 # eg "arcserversukssa"
container_name=$2 # eg "scripts"
blob_name=$3 # eg "preflightchecks.sh"
local_file=$4 # eg "preflightchecks.sh"

# Step 1: Make unauthenticated request to get WWW-Authenticate header
WWW_AUTH_HEADER=$(curl -s -D - -o /dev/null -H "Metadata: true" "$ENDPOINT" | grep -i "WWW-Authenticate")

# Step 2: Extract secret file path from header
SECRET_FILE=""
if [[ $WWW_AUTH_HEADER =~ Basic\ realm=([^\ ]+) ]]; then
    # get rid of '$\r' at end of line
    SECRET_FILE=$(echo ${BASH_REMATCH[1]} | sed 's/[$\r]*$//')
    echo "Secret file path: $SECRET_FILE"
else
    echo "Failed to extract secret file path from WWW-Authenticate header."
    exit 1
fi

# Step 3: Read secret
if [[ ! -f "$SECRET_FILE" ]]; then
    echo "Secret file not found: $SECRET_FILE"
    exit 1
fi

SECRET=$(cat "$SECRET_FILE")

# Step 4: Make authenticated request with Basic token
RESPONSE=$(curl -s -H "Metadata: true" -H "Authorization: Basic $SECRET" "$ENDPOINT")

# Step 5: Extract access token
ACCESS_TOKEN=$(echo "$RESPONSE" | grep -oP '"access_token"\s*:\s*"\K[^"]+')

if [[ -n "$ACCESS_TOKEN" ]]; then
    echo "Access token: $ACCESS_TOKEN"
else
    echo "Failed to retrieve access token."
    echo "Response: $RESPONSE"
    exit 1
fi

# Construct the blob URL
blob_url="https://${storage_account}.blob.core.windows.net/${container_name}/${blob_name}"

# Use curl to download the blob with the access token
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
     -H "x-ms-version: 2020-10-02" \
     "$blob_url" -o "$local_file"

if [[ $local_file == *.sh ]]; then
    chmod +x "$local_file"
    # clean up the line ends
    sed -i 's/\r$//' "./$local_file"
fi

# run the script, output to a log file
echo "Executing script: $local_file"
"./$local_file" > "${local_file%.sh}.log" 2>&1
 
# upload the log file back to the storage account
log_blob_name="${blob_name%.sh}.log"
log_blob_url="https://${storage_account}.blob.core.windows.net/${container_name}/${log_blob_name}"
curl -X PUT -H "Authorization: Bearer $ACCESS_TOKEN" \
     -H "x-ms-version: 2020-10-02" \
     -H "x-ms-blob-type: BlockBlob" \
     --data-binary @"${local_file%.sh}.log" \
     "$log_blob_url"

echo "Log file uploaded to blob: $log_blob_name"