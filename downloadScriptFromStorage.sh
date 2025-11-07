#!/bin/bash

# Storage Variables
storage_account=$1 # eg "arcserversukssa"
container_name=$2 # eg "scripts"
blob_name=$3 # eg "preflightchecks.sh"
local_file=$4 # eg "preflightchecks.sh"

ACCESS_TOKEN=$(./getAccessToken.sh "https://storage.azure.com/")

if [[ -n "$ACCESS_TOKEN" ]]; then
    echo "Access token: $ACCESS_TOKEN"
else
    echo "Failed to retrieve storage access token."
    echo "Response: $RESPONSE"
    exit 1
fi

# Construct the blob URL
blob_url="https://${storage_account}.blob.core.windows.net/${container_name}/${blob_name}"

echo "Downloading blob from URL: $blob_url to local file: $local_file"

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