#!/bin/bash

# Config
# This is the IMDS endpoint used by the System Managed Identity to get tokens
API_VERSION="2020-06-01"
RESOURCE=$1 # eg "https://storage.azure.com/"
IDENTITY_ENDPOINT="${IDENTITY_ENDPOINT:-http://localhost:40342/metadata/identity/oauth2/token}"
ENDPOINT="${IDENTITY_ENDPOINT}?resource=${RESOURCE}&api-version=${API_VERSION}"

# Step 1: Make unauthenticated request to get WWW-Authenticate header
WWW_AUTH_HEADER=$(curl -s -D - -o /dev/null -H "Metadata: true" "$ENDPOINT" | grep -i "WWW-Authenticate")

# Step 2: Extract secret file path from header
SECRET_FILE=""
if [[ $WWW_AUTH_HEADER =~ Basic\ realm=([^\ ]+) ]]; then
    # get rid of '$\r' at end of line
    SECRET_FILE=$(echo ${BASH_REMATCH[1]} | sed 's/[$\r]*$//')
    # if this utility is successful then it returns only the ACCESS_TOKEN
    #echo "Secret file path: $SECRET_FILE"
else
    echo "Failed to extract secret file path from WWW-Authenticate header."
    exit 1
fi

# Step 3: Read secret
if [[ ! -f "$SECRET_FILE" ]]; then
    echo "Secret file not found: $SECRET_FILE"
    exit 1
fi

# Need IMDS Group member or root permissions to read the secret file
SECRET=$(cat "$SECRET_FILE")

# Step 4: Make authenticated request with Basic token
RESPONSE=$(curl -s -H "Metadata: true" -H "Authorization: Basic $SECRET" "$ENDPOINT")

# Step 5: Extract access token
ACCESS_TOKEN=$(echo "$RESPONSE" | grep -oP '"access_token"\s*:\s*"\K[^"]+')

if [[ -n "$ACCESS_TOKEN" ]]; then
    echo "$ACCESS_TOKEN"
else
    echo "Failed to retrieve access token."
    echo "Response: $RESPONSE"
    exit 1
fi
