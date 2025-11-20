#!/bin/bash

###
# save this to the configured Storage Account
###

###
# from getEarliestTimestamp.sh
###

function getEarliestTimestamp() {
    RESOURCE="https://api.loganalytics.io"

    # Note: Workspace Id not Name
    local WORKSPACE_ID=$1 # eg "b5b2874f-f4fb-4581-b606-af3b15af8fea" # "arc-servers-uks-law"

    local TABLE=$2 # eg "WaAgent3_CL "
    local COMPUTER=$3 # eg "jumpbox-linux"
    local FILEPATH=$4 # eg "/var/log/waagent.log"
    local TIMESTAMP_COLUMN=$5 # eg "TimeGenerated"
    local TIMESPAN=$6 # "P1D" # last 1 day
    local LOGFILE=$7 # eg "./getEarliestTimestamp.log"
    local IS_ARC_CONNECTED_MACHINE=$8 # "true" or "false"

    KQL="$TABLE | where Computer == '$COMPUTER' | where FilePath == '$FILEPATH' | summarize EarliestTimestamp=min($TIMESTAMP_COLUMN)"

    # note the values are enclosed in quoutes, which treats them as single strings in printf substitution
    PAYLOAD=$(printf '{ "query": "%s", "timespan": "%s" }' "$KQL" "$TIMESPAN")

    # Get the Entra access token
    if [ "$IS_ARC_CONNECTED_MACHINE" = "true" ] ; then
        ACCESS_TOKEN=$(getAccessTokenArc $RESOURCE)
    else
        ACCESS_TOKEN=$(getAccessTokenAzure $RESOURCE)
    fi

    KQL_RESULT=$(curl -X POST "$RESOURCE/v1/workspaces/$WORKSPACE_ID/query" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD")

    TIMESTAMP=$(echo $KQL_RESULT | awk -F'"rows":\\[\\["|"]]}' '{print $2}')

    echo "Access Token (trunc): ${ACCESS_TOKEN:0:10}..." > $LOGFILE
    echo "KQL Query: $KQL" >> $LOGFILE
    echo "Payload: $PAYLOAD" >> $LOGFILE
    echo "KQL Result: $KQL_RESULT" >> $LOGFILE
    echo "Earliest timestamp for $FILEPATH on $COMPUTER is:" >> $LOGFILE
    echo $TIMESTAMP >> $LOGFILE

    echo $TIMESTAMP
}

###
# from log2json.sh
###
function log2json() {
    local log_file=$1 # eg "/var/log/waagent.log"
    local output_prefix=$2 # eg "waagent_log"
    local maximum_timestamp=$3 # eg "2024-06-15T12:00:00Z"  
    local returnArr=()  # Initialize empty array
    
    max_size=$((1024 * 1024)) # 1 MB in bytes

    # Get today's date in the same format as the log timestamp (assuming YYYY-MM-DD)
    today=$(date +"%Y-%m-%d")

    file_index=1
    current_file="${output_prefix}_${file_index}.json"

    # add first file to return array
    returnArr+=("$current_file")

    echo "[" > "$current_file"
    first_line=true

    current_size=$(stat -c%s "$current_file")

    while IFS= read -r line; do
        timestamp=$(echo "$line" | awk '{print $1}')

        # Convert to epoch seconds
        epoch_timestamp=$(date -d "$timestamp" +%s 2>&1)

        if [[ $? -ne 0 ]]; then
            # If date conversion fails, skip this line
            continue
        fi

        epoch_maximum=$(date -d "$maximum_timestamp" +%s 2>&1)

        if [[ $? -ne 0 ]]; then
            # If date conversion fails, skip this line
            continue
        fi

        # Skip lines that don't match today's date
        if [[ "$timestamp" != "$today"* ]]; then
            continue
        fi

        # Skip lines with timestamp greater than or equal to maximum_timestamp
        if [[ $epoch_timestamp -ge $epoch_maximum ]]; then
            continue
        fi

        # replace quote with \"
        # replace backslashed quote with \\ and \"
        raw_data=$(echo "$line" | sed 's/\"/\\\"/g; s/\\\\\"/\\\\\\\"/g')

        json_line="  {\"TimeGenerated\": \"$timestamp\", \"RawData\": \"$raw_data\"}"

        # Add comma if not first line
        if [ "$first_line" = true ]; then
            first_line=false
        else
            json_line=",$json_line"
        fi

        # Check if adding this line exceeds max size
        if (( current_size + ${#json_line} > max_size )); then
            echo "]" >> "$current_file"
            file_index=$((file_index + 1))
            current_file="${output_prefix}_${file_index}.json"

            # add new file to return array
            returnArr+=("$current_file")
    
            echo "[" > "$current_file"
            first_line=true
            current_size=$(stat -c%s "$current_file")
        fi

        echo "$json_line" >> "$current_file"
        current_size=$(stat -c%s "$current_file")
    done < "$log_file"

    echo "]" >> "$current_file"

    # return the array of generated files
    echo "${returnArr[@]}"
}

###
# from getAccessToken.sh
###
function getAccessTokenArc() {
    local RESOURCE=$1 # eg "https://storage.azure.com/"
    # Config
    # This is the IMDS endpoint used by the System Managed Identity to get tokens
    API_VERSION="2020-06-01"
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
}

function getAccessTokenAzure() {
    local RESOURCE=$1 # eg "https://storage.azure.com/"
    # Config
    # This is the IMDS endpoint used by the System Managed Identity to get tokens
    API_VERSION="2020-06-01"
    IDENTITY_ENDPOINT="${IDENTITY_ENDPOINT:-http://169.254.169.254/metadata/identity/oauth2/token}"
    ENDPOINT="${IDENTITY_ENDPOINT}?resource=${RESOURCE}&api-version=${API_VERSION}"

    # Step 4: Make authenticated request with Basic token
    RESPONSE=$(curl -s -H "Metadata: true" "$ENDPOINT")

    # Step 5: Extract access token
    ACCESS_TOKEN=$(echo "$RESPONSE" | grep -oP '"access_token"\s*:\s*"\K[^"]+')

    if [[ -n "$ACCESS_TOKEN" ]]; then
        echo "$ACCESS_TOKEN"
    else
        echo "Failed to retrieve access token."
        echo "Response: $RESPONSE"
        exit 1
    fi
}

###
# from ingestJson.sh
###
function ingestJson() {
    local DCR_IMMUTABLE_ID=$1 # eg"dcr-00000000000000000000000000"
    local TABLE_NAME=$2 # eg "WaAgent3_CL"
    local ENDPOINT_URI=$3 # eg "https://my-endpoint.uksouth-1.ingest.monitor.azure.com" 
    local JSON_LOG_FILE=$4 # eg "waagent_log_1.json"
    local IS_ARC_CONNECTED_MACHINE=$5 # "true" or "false"

    RESOURCE="https://monitor.azure.com"

    # Get the Entra access token
    if [[ "$IS_ARC_CONNECTED_MACHINE" == "true" ]]; then
        TOKEN=$(getAccessTokenArc $RESOURCE)
    else
        TOKEN=$(getAccessTokenAzure $RESOURCE)
    fi

    #name of the stream in the DCR that represents the destination table
    STREAM_NAME="Custom-Text-$TABLE_NAME" 

    # Build the URI
    URI="$ENDPOINT_URI/dataCollectionRules/$DCR_IMMUTABLE_ID/streams/${STREAM_NAME}?api-version=2023-01-01"

    echo "injestJson $DCR_IMMUTABLE_ID $TABLE_NAME $URI $JSON_LOG_FILE $IS_ARC_CONNECTED_MACHINE ${TOKEN:0:10}"

    # upload the JSON logs
    # there is a limit of 1 MB on the payload
    # the script used to create the JSON from log entries is aware of this and splits the file as required
    curl -X POST "${URI}" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer ${TOKEN}" \
            -d @$JSON_LOG_FILE

}

###
# main loop
###
workspaceId=$1
computerName=$2
sourceLogFile=$3
targetTable=$4
dcrImmutableId=$5
endpointUri=$6
timestampColumn=$7
timeSpan=$8
isArcConnectedMachine=$9

script_name=$(basename "$0")                # Get current script name
logFilePath="${script_name%.*}.log" 

attempts=0

echo "Script $script_name started. Params: workspaceId=$workspaceId, computerName=$computerName, sourceLogFile=$sourceLogFile, targetTable=$targetTable, dcrImmutableId=$dcrImmutableId, endpointUri=$endpointUri, timestampColumn=$timestampColumn, timeSpan=$timeSpan"

while true; do
    echo "Attempt #$((attempts + 1)) to get earliest timestamp..."
    
    timestamp=$(getEarliestTimestamp $workspaceId $targetTable $computerName $sourceLogFile $timestampColumn $timeSpan $logFilePath $isArcConnectedMachine)

    if [[ -n "$timestamp" ]]; then
        echo "Got result: $timestamp"
        break
    else
        echo "Result was empty, retrying in 60 seconds..."
        sleep 60  # try again in 60 seconds
        # if we have no result after 30 attempts then exit with an error
        ((attempts++))
        if [[ $attempts -ge 30 ]]; then
            echo "Failed to get result after 30 attempts, exiting with error."
            exit 1
        fi
    fi
done

# convert logs to JSON format and return array of generated files
echo
jsonFileArr=($(log2json $sourceLogFile $targetTable $timestamp))

# for each JSON file, ingest logs into Log Analytics Workspace table
echo "Ingesting logs into Log Analytics Workspace table..."
for jsonLogFile in "${jsonFileArr[@]}"; do
    echo "Ingesting file: $jsonLogFile"
    ingestJson $dcrImmutableId $targetTable $endpointUri $jsonLogFile $isArcConnectedMachine
done
