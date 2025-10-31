# DCR
DCR_IMMUTABLE_ID=$1 # eg"dcr-00000000000000000000000000"

# LAW Table Name
TABLE_NAME=$2 # eg "WaAgent3_CL"

#Logs ingestion URI for the DCR DCE
ENDPOINT_URI=$3 # eg "https://my-endpoint.uksouth-1.ingest.monitor.azure.com" 

# JSON log file to ingest
JSON_LOG_FILE=$4 # eg "waagent_log_1.json"

# Get token for the System Managed Identity to access the DCR endpoint
RESOURCE="https://monitor.azure.com"
TOKEN_JSON=$(
curl -s -H "Metadata: true" \
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2019-08-01&resource=$RESOURCE"
)
TOKEN=$(echo $TOKEN_JSON | awk -F'"' '{print $4}')

#name of the stream in the DCR that represents the destination table
STREAM_NAME="Custom-Text-$TABLE_NAME" 

# Build the URI
URI="$ENDPOINT_URI/dataCollectionRules/$DCR_IMMUTABLE_ID/streams/${STREAM_NAME}?api-version=2023-01-01"

# upload the JSON logs
# there is a limit of 1 MB on the payload
# the script used to create the JSON from log entries is aware of this and splits the file as required
curl -X POST "${URI}" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${TOKEN}" \
        -d @$JSON_LOG_FILE
