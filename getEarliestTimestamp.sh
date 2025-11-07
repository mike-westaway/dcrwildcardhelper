RESOURCE="https://api.loganalytics.io"

# Note: Workspace Id not Name
WORKSPACE_ID=$1 # eg "b5b2874f-f4fb-4581-b606-af3b15af8fea" # "arc-servers-uks-law"

TABLE=$2 # eg "WaAgent3_CL "
COMPUTER=$3 # eg "jumpbox-linux"
FILEPATH=$4 # eg "/var/log/waagent.log"
TIMESTAMP_COLUMN=$5 # eg "TimeGenerated"

KQL="$TABLE | where Computer == '$COMPUTER' | where FilePath == '$FILEPATH' | summarize EarliestTimestamp=min($TIMESTAMP_COLUMN)"
TIMESPAN="P1D"

# note the values are enclosed in quoutes, which treats them as single strings in printf substitution
PAYLOAD=$(printf '{ "query": "%s", "timespan": "%s" }' "$KQL" "$TIMESPAN")

# Get the Entra access token
ACCESS_TOKEN=$(sudo ./getAccessToken.sh $RESOURCE)

KQL_RESULT=$(curl -X POST "$RESOURCE/v1/workspaces/$WORKSPACE_ID/query" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD")

TIMESTAMP=$(echo $KQL_RESULT | awk -F'"rows":\\[\\["|"]]}' '{print $2}')

echo $TIMESTAMP
