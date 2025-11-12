RESOURCE="https://api.loganalytics.io"

# Note: Workspace Id not Name
WORKSPACE_ID=$1 # eg "b5b2874f-f4fb-4581-b606-af3b15af8fea" # "arc-servers-uks-law"

TABLE=$2 # eg "WaAgent3_CL "
COMPUTER=$3 # eg "jumpbox-linux"
FILEPATH=$4 # eg "/var/log/waagent.log"
TIMESTAMP_COLUMN=$5 # eg "TimeGenerated"
TIMESPAN=$6 # "P1D" # last 1 day
LOGFILE=$7 # eg "./getEarliestTimestamp.log"

KQL="$TABLE | where Computer == '$COMPUTER' | where FilePath == '$FILEPATH' | summarize EarliestTimestamp=min($TIMESTAMP_COLUMN)"

# note the values are enclosed in quoutes, which treats them as single strings in printf substitution
PAYLOAD=$(printf '{ "query": "%s", "timespan": "%s" }' "$KQL" "$TIMESPAN")

# Get the Entra access token
ACCESS_TOKEN=$(sudo ./getAccessToken.sh $RESOURCE)

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
