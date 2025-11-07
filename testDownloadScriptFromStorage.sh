# simulate the conditions for connected machine run-command
# root account
sudo su
# System Managed Identity
az login --identity

# To get the access token requires root or group membership of the IMDS group
sudo ./downloadScriptFromStorage.sh "arcserversukssa" "scripts" "preflightchecks.sh" "preflightchecks.sh"

# to help diagnose any issues, try the az CLI equivalent
# eg az storage blob download -c $container_name -n $blob_name --account-name $storage_account
