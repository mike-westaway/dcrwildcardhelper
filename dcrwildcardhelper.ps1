# Enable strict mode to enforce variable declaration
Set-StrictMode -Version Latest

# Define the Linux paths
$linuxPaths = @(
    "/home/*/.bash_history",
    "/etc",
    "/var/log"
)

# Define the Windows paths
$windowsPaths = @(
)

# location for the DCRs
$dcrLocation = "uksouth"
# storage account for scripts and script logs
$scriptStorageAccount = "arcserversukssa"
# container name for scripts and script logs
$scriptContainerName = "scripts"

#Build array of objects with classification
# These types will be used as the names of exisiting Data Collection Rules (DCRs)
$categorisedWildcards = foreach ($p in $linuxPaths) {
    $dcrName = if ($p -like "*/oracle/*") {
        "Oracle"
    } elseif ($p -like "*/sap/*") {
        "Sap"
    } elseif ($p -like "*.bash_history*") {
        "BashHistory"
    } else {
        "LinuxTextLogs"
    }

    [PSCustomObject]@{
        Path = $p
        DcrName = $dcrName
    }
}

#Display result
$categorisedWildcards | Format-Table -AutoSize

# SubscrioptionId, ResourceGroup, VM Name, DCE Name, Workspace Name, Table Name
$onmpremLinuxVMs = ,@(
    @("862097ad-4b0b-4f09-b98c-bfd14930e1b4", "arc-servers-uks", "LAPTOP-JF9KNPOJ", "arc-servers-uks-endpoint", "arc-servers-uks-law", "LinuxTextLogs_CL")
)

# SubscrioptionId, ResourceGroup, VM Name, DCE Name, Workspace Name, Table Name
$azureWindowsVMs = ,@(
    @("862097ad-4b0b-4f09-b98c-bfd14930e1b4", "ai-foundry-byo-demo", "jumpbox", "arc-servers-uks-endpoint", "arc-servers-uks-law", "WindowsEvent_CL")    
)

# SubscrioptionId, ResourceGroup, VM Name, DCE Name, Workspace Name, Table Name
$azureLinuxVMs = ,@(
    @("862097ad-4b0b-4f09-b98c-bfd14930e1b4", "jumpbox-linux-uks", "jumpbox-linux", "arc-servers-uks-endpoint", "arc-servers-uks-law", "LinuxTextLogs_CL")    
)

# TODO make this a parameter
$dcrResourceGroup = "arc-servers-uks"

# Make a name from a wildcard path by stripping out any wildcard characters
# and prepending dcr_ to the name
function Get-DcrNameFromWildcard {
    param (
        [string]$WildcardPathname
    )

    $dcrName = $WildcardPathname -replace '[\*\?\[\]/]', '_'
    $dcrName = "dcr_" + $dcrName
    return $dcrName
}

# Create a DCR based on a name
function New-DcrFromWildcard {
    param (
        [string]$dcrName,
        [string]$dcrResourceGroupName,
        [string]$dcrSubscriptionId,
        [string]$dcrLocation,
        [string]$dceName,
        [string]$customLogPath,
        [string]$tableName,
        [string]$workspaceName
    )

    $dceId = "/subscriptions/$dcrSubscriptionId/resourceGroups/$dcrResourceGroupName/providers/Microsoft.Insights/dataCollectionEndpoints/$dceName"
    $kind = "Linux"

    # Lookup Workspace Resource Id based on its Id
    $workspaceResourceId = "/subscriptions/$dcrSubscriptionId/resourcegroups/$dcrResourceGroupName/providers/microsoft.operationalinsights/workspaces/$workspaceName"

    # Create DCR payload
    $dcrPayload = @{
        name = $dcrName
        location = $dcrLocation
        kind = $kind
        properties = @{
            dataCollectionEndpointId = "$dceId"
            streamDeclarations = @{
                "Custom-Text-$tableName" = @{
                    columns = @(
                        @{ "name" = "TimeGenerated"; "type" = "datetime" }
                        @{ "name" = "RawData"; "type" = "string" }
                        @{ "name" = "FilePath"; "type" = "string" }
                        @{ "name" = "Computer" ; "type" = "string" }
                    )
                }
            }
            dataSources = @{
                logFiles = @(  # Changed from fileLogs
                    @{
                        streams = @("Custom-Text-$tableName")
                        filePatterns = @($customLogPath)
                        format = "text"
                        settings = @{ "text" = @{ "recordStartTimestampFormat" = "ISO 8601" } }
                        name = "Custom-Text-$tableName"
                    }
                )
            }
            destinations = @{
                logAnalytics = @(
                    @{
                        workspaceResourceId = $workspaceResourceId
                        name = $dcrName
                    }
                )
            }
            dataFlows = @(
                @{
                    streams = @("Custom-Text-$tableName")
                    destinations = @($dcrName)
                    transformKql = "source | extend TimeGenerated, RawData, Computer, FilePath"
                    outputStream = "Custom-$tableName"
                }
            )
        }
    }

    $payload = $dcrPayload | ConvertTo-Json -depth 10
    
    # Deploy DCR
    New-AzDataCollectionRule `
        -Name "$dcrName" `
        -ResourceGroupName "$dcrResourceGroupName" `
        -JsonString $payload
}

# helper function to get the anchor from a wildcard folde pattern
# ie the base folder before any wildcards
# example: Get-AnchorFromWildcard -WildcardPathname "/home/*/.bash_history" returns "/home"
function Get-AnchorFromWildcard {
    param (
        [string]$WildcardPathname
    )

    # Build an "anchor": everything before the first segment that contains a wildcard (* ? [)
    $segments = $WildcardPathname -split '/'
    $anchorSegments = @()
    $sawWildcard = $false
    foreach ($seg in $segments) {
        if ($seg -match '[\*\?\[\.]') { $sawWildcard = $true; break }
        if ($seg -ne '') { $anchorSegments += $seg }
    }

    # If the pattern starts with '/', keep it in the anchor for correct matching
    $leadingSlash = $p.StartsWith('/')

    $anchor = ($anchorSegments -join '/')
    if ($leadingSlash) { $anchor = "/$anchor" }

    return $anchor
}

# helper function to get the first matching wildcard pattern and type for a given folder
function Get-FirstMatchingPath { 
    param (
        [string]$Folder,
        [array]$Categorized
    )

    foreach ($item in $Categorized) {
        $pattern = $item.Path
        $dcrName = $item.dcrName

        # if there are no wildcards then the pattern is a folder itself
        if ($pattern -match '[\*\?\[\.]') {
            $wildcardFolder = $pattern.Substring(0, $pattern.LastIndexOf('/'))
            # this ensures that "/home/admin matches "/home/*" but not "/home/admin/docs" 
            $wildcardFolderRegex = $wildcardFolder + "[^/]+$"
        }
        else {
            $wildcardFolder = $pattern
            # no wildcards to process 
            $wildcardFolderRegex = $wildcardFolder
        }


        if ($Folder -match $wildcardFolderRegex) {
            return [PSCustomObject]@{
                Path = $pattern
                DcrName = $dcrName
            }
        }
    }
    return $null
}

# start an async run-command to monitor the target table and ingest any missing log file entries
function RunCommandAsyncToIngestMissingLogs {
    param (
        [string]$SubscriptionId,
        [string]$ResourceGroupName,
        [string]$VMName,
        [string]$DcrName,
        [string]$LogFilePath,
        [string]$scriptStorageAccount,
        [string]$scriptContainerName,
        [bool]$isArcConnectedMachine,
        [string]$dcrImmutableId,
        [string]$dceEndpointId,
        [string]$workspaceId,
        [string]$tableName,
        [string]$timestampColumn,
        [string]$timespan
    )

    # TODO implement the function to run a command asynchronously to monitor the target table and ingest any missing log file entries
    Write-Host "Starting async command to monitor logs for VM $VMName, DCR $DcrName, Log File Path $LogFilePath" -ForegroundColor Blue

    # script outline:
    # 1. Get an access token for Storage
    # 2. Download scripts from storage to the VM
    # 3. Run the script
    ## 1. Determine the target Log Analytics workspace associated with the DCR
    ## 2. Start a background job or scheduled task on the VM to periodically check the Log Analytics workspace for new log entries from the specified log file path
    ## 3. Ingest any missing log file entries into the target table

    # this script is a compact version of getAccessToken.sh and downloadScriptFromStorage.sh
    # note the backticks prevent the bash variables from being expanded in PowerShell
    # note on Azure VM get a token with:
    # http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=<resource>
    # where resource is eg https://storage.azure.com/
    # on Arc enabled connected machine, use:
    # http://localhost:40342/metadata/identity/oauth2/token?api-version=2020-06-01&resource=<resource>
    # on Azure linux curl -s -H "Metadata: true" "$ENDPOINT" returns JSON with access_token

    $imdsHostVM = "169.254.169.254"
    $imdsHostConnectedMachine = "localhost:40342"
    
    $scriptConnectedMachine = @"
echo "Part I Get Access Token"
API_VERSION="2020-06-01"
RESOURCE="https://storage.azure.com/"
IDENTITY_ENDPOINT="http://$imdsHostConnectedMachine/metadata/identity/oauth2/token"
ENDPOINT="`${IDENTITY_ENDPOINT}?resource=`${RESOURCE}&api-version=`${API_VERSION}"
WWW_AUTH_HEADER=`$(curl -s -D - -o /dev/null -H "Metadata: true" "`$ENDPOINT" | grep -i "WWW-Authenticate")
SECRET_FILE=""
if [[ `$WWW_AUTH_HEADER =~ Basic\ realm=([^\ ]+) ]]; then SECRET_FILE=`$(echo `${BASH_REMATCH[1]} | sed 's/[$\r]*$//'); else echo "Error 001" && exit 1; fi
if [[ ! -f "`$SECRET_FILE" ]]; then echo "Error 2" && exit 1; fi
SECRET=`$(cat "`$SECRET_FILE")
RESPONSE=`$(curl -s -H "Metadata: true" -H "Authorization: Basic `$SECRET" "`$ENDPOINT")
ACCESS_TOKEN=`$(echo "`$RESPONSE" | grep -oP '"access_token"\s*:\s*"\K[^"]+')
if [[ -n "`$ACCESS_TOKEN" ]]; then echo "`$ACCESS_TOKEN"; else echo "Error 003 `$RESPONSE" && exit 1; fi
echo "Part II Download script"
storage_account=$scriptStorageAccount
container_name=$scriptContainerName
source_log_file=$LogFilePath
target_table=$tableName
dcr_immutable_id=$dcrImmutableId
endpoint_uri=$dceEndpointId
timestamp_column=$timestampColumn
time_span=$timespan
blob_name="waitForLogsAndIngest.sh"
local_file="waitForLogsAndIngest.sh"
workspace_id=$workspaceId
computer_name=$VMName
blob_url="https://`${storage_account}.blob.core.windows.net/`${container_name}/`${blob_name}"
curl -H "Authorization: Bearer `$ACCESS_TOKEN" -H "x-ms-version: 2020-10-02" "`$blob_url" -o "`$local_file"
chmod +x "`$local_file"
sed -i 's/\r$//' "./`$local_file"
"./`$local_file" $workspaceId $computer_name $source_log_file $target_table $dcr_immutable_id $endpoint_uri $timestamp_column $time_span > "`${local_file%.sh}.log" 2>&1
echo "Part III Upload log file"
log_blob_name="`${blob_name%.sh}.log"
log_blob_url="https://`${storage_account}.blob.core.windows.net/`${container_name}/`${log_blob_name}"
curl -X PUT -H "Authorization: Bearer `$ACCESS_TOKEN" -H "x-ms-version: 2020-10-02" -H "x-ms-blob-type: BlockBlob" --data-binary @"`${local_file%.sh}.log" "`$log_blob_url"
"@

    $scriptVM = @"
echo "Part I Get Access Token"
API_VERSION="2020-06-01"
RESOURCE="https://storage.azure.com/"
IDENTITY_ENDPOINT="http://$imdsHostVM/metadata/identity/oauth2/token"
ENDPOINT="`${IDENTITY_ENDPOINT}?resource=`${RESOURCE}&api-version=`${API_VERSION}"
RESPONSE=`$(curl -s -H "Metadata: true" "`$ENDPOINT")
ACCESS_TOKEN=`$(echo "`$RESPONSE" | grep -oP '"access_token"\s*:\s*"\K[^"]+')
if [[ -n "`$ACCESS_TOKEN" ]]; then echo "`$ACCESS_TOKEN"; else echo "Error 003 `$RESPONSE" && exit 1; fi
echo "Part II Download script"
storage_account=$scriptStorageAccount
container_name=$scriptContainerName
source_log_file=$LogFilePath
target_table=$tableName
dcr_immutable_id=$dcrImmutableId
endpoint_uri=$dceEndpointId
timestamp_column=$timestampColumn
time_span=$timespan
blob_name="waitForLogsAndIngest.sh"
local_file="waitForLogsAndIngest.sh"
workspace_id=$workspaceId
computer_name=$VMName
blob_url="https://`${storage_account}.blob.core.windows.net/`${container_name}/`${blob_name}"
curl -H "Authorization: Bearer `$ACCESS_TOKEN" -H "x-ms-version: 2020-10-02" "`$blob_url" -o "`$local_file"
chmod +x "`$local_file"
sed -i 's/\r$//' "./`$local_file"
"./`$local_file" $workspace_id $computer_name $source_log_file $target_table $dcr_immutable_id $endpoint_uri $timestamp_column $time_span > "`${local_file%.sh}.log" 2>&1
echo "Part III Upload log file"
log_blob_name="`${blob_name%.sh}.log"
log_blob_url="https://`${storage_account}.blob.core.windows.net/`${container_name}/`${log_blob_name}"
curl -X PUT -H "Authorization: Bearer `$ACCESS_TOKEN" -H "x-ms-version: 2020-10-02" -H "x-ms-blob-type: BlockBlob" --data-binary @"`${local_file%.sh}.log" "`$log_blob_url"
"@

    if ($isArcConnectedMachine -eq $true) {
        $script = $scriptConnectedMachine
    }
    else {
        $script = $scriptVM
    }
    
    $scriptOneLine = ($script -split "`r?`n" | Where-Object { $_.Trim() -ne "" }) -join ";"

    $job = Invoke-AzVMRunCommand `
    -ResourceGroupName $ResourceGroupName `
    -VMName $VMName `
    -CommandId 'RunShellScript' `
    -ScriptString $scriptOneLine  `
    -AsJob

    Write-Host "Started async job for pre ingestion with ID: $($job.Id)" -ForegroundColor Blue
}

foreach ($vm in $azureLinuxVMs) {
    $subscriptionId = $vm[0]
    $resourceGroup = $vm[1]
    $machine = $vm[2]
    $dceName = $vm[3]
    $workspaceName = $vm[4]
    $tableName = $vm[5]

    Set-AzContext -Subscription $subscriptionId

    Write-Host "Processing Azure Windows VM: $machine in Resource Group: $resourceGroup under Subscription: $subscriptionId" -ForegroundColor Green

    # make big command as run-command is expensive, so do once per server
    $cmds = ""
    foreach ($wildcardPath in $linuxPaths) {
        $anchor = Get-AnchorFromWildcard -WildcardPathname $wildcardPath
        # if path contains a wildcard then use dirname to return the folder name only
        # else we already have the folder name eg /etc
        if ($wildcardPath -match '[\*\?\[\.]') {
            $pipeline = "| xargs -I {} dirname {} | sort -u"
        }
        else {
            $pipeline = "| sort -u"
        }
        $cmd = 'find $anchor -wholename "$path" $pipeline' `
            -replace '\$anchor', $anchor `
            -replace '\$path', $wildcardPath `
            -replace '\$pipeline', $pipeline
        $cmds += $cmd + "; "
    }

    # create a runCommand function and pass in OS and IsOnPrem parameters
    # TODO error handling if the VM is not reachable
    $result = $null
    try {
        $result = Invoke-AzVMRunCommand `
            -ResourceGroupName $resourceGroup `
            -VMName $machine `
            -CommandId 'RunShellScript' `
            -ScriptString $cmds        
    }
    catch {
        Write-Host "Error executing Run Command on VM ${machine}: $_" -ForegroundColor Red
        continue
    }


    # convert the multiline string returned to an array
    # Value[0] is StdOut on Windows. 
    # On Linux I bleieve its all combined so just ignore results that do not start with a /
    $resultArr = $result.Value[0].Message -split "`n"

    # keep the unique entries in the array
    $resultArrUnique = $resultArr | Select-Object -Unique

    foreach ($folder in $resultArrUnique) {

        # filter out any non-linux folder paths
        if ($folder -notlike "/*") {
            continue
        }

        # lookup the first wildcard pattern and type associated with this folder
        $firstMatch = Get-FirstMatchingPath -Folder $folder -Categorized $categorisedWildcards

        $dcrFolderPathExists = $false

        Write-Host "Wildcard paths found on ${machine}:" -ForegroundColor Yellow
        Write-Host $folder -ForegroundColor Cyan

        # Get the VM Resource Id
        $vmResourceId = (Get-AzResource -ResourceGroupName $resourceGroup -ResourceName $machine -ResourceType "Microsoft.Compute/virtualMachines").ResourceId

        # Is there a DCR Association for this VM
        $dcrAssociationArr = @(Get-AzDataCollectionRuleAssociation -ResourceUri $vmResourceId)

        foreach ($dcrAssociation in $dcrAssociationArr) {
            $dcrId = $dcrAssociation.DataCollectionRuleId

            if ($null -eq $dcrId) {
                Write-Host "DCR for Assoc. $($dcrAssociation.Name) does not exist - skipping" -ForegroundColor Yellow
                continue
            }

            $dcr = Get-AzResource -ResourceId $dcrId

            # Get the Data Sources from the DCR   
            $logFileDataSourceArr = @($dcr.Properties.dataSources.logFiles) 
            
            foreach ($logFileDataSource in $logFileDataSourceArr) {

                foreach ($filePattern in $logFileDataSource.filePatterns) {
                    Write-Host "Checking DCR File Pattern: $filePattern for VM $machine" -ForegroundColor Magenta

                    # if there are wildcards in the pattern then extract the folder part
                    # else the pattern is a folder only
                    if ($filePattern -match '[\*\?\[\.]') {
                        $dcrFolderPath = $filePattern.Substring(0, $filePattern.LastIndexOf('/'))
                    }
                    else {
                        $dcrFolderPath = $filePattern
                    }

                    if ($dcrFolderPath -eq $folder) {
                        Write-Host "Found matching DCR File Pattern" -ForegroundColor Green
                        $dcrFolderPathExists = $true
                    }                       
                }
            }
        }

        if ($dcrFolderPathExists -eq $false) {
            # lookup the Dcr Id based on the Resource Group and Name
            $dcrName = $(Get-DcrNameFromWildcard $firstMatch.Path)

            $dcr = Get-AzResource -ResourceGroupName $dcrResourceGroup `
            -ResourceType "microsoft.insights/datacollectionrules" `
            -Name $dcrName `
            -ErrorAction SilentlyContinue

            if ($null -eq $dcr) {
            Write-Host "DCR $dcrName does not exist - creating it" -ForegroundColor Yellow
            # create the DCR if it does not exist
            New-DcrFromWildcard `
                -dcrName $dcrName `
                -dcrResourceGroupName $dcrResourceGroup `
                -dcrSubscriptionId $subscriptionId `
                -dcrLocation $dcrLocation `
                -dceName $dceName `
                -customLogPath $firstMatch.Path `
                -tableName $tableName `
                -workspaceName $workspaceName

            # re-fetch the DCR now it exists
            $dcr = Get-AzResource -ResourceGroupName $dcrResourceGroup -ResourceType "microsoft.insights/datacollectionrules" -Name $dcrName
            }
            else {
            # create the new Data Source
            $incomingStream = "Custom-Stream"                 # incoming stream name
            $dataSourceName = $firstMatch.dcrName + "-logfile"   # friendly name for this data source

            # if there are wildcards in the pattern then append the file part
            # else the pattern is a folder only
            if ($firstMatch.Path -match '[\*\?\[\.]') {
                $filePattern = $folder + $firstMatch.Path.Substring($firstMatch.Path.LastIndexOf('/'))           # array of file patterns
            }
            else {
                $filePattern = $folder
            }

            # TODO cannot have more than one Data Source object of a given type (eg Log File)
            # So in this case need to add an extra File Pattern to an exisiting data source object
            if ($null -ne $dcr.Properties.dataSources.logFiles) {
                # the Log Files data source already exists - recreate the object appending the new file pattern
                $exisitingDataSourceLogFiles = $dcr.Properties.dataSources.logFiles[0]

                $newFilePatterns = $exisitingDataSourceLogFiles.filePatterns + @($filePattern)

                $dcrDataSource = New-AzLogFilesDataSourceObject `
                -Name $exisitingDataSourceLogFiles.name  `
                -FilePattern $newFilePatterns `
                -Stream $exisitingDataSourceLogFiles.streams[0]
            }
            else {
                $dcrDataSource = New-AzLogFilesDataSourceObject `
                -Name $dataSourceName  `
                -FilePattern $filePattern `
                -Stream $incomingStream
            }

            # attach this to the exisiting DCR
            Update-AzDataCollectionRule `
                -Name $dcr.Name `
                -ResourceGroupName $dcr.ResourceGroupName `
                -SubscriptionId $dcr.SubscriptionId `
                -DataSourceLogFile  $dcrDataSource
            }
            
            # create the DCR Association
            # TODO this may already exist - so ignore that error
            New-AzDataCollectionRuleAssociation `
            -AssociationName $dcr.Properties.dataSources.logFiles.name `
            -ResourceUri $vmResourceId `
            -DataCollectionRuleId $dcr.ResourceId

            # lookup the workspace immutable id based on the name and resourcegroup
            $workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $dcrResourceGroup -Name $workspaceName
            $workspaceId = $workspace.CustomerId

            # lookup the DCE endpoint
            $dce = Get-AzResource -ResourceId $dceId

            # at this point we have the DCR, Data Source, Folder Path and Association created
            # the detection of the new log file and the creation of the DCR plus time to first ingestion
            # will take some time
            # start an async run-command to monitor the target table and ingest any missing log file entries
            RunCommandAsyncToIngestMissingLogs `
            -SubscriptionId $subscriptionId `
            -ResourceGroupName $resourceGroup `
            -VMName $machine `
            -DcrName $dcr.Name `
            -LogFilePath $filePattern `
            -scriptStorageAccount $scriptStorageAccount `
            -scriptContainerName $scriptContainerName `
            -isArcConnectedMachine $false `
            -dcrImmutableId $dcr.Properties.immutableId `
            -dceEndpointId $dce.Properties.logsIngestion.endpoint `
            -WorkspaceId $workspaceId `
            -tableName $tableName `
            -timestampColumn "TimeGenerated" `
            -timespan "P1D" 
        }
    }
}
