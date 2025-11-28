# waitForLogsAndIngest.ps1

param(
    [string]$workspaceId,
    [string]$computerName,
    [string]$sourceLogFile,
    [string]$targetTable,
    [string]$dcrImmutableId,
    [string]$endpointUri,
    [string]$timestampColumn,
    [string]$timeSpan,
    [string]$isArcConnectedMachine,
    [int]$sleepTime,
    [int]$maxRetries
)

$gblLogFile = [System.IO.Path]::ChangeExtension($MyInvocation.MyCommand.Name, '.log')

function logMessage{
    param(
        [string]$message
    )
    $timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
    "[$timestamp] $message" | Out-File -FilePath $gblLogFile -Append
}

# TODO support returning an array of FilePaths and Timestamps, currently only the first is handled
function Get-EarliestTimestamp {
    param(
        [string]$workspaceId,
        [string]$table,
        [string]$computer,
        [string]$filePath,
        [string]$timestampColumn,
        [string]$timeSpan,
        [string]$isArcConnectedMachine
    )

    $retFilePathAndTimestamp = [PSCustomObject]@{
        FilePath  = $null
        Timestamp = $null
    }

    # after much experimentation, it seems that each backslash in the regex needs to be escaped with another backslash
    $filePathEscaped = $filePath -replace "\\", "\\\\"

    $resource = "https://api.loganalytics.io"

    # this KQL statement will return two columns: FilePath and EarliestTimestamp
    $kql = "$table | where Computer == '$computer' | where FilePath matches regex @'$filePathEscaped' | summarize EarliestTimestamp=min($timestampColumn) by FilePath"
   
    $payload = "{ `"query`": `"$kql`", `"timespan`": `"$timeSpan`" }"

    if ($isArcConnectedMachine -ieq "true") {
        $accessToken = Get-AccessTokenArc -Resource $resource
    } else {
        $accessToken = Get-AccessTokenAzure -Resource $resource
    }

    $headers = @{
        Authorization = "Bearer $accessToken"
        "Content-Type" = "application/json"
    }

    # this forces the resonse to predictably be an array
    $response = ,@(Invoke-RestMethod -Method Post -Uri "$resource/v1/workspaces/$workspaceId/query" -Headers $headers -Body $payload)

    if ($null -eq $response) {
        logMessage "No response from KQL query."
        return $null
    }
    elseif ($null -eq $response.tables) {
        logMessage "No tables in KQL response."
        return $null
    }
    elseif ($null -eq $response.tables.rows) {
        logMessage "No rows in KQL response."
        return $null
    }
    elseif ($response.tables.rows.Count -eq 0) {
        logMessage "No data rows in KQL response."
        return $null
    }
    elseif ([string]::IsNullOrEmpty($response.tables.rows[0][0])) {
        logMessage "No value in KQL response."
        return $null
    }
    # if the value is DateTime, convert to String
    elseif ($response.tables.rows[0][1] -is [DateTime]) {
        $filePath = $response.tables.rows[0][0]
        $timestamp = $response.tables.rows[0][1].ToString("o")
    }
    else {
        $filePath = $response.tables.rows[0][0]
        $timestamp = $response.tables.rows[0][1]
    }

    logMessage "Access Token (trunc): $($accessToken.Substring(0,10))..."
    logMessage "KQL Query: $kql"
    logMessage "Payload: $payload"
    logMessage "KQL Result: $($response | ConvertTo-Json)"
    logMessage "Earliest timestamp for $filePath on $computer"
    logMessage "Timestamp: $timestamp $($timestamp.GetType())"

    $retFilePathAndTimestamp.FilePath  = $filePath
    $retFilePathAndTimestamp.Timestamp = $timestamp

    return $retFilePathAndTimestamp
}

# Note that the Log Ingestion API does NOT call TransformKql from the Data Collection Rule
# So we have to include said transformations here, namely:
# Computer, FilePath
# Note _ResourceId cannot be populated with Log Ingestion API
# https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview
function Log2Json {
    param(
        [string]$logFile,
        [string]$outputPrefix,
        [string]$maximumTimestamp,
        [string]$computer
    )

    $maxSize = 1MB
    $today = Get-Date -Format "yyyy-MM-dd"
    $fileIndex = 1
    $currentFile = "$outputPrefix" + "_$fileIndex.json"
    $returnArr = @($currentFile)
    $textColumnDelimeter = ","
    Set-Content -Path $currentFile -Value "["

    $firstLine = $true
    $currentSize = (Get-Item $currentFile).Length

    Get-Content $logFile | ForEach-Object {
        $line = $_
        $timestamp = $line.Split($textColumnDelimeter)[0]
        $epochTimestamp = [datetime]::Parse($timestamp).ToUniversalTime().Ticks
        $epochMaximum = [datetime]::Parse($maximumTimestamp).ToUniversalTime().Ticks

        if ($timestamp -notlike "$today*") { return }
        if ($epochTimestamp -ge $epochMaximum) { return }

        $rawData = $line -replace '"', '\"'

        $jsonLine = " {`"TimeGenerated`": `"$timestamp`", `"RawData`": `"$rawData`", `"FilePath`": `"$logFile`", `"Computer`": `"$computer`" } "

        if (-not $firstLine) {
            $jsonLine = ",$jsonLine"
        } else {
            $firstLine = $false
        }

        if (($currentSize + $jsonLine.Length) -gt $maxSize) {
            Add-Content -Path $currentFile -Value "]"
            $fileIndex++
            $currentFile = "$outputPrefix" + "_$fileIndex.json"
            $returnArr += $currentFile
            Set-Content -Path $currentFile -Value "["
            $firstLine = $true
            $currentSize = (Get-Item $currentFile).Length
        }

        Add-Content -Path $currentFile -Value $jsonLine
        $currentSize = (Get-Item $currentFile).Length
    }

    Add-Content -Path $currentFile -Value "]"
    return $returnArr
}

function Get-AccessTokenArc {
    param([string]$Resource)

    # Config
    # This is the IMDS endpoint used by the System Managed Identity to get tokens
    $API_VERSION = "2020-06-01"
    $IDENTITY_ENDPOINT = "http://localhost:40342/metadata/identity/oauth2/token"
    $ENDPOINT = "${IDENTITY_ENDPOINT}?resource=${Resource}&api-version=${API_VERSION}"

    # Step 1: Make unauthenticated request to get WWW-Authenticate header
    try { (Invoke-WebRequest -Uri $ENDPOINT -Headers @{Metadata='true'} -UseBasicParsing -ErrorAction Stop).Headers['WWW-Authenticate'] } catch { $WWW_AUTH_HEADER = $_.Exception.Response.Headers.GetValues("WWW-Authenticate")}

    logMessage "Endpoint $ENDPOINT"
    logMessage "WWW $WWW_AUTH_HEADER"
    logMessage "whoami $([Security.Principal.WindowsIdentity]::GetCurrent().Groups)"

    # Step 2: Extract secret file path from header
    $SECRET_FILE = ( $WWW_AUTH_HEADER -split 'Basic realm=')[1] -replace "`r$",""

    # Step 3: Read secret
    if (-not (Test-Path $SECRET_FILE)) { Write-Output "Error 2"; exit 1 }

    # Need IMDS Group member or root permissions to read the secret file
    $SECRET = $(cat "$SECRET_FILE")

    # Step 4: Make authenticated request with Basic token
    $RESPONSE = Invoke-WebRequest -Method Get -Uri $ENDPOINT -Headers @{Metadata='True'; Authorization="Basic $SECRET"} -UseBasicParsing

    # Step 5: Extract access token
    $ACCESS_TOKEN = (ConvertFrom-Json -InputObject $RESPONSE.Content).access_token

    if ([string]::IsNullOrWhiteSpace($ACCESS_TOKEN)) { Write-Output "Error 003 $env:RESPONSE"; exit 1 }

    return $ACCESS_TOKEN
}

function Get-AccessTokenAzure {
    param([string]$Resource)
    # Config
    # This is the IMDS endpoint used by the System Managed Identity to get tokens
    $API_VERSION = "2020-06-01"
    $imdsHost = "169.254.169.254"
    $IDENTITY_ENDPOINT = "http://$imdsHost/metadata/identity/oauth2/token"
    $ENDPOINT = "${IDENTITY_ENDPOINT}?resource=${Resource}&api-version=${API_VERSION}"

    logMessage "Endpoint $ENDPOINT"
    logMessage "whoami $([Security.Principal.WindowsIdentity]::GetCurrent().Groups)"

    $RESPONSE = Invoke-WebRequest -Method Get -Uri $ENDPOINT -Headers @{Metadata='True'} -UseBasicParsing

    # Step 5: Extract access token
    $ACCESS_TOKEN = (ConvertFrom-Json -InputObject $RESPONSE.Content).access_token

    if ([string]::IsNullOrWhiteSpace($ACCESS_TOKEN)) { Write-Output "Error 003 $env:RESPONSE"; exit 1 }

    return $ACCESS_TOKEN
}

function IngestJson {
    param(
        [string]$dcrImmutableId,
        [string]$tableName,
        [string]$endpointUri,
        [string]$jsonLogFile,
        [string]$isArcConnectedMachine
    )

    logMessage "Ingesting JSON file $jsonLogFile to table $tableName using DCR $dcrImmutableId"

    logMessage "Log file content: $(Get-Content $jsonLogFile)"

    $resource = "https://monitor.azure.com"
    if ($isArcConnectedMachine -eq "true") {
        $token = Get-AccessTokenArc -Resource $resource
    } else {
        $token = Get-AccessTokenAzure -Resource $resource
    }

    $streamName = "Custom-Text-$tableName"
    $uri = "$endpointUri/dataCollectionRules/$dcrImmutableId/streams/${streamName}?api-version=2023-01-01"

    logMessage "IngestJson $dcrImmutableId $tableName $uri $jsonLogFile $isArcConnectedMachine $($token.Substring(0,10))"
    
    Invoke-RestMethod -Method Post -Uri $uri -Headers @{
        "Content-Type" = "application/json"
        Authorization = "Bearer $token"
    } -InFile $jsonLogFile
}

# Main loop
$scriptName = $MyInvocation.MyCommand.Name

$attempts = 0

logMessage "Script $scriptName started. Params: workspaceId=$workspaceId, computerName=$computerName, sourceLogFile=$sourceLogFile, targetTable=$targetTable, dcrImmutableId=$dcrImmutableId, endpointUri=$endpointUri, timestampColumn=$timestampColumn, timeSpan=$timeSpan, sleepTime=$sleepTime, maxRetries=$maxRetries"

while ($true) {
    logMessage "Attempt #$($attempts + 1) to get earliest timestamp..."

    $customObject = Get-EarliestTimestamp $workspaceId $targetTable $computerName $sourceLogFile $timestampColumn $timeSpan $isArcConnectedMachine

    # null means something went wrong
    if ($null -eq $customObject) {
        logMessage "No timestamp returned."
        exit 1
    }
    elseif (-not [string]::IsNullOrEmpty($customObject.Timestamp)) {
        logMessage "Got result: $($customObject.Timestamp)"
        break
    }
    # empty string means no logs yet 
    else {
        logMessage "Result was empty, retrying in $sleepTime seconds..."
        Start-Sleep -Seconds $sleepTime
        $attempts++
        if ($attempts -ge $maxRetries) {
            logMessage "Failed to get result after $maxRetries attempts, exiting with error."
            exit 1
        }
    }
}

# Convert logs to JSON format and return array of generated files
$jsonFileArr = Log2Json $customObject.FilePath $targetTable $customObject.Timestamp $computerName

# For each JSON file, ingest logs into Log Analytics Workspace table
logMessage "Ingesting logs into Log Analytics Workspace table..."
foreach ($jsonLogFile in $jsonFileArr) {
    logMessage "Ingesting file: $jsonLogFile"
    IngestJson $dcrImmutableId $targetTable $endpointUri $jsonLogFile $isArcConnectedMachine
}
