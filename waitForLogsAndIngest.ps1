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
    [string]$isArcConnectedMachine
)

function Get-EarliestTimestamp {
    param(
        [string]$workspaceId,
        [string]$table,
        [string]$computer,
        [string]$filePath,
        [string]$timestampColumn,
        [string]$timeSpan,
        [string]$logFile,
        [string]$isArcConnectedMachine
    )

    $resource = "https://api.loganalytics.io"
    $kql = "$table | where Computer == '$computer' | where FilePath == '$filePath' | summarize EarliestTimestamp=min($timestampColumn)"
    $payload = @{
        query = $kql
        timespan = $timeSpan
    } | ConvertTo-Json

    if ($isArcConnectedMachine -eq "true") {
        $accessToken = Get-AccessTokenArc -Resource $resource
    } else {
        $accessToken = Get-AccessTokenAzure -Resource $resource
    }

    $headers = @{
        Authorization = "Bearer $accessToken"
        "Content-Type" = "application/json"
    }

    $response = Invoke-RestMethod -Method Post -Uri "$resource/v1/workspaces/$workspaceId/query" -Headers $headers -Body $payload
    $timestamp = $response.tables.rows[0][0]

    Add-Content -Path $logFile -Value "Access Token (trunc): $($accessToken.Substring(0,10))..."
    Add-Content -Path $logFile -Value "KQL Query: $kql"
    Add-Content -Path $logFile -Value "Payload: $payload"
    Add-Content -Path $logFile -Value "KQL Result: $($response | ConvertTo-Json)"
    Add-Content -Path $logFile -Value "Earliest timestamp for $filePath on $computer is:"
    Add-Content -Path $logFile -Value "$timestamp"

    return $timestamp
}

function Log2Json {
    param(
        [string]$logFile,
        [string]$outputPrefix,
        [string]$maximumTimestamp
    )

    $maxSize = 1MB
    $today = Get-Date -Format "yyyy-MM-dd"
    $fileIndex = 1
    $currentFile = "$outputPrefix" + "_$fileIndex.json"
    $returnArr = @($currentFile)
    Set-Content -Path $currentFile -Value "["

    $firstLine = $true
    $currentSize = (Get-Item $currentFile).Length

    Get-Content $logFile | ForEach-Object {
        $line = $_
        $timestamp = $line.Split(" ")[0]
        $epochTimestamp = [datetime]::Parse($timestamp).ToUniversalTime().Ticks
        $epochMaximum = [datetime]::Parse($maximumTimestamp).ToUniversalTime().Ticks

        if ($timestamp -notlike "$today*") { return }
        if ($epochTimestamp -ge $epochMaximum) { return }

        $rawData = $line -replace '"', '\"'
        $jsonLine = " {`"TimeGenerated`": `"$timestamp`", `"RawData`": `"$rawData`"}"

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
    # Implement the logic for Arc token retrieval here
    throw "Get-AccessTokenArc not implemented in PowerShell. Use Azure CLI or REST API."
}

function Get-AccessTokenAzure {
    param([string]$Resource)
    # Implement the logic for Azure token retrieval here
    throw "Get-AccessTokenAzure not implemented in PowerShell. Use Azure CLI or REST API."
}

function IngestJson {
    param(
        [string]$dcrImmutableId,
        [string]$tableName,
        [string]$endpointUri,
        [string]$jsonLogFile,
        [string]$isArcConnectedMachine
    )

    $resource = "https://monitor.azure.com"
    if ($isArcConnectedMachine -eq "true") {
        $token = Get-AccessTokenArc -Resource $resource
    } else {
        $token = Get-AccessTokenAzure -Resource $resource
    }

    $streamName = "Custom-Text-$tableName"
    $uri = "$endpointUri/dataCollectionRules/$dcrImmutableId/streams/$streamName?api-version=2023-01-01"

    Write-Host "IngestJson $dcrImmutableId $tableName $uri $jsonLogFile $isArcConnectedMachine $($token.Substring(0,10))"
    Invoke-RestMethod -Method Post -Uri $uri -Headers @{
        "Content-Type" = "application/json"
        Authorization = "Bearer $token"
    } -InFile $jsonLogFile
}

# Main loop
$scriptName = $MyInvocation.MyCommand.Name
$logFilePath = "$($scriptName -replace '\\..*$', '').log"
$attempts = 0

Write-Host "Script $scriptName started. Params: workspaceId=$workspaceId, computerName=$computerName, sourceLogFile=$sourceLogFile, targetTable=$targetTable, dcrImmutableId=$dcrImmutableId, endpointUri=$endpointUri, timestampColumn=$timestampColumn, timeSpan=$timeSpan"

while ($true) {
    Write-Host "Attempt #$($attempts + 1) to get earliest timestamp..."
    $timestamp = Get-EarliestTimestamp $workspaceId $targetTable $computerName $sourceLogFile $timestampColumn $timeSpan $logFilePath $isArcConnectedMachine
    if ($timestamp) {
        Write-Host "Got result: $timestamp"
        break
    } else {
        Write-Host "Result was empty, retrying in 60 seconds..."
        Start-Sleep -Seconds 60
        $attempts++
        if ($attempts -ge 30) {
            Write-Host "Failed to get result after 30 attempts, exiting with error."
            exit 1
        }
    }
}

# Convert logs to JSON format and return array of generated files
$jsonFileArr = Log2Json $sourceLogFile $targetTable $timestamp

# For each JSON file, ingest logs into Log Analytics Workspace table
Write-Host "Ingesting logs into Log Analytics Workspace table..."
foreach ($jsonLogFile in $jsonFileArr) {
    Write-Host "Ingesting file: $jsonLogFile"
    IngestJson $dcrImmutableId $targetTable $endpointUri $jsonLogFile $isArcConnectedMachine
}
