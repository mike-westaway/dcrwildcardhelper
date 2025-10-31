param (
    [string]$subscriptionId,
    [string]$resourceGroup,
    [string]$dcrName,
    [string]$dceName,
    [string]$vmName,
    [string]$vmResourceGroup,
    [string]$customLogPath
    )

# eg $dcrName = "WaAgentDcr"
# eg $dceName = "arc-servers-uks-endpoint"
$dceId = "/subscriptions/$subscriptionId/resourceGroups/$resourceGroup/providers/Microsoft.Insights/dataCollectionEndpoints/$dceName"
$kind = "Linux"

# eg $vmName = "jumpbox-linux"
# eg $vmResourceGroup = "jumpbox-linux-uks"
$vmResourceId = "/subscriptions/$subscriptionId/resourceGroups/$vmResourceGroup/providers/Microsoft.Compute/virtualMachines/$vmName"

# eg $customLogPath = "/var/log/waagent*.log" # Path to the custom log file
$dataSourceName = "Custom-Text-$tableName"
$incomingStream = "Custom-Text-$tableName"

# Create DCR payload
$dcrPayload = @{
    name = $dcrName
    location = $location
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
            fileLogs = @(
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
                transformKql = "source |  extend Text = RawData, Computer = Computer, FilePath = FilePath"
                outputStream = "Custom-$tableName"
            }
        )
    }
}

# Deploy DCR
New-AzDataCollectionRule `
	-Name "$dcrName" `
	-ResourceGroupName "$resourceGroup" `
	-JsonString $($dcrPayload | ConvertTo-Json -depth 10)

#
# For Some reason the Data Source is not being added, so add it as an additional step
#

# Get the existing Data Collection Rule
$dcr = Get-AzDataCollectionRule -ResourceGroupName $resourceGroup -Name $dcrName

# Create a new custom log data source
$dcrDataSource = New-AzLogFilesDataSourceObject `
                    -Name $dataSourceName  `
                    -FilePattern $customLogPath `
                    -Stream $incomingStream

# Add the new data source to the DCR
Update-AzDataCollectionRule `
                -Name $dcr.Name `
                -ResourceGroupName $dcr.ResourceGroupName `
                -SubscriptionId $subscriptionId `
                -DataSourceLogFile  $dcrDataSource

# Associate with the VM source
New-AzDataCollectionRuleAssociation `
                -AssociationName $dataSourceName `
                -ResourceUri $vmResourceId `
                -DataCollectionRuleId $dcr.Id
