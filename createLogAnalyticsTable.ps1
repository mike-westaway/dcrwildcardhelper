# create a test table

param(
    [Parameter(Mandatory=$true)]
    [string]$SubscriptionId, # eg "862097ad-4b0b-4f09-b98c-bfd14930e1b4"
    
    [Parameter(Mandatory=$true)]
    [string]$ResourceGroup, # eg "arc-servers-uks"
    
    [Parameter(Mandatory=$true)]
    [string]$WorkspaceName, # eg "arc-servers-uks-law"
    
    [Parameter(Mandatory=$true)]
    [string]$TableName # eg "WindowsCustomTextLogs"
)

$tableParams = @{
    properties = @{
        schema = @{
               name = "${TableName}_CL"
               columns = @(
                    @{ "name" = "TimeGenerated"; "type" = "DateTime" } 
                    @{ "name" = "Computer"; "type" = "string" }                    
                    @{ "name" = "FilePath"; "type" = "string" }
                    @{ "name" = "RawData"; "type" = "string" }
              )
        }
    }
}

$tableParamsJson = $tableParams | ConvertTo-Json -Depth 10

Invoke-AzRestMethod `
    -Path "/subscriptions/${SubscriptionId}/resourcegroups/${ResourceGroup}/providers/microsoft.operationalinsights/workspaces/${WorkspaceName}/tables/${TableName}_CL?api-version=2021-12-01-preview" `
    -Method PUT `
    -payload $tableParamsJson
    
Write-Host "Created table ${TableName}_CL in workspace ${WorkspaceName}"