param(
    [Parameter(Mandatory=$true)]
    [string]$SubscriptionId, # eg "862097ad-4b0b-4f09-b98c-bfd14930e1b4"
    
    [Parameter(Mandatory=$true)]
    [string]$ResourceGroup, # eg "arc-servers-uks"
    
    [Parameter(Mandatory=$true)]
    [string]$WorkspaceName, # eg "arc-servers-uks-law"
    
    [Parameter(Mandatory=$true)]
    [string]$TableName # eg "WindowsCustTxt_CL"
)

$body = @{
    table   = "$TableName"
    filters = @(
        @{"column" = "TimeGenerated"; "operator" = "GreaterThan"; "value" = "0001-01-01T00:00:00Z" }
    )
} | ConvertTo-Json -Depth 3

$token = (az account get-access-token --resource https://management.azure.com --query accessToken --output tsv)

$uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/purge?api-version=2020-08-01"

Invoke-RestMethod -Uri $uri `
    -Method Post `
    -Headers @{ Authorization = "Bearer $token"; "Content-Type" = "application/json" } `
    -Body $body

