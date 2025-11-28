# Variables
$ResourceGroupDcr = "<your-resource-group>"
$ResourceGroupConnectedMachine = "<your-resource-group>"
$ConnectedMachineName = "<your-connected-machine-name>"
$SubscriptionId = "<your-subscription>"
$Scope = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupDcr"  # Change scope if needed
$IsArc = $false

# 1. Get the principalId of the system-assigned managed identity

if ($IsArc -eq $true) {
    $PrincipalId = az connectedmachine show `
        --name $ConnectedMachineName `
        --resource-group $ResourceGroupConnectedMachine `
        --query "identity.principalId" -o tsv
} else {
    $PrincipalId = az vm show `
        --name $ConnectedMachineName `
        --resource-group $ResourceGroupConnectedMachine `
        --query "identity.principalId" -o tsv
}

Write-Host "Managed Identity Principal ID: $PrincipalId"
# 2. Assign roles to the managed identity
$Roles = @(
    "Reader",
    "Log Analytics Reader",
    "Monitoring Metrics Publisher",
    "Storage Blob Data Contributor"
)
foreach ($Role in $Roles) {
    Write-Host "Assigning role: $Role"
    az role assignment create `
        --assignee $PrincipalId `
        --role $Role `
        --scope $Scope
}
Write-Host "Roles assigned successfully!"
