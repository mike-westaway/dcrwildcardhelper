# Variables
$ResourceGroup = "<your-resource-group>"
$ConnectedMachineName = "<your-connected-machine-name>"
$SubscriptionId = "<your-subscription>"
$Scope = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"  # Change scope if needed

# 1. Get the principalId of the system-assigned managed identity
$PrincipalId = az connectedmachine show `
    --name $ConnectedMachineName `
    --resource-group $ResourceGroup `
    --query "identity.principalId" -o tsv
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
