# test DCR creation
$subscriptionId = "862097ad-4b0b-4f09-b98c-bfd14930e1b4"
$resourceGroup = "arc-servers-uks"
$dcrLocation = "uksouth"
$dcrName = "LinuxTextLogs"
$kind = "Linux"
$dceName = "arc-servers-uks-endpoint"
$vmName = "jumpbox-linux"
$vmResourceGroup = "jumpbox-linux-uks"
$workspaceName = "arc-servers-uks-law"
$tableName = "LinuxTextLogs2_CL"

./createDcr.ps1 `
    -subscriptionId $subscriptionId `
    -resourceGroup $resourceGroup `
    -dcrName $dcrName `
    -location $dcrLocation `
    -kind $kind `
    -dceName $dceName `
    -customLogPath $firstMatch.Path `
    -tableName $tableName `
    -workspaceName $workspaceName

