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

# TODO read these arraya from a config file
$onmpremLinuxVMs = ,@(
    @("ME-MngEnvMCAP078583-miwestaw-1", "arc-servers-uks", "LAPTOP-JF9KNPOJ")
)

$azureWindowsVMs = ,@(
    @("ME-MngEnvMCAP078583-miwestaw-1", "ai-foundry-byo-demo", "jumpbox")    
)

$azureLinuxVMs = ,@(
    @("ME-MngEnvMCAP078583-miwestaw-1", "jumpbox-linux-uks", "jumpbox-linux")    
)

# TODO make this a parameter
$dcrResourceGroup = "arc-servers-uks"

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

foreach ($vm in $azureLinuxVMs) {
    $subscription = $vm[0]
    $resourceGroup = $vm[1]
    $machine = $vm[2]

    Set-AzContext -Subscription $subscription

    Write-Host "Processing Azure Windows VM: $machine in Resource Group: $resourceGroup under Subscription: $subscription" -ForegroundColor Green

    # make big command as trun-command is expensive, so do once per server
    $cmds = ""
    foreach ($path in $linuxPaths) {
        $anchor = Get-AnchorFromWildcard -WildcardPathname $path
        # if path contains a wildcard then use dirname to return the folder name only
        # else we already have the folder name eg /etc
        if ($path -match '[\*\?\[\.]') {
            $pipeline = "| xargs -I {} dirname {} | sort -u"
        }
        else {
            $pipeline = "| sort -u"
        }
        $cmd = 'find $anchor -wholename "$path" $pipeline' `
            -replace '\$anchor', $anchor `
            -replace '\$path', $path `
            -replace '\$pipeline', $pipeline
        $cmds += $cmd + "; "
    }

    # TODO create a runCommand function and pass in OS and IsOnPrem parameters
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
            $dcr = Get-AzResource -ResourceGroupName $dcrResourceGroup -ResourceType "microsoft.insights/datacollectionrules" -Name $firstMatch.dcrName

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

            # create the DCR Association
            # TODO this may already exist - so ignore that error
            New-AzDataCollectionRuleAssociation `
                -AssociationName $dataSourceName `
                -ResourceUri $vmResourceId `
                -DataCollectionRuleId $dcr.ResourceId
        }
    }
}
