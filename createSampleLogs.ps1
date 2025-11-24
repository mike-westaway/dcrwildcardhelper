
param(
    [Parameter(Mandatory=$true)]
    [string]$LogFilePath,          # Path to the log file
    [string]$LogTime = "",         # Optional: custom timestamp (format: yyyy-MM-ddTHH:mm:ssZ)
    [string]$Message = "Default log message", # Log message
    [int]$NumberOfRows = 1        # Number of log entries to create
)

for ($i = 1; $i -le $NumberOfRows; $i++) {
    # If no custom time provided, use current time
    if ([string]::IsNullOrWhiteSpace($LogTime)) {
        $LogTime = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
    }

    $EventId = Get-Random -Minimum 1000 -Maximum 1005

    # Severity levels could be: Information, Warning, Error, Critical
    $SeverityLevels = @("Information", "Warning", "Error", "Critical")
    $Severity = $SeverityLevels | Get-Random

    # Department is one of: Sales, Procurement, Data Analytics, HR, IT
    $Departments = @("Sales", "Procurement", "Data Analytics", "HR", "IT")
    $Source = $Departments | Get-Random

    $CurrentMessage = $Message + ' ' + $LogTime

    # Generate log entry
    $LogEntry = "{0},{1},{2},{3},{4}" -f $LogTime, $EventId, $Severity, $Source, $CurrentMessage

    # Append to log file
    Add-Content -Path $LogFilePath -Value $LogEntry

    Write-Host "Log entry $i added to $LogFilePath"
    Write-Host "Log Entry: $LogEntry"
}
