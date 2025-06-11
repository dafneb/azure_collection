<#
.SYNOPSIS
    This script retrieves Activity Logs from Azure for a specified time range and exports them to a CSV file.

.DESCRIPTION
    The script connects to Azure, retrieves activity logs for all subscriptions in all tenants, and exports the logs to a CSV file.
    It allows specifying a case name to organize the output files and supports filtering logs by time range.

.PARAMETER CaseName
    The name of the case folder where the inventory will be saved.
    The case name will be normalized to lowercase and invalid characters will be replaced with underscores.

.PARAMETER EndTime
    The end time for the logs to be retrieved. Defaults to the current date and time.

.PARAMETER StartTime
    The start time for the logs to be retrieved. Defaults to 30 days before the current date and time.

.EXAMPLE
    ./get-activitylogs.ps1 -CaseName "MyAzureCase"
    This command retrieves activity logs for the last 30 days for the case named "MyAzureCase" and exports them to a CSV file.

.NOTES
    This script requires PowerShell 7.4 or higher.
    Ensure that the Microsoft Az PowerShell module is installed before running the script.
    The script requires appropriate permissions to access resource data in Azure.

    Author: David Burel (@dafneb)
    Date: June 11, 2025
    Version: 1.0.1
#>

# Define the script's parameters
[CmdletBinding(DefaultParameterSetName = "Default")]
param (
    [Parameter(Mandatory = $true, ParameterSetName = "Default")]
    [ValidateNotNullOrEmpty()]
    [string]$CaseName,

    [Parameter(Mandatory = $false, ParameterSetName = "Default")]
    [ValidateNotNullOrEmpty()]
    [datetime]$EndTime = (Get-Date),

    [Parameter(Mandatory = $false, ParameterSetName = "Default")]
    [ValidateNotNullOrEmpty()]
    [datetime]$StartTime = (Get-Date).AddDays(-30)

)

$timeStart = Get-Date

Write-Output "***********************************************************"
Write-Output "*********** Activity Logs at Azure ************************"
Write-Output "*********** Author: David Burel (@dafneb) *****************"
Write-Output "***********************************************************"

Write-Verbose -Message "Checking requirements ..."

# Check if PowerShell version is 7.4 or higher
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Verbose -Message "PowerShell version is lower than 7.4, actual version is $($PSVersionTable.PSVersion) ..."
    Write-Warning -Message "PowerShell version 7.4 or higher is required"
    exit
}

# Check if module is already installed
if (-not (Get-Module -Name Az -ListAvailable)) {
    Write-Warning -Message "Az module not found, please install it first"
    exit
}

# Check if Az module is loaded
if (-not (Get-Module -Name Az)) {
    Write-Verbose -Message "Loading Az module ..."
    Import-Module Az -ErrorAction Stop
}

# Check if I am connected to Azure
if (-not (Get-AzContext)) {
    Write-Warning -Message "Not connected to Azure, please connect first"
    exit
}

# Normalize case name to lowercase
$caseFolderName = $CaseName.ToLower()
$caseFolderName = $caseFolderName.Trim()
$caseFolderName = $caseFolderName -replace '[\\/:*?"<>|]', '_'

# Paths for logs
$baseFolderPath = Join-Path -Path (Get-Location) -ChildPath "case"
$caseFolderPath = Join-Path -Path $baseFolderPath -ChildPath "$($caseFolderName)"
$logsFilePath = Join-Path -Path $caseFolderPath -ChildPath "activitylogs.csv"

Write-Verbose -Message "Checking folders and files ..."

# Create case folder if it doesn't exist
if (-not (Test-Path -Path $baseFolderPath)) {
    Write-Verbose -Message "Base folder does not exist, creating it..."
    New-Item -ItemType Directory -Path $baseFolderPath | Out-Null
}

# Create domain folder if it doesn't exist
if (-not (Test-Path -Path $caseFolderPath)) {
    Write-Verbose -Message "Case folder does not exist, creating it..."
    New-Item -ItemType Directory -Path $caseFolderPath | Out-Null
}

# Check if logs file already exists
if (Test-Path -Path $logsFilePath) {
    Write-Verbose -Message "Logs file already exists, removing it..."
    Remove-Item -Path $logsFilePath -Force
}

Write-Verbose -Message "Listing activity logs from Azure ..."

$dataLogs = @()
$difference = New-TimeSpan -End $EndTime -Start $startTime
Write-Output "Time range for traffic data: $($startTime) to $($endTime) ..."
Write-Output "... TotalDays: $($difference.TotalDays) days"
Write-Output "... TotalHours: $($difference.TotalHours) hours"
Write-Output "... TotalMinutes: $($difference.TotalMinutes) minutes"
Write-Output "... TotalSeconds: $($difference.TotalSeconds) seconds"

$tenants = Get-AzTenant -ErrorAction SilentlyContinue
if (-not $tenants) {
    Write-Warning -Message "No tenants found, please check your connection"
}
$tenants | ForEach-Object {
    $tenantId = $_.Id
    $tenantName = $_.Name
    Write-Output "Processing tenant: $tenantName ($tenantId)"

    # Get all subscriptions for the tenant
    $subscriptions = Get-AzSubscription -TenantId $tenantId -ErrorAction SilentlyContinue
    if (-not $subscriptions) {
        Write-Warning -Message "No subscriptions found for tenant $tenantName ($tenantId)"
    }
    $subscriptions | ForEach-Object {
        $subscriptionId = $_.Id
        $subscriptionName = $_.Name
        $subscriptionState = $_.State
        Write-Output "Processing subscription: $subscriptionName ($subscriptionId)"

        if ($subscriptionState -eq "Disabled") {
            Write-Warning -Message "Subscription $subscriptionName ($subscriptionId) is Disabled, skipping ..."
            return
        }
        Set-AzContext -SubscriptionId $subscriptionId -TenantId $tenantId -ErrorAction SilentlyContinue | Out-Null
        if (-not (Get-AzContext)) {
            Write-Warning -Message "Failed to set context for subscription $subscriptionName ($subscriptionId)"
            return
        }
        $activitiesLog = Get-AzActivityLog -StartTime $startTime -EndTime $endTime
        if (-not $activitiesLog) {
            Write-Warning -Message "No activity logs found for subscription $subscriptionName ($subscriptionId)"
            return
        }
        Write-Verbose "Found $($activitiesLog.Count) activity logs"
        $activitiesLog | Where-Object { $_.Category -eq "Administrative" -or $_.Category -eq "Security"} | ForEach-Object {
            $dataLogs += [PSCustomObject]@{
                TenantId       = $tenantId
                TenantName     = $tenantName
                SubscriptionId = $subscriptionId
                SubscriptionName = $subscriptionName
                Level          = $_.Level
                EventDataId    = $_.EventDataId
                CorrelationId  = $_.CorrelationId
                OperationName  = $_.OperationName
                Caller         = $_.Caller
                EventTimestamp = $_.EventTimestamp
                EventName      = $_.EventName
                Description    = $_.Description
                ResourceGroup  = $_.ResourceGroupName
                ResourceId     = $_.ResourceId
                Category       = $_.Category
                Status         = $_.Status
            }
        }

    }
}

Write-Output "Exporting data to files ..."
$dataLogs | Export-Csv -Path $logsFilePath -NoTypeInformation -Encoding UTF8 -Force

# Get actual date and time ...
$timeEnd = Get-Date

# Printout date&times ...
Write-Output "***********************************************************"
Write-Output "Started: $($timeStart)"
Write-Output "Finished: $($timeEnd)"
Write-Output "Elapsed time: $($timeEnd - $timeStart)"
