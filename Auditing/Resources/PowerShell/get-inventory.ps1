

# Define the script's parameters
[CmdletBinding(DefaultParameterSetName = "Default")]
param (
    [Parameter(Mandatory = $true, ParameterSetName = "Default")]
    [ValidateNotNullOrEmpty()]
    [string]$CaseName = "case-name"
)

$timeStart = Get-Date

Write-Output "***********************************************************"
Write-Output "*********** Resources Inventory ***************************"
Write-Output "*********** Author: David Burel (@dafneb) *****************"
Write-Output "***********************************************************"

Write-Verbose -Message "Checking requirements ..."

# Check if PowerShell version is 7.4 or higher
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Verbose -Message "PowerShell version is lower than 7.4, actual version is $($PSVersionTable.PSVersion) ..."
    Write-Output -ForegroundColor Red "PowerShell version 7.4 or higher is required"
    exit
}

# Check if module is already installed
if (-not (Get-Module -Name Az -ListAvailable)) {
    Write-Verbose -Message "Az module not found ..."
    Write-Output -ForegroundColor Red "Az module not found, please install it first"
    exit
}

# Check if Az module is loaded
if (-not (Get-Module -Name Az)) {
    Write-Verbose -Message "Loading Az module ..."
    Import-Module Az -ErrorAction Stop
}

# Normalize case name to lowercase
$caseFolderName = $CaseName.ToLower()
$caseFolderName = $caseFolderName.Trim()
$caseFolderName = $caseFolderName -replace '[\\/:*?"<>|]', '_'

# Paths for logs
$baseFolderPath = Join-Path -Path (Get-Location) -ChildPath "case"
$caseFolderPath = Join-Path -Path $baseFolderPath -ChildPath "$($caseFolderName)"
$inveFilePath = Join-Path -Path $caseFolderPath -ChildPath "inventory.csv"

Write-Verbose -Message "Checking folders (1/2) ..."

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

# Check if the inventory file already exists
if (Test-Path -Path $inveFilePath) {
    Write-Verbose -Message "Inventory file already exists, deleting it ..."
    Remove-Item -Path $inveFilePath -Force
}

Write-Verbose -Message "Listing inventory from Azure ..."

$dataInventory = @()

$tenants = Get-AzTenant
$tenants | ForEach-Object {
    $tenantId = $_.Id
    $tenantName = $_.DisplayName

    # Get all subscriptions for the tenant
    $subscriptions = Get-AzSubscription -TenantId $tenantId
    $subscriptions | ForEach-Object {
        $subscriptionId = $_.Id
        $subscriptionName = $_.Name

        # Get all resource groups for the subscription
        $resourceGroups = Get-AzResourceGroup -SubscriptionId $subscriptionId
        $resourceGroups | ForEach-Object {
            $resourceGroupName = $_.ResourceGroupName

            # Get all resources in the resource group
            $resources = Get-AzResource -ResourceGroupName $resourceGroupName -SubscriptionId $subscriptionId
            foreach ($resource in $resources) {
                $dataInventory += [PSCustomObject]@{
                    TenantName         = $tenantName
                    TenantId           = $tenantId
                    SubscriptionName   = $subscriptionName
                    SubscriptionId     = $subscriptionId
                    ResourceGroupName  = $resourceGroupName
                    ResourceType       = $resource.ResourceType
                    ResourceName       = $resource.Name
                    ResourceLocation   = $resource.Location
                }
            }
        }
    }
}

Write-Verbose -Message "Exporting inventory to CSV file ..."
$dataInventory | Export-Csv -Path $inveFilePath -NoTypeInformation -Force -Encoding UTF8

# Get actual date and time ...
$timeEnd = Get-Date

# Printout date&times ...
Write-Output "***********************************************************"
Write-Output "Started: $($timeStart)"
Write-Output "Finished: $($timeEnd)"
Write-Output "Elapsed time: $($timeEnd - $timeStart)"
