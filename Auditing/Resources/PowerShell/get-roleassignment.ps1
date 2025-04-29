<#
#>


# Define the script's parameters
[CmdletBinding(DefaultParameterSetName = "Default")]
param (
    [Parameter(Mandatory = $true, ParameterSetName = "Default")]
    [Parameter(Mandatory = $true, ParameterSetName = "Append")]
    [ValidateNotNullOrEmpty()]
    [string]$CaseName,

    [Parameter(Mandatory = $true, ParameterSetName = "Append")]
    [switch]$Append
)

$timeStart = Get-Date

Write-Output "***********************************************************"
Write-Output "*********** Roles Assignment ******************************"
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
$roleFilePath = Join-Path -Path $caseFolderPath -ChildPath "roleassignment.csv"

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
if (Test-Path -Path $roleFilePath) {
    if (-not $Append) {
        Write-Verbose -Message "Inventory file already exists, deleting it ..."
        Remove-Item -Path $roleFilePath -Force
    } else {
        Write-Verbose -Message "Appending to existing file ..."
    }
}
Write-Verbose -Message "Listing roles from Azure ..."

$dataRoles = @()

$tenants = Get-AzTenant -ErrorAction SilentlyContinue
if (-not $tenants) {
    Write-Warning -Message "No tenants found, please check your connection"
}
$tenants | ForEach-Object {
    $tenantId = $_.Id
    $tenantName = $_.Name
    Write-Verbose -Message "Processing tenant: $tenantName ($tenantId)"

    # Get all subscriptions for the tenant
    $subscriptions = Get-AzSubscription -TenantId $tenantId -ErrorAction SilentlyContinue
    if (-not $subscriptions) {
        Write-Warning -Message "No subscriptions found for tenant $tenantName ($tenantId)"
    }
    $subscriptions | ForEach-Object {
        $subscriptionId = $_.Id
        $subscriptionName = $_.Name
        Write-Verbose -Message "Processing subscription: $subscriptionName ($subscriptionId)"
        Set-AzContext -SubscriptionId $subscriptionId -TenantId $tenantId -ErrorAction SilentlyContinue | Out-Null
        if (-not (Get-AzContext)) {
            Write-Warning -Message "Failed to set context for subscription $subscriptionName ($subscriptionId)"
            continue
        }

        # Get all role assignments for the subscription
        $roleAssignments = Get-AzRoleAssignment -Scope "/subscriptions/$($subscriptionId)" -ErrorAction SilentlyContinue
        if (-not $roleAssignments) {
            Write-Warning -Message "No role assignments found for subscription $subscriptionName ($subscriptionId)"
        }

        # Process each role assignment
        $roleAssignments | ForEach-Object {
            $roleAssignment = $_
            Write-Verbose -Message "Processing role assignment: $($roleAssignment.RoleDefinitionName) for $($roleAssignment.DisplayName)"
            $dataRoles += [PSCustomObject]@{
                TenantId         = $tenantId
                TenantName       = $tenantName
                SubscriptionId   = $subscriptionId
                SubscriptionName = $subscriptionName
                RoleDefinition   = $roleAssignment.RoleDefinitionName
                DisplayName      = $roleAssignment.DisplayName
                PrincipalType    = $roleAssignment.ObjectType
                PrincipalId      = $roleAssignment.ObjectId
                PrincipalName    = $roleAssignment.SignInName
                Scope            = $roleAssignment.Scope
            }
        }
    }    
}

Write-Verbose -Message "Exporting roles to CSV file ..."
if ($Append) {
    Write-Verbose -Message "Appending to existing file ..."
    $dataRoles | Export-Csv -Path $roleFilePath -NoTypeInformation -Force -Encoding UTF8 -Append
} else {
    Write-Verbose -Message "Creating new file ..."
    $dataRoles | Export-Csv -Path $roleFilePath -NoTypeInformation -Force -Encoding UTF8
}

# Get actual date and time ...
$timeEnd = Get-Date

# Printout date&times ...
Write-Output "***********************************************************"
Write-Output "Started: $($timeStart)"
Write-Output "Finished: $($timeEnd)"
Write-Output "Elapsed time: $($timeEnd - $timeStart)"
