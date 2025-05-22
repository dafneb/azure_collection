<#

.SYNOPSIS
    This script lists all resources in Azure and exports the inventory to a CSV file.

.DESCRIPTION
    This script lists all resources in Azure and exports the inventory to a CSV file.
    It checks if the Az module is installed and loaded, and if the user is connected to Azure.
    It creates a case folder for the inventory and exports the data to a CSV file.

.PARAMETER CaseName
    The name of the case folder where the inventory will be saved.
    The default value is "case-name".
    The case name will be normalized to lowercase and invalid characters will be replaced with underscores.

.PARAMETER Append
    If specified, the script will append the inventory to an existing CSV file instead of creating a new one.

.EXAMPLE
    ./get-inventory.ps1 -CaseName "MyCase"
    This will create a folder named "mycase" in the current directory and save the inventory to "mycase/inventory.csv".

.NOTES
    This script requires PowerShell 7.4 or higher.
    Ensure that the Microsoft Az PowerShell module is installed before running the script.
    The script requires appropriate permissions to access resource data in Azure.

    Author: David Burel (@dafneb)
    Date: April 29, 2025
    Version: 1.0.1
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
Write-Output "*********** Resources Inventory ***************************"
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
    if (-not $Append) {
        Write-Verbose -Message "Inventory file already exists, deleting it ..."
        Remove-Item -Path $inveFilePath -Force
    } else {
        Write-Verbose -Message "Appending to existing inventory file ..."
    }
}

Write-Verbose -Message "Listing inventory from Azure ..."

$dataInventory = @()

$tenants = Get-AzTenant
if (-not $tenants) {
    Write-Warning -Message "No tenants found, please check your connection"
}
$tenants | ForEach-Object {
    $tenantId = $_.Id
    $tenantName = $_.Name
    $tenantDomains = $_.Domains -join ","
    Write-Verbose -Message "Processing tenant: $tenantName ($tenantId)"

    # Get all subscriptions for the tenant
    $subscriptions = Get-AzSubscription -TenantId $tenantId
    if (-not $subscriptions) {
        Write-Warning -Message "No subscriptions found for tenant $tenantName ($tenantId)"
    }
    $subscriptions | ForEach-Object {
        $subscriptionId = $_.Id
        $subscriptionName = $_.Name
        $subscriptionState = $_.State
        Write-Verbose -Message "Processing subscription: $subscriptionName ($subscriptionId)"
        Set-AzContext -SubscriptionId $subscriptionId -TenantId $tenantId | Out-Null
        if (-not (Get-AzContext)) {
            Write-Warning -Message "Failed to set context for subscription $subscriptionName ($subscriptionId)"
            continue
        }

        # Get tags for the subscription
        Write-Verbose -Message "Getting tags for subscription ..."
        $subsTags = Get-AzTag -ResourceId "/subscriptions/$subscriptionId" -ErrorAction SilentlyContinue
        $subscriptionTags = ""
        $subscriptionTagsArray = @()
        if ($subsTags.Properties.TagsProperty.Count -gt 0) {
            # Loop through each tag and add it to the array
            $subsTags.Properties.TagsProperty.Keys | ForEach-Object {
                $tagName = $_
                $tagValue = $subsTags.Properties.TagsProperty[$tagName]
                $subscriptionTagsArray += "[$tagName = $tagValue]"
            }
            $subscriptionTags = $subscriptionTagsArray -join "; "
        }

        # Get management group for the subscription
        $subscriptionGroupName = ""
        # TODO: Uncomment and implement the management group retrieval logic if needed
        # $managementGroups = Get-AzManagementGroupEntity -ErrorAction SilentlyContinue
        # Write-Host -Message "Processing subscription: $subscriptionName ($subscriptionId)"
        # $managementGroups | ForEach-Object {
        #     $mg = $_
        #     $subs = Get-AzManagementGroupSubscription -GroupName $mg.Name -ErrorAction SilentlyContinue
        #     $subs | ForEach-Object {
        #         if ($_.Name -eq "$($subscriptionId)") {
        #             $subscriptionGroupName = $mg.DisplayName
        #         }
        #     }
        #     if ($subscriptionGroupName) {
        #         break
        #     }
        # }

        $dataInventory += [PSCustomObject]@{
            TenantName         = $tenantName
            TenantId           = $tenantId
            TenantDomains      = $tenantDomains
            SubscriptionName   = $subscriptionName
            SubscriptionId     = $subscriptionId
            SubscriptionState  = $subscriptionState
            SubscriptionTags   = $subscriptionTags
            SubscriptionGroup  = $subscriptionGroupName
            ResourceGroupName  = ""
            ResourceGroupId    = ""
            ResourceGroupTags  = ""
            ResourceName       = ""
            ResourceId         = ""
            ResourceType       = ""
            ResourceLocation   = ""
            ResourceSku        = ""
            ResourceKind       = ""
            ResourceTags       = ""
        }

        # Get all resource groups for the subscription
        Write-Verbose -Message "Getting resource groups for subscription ..."
        $resourceGroups = Get-AzResourceGroup -ApiVersion "2024-11-01" -ErrorAction SilentlyContinue
        $resourceGroups | ForEach-Object {
            $resourceGroupName = $_.ResourceGroupName
            $resourceGroupId = $_.ResourceId
            Write-Verbose -Message "Processing resource group: $resourceGroupName"

            # Get all resources in the resource group
            $resources = Get-AzResource -ResourceGroupName $resourceGroupName -ApiVersion "2024-11-01" -ErrorAction SilentlyContinue
            if (-not $resources) {
                $dataInventory += [PSCustomObject]@{
                    TenantName         = $tenantName
                    TenantId           = $tenantId
                    TenantDomains      = $tenantDomains
                    SubscriptionName   = $subscriptionName
                    SubscriptionId     = $subscriptionId
                    SubscriptionState  = $subscriptionState
                    SubscriptionTags   = $subscriptionTags
                    SubscriptionGroup  = $subscriptionGroupName
                    ResourceGroupName  = $resourceGroupName
                    ResourceGroupId    = $resourceGroupId
                    ResourceGroupTags  = ""
                    ResourceName       = ""
                    ResourceId         = ""
                    ResourceType       = ""
                    ResourceLocation   = ""
                    ResourceSku        = ""
                    ResourceKind       = ""
                    ResourceTags       = ""
                }
            }
            $resources | ForEach-Object {
                $resource = $_
                Write-Verbose -Message "Processing resource: $($resource.Name) ($($resource.ResourceType))"
                $dataInventory += [PSCustomObject]@{
                    TenantName         = $tenantName
                    TenantId           = $tenantId
                    TenantDomains      = $tenantDomains
                    SubscriptionName   = $subscriptionName
                    SubscriptionId     = $subscriptionId
                    SubscriptionState  = $subscriptionState
                    SubscriptionTags   = $subscriptionTags
                    SubscriptionGroup  = $subscriptionGroupName
                    ResourceGroupName  = $resourceGroupName
                    ResourceGroupId    = $resourceGroupId
                    ResourceGroupTags  = ""
                    ResourceName       = $resource.Name
                    ResourceId         = $resource.ResourceId
                    ResourceType       = $resource.ResourceType
                    ResourceLocation   = $resource.Location
                    ResourceSku        = $resource.Sku
                    ResourceKind       = $resource.Kind
                    ResourceTags       = ""
                }
            }
        }
    }
}

Write-Verbose -Message "Exporting inventory to CSV file ..."
if ($Append) {
    Write-Verbose -Message "Appending to existing file ..."
    $dataInventory | Export-Csv -Path $inveFilePath -NoTypeInformation -Force -Encoding UTF8 -Append
} else {
    Write-Verbose -Message "Creating new file ..."
    $dataInventory | Export-Csv -Path $inveFilePath -NoTypeInformation -Force -Encoding UTF8
}

# Get actual date and time ...
$timeEnd = Get-Date

# Printout date&times ...
Write-Output "***********************************************************"
Write-Output "Started: $($timeStart)"
Write-Output "Finished: $($timeEnd)"
Write-Output "Elapsed time: $($timeEnd - $timeStart)"
