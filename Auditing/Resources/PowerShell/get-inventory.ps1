<#
.SYNOPSIS
    This script lists all resources in Azure and exports the inventory to a CSV file.

.DESCRIPTION
    This script lists all resources in Azure and exports the inventory to a CSV file.
    It checks if the Az module is installed and loaded, and if the user is connected to Azure.
    It creates a case folder for the inventory and exports the data to a CSV file.

.PARAMETER CaseName
    The name of the case folder where the inventory will be saved.
    The case name will be normalized to lowercase and invalid characters will be replaced with underscores.

.EXAMPLE
    ./get-inventory.ps1 -CaseName "MyCase"
    This will create a folder named "mycase" in the case directory, saving the results in a CSV file within that folder.

.NOTES
    This script requires PowerShell 7.4 or higher.
    Ensure that the Microsoft Az PowerShell module is installed before running the script.
    The script requires appropriate permissions to access resource data in Azure.

    Author: David Burel (@dafneb)
    Date: June 9, 2025
    Version: 1.0.2
#>

# Define the script's parameters
[CmdletBinding(DefaultParameterSetName = "Default")]
param (
    [Parameter(Mandatory = $true, ParameterSetName = "Default")]
    [ValidateNotNullOrEmpty()]
    [string]$CaseName

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
$inveFilePath = Join-Path -Path $caseFolderPath -ChildPath "inventory-resources.csv"
$subscriptionFilePath = Join-Path -Path $caseFolderPath -ChildPath "inventory-subscriptions.csv"

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

# Check if the inventory file already exists
if (Test-Path -Path $inveFilePath) {
    Write-Verbose -Message "Inventory file already exists, deleting it ..."
    Remove-Item -Path $inveFilePath -Force
}

# Check if the subscription file already exists
if (Test-Path -Path $subscriptionFilePath) {
    Write-Verbose -Message "Subscription file already exists, deleting it ..."
    Remove-Item -Path $subscriptionFilePath -Force
}

Write-Verbose -Message "Listing inventory from Azure ..."

$dataInventory = @()
$dataSubscriptions = @()

$tenants = Get-AzTenant -ErrorAction SilentlyContinue
if (-not $tenants) {
    Write-Warning -Message "No tenants found, please check your connection"
}
$tenants | ForEach-Object {
    $tenantId = $_.Id
    $tenantName = $_.Name
    $tenantDomains = $_.Domains -join "; "
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

        $dataSubscriptions += [PSCustomObject]@{
            TenantName        = $tenantName
            TenantId          = $tenantId
            TenantDomains     = $tenantDomains
            SubscriptionName  = $subscriptionName
            SubscriptionId    = $subscriptionId
            SubscriptionState = $subscriptionState
            SubscriptionTags  = $subscriptionTags
            SubscriptionGroup = $subscriptionGroupName
        }

        # Skip if the subscription is disabled
        if ($subscriptionState -eq "Disabled") {
            Write-Warning -Message "Subscription $subscriptionName ($subscriptionId) is Disabled, skipping ..."
            return
        }
        Set-AzContext -SubscriptionId $subscriptionId -TenantId $tenantId | Out-Null
        if (-not (Get-AzContext)) {
            Write-Warning -Message "Failed to set context for subscription $subscriptionName ($subscriptionId)"
            return
        }

        # Get all resource groups for the subscription
        Write-Verbose -Message "Getting resource groups for subscription ..."
        $resourceGroups = Get-AzResourceGroup -ApiVersion "2024-11-01" -ErrorAction SilentlyContinue
        $resourceGroups | ForEach-Object {
            $resourceGroup = $_
            Write-Output "Processing resource group: $($resourceGroup.ResourceGroupName)"

            # Get tags for the resource group
            $resourceGroupTags = ""
            $resourceGroupTagsArray = @()
            if ($resourceGroup.Tags -and $resourceGroup.Tags.Count -gt 0) {
                # Loop through each tag and add it to the array
                $resourceGroup.Tags.Keys | ForEach-Object {
                    $tagName = $_
                    $tagValue = $resourceGroup.Tags[$tagName]
                    $resourceGroupTagsArray += "[$tagName = $tagValue]"
                }
                $resourceGroupTags = $resourceGroupTagsArray -join "; "
            }

            # Get all resources in the resource group
            $resources = Get-AzResource -ResourceGroupName $resourceGroup.ResourceGroupName -ApiVersion "2024-11-01" -ErrorAction SilentlyContinue
            $resources | ForEach-Object {
                $resource = $_
                Write-Verbose -Message "Processing resource: $($resource.Name) ($($resource.ResourceType))"

                # Get tags for the resource
                $resourceTags = ""
                $resourceTagsArray = @()
                if ($resource.Tags -and $resource.Tags.Count -gt 0) {
                    # Loop through each tag and add it to the array
                    $resource.Tags.Keys | ForEach-Object {
                        $tagName = $_
                        $tagValue = $resource.Tags[$tagName]
                        $resourceTagsArray += "[$tagName = $tagValue]"
                    }
                    $resourceTags = $resourceTagsArray -join "; "
                }

                $dataInventory += [PSCustomObject]@{
                    TenantName            = $tenantName
                    TenantId              = $tenantId
                    SubscriptionName      = $subscriptionName
                    SubscriptionId        = $subscriptionId
                    ResourceGroupName     = $resourceGroup.ResourceGroupName
                    ResourceGroupId       = $resourceGroup.ResourceId
                    ResourceGroupTags     = $resourceGroupTags
                    ResourceGroupLocation = $resourceGroup.Location
                    ResourceName          = $resource.Name
                    ResourceId            = $resource.ResourceId
                    ResourceType          = $resource.ResourceType
                    ResourceLocation      = $resource.Location
                    ResourceSku           = $resource.Sku
                    ResourceKind          = $resource.Kind
                    ResourceTags          = $resourceTags
                }
            }
        }
    }
}

Write-Output "Exporting data to files ..."
$dataInventory | Export-Csv -Path $inveFilePath -NoTypeInformation -Force -Encoding UTF8
$dataSubscriptions | Export-Csv -Path $subscriptionFilePath -NoTypeInformation -Force -Encoding UTF8

# Get actual date and time ...
$timeEnd = Get-Date

# Printout date&times ...
Write-Output "***********************************************************"
Write-Output "Started: $($timeStart)"
Write-Output "Finished: $($timeEnd)"
Write-Output "Elapsed time: $($timeEnd - $timeStart)"
