

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
    Write-Warning -Message "PowerShell version 7.4 or higher is required"
    exit
}

# Check if module is already installed
if (-not (Get-Module -Name Az -ListAvailable)) {
    Write-Verbose -Message "Az module not found ..."
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
    Write-Verbose -Message "Not connected to Azure, please connect first ..."
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
    Write-Verbose -Message "Inventory file already exists, deleting it ..."
    Remove-Item -Path $inveFilePath -Force
}

Write-Verbose -Message "Listing inventory from Azure ..."

$dataInventory = @()

$tenants = Get-AzTenant
$tenants | ForEach-Object {
    $tenantId = $_.Id
    $tenantName = $_.Name
    $tenantDomains = $_.Domains -join ","
    Write-Verbose -Message "Processing tenant: $tenantName ($tenantId)"

    # Get all subscriptions for the tenant
    $subscriptions = Get-AzSubscription -TenantId $tenantId
    $subscriptions | ForEach-Object {
        $subscriptionId = $_.Id
        $subscriptionName = $_.Name
        $subscriptionState = $_.State
        Write-Verbose -Message "Processing subscription: $subscriptionName ($subscriptionId)"
        Set-AzContext -SubscriptionId $subscriptionId -TenantId $tenantId | Out-Null

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
        $managementGroups = Get-AzManagementGroupEntity -ErrorAction SilentlyContinue
        $managementGroups | Format-List
        # $managementGroups | ForEach-Object {
        #     $mg = $_
        #     $subs = Get-AzManagementGroupSubscription -GroupName $mg.Name
        #     $subs | ForEach-Object {
        #         if ($_.Name -eq "$($subscriptionId)") {
        #             $subscriptionGroupName = $mg.DisplayName
        #         }
        #     }
        #     if ($subscriptionGroupName) {
        #         break
        #     }
        # }

        # Get all resource groups for the subscription
        Write-Verbose -Message "Getting resource groups for subscription ..."
        $resourceGroups = Get-AzResourceGroup -ApiVersion "2024-11-01"
        $resourceGroups | ForEach-Object {
            $resourceGroupName = $_.ResourceGroupName
            $resourceGroupId = $_.ResourceId
            Write-Verbose -Message "Processing resource group: $resourceGroupName"

            # Get all resources in the resource group
            $resources = Get-AzResource -ResourceGroupName $resourceGroupName -ApiVersion "2024-11-01"
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
