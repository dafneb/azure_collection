
### Progress bars functions
# Function: Showing progress bar for subscription
function Show-ProgressBarSubscription {

    param (
        [Parameter(Mandatory=$true,
        HelpMessage="Actual index of object.")]
        [ValidateRange(0, [int]::MaxValue)]
        [Int32] $Index,

        [Parameter(Mandatory=$true,
        HelpMessage="Maximum amount of objects (has to be higher than 0).")]
        [ValidateRange(1, [int]::MaxValue)]
        [Int32] $Max,

        [Parameter(Mandatory=$true,
        HelpMessage="Name of subscription.")]
        [ValidateNotNullOrEmpty()]
        [string] $SubName
    )

    $progCompleted = ($Index/$Max) * 100
    $progParameters = @{
        Id               = 0
        Activity         = 'Subscriptions'
        Status           = $SubName
        PercentComplete  = $progCompleted
    }
    Write-Progress @progParameters    

}

# Function: Hide progress bar for subscription
function Hide-ProgressBarSubscription {

    $progParameters = @{
        Id               = 0
        Activity         = 'Subscriptions'
        Status           = 'Done'
    }
    Write-Progress @progParameters -Completed   

} 

# Function: Showing progress bar for sub-process level 1
function Show-ProgressBarLevel1 {

    param (
        [Parameter(Mandatory=$true,
        HelpMessage="Actual index of object.")]
        [ValidateRange(0, [int]::MaxValue)]
        [Int32] $Index,

        [Parameter(Mandatory=$true,
        HelpMessage="Maximum amount of objects (has to be higher than 0).")]
        [ValidateRange(1, [int]::MaxValue)]
        [Int32] $Max,

        [Parameter(Mandatory=$true,
        HelpMessage="Name of activity.")]
        [ValidateNotNullOrEmpty()]
        [string] $ActivityName,

        [Parameter(Mandatory=$true,
        HelpMessage="Name of object.")]
        [ValidateNotNullOrEmpty()]
        [string] $ObjectName
    )

    $progCompleted = ($Index/$Max) * 100
    $progParameters = @{
        Id               = 1
        ParentId         = 0
        Activity         = $ActivityName
        Status           = $ObjectName
        PercentComplete  = $progCompleted
    }
    Write-Progress @progParameters    

}

# Function: Hide progress bar for sub-process level 1
function Hide-ProgressBarLevel1 {

    $progParameters = @{
        Id               = 1
        ParentId         = 0
        Activity         = 'Nothing'
        Status           = 'Done'
    }
    Write-Progress @progParameters -Completed   

}

# Function: Showing progress bar for sub-process level 2
function Show-ProgressBarLevel2 {

    param (
        [Parameter(Mandatory=$true,
        HelpMessage="Actual index of object.")]
        [ValidateRange(0, [int]::MaxValue)]
        [Int32] $Index,

        [Parameter(Mandatory=$true,
        HelpMessage="Maximum amount of objects (has to be higher than 0).")]
        [ValidateRange(1, [int]::MaxValue)]
        [Int32] $Max,

        [Parameter(Mandatory=$true,
        HelpMessage="Name of activity.")]
        [ValidateNotNullOrEmpty()]
        [string] $ActivityName,

        [Parameter(Mandatory=$true,
        HelpMessage="Name of object.")]
        [ValidateNotNullOrEmpty()]
        [string] $ObjectName
    )

    $progCompleted = ($Index/$Max) * 100
    $progParameters = @{
        Id               = 2
        ParentId         = 1
        Activity         = $ActivityName
        Status           = $ObjectName
        PercentComplete  = $progCompleted
    }
    Write-Progress @progParameters    

}

# Function: Hide progress bar for sub-process level 2
function Hide-ProgressBarLevel2 {

    $progParameters = @{
        Id               = 2
        ParentId         = 1
        Activity         = 'Nothing'
        Status           = 'Done'
    }
    Write-Progress @progParameters -Completed   

}

# Function: Showing progress bar for sub-process level 3
function Show-ProgressBarLevel3 {

    param (
        [Parameter(Mandatory=$true,
        HelpMessage="Actual index of object.")]
        [ValidateRange(0, [int]::MaxValue)]
        [Int32] $Index,

        [Parameter(Mandatory=$true,
        HelpMessage="Maximum amount of objects (has to be higher than 0).")]
        [ValidateRange(1, [int]::MaxValue)]
        [Int32] $Max,

        [Parameter(Mandatory=$true,
        HelpMessage="Name of activity.")]
        [ValidateNotNullOrEmpty()]
        [string] $ActivityName,

        [Parameter(Mandatory=$true,
        HelpMessage="Name of object.")]
        [ValidateNotNullOrEmpty()]
        [string] $ObjectName
    )

    $progCompleted = ($Index/$Max) * 100
    $progParameters = @{
        Id               = 3
        ParentId         = 2
        Activity         = $ActivityName
        Status           = $ObjectName
        PercentComplete  = $progCompleted
    }
    Write-Progress @progParameters    

}

# Function: Hide progress bar for sub-process level 3
function Hide-ProgressBarLevel3 {

    $progParameters = @{
        Id               = 3
        ParentId         = 2
        Activity         = 'Nothing'
        Status           = 'Done'
    }
    Write-Progress @progParameters -Completed   

}

###################################################################

### Azure functions
# Function: Get list of roles for subscription and go through it
function Get-RolesForSubscription {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,
        HelpMessage="Subscription ID.")]
        [ValidateNotNullOrEmpty()]
        [string] $SubscriptionId
    )

    begin {
        $loopRolesIndex = 0
        $scope="/subscriptions/$($SubscriptionId)"
        Write-Verbose -Message "Begin of Get-RolesForSubscription"
    
    }

    process {
        Write-Verbose -Message "Get all roles at $($scope)"
        Show-ProgressBarLevel1 -Index 0 -Max 100 -ActivityName "Roles" -ObjectName "Getting all roles from Azure"
        $roles = Get-AzRoleAssignment -Scope $scope | Where-Object Scope -EQ $scope
        Write-Verbose -Message "Received $($roles.Count) records"
        $roles | ForEach-Object {

            $roleItem = $_
            $loopRolesIndex = $loopRolesIndex + 1
            Show-ProgressBarLevel1 -Index $loopRolesIndex -Max $roles.Count -ActivityName "Roles" -ObjectName "$($loopRolesIndex) / $($roles.Count) - $($roleItem.RoleDefinitionName)"

            Write-Verbose -Message "Role: $($roleItem.RoleDefinitionName); PrincipalName: $($roleItem.DisplayName) ($($roleItem.ObjectType))"
            $script:dataRoles +=  [PSCustomObject]@{RoleName="$($roleItem.RoleDefinitionName)"; PrincipalName="$($roleItem.DisplayName)"; PrincipalType="$($roleItem.ObjectType)"; Scope="$($roleItem.Scope)"}

        }

    }

    end {
        Hide-ProgressBarLevel1
        Write-Verbose -Message "End of Get-RolesForSubscription"
    }

}

# Function: Get list of roles for resource group and go through it
function Get-RolesForResourceGroup {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,
        HelpMessage="Resource ID.")]
        [ValidateNotNullOrEmpty()]
        [string] $ResourceId
    )

    begin {
        $loopRolesIndex = 0
        $scope = $ResourceId
        Write-Verbose -Message "Begin of Get-RolesForResourceGroup"
    
    }

    process {
        Write-Verbose -Message "Get all roles at $($scope)"
        Show-ProgressBarLevel2 -Index 0 -Max 100 -ActivityName "Roles" -ObjectName "Getting all roles from Azure"
        $roles = Get-AzRoleAssignment -Scope $scope | Where-Object Scope -EQ $scope
        Write-Verbose -Message "Received $($roles.Count) records"
        $roles | ForEach-Object {

            $roleItem = $_
            $loopRolesIndex = $loopRolesIndex + 1
            Show-ProgressBarLevel2 -Index $loopRolesIndex -Max $roles.Count -ActivityName "Roles" -ObjectName "$($loopRolesIndex) / $($roles.Count) - $($roleItem.RoleDefinitionName)"

            Write-Verbose -Message "Role: $($roleItem.RoleDefinitionName); PrincipalName: $($roleItem.DisplayName) ($($roleItem.ObjectType))"
            $script:dataRoles +=  [PSCustomObject]@{RoleName="$($roleItem.RoleDefinitionName)"; PrincipalName="$($roleItem.DisplayName)"; PrincipalType="$($roleItem.ObjectType)"; Scope="$($roleItem.Scope)"}

        }

    }

    end {
        Hide-ProgressBarLevel2
        Write-Verbose -Message "End of Get-RolesForResourceGroup"
    }

}

# Function: Get list of roles for resource and go through it
function Get-RolesForResource {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,
        HelpMessage="Resource ID.")]
        [ValidateNotNullOrEmpty()]
        [string] $ResourceId
    )

    begin {
        $loopRolesIndex = 0
        $scope = $ResourceId
        Write-Verbose -Message "Begin of Get-RolesForResource"
    
    }

    process {
        Write-Verbose -Message "Get all roles at $($scope)"
        Show-ProgressBarLevel3 -Index 0 -Max 100 -ActivityName "Roles" -ObjectName "Getting all roles from Azure"
        $roles = Get-AzRoleAssignment -Scope $scope | Where-Object Scope -EQ $scope
        Write-Verbose -Message "Received $($roles.Count) records"
        $roles | ForEach-Object {

            $roleItem = $_
            $loopRolesIndex = $loopRolesIndex + 1
            Show-ProgressBarLevel3 -Index $loopRolesIndex -Max $roles.Count -ActivityName "Roles" -ObjectName "$($loopRolesIndex) / $($roles.Count) - $($roleItem.RoleDefinitionName)"

            Write-Verbose -Message "Role: $($roleItem.RoleDefinitionName); PrincipalName: $($roleItem.DisplayName) ($($roleItem.ObjectType))"
            $script:dataRoles +=  [PSCustomObject]@{RoleName="$($roleItem.RoleDefinitionName)"; PrincipalName="$($roleItem.DisplayName)"; PrincipalType="$($roleItem.ObjectType)"; Scope="$($roleItem.Scope)"}

        }

    }

    end {
        Hide-ProgressBarLevel3
        Write-Verbose -Message "End of Get-RolesForResource"
    }

}

# Function: Get details about Virtual Machine
function Get-VirtualMachineDetails {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,
        HelpMessage="Resource group name.")]
        [ValidateNotNullOrEmpty()]
        [string] $ResourceGroupName,

        [Parameter(Mandatory=$true,
        HelpMessage="Virtual machine name.")]
        [ValidateNotNullOrEmpty()]
        [string] $VMName
    )

    begin {
        Write-Verbose -Message "Begin of Get-VirtualMachineDetails"
        Show-ProgressBarLevel3 -ActivityName "Getting details" -ObjectName "VirtualMachine" -Index 0 -Max 100
    
    }

    process {
        Write-Verbose -Message "Get details of virtual machine"
        $machine = Get-AZVm -ResourceGroupName $ResourceGroupName -Name $VMName
        $machine.NetworkProfile | Format-Table
        $script:dataInventory += "`t`t`tSize: $($machine.HardwareProfile.VmSize)"
        $script:dataInventory += "`t`t`tvCPU: $($machine.HardwareProfile.VmSizeProperties.VCPUsAvailable)"
        $script:dataInventory += "`t`t`tvCPU per Core: $($machine.HardwareProfile.VmSizeProperties.VCPUsPerCore)"
        $script:dataInventory += "`t`t`tImage reference:"
        $script:dataInventory += "`t`t`t`tPublisher: $($machine.StorageProfile.ImageReference.Publisher)"
        $script:dataInventory += "`t`t`t`tOffer: $($machine.StorageProfile.ImageReference.Offer)"
        $script:dataInventory += "`t`t`t`tSKU: $($machine.StorageProfile.ImageReference.Sku)"
        $script:dataInventory += "`t`t`tComputerName: $($machine.OSProfile.ComputerName)"
        $script:dataInventory += "`t`t`tOSName: $($machine.OsName)"
        $script:dataInventory += "`t`t`tAdminUserName: $($machine.OSProfile.AdminUsername)"
        if ($machine.OSProfile.LinuxConfiguration) {
            $script:dataInventory += "`t`t`tLinuxConfiguration:"
            $script:dataInventory += "`t`t`t`tDisablePasswordAuthentication: $($machine.OSProfile.LinuxConfiguration.DisablePasswordAuthentication)"
            $script:dataInventory += "`t`t`t`tEnableVMAgentPlatformUpdates: $($machine.OSProfile.LinuxConfiguration.EnableVMAgentPlatformUpdates)"
            $script:dataInventory += "`t`t`t`tAssessmentMode: $($machine.OSProfile.LinuxConfiguration.PatchSettings.AssessmentMode)"
            $script:dataInventory += "`t`t`t`tPatchMode: $($machine.OSProfile.LinuxConfiguration.PatchSettings.PatchMode)"
            $script:dataInventory += "`t`t`t`tProvisionVMAgent: $($machine.OSProfile.LinuxConfiguration.ProvisionVMAgent)"
        }
        if ($machine.OSProfile.WindowsConfiguration) {
            $script:dataInventory += "`t`t`tWindowsConfiguration:"
            #$script:dataInventory += "`t`t`t`txxx: $($machine.xxx)"
        }
        #$script:dataInventory += "`t`t`txxx: $($machine.xxx)"
        #$script:dataInventory += "`t`t`txxx: $($machine.xxx)"
        #$script:dataInventory += "`t`t`txxx: $($machine.xxx)"
        #$script:dataInventory += "`t`t`txxx: $($machine.xxx)"
        #$script:dataInventory += "`t`t`txxx: $($machine.xxx)"
        #$script:dataInventory += "`t`t`txxx: $($machine.xxx)"
        #$script:dataInventory += "`t`t`txxx: $($machine.xxx)"
        #$script:dataInventory += "`t`t`txxx: $($machine.xxx)"
        #$script:dataInventory += "`t`t`txxx: $($machine.xxx)"
        #$script:dataInventory += "`t`t`txxx: $($machine.xxx)"
        #$script:dataInventory += "`t`t`txxx: $($machine.xxx)"
        #$script:dataInventory += "`t`t`txxx: $($machine.xxx)"

    }

    end {
        Hide-ProgressBarLevel3
        Write-Verbose -Message "End of Get-VirtualMachineDetails"

    }
}

# Function: Get details about KeyVault
function Get-KeyVaultDetails {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,
        HelpMessage="KeyVault name.")]
        [ValidateNotNullOrEmpty()]
        [string] $KeyVaultName
    )

    begin {
        Write-Verbose -Message "Begin of Get-KeyVaultDetails"
        Show-ProgressBarLevel3 -ActivityName "Getting details" -ObjectName "KeyVault" -Index 0 -Max 100
    
    }

    process {

        Write-Verbose -Message "Get details of key vault"
        $kv = Get-AzKeyVault -VaultName $KeyVaultName
        $script:dataInventory += "`t`t`tSku: $($kv.Sku)"
        $script:dataInventory += "`t`t`tVaultUri: $($kv.VaultUri)"
        $script:dataInventory += "`t`t`tEnabledForDeployment: $($kv.EnabledForDeployment)"
        $script:dataInventory += "`t`t`tEnabledForDiskEncryption: $($kv.EnabledForDiskEncryption)"
        $script:dataInventory += "`t`t`tEnabledForTemplateDeployment: $($kv.EnabledForTemplateDeployment)"
        $script:dataInventory += "`t`t`tEnablePurgeProtection: $($kv.EnablePurgeProtection)"
        $script:dataInventory += "`t`t`tEnableRbacAuthorization: $($kv.EnableRbacAuthorization)"
        $script:dataInventory += "`t`t`tEnableSoftDelete: $($kv.EnableSoftDelete)"
        $script:dataInventory += "`t`t`tPublicNetworkAccess: $($kv.PublicNetworkAccess)"
        $script:dataInventory += "`t`t`tNetworkAcls:"
        $script:dataInventory += "`t`t`t`tBypass: $($kv.NetworkAcls.Bypass)"
        $script:dataInventory += "`t`t`t`tDefault: $($kv.NetworkAcls.DefaultAction)"
        $script:dataInventory += "`t`t`t`tvNet Rules:"
        $kv.NetworkAcls.VirtualNetworkResourceIds | ForEach-Object {
            $rule = $_
            if ($rule.Length -gt 0) {
                $script:dataInventory += "`t`t`t`t`t$($rule)"
            }

        }
        $script:dataInventory += "`t`t`t`tIP Rules:"
        $kv.NetworkAcls.IpAddressRanges | ForEach-Object {
            $rule = $_
            if ($rule.Length -gt 0) {
                $script:dataInventory += "`t`t`t`t`t$($rule)"
            }

        }

    }

    end {
        Hide-ProgressBarLevel3
        Write-Verbose -Message "End of Get-KeyVaultDetails"

    }
}

# Function: Get details about StorageAccount
function Get-StorageAccountDetails {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,
        HelpMessage="Resource group name.")]
        [ValidateNotNullOrEmpty()]
        [string] $ResourceGroupName,

        [Parameter(Mandatory=$true,
        HelpMessage="Storage account name.")]
        [ValidateNotNullOrEmpty()]
        [string] $StorageName
    )

    begin {
        Write-Verbose -Message "Begin of Get-StorageAccountDetails"
        Show-ProgressBarLevel3 -ActivityName "Getting details" -ObjectName "StorageAccount" -Index 0 -Max 100
    
    }

    process {

        Write-Verbose -Message "Get details of storage account"
        $account = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageName
        $script:dataInventory += "`t`t`tSku: $($account.Sku.Name)"
        $script:dataInventory += "`t`t`tKind: $($account.Kind)"
        $script:dataInventory += "`t`t`tProvisioningState: $($account.ProvisioningState)"
        $script:dataInventory += "`t`t`tAccessTier: $($account.AccessTier)"
        $script:dataInventory += "`t`t`tStatusOfPrimary: $($account.StatusOfPrimary)"
        $script:dataInventory += "`t`t`tStatusOfSecondary: $($account.StatusOfSecondary)"
        $script:dataInventory += "`t`t`tEncryption.KeySource: $($account.Encryption.KeySource)"
        $script:dataInventory += "`t`t`tEncryption.RequireInfrastructureEncryption: $($account.Encryption.RequireInfrastructureEncryption)"
        $script:dataInventory += "`t`t`tEnableHttpsTrafficOnly: $($account.EnableHttpsTrafficOnly)"
        $script:dataInventory += "`t`t`tMinimumTlsVersion: $($account.MinimumTlsVersion)"
        $script:dataInventory += "`t`t`tPublicNetworkAccess: $($account.PublicNetworkAccess)"
        $script:dataInventory += "`t`t`tNetworkRuleSet:"
        $script:dataInventory += "`t`t`t`tBypass: $($account.NetworkRuleSet.Bypass)"
        $script:dataInventory += "`t`t`t`tDefault: $($account.NetworkRuleSet.DefaultAction)"
        $script:dataInventory += "`t`t`t`tvNet Rules:"
        $account.NetworkRuleSet.VirtualNetworkRules | ForEach-Object {
            $rule = $_
            $script:dataInventory += "`t`t`t`t`t[$($rule.State)] $($rule.Action): $($rule.VirtualNetworkResourceId)"
        }
        $script:dataInventory += "`t`t`t`tIP Rules:"
        $account.NetworkRuleSet.IpRules | ForEach-Object {
            $rule = $_
            $script:dataInventory += "`t`t`t`t`t$($rule.Action): $($rule.IPAddressOrRange)"
        }
        $script:dataInventory += "`t`t`t`tResource Rules:"
        $account.NetworkRuleSet.ResourceAccessRules | ForEach-Object {
            $rule = $_
            $script:dataInventory += "`t`t`t`t`t$($rule.ResourceId) (Tenant: $($rule.TenantId))"
        }
        $script:dataInventory += "`t`t`tAllowBlobPublicAccess: $($account.AllowBlobPublicAccess)"
        $script:dataInventory += "`t`t`tEnableNfsV3: $($account.EnableNfsV3)"
        $script:dataInventory += "`t`t`tEnableSftp: $($account.EnableSftp)"
        $script:dataInventory += "`t`t`tEnableLocalUser: $($account.EnableLocalUser)"
        $script:dataInventory += "`t`t`tAllowSharedKeyAccess: $($account.AllowSharedKeyAccess)"
        
    }

    end {
        Hide-ProgressBarLevel3
        Write-Verbose -Message "End of Get-StorageAccountDetails"

    }

}

# Function: Get list of resources and go through it
function Get-ResourceForResourceGroup {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,
        HelpMessage="Resource group name.")]
        [ValidateNotNullOrEmpty()]
        [string] $ResourceGroupName
    )

    begin {
        $loopResourcesIndex = 0
        Write-Verbose -Message "Begin of Get-ResourceForResourceGroup"
    }

    process {

        Write-Verbose -Message "Get all resources at resource group $($ResourceGroupName)"
        Show-ProgressBarLevel2 -Index 0 -Max 100 -ActivityName "Resources" -ObjectName "Getting all resources from Azure"
        $resources = Get-AzResource -ResourceGroupName $ResourceGroupName
        Write-Verbose -Message "Received $($resources.Count) records"
        $resources | ForEach-Object {

            $resItem = $_
            $loopResourcesIndex = $loopResourcesIndex + 1
            Show-ProgressBarLevel2 -Index $loopResourcesIndex -Max $resources.Count -ActivityName "Resources" -ObjectName "$($loopResourcesIndex) / $($resources.Count) - $($resItem.Name)"

            Write-Verbose -Message "Resource: $($resItem.Name); Type: $($resItem.ResourceType)"
            $script:dataInventory += "`t`tResource: $($resItem.Name); Type: $($resItem.ResourceType)"

            Get-RolesForResource -ResourceId $resItem.ResourceId

            if ($processDetails) {

                switch ($resItem.ResourceType)
                {
                    'Microsoft.Storage/storageAccounts'
                    {
                        Write-Verbose -Message 'Get details for StorageAccount'
                        Get-StorageAccountDetails -ResourceGroupName $resItem.ResourceGroupName -StorageName $resItem.Name
                    }
                    'Microsoft.KeyVault/vaults'
                    {
                        Write-Verbose -Message 'Get details for KeyVault'
                        Get-KeyVaultDetails -KeyVaultName $resItem.Name
                    }
                    'Microsoft.Compute/virtualMachines'
                    {
                        Write-Verbose -Message 'Get details for VirtualMachine'
                        Get-VirtualMachineDetails -ResourceGroupName $resItem.ResourceGroupName -VMName $resItem.Name
                    }
                }
    
            }

        }

    }

    end {
        Hide-ProgressBarLevel2
        Write-Verbose -Message "End of Get-ResourceForResourceGroup"
    }

}

# Function: Get list of resource groups and go through it
function Get-ResourceGroupsForSubscription {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,
        HelpMessage="Subscription ID.")]
        [ValidateNotNullOrEmpty()]
        [string] $SubscriptionId
    )

    begin {
        $loopGroupsIndex = 0
        Write-Verbose -Message "Begin of Get-ResourceGroupsForSubscription"
        Write-Verbose -Message "Adjusting AzContext to $($SubscriptionId)"
        Set-AzContext -Subscription $SubscriptionId | Out-Null
    
    }

    process {

        Write-Verbose -Message "Get all resource groups at subscription $($SubscriptionId)"
        Show-ProgressBarLevel1 -Index 0 -Max 100 -ActivityName "Resource Groups" -ObjectName "Getting all resource groups from Azure"
        $resGroups = Get-AzResourceGroup
        Write-Verbose -Message "Received $($resGroups.Count) records"
        $resGroups | ForEach-Object {

            $resGrpItem = $_
            $loopGroupsIndex = $loopGroupsIndex + 1
            Show-ProgressBarLevel1 -Index $loopGroupsIndex -Max $resGroups.Count -ActivityName "Resource Groups" -ObjectName "$($loopGroupsIndex) / $($resGroups.Count) - $($resGrpItem.ResourceGroupName)"

            Write-Verbose -Message "ResourceGroup: $($resGrpItem.ResourceGroupName); Location: $($resGrpItem.Location)"
            $script:dataInventory += "`tResourceGroup: $($resGrpItem.ResourceGroupName); Location: $($resGrpItem.Location)"
            
            Get-RolesForResourceGroup -ResourceId $resGrpItem.ResourceId
            Get-ResourceForResourceGroup -ResourceGroupName $resGrpItem.ResourceGroupName

        }

    }

    end {
        Hide-ProgressBarLevel1
        Write-Verbose -Message "End of Get-ResourceGroupsForSubscription"
    }

}

# Function: Get list of subscriptions and go through it
function Get-Subscriptions {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,
        HelpMessage="AzContext for actual tenant.")]
        [Microsoft.Azure.Commands.Profile.Models.Core.PSAzureContext] $Context
    )

    begin {
        Write-Verbose -Message "Begin of Get-Subscriptions"

        # Clear host output ...
        Clear-Host

        # Reset loop to zero
        $loopSubIndex = 0
    }

    process {
        # Get all subscriptions at Tenant
        Write-Verbose -Message "Get all subscriptions at Tenant $($Context.Tenant)"
        Show-ProgressBarSubscription -Index 0 -Max 100 -SubName "Getting all subscriptions from Azure"
        $subscriptions = Get-AzSubscription -TenantId $Context.Tenant
        Write-Verbose -Message "Received $($subscriptions.Count) records"
        $subscriptions | ForEach-Object {

            $item = $_
            $loopSubIndex += 1
            Show-ProgressBarSubscription -Index $loopSubIndex -Max $subscriptions.Count -SubName "$($loopSubIndex) / $($subscriptions.Count) - $($item.Name)"
                    
            Write-Verbose -Message "Subscription: $($item.Name); ID: $($item.Id)"
            $script:dataInventory += "Subscription: $($item.Name); ID: $($item.Id); TenantID: $($item.TenantId); State: $($item.State)"

            Get-RolesForSubscription -SubscriptionId $item.Id
            Get-ResourceGroupsForSubscription -SubscriptionId $item.Id

        }

    }

    end {
        Hide-ProgressBarSubscription
        Write-Verbose -Message "End of Get-Subscriptions"
        Write-Output "Scanning done!"

    }

}
###################################################################

# Get actual date and time ...
$timeStart = Get-Date

# Some variables ...
$processDetails = $false
$processAudits = $false

# Get actual Azure context ...
$context = Get-AzContext

# Define path to files ...
$fileInventory = "azure-inventory-$($context.Tenant).txt"
$fileRoles = "azure-roles-$($context.Tenant).csv"
$fileIps = "azure-ips-$($context.Tenant).csv"
$fileUrls = "azure-urls-$($context.Tenant).csv"
$fileAudit = "azure-audit-$($context.Tenant).csv" 
$fileOSystems = "azure-osystems-$($context.Tenant).csv" 
$fileLanguages = "azure-languages-$($context.Tenant).csv"

# Definition of lists for data ...
[string[]]$script:dataInventory = @()
$script:dataRoles = @()
$script:dataIps = @()
$script:dataUrls = @()
$script:dataAudit = @()
$script:dataOSystems = @()
$script:dataLanguages = @()

# Get inventory from Azure ...
Get-Subscriptions -Context $context

# Clear previous data from files ...
Clear-Content -Path $fileInventory
Clear-Content -Path $fileRoles
Clear-Content -Path $fileIps
Clear-Content -Path $fileUrls
Clear-Content -Path $fileAudit
Clear-Content -Path $fileOSystems
Clear-Content -Path $fileLanguages

# Export collected data to files ...
$script:dataInventory | ForEach-Object { Add-Content -Path $fileInventory -Value $_ }
$script:dataRoles | Export-Csv -Path $fileRoles -NoTypeInformation
$script:dataIps | Export-Csv -Path $fileIps -NoTypeInformation
$script:dataUrls | Export-Csv -Path $fileUrls -NoTypeInformation
$script:dataAudit | Export-Csv -Path $fileAudit -NoTypeInformation
$script:dataOSystems | Export-Csv -Path $fileOSystems -NoTypeInformation
$script:dataLanguages | Export-Csv -Path $fileLanguages -NoTypeInformation

# Get actual date and time ...
$timeEnd = Get-Date

# Printout date&times ...
Write-Output $timeStart
Write-Output $timeEnd
