
### Progress bars functions
<#
.SYNOPSIS
    Displays a progress bar for subscription-related tasks.

.DESCRIPTION
    The Show-ProgressBarSubscription function provides a visual representation of the progress of subscription-related tasks. It calculates the percentage of completion based on the current index and the maximum number of objects, and displays a progress bar with the specified subscription name.

.PARAMETER Index
    The current index of the object being processed. This value should be between 0 and the maximum number of objects.

.PARAMETER Max
    The maximum number of objects to be processed. This value should be greater than 0.

.PARAMETER SubName
    The name of the subscription for which the progress is being displayed.

.EXAMPLE
    Show-ProgressBarSubscription -Index 5 -Max 100 -SubName "MySubscription"
    This command displays a progress bar indicating that 5% of the task for "MySubscription" has been completed.

.NOTES
    Author: David Burel (@dafneb)
    Date: February 17, 2025
    Version: 1.0
#>
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

<#
.SYNOPSIS
    Hides the progress bar for subscription-related tasks.

.DESCRIPTION
    The Hide-ProgressBarSubscription function is designed to hide the progress bar that was previously displayed for subscription-related tasks. It marks the progress bar as completed, clearing it from the display and indicating that the task is done.

.EXAMPLE
    Hide-ProgressBarSubscription
    This command hides the progress bar for subscription-related tasks, marking it as completed.

.NOTES
    Author: David Burel (@dafneb)
    Date: February 17, 2025
    Version: 1.0
#>
function Hide-ProgressBarSubscription {

    $progParameters = @{
        Id               = 0
        Activity         = 'Subscriptions'
        Status           = 'Done'
    }
    Write-Progress @progParameters -Completed   

} 

<#
.SYNOPSIS
    Displays a progress bar for sub-process level 1 tasks.

.DESCRIPTION
    The Show-ProgressBarLevel1 function provides a visual representation of the progress of sub-process level 1 tasks. It calculates the percentage of completion based on the current index and the maximum number of objects, and displays a progress bar with the specified activity name and object name.

.PARAMETER Index
    The current index of the object being processed. This value should be between 0 and the maximum number of objects.

.PARAMETER Max
    The maximum number of objects to be processed. This value should be greater than 0.

.PARAMETER ActivityName
    The name of the activity for which the progress is being displayed.

.PARAMETER ObjectName
    The name of the object for which the progress is being displayed.

.EXAMPLE
    Show-ProgressBarLevel1 -Index 5 -Max 100 -ActivityName "Roles" -ObjectName "Getting all roles from Azure"
    This command displays a progress bar indicating that 5% of the task for "Roles" has been completed, with the status "Getting all roles from Azure".

.NOTES
    Author: David Burel (@dafneb)
    Date: February 17, 2025
    Version: 1.0
#>
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

<#
.SYNOPSIS
    Hides the progress bar for sub-process level 1 tasks.

.DESCRIPTION
    The Hide-ProgressBarLevel1 function is designed to hide the progress bar that was previously displayed for sub-process level 1 tasks. It marks the progress bar as completed, clearing it from the display and indicating that the task is done.

.EXAMPLE
    Hide-ProgressBarLevel1
    This command hides the progress bar for sub-process level 1 tasks, marking it as completed.

.NOTES
    Author: David Burel (@dafneb)
    Date: February 17, 2025
    Version: 1.0
#>
function Hide-ProgressBarLevel1 {

    $progParameters = @{
        Id               = 1
        ParentId         = 0
        Activity         = 'Nothing'
        Status           = 'Done'
    }
    Write-Progress @progParameters -Completed   

}

<#
.SYNOPSIS
    Displays a progress bar for sub-process level 2 tasks.

.DESCRIPTION
    The Show-ProgressBarLevel2 function provides a visual representation of the progress of sub-process level 2 tasks. It calculates the percentage of completion based on the current index and the maximum number of objects, and displays a progress bar with the specified activity name and object name.

.PARAMETER Index
    The current index of the object being processed. This value should be between 0 and the maximum number of objects.

.PARAMETER Max
    The maximum number of objects to be processed. This value should be greater than 0.

.PARAMETER ActivityName
    The name of the activity for which the progress is being displayed.

.PARAMETER ObjectName
    The name of the object for which the progress is being displayed.

.EXAMPLE
    Show-ProgressBarLevel2 -Index 5 -Max 100 -ActivityName "Resources" -ObjectName "Getting all resources from Azure"
    This command displays a progress bar indicating that 5% of the task for "Resources" has been completed, with the status "Getting all resources from Azure".

.NOTES
    Author: David Burel (@dafneb)
    Date: February 17, 2025
    Version: 1.0
#>
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

<#
.SYNOPSIS
    Hides the progress bar for sub-process level 2 tasks.

.DESCRIPTION
    The Hide-ProgressBarLevel2 function is designed to hide the progress bar that was previously displayed for sub-process level 2 tasks. It marks the progress bar as completed, clearing it from the display and indicating that the task is done.

.EXAMPLE
    Hide-ProgressBarLevel2
    This command hides the progress bar for sub-process level 2 tasks, marking it as completed.

.NOTES
    Author: David Burel (@dafneb)
    Date: February 17, 2025
    Version: 1.0
#>
function Hide-ProgressBarLevel2 {

    $progParameters = @{
        Id               = 2
        ParentId         = 1
        Activity         = 'Nothing'
        Status           = 'Done'
    }
    Write-Progress @progParameters -Completed   

}

<#
.SYNOPSIS
    Displays a progress bar for sub-process level 3 tasks.

.DESCRIPTION
    The Show-ProgressBarLevel3 function provides a visual representation of the progress of sub-process level 3 tasks. It calculates the percentage of completion based on the current index and the maximum number of objects, and displays a progress bar with the specified activity name and object name.

.PARAMETER Index
    The current index of the object being processed. This value should be between 0 and the maximum number of objects.

.PARAMETER Max
    The maximum number of objects to be processed. This value should be greater than 0.

.PARAMETER ActivityName
    The name of the activity for which the progress is being displayed.

.PARAMETER ObjectName
    The name of the object for which the progress is being displayed.

.EXAMPLE
    Show-ProgressBarLevel3 -Index 5 -Max 100 -ActivityName "Resources" -ObjectName "Getting all resources from Azure"
    This command displays a progress bar indicating that 5% of the task for "Resources" has been completed, with the status "Getting all resources from Azure".

.NOTES
    Author: David Burel (@dafneb)
    Date: February 17, 2025
    Version: 1.0
#>
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

<#
.SYNOPSIS
Hides the progress bar for Level 3 operations.

.DESCRIPTION
This function, Hide-ProgressBarLevel3, is designed to hide the progress bar specifically associated with Level 3 operations within a larger script or process. It provides a way to clear the visual clutter of a progress indicator when it's no longer needed, typically after a Level 3 task has completed or been canceled.  This helps maintain a clean and focused user interface. It assumes that a progress bar for Level 3 was previously displayed using other functions or mechanisms within the script.

.EXAMPLE
Hide-ProgressBarLevel3

.NOTES
    Author: David Burel (@dafneb)
    Date: February 17, 2025
    Version: 1.0
#>
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
<#
.SYNOPSIS
    Retrieves and processes the list of roles for a specified Azure subscription.

.DESCRIPTION
    The Get-RolesForSubscription function retrieves all role assignments for a specified Azure subscription. It processes each role assignment, displaying progress and collecting data about the roles, including the role name, principal name, principal type, and scope.

.PARAMETER SubscriptionId
    The ID of the Azure subscription for which to retrieve role assignments.

.EXAMPLE
    Get-RolesForSubscription -SubscriptionId "12345678-1234-1234-1234-123456789012"
    This command retrieves and processes the list of roles for the Azure subscription with the ID "12345678-1234-1234-1234-123456789012".

.NOTES
    Author: David Burel (@dafneb)
    Date: February 17, 2025
    Version: 1.0
#>
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

<#
.SYNOPSIS
    Retrieves and processes the list of roles for a specified Azure resource group.

.DESCRIPTION
    The Get-RolesForResourceGroup function retrieves all role assignments for a specified Azure resource group. It processes each role assignment, displaying progress and collecting data about the roles, including the role name, principal name, principal type, and scope.

.PARAMETER ResourceId
    The ID of the Azure resource group for which to retrieve role assignments.

.EXAMPLE
    Get-RolesForResourceGroup -ResourceId "/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/myResourceGroup"
    This command retrieves and processes the list of roles for the Azure resource group with the specified resource ID.

.NOTES
    Author: David Burel (@dafneb)
    Date: February 17, 2025
    Version: 1.0
#>
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

<#
.SYNOPSIS
    Retrieves and processes the list of roles for a specified Azure resource.

.DESCRIPTION
    The Get-RolesForResource function retrieves all role assignments for a specified Azure resource. It processes each role assignment, displaying progress and collecting data about the roles, including the role name, principal name, principal type, and scope.

.PARAMETER ResourceId
    The ID of the Azure resource for which to retrieve role assignments.

.EXAMPLE
    Get-RolesForResource -ResourceId "/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/myResourceGroup/providers/Microsoft.Web/sites/myWebApp"
    This command retrieves and processes the list of roles for the Azure resource with the specified resource ID.

.NOTES
    Author: David Burel (@dafneb)
    Date: February 17, 2025
    Version: 1.0
#>
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

<#
.SYNOPSIS
    Retrieves detailed information about a specified Azure Web App.

.DESCRIPTION
    The Get-WebAppDetails function retrieves detailed information about a specified Azure Web App, including its configuration, state, and various settings.

.PARAMETER ResourceGroupName
    The name of the resource group that contains the Web App.

.PARAMETER WebAppName
    The name of the Web App to retrieve details for.

.EXAMPLE
    Get-WebAppDetails -ResourceGroupName "resource-group" -WebAppName "web-app-name"
    This command retrieves details for the Web App named "web-app-name" in the "resource-group" resource group.

.NOTES
    Author: David Burel (@dafneb)
    Date: February 14, 2025
    Version: 1.0

#>
function Get-WebAppDetails {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,
        HelpMessage="Resource group name.")]
        [ValidateNotNullOrEmpty()]
        [string] $ResourceGroupName,

        [Parameter(Mandatory=$true,
        HelpMessage="Web app name.")]
        [ValidateNotNullOrEmpty()]
        [string] $WebAppName
    )

    begin {
        Write-Verbose -Message "Begin of Get-WebAppDetails"
        Show-ProgressBarLevel3 -ActivityName "Getting details" -ObjectName "WebApp" -Index 0 -Max 100
    
    }

    process {
        Write-Verbose -Message "Get details of web app $($WebAppName)"
        $webApp = Get-AzWebApp -ResourceGroupName $ResourceGroupName -Name $WebAppName
        Write-Verbose -Message "Name: $($webApp.Name)"
        Write-Verbose -Message "DefaultHostName: $($webApp.DefaultHostName)"
        $script:dataInventory += "`t`t`tName: $($webApp.Name)"
        $script:dataInventory += "`t`t`tKind: $($webApp.Kind)"
        $script:dataInventory += "`t`t`tEnabled: $($webApp.Enabled)"
        $script:dataInventory += "`t`t`tDefaultHostName: $($webApp.DefaultHostName)"
        $script:dataInventory += "`t`t`tHostNames:"
        $webApp.HostNames | ForEach-Object { 
            $appHost = $_
            $script:dataInventory += "`t`t`t`t$($appHost)"
            $webApp.SiteConfig.VirtualApplications | ForEach-Object {
                $app = $_
                $script:dataUrls += [PSCustomObject]@{PublicURL="https://$($appHost)$($app.VirtualPath)"; ResourceType="Microsoft.Web/sites"; ResourceName="$($WebAppName)"}
            }
        }
        $script:dataInventory += "`t`t`tState: $($webApp.State)"
        $script:dataInventory += "`t`t`tUsageState: $($webApp.UsageState)"
        $script:dataInventory += "`t`t`tAvailabilityState: $($webApp.AvailabilityState)"
        $script:dataInventory += "`t`t`tServerFarmId: $($webApp.ServerFarmId)"
        $script:dataInventory += "`t`t`tHostingEnvironmentProfile: $($webApp.HostingEnvironmentProfile)"
        $script:dataInventory += "`t`t`tGitRemoteName: $($webApp.GitRemoteName)"
        $script:dataInventory += "`t`t`tGitRemoteUri: $($webApp.GitRemoteUri)"
        $script:dataInventory += "`t`t`tGitRemoteUsername: $($webApp.GitRemoteUsername)"
        $script:dataInventory += "`t`t`tAzureStorageAccounts: $($webApp.AzureStorageAccounts)"
        $script:dataInventory += "`t`t`tAzureStoragePath: $($webApp.AzureStoragePath)"
        $script:dataInventory += "`t`t`tRepositorySiteName: $($webApp.RepositorySiteName)"
        $script:dataInventory += "`t`t`tVnetInfo: $($webApp.VnetInfo)"
        $script:dataInventory += "`t`t`tVirtualNetworkSubnetId: $($webApp.VirtualNetworkSubnetId)"
        $script:dataInventory += "`t`t`tHttpsOnly: $($webApp.HttpsOnly)"
        $script:dataInventory += "`t`t`tClientAffinityEnabled: $($webApp.ClientAffinityEnabled)"
        $script:dataInventory += "`t`t`tClientCertEnabled: $($webApp.ClientCertEnabled)"
        $script:dataInventory += "`t`t`tClientCertMode: $($webApp.ClientCertMode)"
        ## SiteConfig
        $script:dataInventory += "`t`t`tSiteConfig:"
        # SCM ...        
        $script:dataInventory += "`t`t`t`tScmType: $($webApp.SiteConfig.ScmType)"
        $script:dataInventory += "`t`t`t`tScmMinTlsVersion: $($webApp.SiteConfig.ScmMinTlsVersion)"
        $script:dataInventory += "`t`t`t`tScmIpSecurityRestrictionsUseMain: $($webApp.SiteConfig.ScmIpSecurityRestrictionsUseMain)"
        $script:dataInventory += "`t`t`t`tScmIpSecurityRestrictions:"
        $webApp.SiteConfig.ScmIpSecurityRestrictions | ForEach-Object {
            $rule = $_
            $script:dataInventory += "`t`t`t`t`t$($rule.Name) - $($rule.Action) [Priority=$($rule.Priority)]:"
            $script:dataInventory += "`t`t`t`t`t`tDescription: $($rule.Description)"
            $script:dataInventory += "`t`t`t`t`t`tIP: $($rule.IpAddress) ($($rule.SubnetMask))"
            $script:dataInventory += "`t`t`t`t`t`tVnetSubnetResourceId: $($rule.VnetSubnetResourceId)"
            $script:dataInventory += "`t`t`t`t`t`tVnetTrafficTag: $($rule.VnetTrafficTag)"
            $script:dataInventory += "`t`t`t`t`t`tSubnetTrafficTag: $($rule.SubnetTrafficTag)"
        }
        # Application ...
        $script:dataInventory += "`t`t`t`tAlwaysOn: $($webApp.SiteConfig.AlwaysOn)"
        $script:dataInventory += "`t`t`t`tAppCommandLine: $($webApp.SiteConfig.AppCommandLine)"
        $script:dataInventory += "`t`t`t`tUse32BitWorkerProcess: $($webApp.SiteConfig.Use32BitWorkerProcess)"
        $script:dataInventory += "`t`t`t`tApiDefinition: $($webApp.SiteConfig.ApiDefinition.Url)"
        $script:dataInventory += "`t`t`t`tApiManagementConfig: $($webApp.SiteConfig.ApiManagementConfig.Id)"
        $script:dataInventory += "`t`t`t`tDetailedErrorLoggingEnabled: $($webApp.SiteConfig.DetailedErrorLoggingEnabled)"
        # Languages ... 
        $script:dataInventory += "`t`t`t`tNetFrameworkVersion: $($webApp.SiteConfig.NetFrameworkVersion)"
        if ($webApp.SiteConfig.NetFrameworkVersion.Length -gt 0) {
            $script:dataLanguages += [PSCustomObject]@{Language=".NET"; Version="$($webApp.SiteConfig.NetFrameworkVersion)"; ResourceType="Microsoft.Web/sites"; ResourceName="$($WebAppName)"}
        }
        $script:dataInventory += "`t`t`t`tPhpVersion: $($webApp.SiteConfig.PhpVersion)"
        if ($webApp.SiteConfig.PhpVersion.Length -gt 0) {
            $script:dataLanguages += [PSCustomObject]@{Language="PHP"; Version="$($webApp.SiteConfig.PhpVersion)"; ResourceType="Microsoft.Web/sites"; ResourceName="$($WebAppName)"}
        }
        $script:dataInventory += "`t`t`t`tPythonVersion: $($webApp.SiteConfig.PythonVersion)"
        if ($webApp.SiteConfig.PythonVersion.Length -gt 0) {
            $script:dataLanguages += [PSCustomObject]@{Language="Python"; Version="$($webApp.SiteConfig.PythonVersion)"; ResourceType="Microsoft.Web/sites"; ResourceName="$($WebAppName)"}
        }
        $script:dataInventory += "`t`t`t`tNodeVersion: $($webApp.SiteConfig.NodeVersion)"
        if ($webApp.SiteConfig.NodeVersion.Length -gt 0) {
            $script:dataLanguages += [PSCustomObject]@{Language="Node.js"; Version="$($webApp.SiteConfig.NodeVersion)"; ResourceType="Microsoft.Web/sites"; ResourceName="$($WebAppName)"}
        }
        $script:dataInventory += "`t`t`t`tPowerShellVersion: $($webApp.SiteConfig.PowerShellVersion)"
        if ($webApp.SiteConfig.PowerShellVersion.Length -gt 0) {
            $script:dataLanguages += [PSCustomObject]@{Language="PowerShell"; Version="$($webApp.SiteConfig.PowerShellVersion)"; ResourceType="Microsoft.Web/sites"; ResourceName="$($WebAppName)"}
        }
        $script:dataInventory += "`t`t`t`tJavaVersion: $($webApp.SiteConfig.JavaVersion)"
        if ($webApp.SiteConfig.JavaVersion.Length -gt 0) {
            $script:dataLanguages += [PSCustomObject]@{Language="Java"; Version="$($webApp.SiteConfig.JavaVersion)"; ResourceType="Microsoft.Web/sites"; ResourceName="$($WebAppName)"}
        }
        $script:dataInventory += "`t`t`t`tJavaContainer: $($webApp.SiteConfig.JavaContainer)"
        $script:dataInventory += "`t`t`t`tJavaContainerVersion: $($webApp.SiteConfig.JavaContainerVersion)"
        $script:dataInventory += "`t`t`t`tLinuxFxVersion: $($webApp.SiteConfig.LinuxFxVersion)"
        if ($webApp.SiteConfig.LinuxFxVersion.Length -gt 0) {
            if ($webApp.SiteConfig.LinuxFxVersion.Contains('|')) {
                $linuxFx = $webApp.SiteConfig.LinuxFxVersion -split '\|'
                if ($linuxFx[0].ToUpper() -eq "DOCKER") {
                    $script:dataOSystems += [PSCustomObject]@{Publisher="Docker"; Offer="docker-image"; SKU="$($linuxFx[1])"; ResourceType="Microsoft.Web/sites"; ResourceName="$($WebAppName)"}
                } elseif ($linuxFx[0].ToUpper() -eq "DOTNETCORE") {
                    $script:dataLanguages += [PSCustomObject]@{Language=".NET Core"; Version="$($linuxFx[1])"; ResourceType="Microsoft.Web/sites"; ResourceName="$($WebAppName)"}
                } elseif ($linuxFx[0].ToUpper() -eq "NODE") {
                    $script:dataLanguages += [PSCustomObject]@{Language="Node.js"; Version="$($linuxFx[1])"; ResourceType="Microsoft.Web/sites"; ResourceName="$($WebAppName)"}
                } elseif ($linuxFx[0].ToUpper() -eq "PHP") {
                    $script:dataLanguages += [PSCustomObject]@{Language="PHP"; Version="$($linuxFx[1])"; ResourceType="Microsoft.Web/sites"; ResourceName="$($WebAppName)"}
                } elseif ($linuxFx[0].ToUpper() -eq "PYTHON") {
                    $script:dataLanguages += [PSCustomObject]@{Language="Python"; Version="$($linuxFx[1])"; ResourceType="Microsoft.Web/sites"; ResourceName="$($WebAppName)"}
                } elseif ($linuxFx[0].ToUpper() -eq "RUBY") {
                    $script:dataLanguages += [PSCustomObject]@{Language="Ruby"; Version="$($linuxFx[1])"; ResourceType="Microsoft.Web/sites"; ResourceName="$($WebAppName)"}
                } else {
                    $script:dataLanguages += [PSCustomObject]@{Language="$($linuxFx[0].ToUpper())"; Version="$($linuxFx[1])"; ResourceType="Microsoft.Web/sites"; ResourceName="$($WebAppName)"}
                }
            } else {
                $script:dataLanguages += [PSCustomObject]@{Language="Linux"; Version="$($webApp.SiteConfig.LinuxFxVersion)"; ResourceType="Microsoft.Web/sites"; ResourceName="$($WebAppName)"}
            }
        }
        $script:dataInventory += "`t`t`t`tWindowsFxVersion: $($webApp.SiteConfig.WindowsFxVersion)"
        if ($webApp.SiteConfig.WindowsFxVersion.Length -gt 0) {
            $script:dataLanguages += [PSCustomObject]@{Language="Windows"; Version="$($webApp.SiteConfig.WindowsFxVersion)"; ResourceType="Microsoft.Web/sites"; ResourceName="$($WebAppName)"}
        }
        # Network ...
        $script:dataInventory += "`t`t`t`tHttp20Enabled: $($webApp.SiteConfig.Http20Enabled)"
        $script:dataInventory += "`t`t`t`tMinTlsVersion: $($webApp.SiteConfig.MinTlsVersion)"
        $script:dataInventory += "`t`t`t`tFtpsState: $($webApp.SiteConfig.FtpsState)"
        $script:dataInventory += "`t`t`t`tPublicNetworkAccess: $($webApp.SiteConfig.PublicNetworkAccess)"
        $script:dataInventory += "`t`t`t`tWebSocketsEnabled: $($webApp.SiteConfig.WebSocketsEnabled)"
        $script:dataInventory += "`t`t`t`tIpSecurityRestrictions:"
        $webApp.SiteConfig.IpSecurityRestrictions | ForEach-Object {
            $rule = $_
            $script:dataInventory += "`t`t`t`t`t$($rule.Name) - $($rule.Action) [Priority=$($rule.Priority)]:"
            $script:dataInventory += "`t`t`t`t`t`tDescription: $($rule.Description)"
            $script:dataInventory += "`t`t`t`t`t`tIP: $($rule.IpAddress) ($($rule.SubnetMask))"
            $script:dataInventory += "`t`t`t`t`t`tVnetSubnetResourceId: $($rule.VnetSubnetResourceId)"
            $script:dataInventory += "`t`t`t`t`t`tVnetTrafficTag: $($rule.VnetTrafficTag)"
            $script:dataInventory += "`t`t`t`t`t`tSubnetTrafficTag: $($rule.SubnetTrafficTag)"
        }
        $script:dataInventory += "`t`t`t`tVirtualApplications:"
        $webApp.SiteConfig.VirtualApplications | ForEach-Object {
            $app = $_
            $script:dataInventory += "`t`t`t`t`t$($app.VirtualPath) -> $($app.PhysicalPath)"
        }
        # Vnet ...
        $script:dataInventory += "`t`t`t`tVnetName: $($webApp.SiteConfig.VnetName)"
        $script:dataInventory += "`t`t`t`tVnetRouteAllEnabled: $($webApp.SiteConfig.VnetRouteAllEnabled)"
        $script:dataInventory += "`t`t`t`tVnetPrivatePortsCount: $($webApp.SiteConfig.VnetPrivatePortsCount)"

    }

    end {
        Hide-ProgressBarLevel3
        Write-Verbose -Message "End of Get-WebAppDetails"

    }
}

# Function: Get details about FunctionApp
function Get-FunctionAppDetails {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,
        HelpMessage="Resource group name.")]
        [ValidateNotNullOrEmpty()]
        [string] $ResourceGroupName,

        [Parameter(Mandatory=$true,
        HelpMessage="Function app name.")]
        [ValidateNotNullOrEmpty()]
        [string] $FunctionAppName
    )

    begin {
        Write-Verbose -Message "Begin of Get-FunctionAppDetails"
        Show-ProgressBarLevel3 -ActivityName "Getting details" -ObjectName "FunctionApp" -Index 0 -Max 100
    
    }

    process {
        Write-Verbose -Message "Get details of function app $($FunctionAppName)"
        $functionApp = Get-AzFunctionApp -ResourceGroupName $ResourceGroupName -Name $FunctionAppName
        Write-Verbose -Message "Name: $($functionApp.Name)"
        Write-Verbose -Message "DefaultHostName: $($functionApp.DefaultHostName)"
        $script:dataInventory += "`t`t`tName: $($functionApp.Name)"
        $script:dataInventory += "`t`t`tKind: $($functionApp.Kind)"
        $script:dataInventory += "`t`t`tEnabled: $($functionApp.Enabled)"
        $script:dataInventory += "`t`t`tDefaultHostName: $($functionApp.DefaultHostName)"
        $script:dataInventory += "`t`t`tHostName: $($functionApp.HostName)"
        $script:dataInventory += "`t`t`tStatus: $($functionApp.Status)"
        $script:dataInventory += "`t`t`tState: $($functionApp.State)"
        $script:dataInventory += "`t`t`tUsageState: $($functionApp.UsageState)"
        $script:dataInventory += "`t`t`tAvailabilityState: $($functionApp.AvailabilityState)"
        $script:dataInventory += "`t`t`tServerFarmId: $($functionApp.ServerFarmId)"
        $script:dataInventory += "`t`t`tAppServicePlan: $($functionApp.AppServicePlan)"
        $script:dataInventory += "`t`t`tOSType: $($functionApp.OSType)"
        $script:dataInventory += "`t`t`tRuntime: $($functionApp.Runtime)"
        $script:dataInventory += "`t`t`tRuntimeName: $($functionApp.RuntimeName)"
        $script:dataInventory += "`t`t`tRuntimeVersion: $($functionApp.RuntimeVersion)"
        $script:dataInventory += "`t`t`tRepositorySiteName: $($functionApp.RepositorySiteName)"
        $script:dataInventory += "`t`t`tVirtualNetworkSubnetId: $($functionApp.VirtualNetworkSubnetId)"
        $script:dataInventory += "`t`t`tPublicNetworkAccess: $($functionApp.PublicNetworkAccess)"
        $script:dataInventory += "`t`t`tHttpsOnly: $($functionApp.HttpsOnly)"
        $script:dataInventory += "`t`t`tClientAffinityEnabled: $($functionApp.ClientAffinityEnabled)"
        $script:dataInventory += "`t`t`tClientCertEnabled: $($functionApp.ClientCertEnabled)"
        $script:dataInventory += "`t`t`tClientCertMode: $($functionApp.ClientCertMode)"
        ## Config
        $script:dataInventory += "`t`t`tConfig:"
        # SCM ...        
        $script:dataInventory += "`t`t`t`tScmType: $($functionApp.Config.ScmType)"
        $script:dataInventory += "`t`t`t`tScmMinTlsVersion: $($functionApp.Config.ScmMinTlsVersion)"
        $script:dataInventory += "`t`t`t`tScmIpSecurityRestrictionsUseMain: $($functionApp.Config.ScmIpSecurityRestrictionsUseMain)"
        $script:dataInventory += "`t`t`t`tScmIpSecurityRestrictions:"
        $functionApp.Config.ScmIpSecurityRestrictions | ForEach-Object {
            $rule = $_
            $script:dataInventory += "`t`t`t`t`t$($rule.Name) - $($rule.Action) [Priority=$($rule.Priority)]:"
            $script:dataInventory += "`t`t`t`t`t`tDescription: $($rule.Description)"
            $script:dataInventory += "`t`t`t`t`t`tIP: $($rule.IpAddress) ($($rule.SubnetMask))"
            $script:dataInventory += "`t`t`t`t`t`tVnetSubnetResourceId: $($rule.VnetSubnetResourceId)"
            $script:dataInventory += "`t`t`t`t`t`tVnetTrafficTag: $($rule.VnetTrafficTag)"
            $script:dataInventory += "`t`t`t`t`t`tSubnetTrafficTag: $($rule.SubnetTrafficTag)"
        }
        # Application ...
        $script:dataInventory += "`t`t`t`tAlwaysOn: $($functionApp.Config.AlwaysOn)"
        $script:dataInventory += "`t`t`t`tAppCommandLine: $($functionApp.Config.AppCommandLine)"
        $script:dataInventory += "`t`t`t`tUse32BitWorkerProcess: $($functionApp.Config.Use32BitWorkerProcess)"
        $script:dataInventory += "`t`t`t`tApiDefinitionUrl: $($functionApp.Config.ApiDefinitionUrl)"
        $script:dataInventory += "`t`t`t`tDetailedErrorLoggingEnabled: $($functionApp.Config.DetailedErrorLoggingEnabled)"
        # Languages ... 
        $script:dataInventory += "`t`t`t`tNetFrameworkVersion: $($functionApp.Config.NetFrameworkVersion)"
        if ($functionApp.Config.NetFrameworkVersion.Length -gt 0) {
            $script:dataLanguages += [PSCustomObject]@{Language=".NET"; Version="$($functionApp.Config.NetFrameworkVersion)"; ResourceType="Microsoft.Web/sites"; ResourceName="$($FunctionAppName)"}
        }
        $script:dataInventory += "`t`t`t`tPhpVersion: $($functionApp.Config.PhpVersion)"
        if ($functionApp.Config.PhpVersion.Length -gt 0) {
            $script:dataLanguages += [PSCustomObject]@{Language="PHP"; Version="$($functionApp.Config.PhpVersion)"; ResourceType="Microsoft.Web/sites"; ResourceName="$($FunctionAppName)"}
        }
        $script:dataInventory += "`t`t`t`tPythonVersion: $($functionApp.Config.PythonVersion)"
        if ($functionApp.Config.PythonVersion.Length -gt 0) {
            $script:dataLanguages += [PSCustomObject]@{Language="Python"; Version="$($functionApp.Config.PythonVersion)"; ResourceType="Microsoft.Web/sites"; ResourceName="$($FunctionAppName)"}
        }
        $script:dataInventory += "`t`t`t`tNodeVersion: $($functionApp.Config.NodeVersion)"
        if ($functionApp.Config.NodeVersion.Length -gt 0) {
            $script:dataLanguages += [PSCustomObject]@{Language="Node.js"; Version="$($functionApp.Config.NodeVersion)"; ResourceType="Microsoft.Web/sites"; ResourceName="$($FunctionAppName)"}
        }
        $script:dataInventory += "`t`t`t`tPowerShellVersion: $($functionApp.Config.PowerShellVersion)"
        if ($functionApp.Config.PowerShellVersion.Length -gt 0) {
            $script:dataLanguages += [PSCustomObject]@{Language="PowerShell"; Version="$($functionApp.Config.PowerShellVersion)"; ResourceType="Microsoft.Web/sites"; ResourceName="$($FunctionAppName)"}
        }
        $script:dataInventory += "`t`t`t`tJavaVersion: $($functionApp.Config.JavaVersion)"
        if ($functionApp.Config.JavaVersion.Length -gt 0) {
            $script:dataLanguages += [PSCustomObject]@{Language="Java"; Version="$($functionApp.Config.JavaVersion)"; ResourceType="Microsoft.Web/sites"; ResourceName="$($FunctionAppName)"}
        }
        $script:dataInventory += "`t`t`t`tJavaContainer: $($functionApp.Config.JavaContainer)"
        $script:dataInventory += "`t`t`t`tJavaContainerVersion: $($functionApp.Config.JavaContainerVersion)"
        $script:dataInventory += "`t`t`t`tLinuxFxVersion: $($functionApp.Config.LinuxFxVersion)"
        if ($functionApp.Config.LinuxFxVersion.Length -gt 0) {
            if ($functionApp.Config.LinuxFxVersion.Contains('|')) {
                $linuxFx = $functionApp.Config.LinuxFxVersion -split '\|'
                if ($linuxFx[0].ToUpper() -eq "DOCKER") {
                    $script:dataOSystems += [PSCustomObject]@{Publisher="Docker"; Offer="docker-image"; SKU="$($linuxFx[1])"; ResourceType="Microsoft.Web/sites"; ResourceName="$($FunctionAppName)"}
                } elseif ($linuxFx[0].ToUpper() -eq "DOTNETCORE") {
                    $script:dataLanguages += [PSCustomObject]@{Language=".NET Core"; Version="$($linuxFx[1])"; ResourceType="Microsoft.Web/sites"; ResourceName="$($FunctionAppName)"}
                } elseif ($linuxFx[0].ToUpper() -eq "NODE") {
                    $script:dataLanguages += [PSCustomObject]@{Language="Node.js"; Version="$($linuxFx[1])"; ResourceType="Microsoft.Web/sites"; ResourceName="$($FunctionAppName)"}
                } elseif ($linuxFx[0].ToUpper() -eq "PHP") {
                    $script:dataLanguages += [PSCustomObject]@{Language="PHP"; Version="$($linuxFx[1])"; ResourceType="Microsoft.Web/sites"; ResourceName="$($FunctionAppName)"}
                } elseif ($linuxFx[0].ToUpper() -eq "PYTHON") {
                    $script:dataLanguages += [PSCustomObject]@{Language="Python"; Version="$($linuxFx[1])"; ResourceType="Microsoft.Web/sites"; ResourceName="$($FunctionAppName)"}
                } elseif ($linuxFx[0].ToUpper() -eq "RUBY") {
                    $script:dataLanguages += [PSCustomObject]@{Language="Ruby"; Version="$($linuxFx[1])"; ResourceType="Microsoft.Web/sites"; ResourceName="$($FunctionAppName)"}
                } else {
                    $script:dataLanguages += [PSCustomObject]@{Language="$($linuxFx[0].ToUpper())"; Version="$($linuxFx[1])"; ResourceType="Microsoft.Web/sites"; ResourceName="$($FunctionAppName)"}
                }
            } else {
                $script:dataLanguages += [PSCustomObject]@{Language="Linux"; Version="$($functionApp.Config.LinuxFxVersion)"; ResourceType="Microsoft.Web/sites"; ResourceName="$($FunctionAppName)"}
            }
        }
        $script:dataInventory += "`t`t`t`tWindowsFxVersion: $($functionApp.Config.WindowsFxVersion)"
        if ($functionApp.Config.WindowsFxVersion.Length -gt 0) {
            $script:dataLanguages += [PSCustomObject]@{Language="Windows"; Version="$($functionApp.Config.WindowsFxVersion)"; ResourceType="Microsoft.Web/sites"; ResourceName="$($FunctionAppName)"}
        }
        # Network ...
        $script:dataInventory += "`t`t`t`tHttp20Enabled: $($functionApp.Config.Http20Enabled)"
        $script:dataInventory += "`t`t`t`tMinTlsVersion: $($functionApp.Config.MinTlsVersion)"
        $script:dataInventory += "`t`t`t`tFtpsState: $($functionApp.Config.FtpsState)"
        $script:dataInventory += "`t`t`t`tPublicNetworkAccess: $($functionApp.Config.PublicNetworkAccess)"
        $script:dataInventory += "`t`t`t`tWebSocketsEnabled: $($functionApp.Config.WebSocketsEnabled)"
        $script:dataInventory += "`t`t`t`tIpSecurityRestrictions:"
        $functionApp.Config.IpSecurityRestrictions | ForEach-Object {
            $rule = $_
            $script:dataInventory += "`t`t`t`t`t$($rule.Name) - $($rule.Action) [Priority=$($rule.Priority)]:"
            $script:dataInventory += "`t`t`t`t`t`tDescription: $($rule.Description)"
            $script:dataInventory += "`t`t`t`t`t`tIP: $($rule.IpAddress) ($($rule.SubnetMask))"
            $script:dataInventory += "`t`t`t`t`t`tVnetSubnetResourceId: $($rule.VnetSubnetResourceId)"
            $script:dataInventory += "`t`t`t`t`t`tVnetTrafficTag: $($rule.VnetTrafficTag)"
            $script:dataInventory += "`t`t`t`t`t`tSubnetTrafficTag: $($rule.SubnetTrafficTag)"
        }
        # Vnet ...
        $script:dataInventory += "`t`t`t`tVnetName: $($functionApp.Config.VnetName)"
        $script:dataInventory += "`t`t`t`tVnetRouteAllEnabled: $($functionApp.Config.VnetRouteAllEnabled)"
        $script:dataInventory += "`t`t`t`tVnetPrivatePortsCount: $($functionApp.Config.VnetPrivatePortsCount)"

    }

    end {
        Hide-ProgressBarLevel3
        Write-Verbose -Message "End of Get-FunctionAppDetails"

    }
}

<#
.SYNOPSIS
    Retrieves detailed information about a specified Azure SQL Server.

.DESCRIPTION
    The Get-SqlServerDetails function retrieves detailed information about a specified Azure SQL Server, including its configuration, state, and various settings. It collects data such as server name, version, domain name, network rules, and firewall rules.

.PARAMETER ResourceGroupName
    The name of the resource group that contains the SQL Server.

.PARAMETER ServerName
    The name of the SQL Server to retrieve details for.

.EXAMPLE
    Get-SqlServerDetails -ResourceGroupName "resource-group" -ServerName "sql-server-name"
    This command retrieves details for the SQL Server named "sql-server-name" in the "resource-group" resource group.

.NOTES
    Author: David Burel (@dafneb)
    Date: February 17, 2025
    Version: 1.0
#>
function Get-SqlServerDetails {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,
        HelpMessage="Resource group name.")]
        [ValidateNotNullOrEmpty()]
        [string] $ResourceGroupName,

        [Parameter(Mandatory=$true,
        HelpMessage="SQL server name.")]
        [ValidateNotNullOrEmpty()]
        [string] $ServerName
    )

    begin {
        Write-Verbose -Message "Begin of Get-SqlServerDetails"
        Show-ProgressBarLevel3 -ActivityName "Getting details" -ObjectName "AzureSQLServer" -Index 0 -Max 100
    
    }

    process {
        Write-Verbose -Message "Get details of Azure SQL server $($ServerName)"
        $server = Get-AzSqlServer -ResourceGroupName $ResourceGroupName -ServerName $ServerName
        Write-Verbose -Message "ServerName: $($server.ServerName)"
        Write-Verbose -Message "ServerVersion: $($server.ServerVersion)"
        Write-Verbose -Message "FullyQualifiedDomainName: $($server.FullyQualifiedDomainName)"
        $script:dataInventory += "`t`t`tServerName: $($server.ServerName)"
        $script:dataInventory += "`t`t`tServerVersion: $($server.ServerVersion)"
        $script:dataInventory += "`t`t`tFullyQualifiedDomainName: $($server.FullyQualifiedDomainName)"
        $script:dataInventory += "`t`t`tMinimalTlsVersion: $($server.MinimalTlsVersion)"
        $script:dataInventory += "`t`t`tPublicNetworkAccess: $($server.PublicNetworkAccess)"
        $script:dataInventory += "`t`t`tRestrictOutboundNetworkAccess: $($server.RestrictOutboundNetworkAccess)"
        $script:dataInventory += "`t`t`tNetworkRules:"
        $networkRules = Get-AzSqlServerVirtualNetworkRule -ResourceGroupName $ResourceGroupName -ServerName $ServerName
        $networkRules | ForEach-Object {
            $rule = $_
            $script:dataInventory += "`t`t`t`t$($rule.VirtualNetworkRuleName): $($rule.VirtualNetworkSubnetId) ($($rule.State))"
        }
        $script:dataInventory += "`t`t`tFirewallInboundRules:"
        $fwInboudRules = Get-AzSqlServerFirewallRule -ResourceGroupName $ResourceGroupName -ServerName $ServerName
        $fwInboudRules | ForEach-Object {
            $rule = $_
            $script:dataInventory += "`t`t`t`t$($rule.FirewallRuleName): $($rule.StartIpAddress) - $($rule.EndIpAddress)"
        }
        $fw6InboundRules = Get-AzSqlServerIpv6FirewallRule -ResourceGroupName $ResourceGroupName -ServerName $ServerName
        $fw6InboundRules | ForEach-Object {
            $rule = $_
            $script:dataInventory += "`t`t`t`t$($rule.Ipv6FirewallRuleName): $($rule.StartIpAddress) - $($rule.EndIpAddress)"
        }
        $script:dataInventory += "`t`t`tFirewallOutboundRules:"
        $fwOutboundRules = Get-AzSqlServerOutboundFirewallRule -ResourceGroupName $ResourceGroupName -ServerName $ServerName
        $fwOutboundRules | ForEach-Object {
            $rule = $_
            $script:dataInventory += "`t`t`t`tAllowedFQDN: $($rule.AllowedFQDN)"
        }

    }

    end {
        Hide-ProgressBarLevel3
        Write-Verbose -Message "End of Get-SqlServerDetails"

    }
}

<#
.SYNOPSIS
    Retrieves detailed information about a specified Azure Virtual Machine.

.DESCRIPTION
    The Get-VirtualMachineDetails function retrieves detailed information about a specified Azure Virtual Machine, including its hardware profile, storage profile, OS profile, network profile, and security profile. It collects data such as VM size, image reference, OS configuration, disk details, and network interfaces.

.PARAMETER ResourceGroupName
    The name of the resource group that contains the Virtual Machine.

.PARAMETER VMName
    The name of the Virtual Machine to retrieve details for.

.EXAMPLE
    Get-VirtualMachineDetails -ResourceGroupName "resource-group" -VMName "vm-name"
    This command retrieves details for the Virtual Machine named "vm-name" in the "resource-group" resource group.

.NOTES
    Author: David Burel (@dafneb)
    Date: February 17, 2025
    Version: 1.0
#>
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
        Write-Verbose -Message "Get details of virtual machine $($VMName)"
        $machine = Get-AZVm -ResourceGroupName $ResourceGroupName -Name $VMName
        Write-Verbose -Message "Size: $($machine.HardwareProfile.VmSize)"
        Write-Verbose -Message "Publisher: $($machine.StorageProfile.ImageReference.Publisher)"
        Write-Verbose -Message "Offer: $($machine.StorageProfile.ImageReference.Offer)"
        Write-Verbose -Message "SKU: $($machine.StorageProfile.ImageReference.Sku)"
        $script:dataInventory += "`t`t`tSize: $($machine.HardwareProfile.VmSize)"
        $script:dataInventory += "`t`t`tvCPU: $($machine.HardwareProfile.VmSizeProperties.VCPUsAvailable)"
        $script:dataInventory += "`t`t`tvCPU per Core: $($machine.HardwareProfile.VmSizeProperties.VCPUsPerCore)"
        $script:dataInventory += "`t`t`tImage reference:"
        $script:dataInventory += "`t`t`t`tPublisher: $($machine.StorageProfile.ImageReference.Publisher)"
        $script:dataInventory += "`t`t`t`tOffer: $($machine.StorageProfile.ImageReference.Offer)"
        $script:dataInventory += "`t`t`t`tSKU: $($machine.StorageProfile.ImageReference.Sku)"
        $script:dataOSystems += [PSCustomObject]@{Publisher="$($machine.StorageProfile.ImageReference.Publisher)"; Offer="$($machine.StorageProfile.ImageReference.Offer)"; SKU="$($machine.StorageProfile.ImageReference.Sku)"; ResourceType="Microsoft.Compute/virtualMachines"; ResourceName="$($VMName)"}
        $script:dataInventory += "`t`t`tComputerName: $($machine.OSProfile.ComputerName)"
        $script:dataInventory += "`t`t`tFullyQualifiedDomainName: $($machine.FullyQualifiedDomainName)"
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
            $script:dataInventory += "`t`t`t`tEnableAutomaticUpdates: $($machine.OSProfile.WindowsConfiguration.EnableAutomaticUpdates)"
            $script:dataInventory += "`t`t`t`tEnableVMAgentPlatformUpdates: $($machine.OSProfile.WindowsConfiguration.EnableVMAgentPlatformUpdates)"
            $script:dataInventory += "`t`t`t`tAssessmentMode: $($machine.OSProfile.WindowsConfiguration.PatchSettings.AssessmentMode)"
            $script:dataInventory += "`t`t`t`tPatchMode: $($machine.OSProfile.WindowsConfiguration.PatchSettings.PatchMode)"
            $script:dataInventory += "`t`t`t`tProvisionVMAgent: $($machine.OSProfile.WindowsConfiguration.ProvisionVMAgent)"
            $script:dataInventory += "`t`t`t`tTimeZone: $($machine.OSProfile.WindowsConfiguration.TimeZone)"
        }
        $script:dataInventory += "`t`t`tStorageProfile:"
        $osDisk = Get-AzDisk -DiskName $machine.StorageProfile.OsDisk.Name -ResourceGroupName $machine.ResourceGroupName
        $script:dataInventory += "`t`t`t`tOS Disk: $($osDisk.Name)"
        $script:dataInventory += "`t`t`t`t`tOS Type: $($osDisk.OsType)"
        $script:dataInventory += "`t`t`t`t`tHyper-V Gen: $($osDisk.HyperVGeneration)"
        $script:dataInventory += "`t`t`t`t`tSKU: $($osDisk.Sku.Name) ($($osDisk.Sku.Tier))"
        $script:dataInventory += "`t`t`t`t`tTier: $($osDisk.Tier)"
        $script:dataInventory += "`t`t`t`t`tDiskSizeGB: $($osDisk.DiskSizeGB)"
        $script:dataInventory += "`t`t`t`t`tPublicNetworkAccess: $($osDisk.PublicNetworkAccess)"
        $script:dataInventory += "`t`t`t`t`tNetworkAccessPolicy: $($osDisk.NetworkAccessPolicy)"
        $script:dataInventory += "`t`t`t`t`tEncryption.Type: $($osDisk.Encryption.Type)"
        $machine.StorageProfile.DataDisks | ForEach-Object {
            $dataDisk = Get-AzDisk -DiskName $_.Name -ResourceGroupName $machine.ResourceGroupName
            $script:dataInventory += "`t`t`t`tData Disk: $($dataDisk.Name)"
            $script:dataInventory += "`t`t`t`t`tSKU: $($dataDisk.Sku.Name) ($($dataDisk.Sku.Tier))"
            $script:dataInventory += "`t`t`t`t`tTier: $($dataDisk.Tier)"
            $script:dataInventory += "`t`t`t`t`tDiskSizeGB: $($dataDisk.DiskSizeGB)"
            $script:dataInventory += "`t`t`t`t`tPublicNetworkAccess: $($dataDisk.PublicNetworkAccess)"
            $script:dataInventory += "`t`t`t`t`tNetworkAccessPolicy: $($dataDisk.NetworkAccessPolicy)"
            $script:dataInventory += "`t`t`t`t`tEncryption.Type: $($dataDisk.Encryption.Type)"
        }
        $script:dataInventory += "`t`t`tEncryptionAtHost: $($machine.SecurityProfile.EncryptionAtHost)"
        $script:dataInventory += "`t`t`tSecurityType: $($machine.SecurityProfile.SecurityType)"
        $script:dataInventory += "`t`t`tSecureBootEnabled: $($machine.SecurityProfile.UefiSettings.SecureBootEnabled)"
        $script:dataInventory += "`t`t`tVTpmEnabled: $($machine.SecurityProfile.UefiSettings.VTpmEnabled)"
        $script:dataInventory += "`t`t`tNetworkInterfaces:"
        $machine.NetworkProfile.NetworkInterfaces | ForEach-Object {
            $script:dataInventory += "`t`t`t`tInterface:"
            $script:dataInventory += "`t`t`t`t`t[Primary=$($_.Primary)] ID: $($_.Id)"
            $networkInt = Get-AzNetworkInterface -ResourceId $_.Id
            $script:dataInventory += "`t`t`t`t`tName: $($networkInt.Name)"
            $script:dataInventory += "`t`t`t`t`tEnableAcceleratedNetworking: $($networkInt.EnableAcceleratedNetworking)"
            $script:dataInventory += "`t`t`t`t`tEnableIPForwarding: $($networkInt.EnableIPForwarding)"
            $script:dataInventory += "`t`t`t`t`tVnetEncryptionSupported: $($networkInt.VnetEncryptionSupported)"
            $script:dataInventory += "`t`t`t`t`tDefaultOutboundConnectivityEnabled: $($networkInt.DefaultOutboundConnectivityEnabled)"
            $networkInt.IpConfigurations | ForEach-Object {
                $ipconfig = $_
                $script:dataInventory += "`t`t`t`t`tIPConfiguration:"
                $script:dataInventory += "`t`t`t`t`t`t[Primary=$($ipconfig.Primary)] Name: $($ipconfig.Name)"
                # TODO: Add AppGateway and LoadBalancer reference? There could be relevant PublicIP
                # FIXME: ApplicationGatewayBackendAddressPools
                # FIXME: LoadBalancerBackendAddressPools
                $script:dataInventory += "`t`t`t`t`t`tApplicationSecurityGroups:"
                $ipconfig.ApplicationSecurityGroups | ForEach-Object {
                    $script:dataInventory += "`t`t`t`t`t`t`t$($_.Id)"
                }
                $script:dataInventory += "`t`t`t`t`t`tSubnet: $($ipconfig.Subnet.Id)"
                $script:dataInventory += "`t`t`t`t`t`tPrivateIpAddress: $($ipconfig.PrivateIpAddress)"
                $script:dataInventory += "`t`t`t`t`t`tPublicIp.Id: $($ipconfig.PublicIpAddress.Id)"
                if ($ipconfig.PublicIpAddress.Id.Length -gt 0) {
                    $resourcePublicIp = Get-AzResource -ResourceId $ipconfig.PublicIpAddress.Id
                    $publicIpItem = Get-AzPublicIpAddress -ResourceGroupName $networkInt.ResourceGroupName -Name $resourcePublicIp.Name
                    $script:dataInventory += "`t`t`t`t`t`tPublicIp.Name: $($publicIpItem.Name)"
                    $script:dataInventory += "`t`t`t`t`t`tPublicIp.IpAddress: $($publicIpItem.IpAddress)"
                    $script:dataIps += [PSCustomObject]@{PublicIp="$($publicIpItem.IpAddress)"; ResourceType="Microsoft.Compute/virtualMachines"; ResourceName="$($VMName)"}
                }
            }
            $script:dataInventory += "`t`t`t`t`t`tNetworkSecurityGroup:"
            if ($networkInt.NetworkSecurityGroup.Id.Length -gt 0) {
                $resourceNSG = Get-AzResource -ResourceId $networkInt.NetworkSecurityGroup.Id
                $NSG = Get-AzNetworkSecurityGroup -Name $resourceNSG.Name -ResourceGroupName $resourceNSG.ResourceGroupName
                $NSG.SecurityRules | ForEach-Object {
                    $nsgRule = $_
                    $script:dataInventory += "`t`t`t`t`t`t`tName: $($nsgRule.Name)"
                    $nsgRuleSrcArray = @()
                    $nsgRuleDstArray = @()
                    $nsgRuleSrcPortArray = @()
                    $nsgRuleDstPortArray = @()
                    $nsgRule.SourceApplicationSecurityGroups | ForEach-Object { $nsgRuleSrcArray += $_.Name }
                    $nsgRule.SourceAddressPrefix | ForEach-Object { $nsgRuleSrcArray += $_ }
                    $nsgRule.SourcePortRange | ForEach-Object { $nsgRuleSrcPortArray += $_ }
                    $nsgRule.DestinationApplicationSecurityGroups | ForEach-Object { $nsgRuleDstArray += $_.Name}
                    $nsgRule.DestinationAddressPrefix | ForEach-Object { $nsgRuleDstArray += $_ }
                    $nsgRule.DestinationPortRange | ForEach-Object { $nsgRuleDstPortArray += $_ }
                    $nsgRuleSrcText = ""
                    $nsgRuleSrcText += $nsgRuleSrcArray | Join-String -Separator ", "
                    $nsgRuleSrcText += " ($($nsgRuleSrcPortArray | Join-String -Separator ", "))"
                    $nsgRuleDstText = ""
                    $nsgRuleDstText += $nsgRuleDstArray | Join-String -Separator ", "
                    $nsgRuleDstText += " ($($nsgRuleDstPortArray | Join-String -Separator ", "))"
                    $script:dataInventory += "`t`t`t`t`t`t`t`t[$($nsgRule.Priority) $($nsgRule.Access) - $($nsgRule.Direction)]: $($nsgRule.Protocol) $($nsgRuleSrcText) -> $($nsgRuleDstText)"

                }
                
            }

        }
        $script:dataInventory += "`t`t`tExtensions:"
        $machine.Extensions | ForEach-Object {
            $script:dataInventory += "`t`t`t`tName: $($_.Name); Publisher: $($_.Publisher)"
        }
        $script:dataInventory += "`t`t`tPlan:"
        $script:dataInventory += "`t`t`t`tPublisher: $($machine.Plan.Publisher)"
        $script:dataInventory += "`t`t`t`tName: $($machine.Plan.Name)"
        $script:dataInventory += "`t`t`t`tProduct: $($machine.Plan.Product)"

    }

    end {
        Hide-ProgressBarLevel3
        Write-Verbose -Message "End of Get-VirtualMachineDetails"

    }
}

<#
.SYNOPSIS
    Retrieves detailed information about a specified Azure Key Vault.

.DESCRIPTION
    The Get-KeyVaultDetails function retrieves detailed information about a specified Azure Key Vault, including its SKU, URI, and various settings. It collects data such as deployment settings, network access rules, and security configurations.

.PARAMETER KeyVaultName
    The name of the Key Vault to retrieve details for.

.EXAMPLE
    Get-KeyVaultDetails -KeyVaultName "myKeyVault"
    This command retrieves details for the Key Vault named "myKeyVault".

.NOTES
    Author: David Burel (@dafneb)
    Date: February 17, 2025
    Version: 1.0
#>
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

        Write-Verbose -Message "Get details of key vault $($KeyVaultName)"
        $kv = Get-AzKeyVault -VaultName $KeyVaultName
        Write-Verbose -Message "Sku: $($kv.Sku)"
        Write-Verbose -Message "VaultUri: $($kv.VaultUri)"
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

<#
.SYNOPSIS
    Retrieves detailed information about a specified Azure Storage Account.

.DESCRIPTION
    The Get-StorageAccountDetails function retrieves detailed information about a specified Azure Storage Account, including its SKU, kind, provisioning state, and various settings. It collects data such as access tier, encryption settings, network rules, and public network access.

.PARAMETER ResourceGroupName
    The name of the resource group that contains the Storage Account.

.PARAMETER StorageName
    The name of the Storage Account to retrieve details for.

.EXAMPLE
    Get-StorageAccountDetails -ResourceGroupName "resource-group" -StorageName "storage-account-name"
    This command retrieves details for the Storage Account named "storage-account-name" in the "resource-group" resource group.

.NOTES
    Author: David Burel (@dafneb)
    Date: February 17, 2025
    Version: 1.0
#>
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

        Write-Verbose -Message "Get details of storage account $($StorageName)"
        $account = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageName
        Write-Verbose -Message "Sku: $($account.Sku.Name)"
        Write-Verbose -Message "Kind: $($account.Kind)"
        Write-Verbose -Message "ProvisioningState: $($account.ProvisioningState)"
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

<#
.SYNOPSIS
    Retrieves and processes the list of resources for a specified Azure resource group.

.DESCRIPTION
    The Get-ResourceForResourceGroup function retrieves all resources for a specified Azure resource group. It processes each resource, displaying progress and collecting data about the resources, including their names and types. Additionally, it retrieves detailed information for specific resource types such as Storage Accounts, Key Vaults, Virtual Machines, SQL Servers, Web Apps, and Function Apps.

.PARAMETER ResourceGroupName
    The name of the resource group for which to retrieve resources.

.EXAMPLE
    Get-ResourceForResourceGroup -ResourceGroupName "myResourceGroup"
    This command retrieves and processes the list of resources for the Azure resource group named "myResourceGroup".

.NOTES
    Author: David Burel (@dafneb)
    Date: February 17, 2025
    Version: 1.0
#>
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
            $script:dataInventory += "`t`tResource: $($resItem.Name); ResourceType: $($resItem.ResourceType)"

            Get-RolesForResource -ResourceId $resItem.ResourceId

            Write-Verbose -Message "Details about resources: $($processDetails)"
            Write-Verbose -Message "Audit of resources: $($processAudits)"
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
                    'Microsoft.Sql/servers'
                    {
                        Write-Verbose -Message 'Get details for AzureSQLServer'
                        Get-SqlServerDetails -ResourceGroupName $resItem.ResourceGroupName -ServerName $resItem.Name
                    }
                    'Microsoft.Web/sites'
                    {
                        Write-Verbose -Message 'Get details for WebApp or FunctionApp'
                        Write-Verbose -Message "Kind: $($resItem.Kind)"
                        $listKind = $resItem.Kind -split ','
                        $listKind | ForEach-Object {
                            $kindItem = $_
                            if ($kindItem -eq "app")
                            {
                                Write-Verbose -Message 'Get details for WebApp'
                                Get-WebAppDetails -ResourceGroupName $resItem.ResourceGroupName -WebAppName $resItem.Name
                            }
                            if ($kindItem -eq "functionapp")
                            {
                                Write-Verbose -Message 'Get details for FunctionApp'
                                Get-FunctionAppDetails -ResourceGroupName $resItem.ResourceGroupName -FunctionAppName $resItem.Name
                            }
                        }
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

<#
.SYNOPSIS
    Retrieves and processes the list of resource groups for a specified Azure subscription.

.DESCRIPTION
    The Get-ResourceGroupsForSubscription function retrieves all resource groups for a specified Azure subscription. It processes each resource group, displaying progress and collecting data about the resource groups, including their names and locations. Additionally, it retrieves detailed information for each resource group, including roles and resources within the group.

.PARAMETER SubscriptionId
    The ID of the Azure subscription for which to retrieve resource groups.

.EXAMPLE
    Get-ResourceGroupsForSubscription -SubscriptionId "12345678-1234-1234-1234-123456789012"
    This command retrieves and processes the list of resource groups for the Azure subscription with the ID "12345678-1234-1234-1234-123456789012".

.NOTES
    Author: David Burel (@dafneb)
    Date: February 17, 2025
    Version: 1.0
#>
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

<#
.SYNOPSIS
    Retrieves and processes the list of subscriptions for the specified Azure tenant.

.DESCRIPTION
    The Get-Subscriptions function retrieves all subscriptions for the specified Azure tenant. It processes each subscription, displaying progress and collecting data about the subscriptions, including their names, IDs, tenant IDs, and states. Additionally, it retrieves detailed information for each subscription, including roles and resource groups within the subscription.

.PARAMETER Context
    The Azure context for the actual tenant.

.EXAMPLE
    Get-Subscriptions -Context $context
    This command retrieves and processes the list of subscriptions for the specified Azure tenant context.

.NOTES
    Author: David Burel (@dafneb)
    Date: February 17, 2025
    Version: 1.0
#>
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
$processDetails = $true
$processAudits = $true

# Get actual Azure context ...
$context = Get-AzContext

# Define path to files ...
$fileInventory = "azure-inventory-$($context.Tenant).txt"
$fileRoles = "azure-roles-$($context.Tenant).csv"
$fileIps = "azure-ips-$($context.Tenant).csv"
$fileIpsScan = "azure-ips-scan-$($context.Tenant).txt"
$fileUrls = "azure-urls-$($context.Tenant).csv"
$fileUrlsScan = "azure-urls-scan-$($context.Tenant).txt"
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
Clear-Content -Path $fileIpsScan
Clear-Content -Path $fileUrls
Clear-Content -Path $fileUrlsScan
Clear-Content -Path $fileAudit
Clear-Content -Path $fileOSystems
Clear-Content -Path $fileLanguages

# Export collected data to files ...
$script:dataInventory | ForEach-Object { Add-Content -Path $fileInventory -Value $_ }
$script:dataRoles | Export-Csv -Path $fileRoles -NoTypeInformation
$script:dataIps | Export-Csv -Path $fileIps -NoTypeInformation
$script:dataIps | ForEach-Object { Add-Content -Path $fileIpsScan -Value $_.'PublicIP' }
$script:dataUrls | Export-Csv -Path $fileUrls -NoTypeInformation
$script:dataUrls | ForEach-Object { Add-Content -Path $fileUrlsScan -Value $_.'PublicURL' }
$script:dataAudit | Export-Csv -Path $fileAudit -NoTypeInformation
$script:dataOSystems | Export-Csv -Path $fileOSystems -NoTypeInformation
$script:dataLanguages | Export-Csv -Path $fileLanguages -NoTypeInformation

# Get actual date and time ...
$timeEnd = Get-Date

# Printout date&times ...
Write-Output $timeStart
Write-Output $timeEnd
