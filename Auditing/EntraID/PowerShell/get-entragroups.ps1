<#
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
Write-Output "*********** Groups at Entra Id ****************************"
Write-Output "*********** Author: David Burel (@dafneb) *****************"
Write-Output "***********************************************************"

Write-Verbose -Message "Checking requirements ..."

# Check if PowerShell version is 7.4 or higher
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Verbose -Message "PowerShell version is lower than 7.4, actual version is $($PSVersionTable.PSVersion) ..."
    Write-Error -Message "PowerShell version 7.4 or higher is required" -Category NotInstalled
    exit
}

# Check if module is already installed
if (-not (Get-Module -Name Microsoft.Graph -ListAvailable)) {
    Write-Verbose -Message "Microsoft.Graph module not found ..."
    Write-Error -Message "Microsoft.Graph module not found, please install it first" -Category NotInstalled
    exit
}

# Check if Microsoft.Graph module is loaded
if (-not (Get-Module -Name Microsoft.Graph)) {
    Write-Verbose "Loading Microsoft.Graph module ..."
    Import-Module Microsoft.Graph -ErrorAction Stop
}

# Normalize case name to lowercase
$caseFolderName = $CaseName.ToLower()
$caseFolderName = $caseFolderName.Trim()
$caseFolderName = $caseFolderName -replace '[\\/:*?"<>|]', '_'

# Paths for logs
$baseFolderPath = Join-Path -Path (Get-Location) -ChildPath "case"
$caseFolderPath = Join-Path -Path $baseFolderPath -ChildPath "$($caseFolderName)"
$detailsFilePath = Join-Path -Path $caseFolderPath -ChildPath "groups-details.txt"
$groupsFilePath = Join-Path -Path $caseFolderPath -ChildPath "groups.csv"
$syncedFilePath = Join-Path -Path $caseFolderPath -ChildPath "groups-synced.csv"
$ownersFilePath = Join-Path -Path $caseFolderPath -ChildPath "groups-owners.csv"
$membersFilePath = Join-Path -Path $caseFolderPath -ChildPath "groups-members.csv"
$membershipFilePath = Join-Path -Path $caseFolderPath -ChildPath "groups-membership.csv"
$permissionsFilePath = Join-Path -Path $caseFolderPath -ChildPath "groups-permissions.csv"

Write-Verbose -Message "Checking folders & files (1/2) ..."

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

# Check if the groups file already exists
if (-not (Test-Path -Path $groupsFilePath)) {
    Write-Verbose -Message "Groups file does not exist, creating it..."
    New-Item -ItemType File -Path $groupsFilePath | Out-Null
} else {
    Write-Verbose -Message "Groups file already exists, clear it..."
    Clear-Content -Path $groupsFilePath | Out-Null
}

# Check if the groups details file already exists
if (-not (Test-Path -Path $detailsFilePath)) {
    Write-Verbose -Message "Details file does not exist, creating it..."
    New-Item -ItemType File -Path $detailsFilePath | Out-Null
} else {
    Write-Verbose -Message "Details file already exists, clear it..."
    Clear-Content -Path $detailsFilePath | Out-Null
}

# Check if the sync details file already exists
if (-not (Test-Path -Path $syncedFilePath)) {
    Write-Verbose -Message "Synced groups file does not exist, creating it..."
    New-Item -ItemType File -Path $syncedFilePath | Out-Null
} else {
    Write-Verbose -Message "Synced groups file already exists, clear it..."
    Clear-Content -Path $syncedFilePath | Out-Null
}

# Check if the groups ownership file already exists
if (-not (Test-Path -Path $ownersFilePath)) {
    Write-Verbose -Message "Owners file does not exist, creating it..."
    New-Item -ItemType File -Path $ownersFilePath | Out-Null
} else {
    Write-Verbose -Message "Owners file already exists, clear it..."
    Clear-Content -Path $ownersFilePath | Out-Null
}

# Check if the groups membership file already exists
if (-not (Test-Path -Path $membersFilePath)) {
    Write-Verbose -Message "Members file does not exist, creating it..."
    New-Item -ItemType File -Path $membersFilePath | Out-Null
} else {
    Write-Verbose -Message "Members file already exists, clear it..."
    Clear-Content -Path $membersFilePath | Out-Null
}

# Check if the membership of group file already exists
if (-not (Test-Path -Path $membershipFilePath)) {
    Write-Verbose -Message "Membership file does not exist, creating it..."
    New-Item -ItemType File -Path $membershipFilePath | Out-Null
} else {
    Write-Verbose -Message "Membership file already exists, clear it..."
    Clear-Content -Path $membershipFilePath | Out-Null
}

# Check if the permissions file already exists
if (-not (Test-Path -Path $permissionsFilePath)) {
    Write-Verbose -Message "Permissions file does not exist, creating it..."
    New-Item -ItemType File -Path $permissionsFilePath | Out-Null
} else {
    Write-Verbose -Message "Permissions file already exists, clear it..."
    Clear-Content -Path $permissionsFilePath | Out-Null
}

Write-Verbose -Message "ParameterSetName: $($PSCmdlet.ParameterSetName)"

# Check if the connection was successful
if ($null -eq (Get-MgContext)) {
    Write-Verbose -Message "Connection to Microsoft Graph failed!"
    Write-Error -Message "Failed to connect to Microsoft Graph. Please check your credentials and permissions." -Category ConnectionError
    exit
}

Write-Verbose -Message "Getting data from Entra ID ..."

# Prepare arrays for storing data
$dataGroups = @()
[string[]]$dataDetails = @()
$dataSynced = @()
$dataOwners = @()
$dataMembers = @()
$dataMembersOf = @()
$dataPermissions = @()

# Get the list of all groups in the organization
$groups = Get-MgGroup -All -Property  "id,displayName,groupTypes,createdDateTime,onPremisesSyncEnabled,Mail" | Select-Object -Property id,displayName,groupTypes,createdDateTime,onPremisesSyncEnabled,Mail
# Loop through each group and get its details
$groups | ForEach-Object {
    $group = $_
    Write-Verbose -Message "Processing group: $($group.DisplayName)"

    # TODO: Add code here to get groups and their details
    $dataDetails += "ID: $($group.ID); DisplayName: $($group.DisplayName); GroupTypes: $($group.GroupTypes -join ", ")"
    $dataDetails += "`tGroup created: $($group.createdDateTime)"
    $dataDetails += "`tVisibility: $($group.Visibility)"
    $dataDetails += "`tMail: $($group.Mail)"
    $dataDetails += "`tOn-prem sync enabled: $($group.OnPremisesSyncEnabled)"
    $dataGroups += [PSCustomObject]@{
        GroupID = $group.ID
        DisplayName = $group.DisplayName
        GroupTypes = $group.GroupTypes -join ", "
        CreatedDateTime = $group.createdDateTime
        OnPremisesSyncEnabled = $group.OnPremisesSyncEnabled
        Mail = $group.Mail
        Visibility = $group.Visibility
    }
    $dataDetails += "`tOwners:"
    $grpOwners = Get-MgGroupOwner -GroupId $group.ID -All -ErrorAction SilentlyContinue
    if ($grpOwners) {
        $grpOwners | ForEach-Object {
            $entity = $_
            $entityDisplayName = ""
            $entityDetails = ""
            $entityType = $entity.AdditionalProperties["@odata.type"]
            switch ($entity.AdditionalProperties["@odata.type"]) {
                "#microsoft.graph.user" {
                    $dataDetails += "`t`tUser: $($entity.AdditionalProperties["displayName"]) ($($entity.AdditionalProperties["userPrincipalName"]))"
                    $entityDisplayName = $entity.AdditionalProperties["displayName"]
                    $entityDetails = $entity.AdditionalProperties["userPrincipalName"]
                }
                "#microsoft.graph.group" {
                    $dataDetails += "`t`tGroup: $($entity.AdditionalProperties["displayName"]) ($($entity.AdditionalProperties["mail"]))"
                    $entityDisplayName = $entity.AdditionalProperties["displayName"]
                    $entityDetails = $entity.AdditionalProperties["mail"]
                }
                "#microsoft.graph.device" {
                    $dataDetails += "`t`tDevice: $($entity.AdditionalProperties["displayName"]) ($($entity.AdditionalProperties["deviceId"]))"
                    $entityDisplayName = $entity.AdditionalProperties["displayName"]
                    $entityDetails = $entity.AdditionalProperties["deviceId"]
                }
                "#microsoft.graph.administrativeUnit" {
                    $dataDetails += "`t`tAdministrative Unit: $($entity.AdditionalProperties["displayName"])"
                    $entityDisplayName = $entity.AdditionalProperties["displayName"]
                }
                "#microsoft.graph.directoryRole" {
                    $dataDetails += "`t`tAdministrative Unit: $($entity.AdditionalProperties["displayName"]) ($($entity.AdditionalProperties["roleTemplateId"]))"
                    $entityDisplayName = $entity.AdditionalProperties["displayName"]
                    $entityDetails = $entity.AdditionalProperties["roleTemplateId"]
                }
                "#microsoft.graph.orgContact" {
                    $orgMail = ($entity.AdditionalProperties["mail"] -ne $null) ? $entity.AdditionalProperties["mail"] : "No mail"
                    $dataDetails += "`t`tContact: $($entity.AdditionalProperties["displayName"]) ($($orgMail))"
                    $entityDisplayName = $entity.AdditionalProperties["displayName"]
                    $entityDetails = $orgMail
                }
                # "#microsoft.graph.servicePrincipal" {
                #     # $dataDetails += "`t`tService Principal: $($_.DisplayName) ($($_.Mail))"
                # }
                default {
                    $dataDetails += "`t`tUnknown type [$($entity.AdditionalProperties["@odata.type"])]"
                    Write-Warning "Unknown type [$($entity.AdditionalProperties["@odata.type"])]"
                    $entity.AdditionalProperties | Format-List
                }
            }
            $dataOwners += [PSCustomObject]@{
                GroupID = $group.ID
                GroupDisplayName = $group.DisplayName
                GroupTypes = $group.GroupTypes -join ", "
                OwnerType = $entityType
                OwnerDisplayName = $entityDisplayName
                OwnerDetails = $entityDetails
            }
        }
    } else {
        $dataDetails += "`t`tNo owners found"
    }
    $dataDetails += "`tMembers:"
    $grpMembers = Get-MgGroupMember -GroupId $group.ID -All -ErrorAction SilentlyContinue
    if ($grpMembers) {
        $grpMembers | ForEach-Object {
            $entity = $_
            $entityDisplayName = ""
            $entityDetails = ""
            $entityType = $entity.AdditionalProperties["@odata.type"]
            switch ($entity.AdditionalProperties["@odata.type"]) {
                "#microsoft.graph.user" {
                    $dataDetails += "`t`tUser: $($entity.AdditionalProperties["displayName"]) ($($entity.AdditionalProperties["userPrincipalName"]))"
                    $entityDisplayName = $entity.AdditionalProperties["displayName"]
                    $entityDetails = $entity.AdditionalProperties["userPrincipalName"]
                }
                "#microsoft.graph.group" {
                    $dataDetails += "`t`tGroup: $($entity.AdditionalProperties["displayName"]) ($($entity.AdditionalProperties["mail"]))"
                    $entityDisplayName = $entity.AdditionalProperties["displayName"]
                    $entityDetails = $entity.AdditionalProperties["mail"]
                }
                "#microsoft.graph.device" {
                    $dataDetails += "`t`tDevice: $($entity.AdditionalProperties["displayName"]) ($($entity.AdditionalProperties["deviceId"]))"
                    $entityDisplayName = $entity.AdditionalProperties["displayName"]
                    $entityDetails = $entity.AdditionalProperties["deviceId"]
                }
                "#microsoft.graph.administrativeUnit" {
                    $dataDetails += "`t`tAdministrative Unit: $($entity.AdditionalProperties["displayName"])"
                    $entityDisplayName = $entity.AdditionalProperties["displayName"]
                }
                "#microsoft.graph.directoryRole" {
                    $dataDetails += "`t`tAdministrative Unit: $($entity.AdditionalProperties["displayName"]) ($($entity.AdditionalProperties["roleTemplateId"]))"
                    $entityDisplayName = $entity.AdditionalProperties["displayName"]
                    $entityDetails = $entity.AdditionalProperties["roleTemplateId"]
                }
                "#microsoft.graph.orgContact" {
                    $orgMail = ($entity.AdditionalProperties["mail"] -ne $null) ? $entity.AdditionalProperties["mail"] : "No mail"
                    $dataDetails += "`t`tContact: $($entity.AdditionalProperties["displayName"]) ($($orgMail))"
                    $entityDisplayName = $entity.AdditionalProperties["displayName"]
                    $entityDetails = $orgMail
                }
                # "#microsoft.graph.servicePrincipal" {
                #     # $dataDetails += "`t`tService Principal: $($_.DisplayName) ($($_.Mail))"
                # }
                default {
                    $dataDetails += "`t`tUnknown type [$($entity.AdditionalProperties["@odata.type"])]"
                    Write-Warning "Unknown type [$($entity.AdditionalProperties["@odata.type"])]"
                    $entity.AdditionalProperties | Format-List
                }
            }
            $dataMembers += [PSCustomObject]@{
                GroupID = $group.ID
                GroupDisplayName = $group.DisplayName
                GroupTypes = $group.GroupTypes -join ", "
                MemberType = $entityType
                MemberDisplayName = $entityDisplayName
                MemberDetails = $entityDetails
            }
        }
    } else {
        $dataDetails += "`t`tNo members found"
    }
    $dataDetails += "`tMemberOf:"
    $grpMemberOf = Get-MgGroupMemberOf -GroupId $group.ID -All -ErrorAction SilentlyContinue
    if ($grpMemberOf) {
        $grpMemberOf | ForEach-Object {
            $entity = $_
            $entityDisplayName = ""
            $entityDetails = ""
            $entityType = $entity.AdditionalProperties["@odata.type"]
            switch ($entity.AdditionalProperties["@odata.type"]) {
                "#microsoft.graph.user" {
                    $dataDetails += "`t`tUser: $($entity.AdditionalProperties["displayName"]) ($($entity.AdditionalProperties["userPrincipalName"]))"
                    $entityDisplayName = $entity.AdditionalProperties["displayName"]
                    $entityDetails = $entity.AdditionalProperties["userPrincipalName"]
                }
                "#microsoft.graph.group" {
                    $dataDetails += "`t`tGroup: $($entity.AdditionalProperties["displayName"]) ($($entity.AdditionalProperties["mail"]))"
                    $entityDisplayName = $entity.AdditionalProperties["displayName"]
                    $entityDetails = $entity.AdditionalProperties["mail"]
                }
                "#microsoft.graph.device" {
                    $dataDetails += "`t`tDevice: $($entity.AdditionalProperties["displayName"]) ($($entity.AdditionalProperties["deviceId"]))"
                    $entityDisplayName = $entity.AdditionalProperties["displayName"]
                    $entityDetails = $entity.AdditionalProperties["deviceId"]
                }
                "#microsoft.graph.administrativeUnit" {
                    $dataDetails += "`t`tAdministrative Unit: $($entity.AdditionalProperties["displayName"])"
                    $entityDisplayName = $entity.AdditionalProperties["displayName"]
                }
                "#microsoft.graph.directoryRole" {
                    $dataDetails += "`t`tAdministrative Unit: $($entity.AdditionalProperties["displayName"]) ($($entity.AdditionalProperties["roleTemplateId"]))"
                    $entityDisplayName = $entity.AdditionalProperties["displayName"]
                    $entityDetails = $entity.AdditionalProperties["roleTemplateId"]
                }
                "#microsoft.graph.orgContact" {
                    $orgMail = ($entity.AdditionalProperties["mail"] -ne $null) ? $entity.AdditionalProperties["mail"] : "No mail"
                    $dataDetails += "`t`tContact: $($entity.AdditionalProperties["displayName"]) ($($orgMail))"
                    $entityDisplayName = $entity.AdditionalProperties["displayName"]
                    $entityDetails = $orgMail
                }
                # "#microsoft.graph.servicePrincipal" {
                #     # $dataDetails += "`t`tService Principal: $($_.DisplayName) ($($_.Mail))"
                # }
                default {
                    $dataDetails += "`t`tUnknown type [$($entity.AdditionalProperties["@odata.type"])]"
                    Write-Warning "Unknown type [$($entity.AdditionalProperties["@odata.type"])]"
                    $entity.AdditionalProperties | Format-List
                }
            }
            $dataMembersOf += [PSCustomObject]@{
                GroupID = $group.ID
                GroupDisplayName = $group.DisplayName
                GroupTypes = $group.GroupTypes -join ", "
                MemberOfType = $entityType
                MemberOfDisplayName = $entityDisplayName
                MemberOfDetails = $entityDetails
            }
        }
    } else {
        $dataDetails += "`t`tNo memberOf found"
    }

    if ($group.GroupTypes.Contains("Unified")) {
        $grpPermissions = Get-MgGroupPermissionGrant -GroupId $group.ID -All #-ErrorAction SilentlyContinue
        if ($grpPermissions) {
            $dataDetails += "`tPermissions:"
            $grpPermissions | ForEach-Object {
                $permission = $_
                $dataPermissions += [PSCustomObject]@{
                    GroupID = $group.ID
                    GroupDisplayName = $group.DisplayName
                    GroupTypes = $group.GroupTypes -join ", "
                    ClientAppId = $permission.ClientAppId
                    ClientId = $permission.ClientId
                    Permission = $permission.Permission
                    PermissionType = $permission.PermissionType
                    ResourceAppId = $permission.ResourceAppId
                }
                $dataDetails += "`t`tClientAppId: $($permission.ClientAppId)"
                $dataDetails += "`t`t`tClientId: $($permission.ClientId)"
                $dataDetails += "`t`t`tPermission: $($permission.Permission) ($($permission.PermissionType))"
                $dataDetails += "`t`t`tResourceAppId: $($permission.ResourceAppId)"
            }
        }
    }

    if ($group.onPremisesSyncEnabled) {
        $dataSynced += [PSCustomObject]@{
            GroupID = $group.ID
            DisplayName = $group.DisplayName
            GroupTypes = $group.GroupTypes -join ", "
        }
    }
}

$dataDetails | ForEach-Object { $_ | Out-File -FilePath $detailsFilePath -Append }
$dataGroups | Export-Csv -Path $groupsFilePath -NoTypeInformation -Force
$dataSynced | Export-Csv -Path $syncedFilePath -NoTypeInformation -Force
$dataOwners | Export-Csv -Path $ownersFilePath -NoTypeInformation -Force
$dataMembers | Export-Csv -Path $membersFilePath -NoTypeInformation -Force
$dataMembersOf | Export-Csv -Path $membershipFilePath -NoTypeInformation -Force
$dataPermissions | Export-Csv -Path $permissionsFilePath -NoTypeInformation -Force

# Get actual date and time ...
$timeEnd = Get-Date

# Printout date&times ...
Write-Output "***********************************************************"
Write-Output "Started: $($timeStart)"
Write-Output "Finished: $($timeEnd)"
Write-Output "Elapsed time: $($timeEnd - $timeStart)"
