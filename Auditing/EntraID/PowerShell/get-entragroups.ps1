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
$syncedFilePath = Join-Path -Path $caseFolderPath -ChildPath "synced-groups.csv"

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

if (-not (Test-Path -Path $syncedFilePath)) {
    Write-Verbose -Message "Synced groups file does not exist, creating it..."
    New-Item -ItemType File -Path $syncedFilePath | Out-Null
} else {
    Write-Verbose -Message "Synced groups file already exists, clear it..."
    Clear-Content -Path $syncedFilePath | Out-Null
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
    $dataDetails += "`tOwners:"
    $grpOwners = Get-MgGroupOwner -GroupId $group.ID -All
    if ($grpOwners) {
        $grpOwners | ForEach-Object {
            $entity = $_
            switch ($entity.AdditionalProperties["@odata.type"]) {
                "#microsoft.graph.user" {
                    $dataDetails += "`t`tUser: $($entity.AdditionalProperties["displayName"]) ($($entity.AdditionalProperties["userPrincipalName"]))"
                }
                "#microsoft.graph.group" {
                    $dataDetails += "`t`tGroup: $($entity.AdditionalProperties["displayName"]) ($($entity.AdditionalProperties["mail"]))"
                }
                "#microsoft.graph.device" {
                    $dataDetails += "`t`tDevice: $($entity.AdditionalProperties["displayName"]) ($($entity.AdditionalProperties["deviceId"]))"
                }
                "#microsoft.graph.administrativeUnit" {
                    $dataDetails += "`t`tAdministrative Unit: $($entity.AdditionalProperties["displayName"])"
                }
                "#microsoft.graph.directoryRole" {
                    $dataDetails += "`t`tAdministrative Unit: $($entity.AdditionalProperties["displayName"]) ($($entity.AdditionalProperties["roleTemplateId"]))"
                }
                # "#microsoft.graph.servicePrincipal" {
                #     # $dataDetails += "`t`tService Principal: $($_.DisplayName) ($($_.Mail))"
                # }
                default {
                    $dataDetails += "`t`tUnknown type [$($entity.AdditionalProperties["@odata.type"])]"
                    Write-Host "Unknown type [$($entity.AdditionalProperties["@odata.type"])]"
                    $entity.AdditionalProperties | Format-List
                }
            }
        }
    } else {
        $dataDetails += "`t`tNo owners found"
    }
    $dataDetails += "`tMembers:"
    $grpMembers = Get-MgGroupMember -GroupId $group.ID -All
    if ($grpMembers) {
        $grpMembers | ForEach-Object {
            $entity = $_
            switch ($entity.AdditionalProperties["@odata.type"]) {
                "#microsoft.graph.user" {
                    $dataDetails += "`t`tUser: $($entity.AdditionalProperties["displayName"]) ($($entity.AdditionalProperties["userPrincipalName"]))"
                }
                "#microsoft.graph.group" {
                    $dataDetails += "`t`tGroup: $($entity.AdditionalProperties["displayName"]) ($($entity.AdditionalProperties["mail"]))"
                }
                "#microsoft.graph.device" {
                    $dataDetails += "`t`tDevice: $($entity.AdditionalProperties["displayName"]) ($($entity.AdditionalProperties["deviceId"]))"
                }
                "#microsoft.graph.administrativeUnit" {
                    $dataDetails += "`t`tAdministrative Unit: $($entity.AdditionalProperties["displayName"])"
                }
                "#microsoft.graph.directoryRole" {
                    $dataDetails += "`t`tAdministrative Unit: $($entity.AdditionalProperties["displayName"]) ($($entity.AdditionalProperties["roleTemplateId"]))"
                }
                # "#microsoft.graph.servicePrincipal" {
                #     # $dataDetails += "`t`tService Principal: $($_.DisplayName) ($($_.Mail))"
                # }
                default {
                    $dataDetails += "`t`tUnknown type [$($entity.AdditionalProperties["@odata.type"])]"
                    Write-Host "Unknown type [$($entity.AdditionalProperties["@odata.type"])]"
                    $entity.AdditionalProperties | Format-List
                }
            }
        }
    } else {
        $dataDetails += "`t`tNo members found"
    }
    $dataDetails += "`tMemberOf:"
    $grpMemberOf = Get-MgGroupMemberOf -GroupId $group.ID -All
    if ($grpMemberOf) {
        $grpMemberOf | ForEach-Object {
            $entity = $_
            switch ($entity.AdditionalProperties["@odata.type"]) {
                "#microsoft.graph.user" {
                    $dataDetails += "`t`tUser: $($entity.AdditionalProperties["displayName"]) ($($entity.AdditionalProperties["userPrincipalName"]))"
                }
                "#microsoft.graph.group" {
                    $dataDetails += "`t`tGroup: $($entity.AdditionalProperties["displayName"]) ($($entity.AdditionalProperties["mail"]))"
                }
                "#microsoft.graph.device" {
                    $dataDetails += "`t`tDevice: $($entity.AdditionalProperties["displayName"]) ($($entity.AdditionalProperties["deviceId"]))"
                }
                "#microsoft.graph.administrativeUnit" {
                    $dataDetails += "`t`tAdministrative Unit: $($entity.AdditionalProperties["displayName"])"
                }
                "#microsoft.graph.directoryRole" {
                    $dataDetails += "`t`tAdministrative Unit: $($entity.AdditionalProperties["displayName"]) ($($entity.AdditionalProperties["roleTemplateId"]))"
                }
                # "#microsoft.graph.servicePrincipal" {
                #     # $dataDetails += "`t`tService Principal: $($_.DisplayName) ($($_.Mail))"
                # }
                default {
                    $dataDetails += "`t`tUnknown type [$($entity.AdditionalProperties["@odata.type"])]"
                    Write-Host "Unknown type [$($entity.AdditionalProperties["@odata.type"])]"
                    $entity.AdditionalProperties | Format-List
                }
            }
        }
    } else {
        $dataDetails += "`t`tNo memberOf found"
    }

    if ($group.onPremisesSyncEnabled) {
        $dataSynced += [PSCustomObject]@{
            GroupID = $group.ID
            DisplayName = $group.DisplayName
            GroupTypes = $group.GroupTypes -join ", "
        }
    }
}

$dataGroups | Export-Csv -Path $groupsFilePath -NoTypeInformation -Force
$dataDetails | ForEach-Object { $_ | Out-File -FilePath $detailsFilePath -Append }
$dataSynced | Export-Csv -Path $syncedFilePath -NoTypeInformation -Force

# Get actual date and time ...
$timeEnd = Get-Date

# Printout date&times ...
Write-Output "***********************************************************"
Write-Output "Started: $($timeStart)"
Write-Output "Finished: $($timeEnd)"
Write-Output "Elapsed time: $($timeEnd - $timeStart)"
