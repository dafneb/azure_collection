<#
#>

# Define the script's parameters
[CmdletBinding(DefaultParameterSetName = "Default")]
param (
    [Parameter(Mandatory = $true, ParameterSetName = "Default")]
    [Parameter(Mandatory = $true, ParameterSetName = "AllDetails")]
    [Parameter(Mandatory = $true, ParameterSetName = "InactMembers")]
    [Parameter(Mandatory = $true, ParameterSetName = "InactGuests")]
    [Parameter(Mandatory = $true, ParameterSetName = "Groupies")]
    [ValidateNotNullOrEmpty()]
    [string]$CaseName,

    [Parameter(Mandatory = $true, ParameterSetName = "AllDetails")]
    [switch]$AllDetails,

    [Parameter(Mandatory = $true, ParameterSetName = "InactMembers")]
    [switch]$InactiveMembers,

    [Parameter(Mandatory = $true, ParameterSetName = "InactGuests")]
    [switch]$InactiveGuests,

    [Parameter(Mandatory = $false, ParameterSetName = "InactMembers")]
    [Parameter(Mandatory = $false, ParameterSetName = "InactGuests")]
    [Parameter(Mandatory = $false, ParameterSetName = "AllDetails")]
    [ValidateRange(1, [int]::MaxValue)]
    [int]$InactiveDays = 90,

    [Parameter(Mandatory = $true, ParameterSetName = "Groupies")]
    [switch]$GroupsDetails
)

$timeStart = Get-Date

Write-Output "***********************************************************"
Write-Output "*********** Users at Entra Id *****************************"
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
$usersFilePath = Join-Path -Path $caseFolderPath -ChildPath "users.csv"
$detailsFilePath = Join-Path -Path $caseFolderPath -ChildPath "users-details.txt"
$inactiveMemFilePath = Join-Path -Path $caseFolderPath -ChildPath "users-inactive-members.csv"
$inactiveGueFilePath = Join-Path -Path $caseFolderPath -ChildPath "users-inactive-guests.csv"
$groupsFilePath = Join-Path -Path $caseFolderPath -ChildPath "users-groups.csv"
$licensesFilePath = Join-Path -Path $caseFolderPath -ChildPath "users-licenses.csv"
$syncedFilePath = Join-Path -Path $caseFolderPath -ChildPath "users-synced.csv"

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

Write-Verbose -Message "ParameterSetName: $($PSCmdlet.ParameterSetName)"
Write-Verbose -Message "Checking folders & files (2/2) ..."

# Create log files if they don't exist
if ($AllDetails) {
    if (-not (Test-Path -Path $usersFilePath)) {
        Write-Verbose -Message "Users file does not exist, creating it..."
        New-Item -ItemType File -Path $usersFilePath | Out-Null
    } else {
        Write-Verbose -Message "Users file already exists, clear it..."
        Clear-Content -Path $usersFilePath | Out-Null
    }

    if (-not (Test-Path -Path $detailsFilePath)) {
        Write-Verbose -Message "Details file does not exist, creating it..."
        New-Item -ItemType File -Path $detailsFilePath | Out-Null
    } else {
        Write-Verbose -Message "Details file already exists, clear it..."
        Clear-Content -Path $detailsFilePath | Out-Null
    }

    if (-not (Test-Path -Path $inactiveMemFilePath)) {
        Write-Verbose -Message "Inactive members file does not exist, creating it..."
        New-Item -ItemType File -Path $inactiveMemFilePath | Out-Null
    } else {
        Write-Verbose -Message "Inactive members file already exists, clear it..."
        Clear-Content -Path $inactiveMemFilePath | Out-Null
    }

    if (-not (Test-Path -Path $inactiveGueFilePath)) {
        Write-Verbose -Message "Inactive guests file does not exist, creating it..."
        New-Item -ItemType File -Path $inactiveGueFilePath | Out-Null
    } else {
        Write-Verbose -Message "Inactive guests file already exists, clear it..."
        Clear-Content -Path $inactiveGueFilePath | Out-Null
    }

    if (-not (Test-Path -Path $groupsFilePath)) {
        Write-Verbose -Message "Groups file does not exist, creating it..."
        New-Item -ItemType File -Path $groupsFilePath | Out-Null
    } else {
        Write-Verbose -Message "Groups file already exists, clear it..."
        Clear-Content -Path $groupsFilePath | Out-Null
    }

    if (-not (Test-Path -Path $licensesFilePath)) {
        Write-Verbose -Message "Licenses file does not exist, creating it..."
        New-Item -ItemType File -Path $licensesFilePath | Out-Null
    } else {
        Write-Verbose -Message "Licenses file already exists, clear it..."
        Clear-Content -Path $licensesFilePath | Out-Null
    }

    if (-not (Test-Path -Path $syncedFilePath)) {
        Write-Verbose -Message "Synced users file does not exist, creating it..."
        New-Item -ItemType File -Path $syncedFilePath | Out-Null
    } else {
        Write-Verbose -Message "Synced users file already exists, clear it..."
        Clear-Content -Path $syncedFilePath | Out-Null
    }

} elseif ($InactiveMembers) {
    if (-not (Test-Path -Path $inactiveMemFilePath)) {
        Write-Verbose -Message "Inactive members file does not exist, creating it..."
        New-Item -ItemType File -Path $inactiveMemFilePath | Out-Null
    } else {
        Write-Verbose -Message "Inactive members file already exists, clear it..."
        Clear-Content -Path $inactiveMemFilePath | Out-Null
    }

} elseif ($InactiveGuests) {
    if (-not (Test-Path -Path $inactiveGueFilePath)) {
        Write-Verbose -Message "Inactive guests file does not exist, creating it..."
        New-Item -ItemType File -Path $inactiveGueFilePath | Out-Null
    } else {
        Write-Verbose -Message "Inactive guests file already exists, clear it..."
        Clear-Content -Path $inactiveGueFilePath | Out-Null
    }

} elseif ($GroupsDetails) {
    if (-not (Test-Path -Path $groupsFilePath)) {
        Write-Verbose -Message "Groups file does not exist, creating it..."
        New-Item -ItemType File -Path $groupsFilePath | Out-Null
    } else {
        Write-Verbose -Message "Groups file already exists, clear it..."
        Clear-Content -Path $groupsFilePath | Out-Null
    }

} else {
    if (-not (Test-Path -Path $usersFilePath)) {
        Write-Verbose -Message "Users file does not exist, creating it..."
        New-Item -ItemType File -Path $usersFilePath | Out-Null
    } else {
        Write-Verbose -Message "Users file already exists, clear it..."
        Clear-Content -Path $usersFilePath | Out-Null
    }

}

# Check if the connection was successful
if ($null -eq (Get-MgContext)) {
    Write-Verbose -Message "Connection to Microsoft Graph failed!"
    Write-Error -Message "Failed to connect to Microsoft Graph. Please check your credentials and permissions." -Category ConnectionError
    exit
}

Write-Verbose -Message "Getting data from Entra ID ..."

# Prepare arrays for storing data
$dataUsers = @()
[string[]]$dataDetails = @()
$dataInactiveMem = @()
$dataInactiveGue = @()
$dataGroups = @()
$dataLicenses = @()
$dataSynced = @()

# Get the list of all users in the organization
$users = Get-MgUser -All -Property "id,displayName,userPrincipalName,userType,customSecurityAttributes,SignInActivity,createdDateTime,onPremisesSyncEnabled" | Select-Object -Property id,displayName,userPrincipalName,userType,customSecurityAttributes,SignInActivity,createdDateTime,onPremisesSyncEnabled
# Loop through each user and retrieve their custom security attributes
$users | ForEach-Object {
    $user = $_
    Write-Verbose -Message "Processing user: $($user.DisplayName)"

    if ($AllDetails) {
        # Get all possible details for the user
        $dataDetails += "ID: $($user.ID); DisplayName: $($user.DisplayName); UserPrincipalName: $($user.UserPrincipalName); UserType: $($user.UserType)"
        # Basic user information
        $dataUsers += [PSCustomObject]@{
            UserID = $user.ID
            DisplayName = $user.DisplayName
            UserPrincipalName = $user.UserPrincipalName
            UserType = $user.UserType
        }
        # Get the groups the user is a member of
        $userMemberOf = Get-MgUserMemberOf -UserId $user.Id | Select-Object * -ExpandProperty additionalProperties
        $userMemberOf | ForEach-Object {
            $group = $_
            $dataGroups += [PSCustomObject]@{
                GroupID = $group.ID
                DisplayName = $group.AdditionalProperties["displayName"]
                Description = $group.AdditionalProperties["description"]
                Mail = $group.AdditionalProperties["mail"]
                SecurityEnabled = $group.AdditionalProperties["securityEnabled"]
                MemberId = $user.ID
                MemberDisplayName = $user.DisplayName
                MemberUserPrincipalName = $user.UserPrincipalName
            }

            $dataDetails += "`tGroup Membership:"
            $dataDetails += "`t`tDisplayName: $($group.AdditionalProperties["displayName"])"
            $dataDetails += "`t`tDescription: $($group.AdditionalProperties["description"])"
            $dataDetails += "`t`tMail: $($group.AdditionalProperties["mail"])"
            $dataDetails += "`t`tSecurityEnabled: $($group.AdditionalProperties["securityEnabled"])"
        }

        # Retrieve the user's assigned licenses
        $licenses = Get-MgUserLicenseDetail -UserId $user.Id
        $licenses | ForEach-Object {
            $license = $_
            $dataLicenses += [PSCustomObject]@{
                UserID = $user.ID
                DisplayName = $user.DisplayName
                UserPrincipalName = $user.UserPrincipalName
                SkuId = $license.SkuId
                SkuPartNumber = $license.SkuPartNumber
            }
            $dataDetails += "`tLicense: $($license.SkuId)"
            $dataDetails += "`t`tSkuPartNumber: $($license.SkuPartNumber)"
        }

        # Retrieve the custom security attributes for the user
        if ($user.CustomSecurityAttributes.AdditionalProperties.Count -gt 0) {
            $dataDetails += "`tCustom Security Attributes:"
            $user.CustomSecurityAttributes.AdditionalProperties.Keys | ForEach-Object {
                $key = $_
                $value = $user.CustomSecurityAttributes.AdditionalProperties.$($key) | Out-String
                # Append the custom attribute to the user information
                $dataDetails += "`t`t$($key): $($value)"
            }
        }

        # Check if the user is a member
        if ($user.UserType -eq "Member") {
            # Check if the user has been inactive for more than the specified number of days
            $requestDateTime = (Get-Date).AddDays(-$InactiveDays)
            $dataDetails += "`tAccount created: $($user.createdDateTime)"
            $dataDetails += ($user.SignInActivity.LastSignInDateTime) ? "`tLast sign-in: $($user.SignInActivity.LastSignInDateTime)" : "`tLast sign-in: Not defined"
            $dataDetails += ($user.SignInActivity.LastNonInteractiveSignInDateTime) ? "`tLast non-interactive sign-in: $($user.SignInActivity.LastNonInteractiveSignInDateTime)" : "`tLast non-interactive sign-in: Not defined"
            if ((($user.SignInActivity.LastSignInDateTime -lt $requestDateTime) -or ($user.SignInActivity.LastSignInDateTime -eq $null)) -and $user.createdDateTime -lt $requestDateTime) {
                # Add the user to the inactive members list
                $dataInactiveMem += [PSCustomObject]@{
                    UserID = $user.ID
                    DisplayName = $user.DisplayName
                    UserPrincipalName = $user.UserPrincipalName
                    UserType = $user.UserType
                    CreatedDateTime = $user.createdDateTime
                    LastSignInDateTime = ($user.SignInActivity.LastSignInDateTime) ? $user.SignInActivity.LastSignInDateTime : "Not defined"
                    LastNonInteractive = ($user.SignInActivity.LastNonInteractiveSignInDateTime) ? $user.SignInActivity.LastNonInteractiveSignInDateTime : "Not defined"
                    LastSuccessfulSignIn = ($user.SignInActivity.LastSuccessfulSignInDateTime) ? $user.SignInActivity.LastSuccessfulSignInDateTime : "Not defined"
                }
            }
        }

        # Check if the user is a guest
        if ($user.UserType -eq "Guest") {
            # Check if the user has been inactive for more than the specified number of days
            $requestDateTime = (Get-Date).AddDays(-$InactiveDays)
            $dataDetails += "`tAccount created: $($user.createdDateTime)"
            $dataDetails += ($user.SignInActivity.LastSignInDateTime) ? "`tLast sign-in: $($user.SignInActivity.LastSignInDateTime)" : "`tLast sign-in: Not defined"
            $dataDetails += ($user.SignInActivity.LastNonInteractiveSignInDateTime) ? "`tLast non-interactive sign-in: $($user.SignInActivity.LastNonInteractiveSignInDateTime)" : "`tLast non-interactive sign-in: Not defined"
            if ((($user.SignInActivity.LastSignInDateTime -lt $requestDateTime) -or ($user.SignInActivity.LastSignInDateTime -eq $null)) -and $user.createdDateTime -lt $requestDateTime) {
                # Add the user to the inactive guests list
                $dataInactiveGue += [PSCustomObject]@{
                    UserID = $user.ID
                    DisplayName = $user.DisplayName
                    UserPrincipalName = $user.UserPrincipalName
                    UserType = $user.UserType
                    CreatedDateTime = $user.createdDateTime
                    LastSignInDateTime = ($user.SignInActivity.LastSignInDateTime) ? $user.SignInActivity.LastSignInDateTime : "Not defined"
                    LastNonInteractive = ($user.SignInActivity.LastNonInteractiveSignInDateTime) ? $user.SignInActivity.LastNonInteractiveSignInDateTime : "Not defined"
                    LastSuccessfulSignIn = ($user.SignInActivity.LastSuccessfulSignInDateTime) ? $user.SignInActivity.LastSuccessfulSignInDateTime : "Not defined"
                }
            }
        }

        # Check if the user is synced from on-premises
        $dataDetails += "`tOn-prem sync enabled: $($user.OnPremisesSyncEnabled)"
        if ($user.onPremisesSyncEnabled) {
            $dataSynced += [PSCustomObject]@{
                UserID = $user.ID
                DisplayName = $user.DisplayName
                UserPrincipalName = $user.UserPrincipalName
                UserType = $user.UserType
            }
        }

    } elseif ($InactiveMembers) {
        # Check if the user is a member
        if ($user.UserType -eq "Member") {
            # Check if the user has been inactive for more than the specified number of days
            $requestDateTime = (Get-Date).AddDays(-$InactiveDays)
            if ((($user.SignInActivity.LastSignInDateTime -lt $requestDateTime) -or ($user.SignInActivity.LastSignInDateTime -eq $null)) -and $user.createdDateTime -lt $requestDateTime) {
                # Add the user to the inactive members list
                $dataInactiveMem += [PSCustomObject]@{
                    UserID = $user.ID
                    DisplayName = $user.DisplayName
                    UserPrincipalName = $user.UserPrincipalName
                    UserType = $user.UserType
                    CreatedDateTime = $user.createdDateTime
                    LastSignInDateTime = ($user.SignInActivity.LastSignInDateTime) ? $user.SignInActivity.LastSignInDateTime : "Not defined"
                    LastNonInteractive = ($user.SignInActivity.LastNonInteractiveSignInDateTime) ? $user.SignInActivity.LastNonInteractiveSignInDateTime : "Not defined"
                    LastSuccessfulSignIn = ($user.SignInActivity.LastSuccessfulSignInDateTime) ? $user.SignInActivity.LastSuccessfulSignInDateTime : "Not defined"
                }
            }
        }

    } elseif ($InactiveGuests) {
        # Check if the user is a guest
        if ($user.UserType -eq "Guest") {
            # Check if the user has been inactive for more than the specified number of days
            $requestDateTime = (Get-Date).AddDays(-$InactiveDays)
            if ((($user.SignInActivity.LastSignInDateTime -lt $requestDateTime) -or ($user.SignInActivity.LastSignInDateTime -eq $null)) -and $user.createdDateTime -lt $requestDateTime) {
                # Add the user to the inactive guests list
                $dataInactiveGue += [PSCustomObject]@{
                    UserID = $user.ID
                    DisplayName = $user.DisplayName
                    UserPrincipalName = $user.UserPrincipalName
                    UserType = $user.UserType
                    CreatedDateTime = $user.createdDateTime
                    LastSignInDateTime = ($user.SignInActivity.LastSignInDateTime) ? $user.SignInActivity.LastSignInDateTime : "Not defined"
                    LastNonInteractive = ($user.SignInActivity.LastNonInteractiveSignInDateTime) ? $user.SignInActivity.LastNonInteractiveSignInDateTime : "Not defined"
                    LastSuccessfulSignIn = ($user.SignInActivity.LastSuccessfulSignInDateTime) ? $user.SignInActivity.LastSuccessfulSignInDateTime : "Not defined"
                }
            }
        }

    } elseif ($GroupsDetails) {
        # Basic user information
        $dataUsers += [PSCustomObject]@{
            UserID = $user.ID
            DisplayName = $user.DisplayName
            UserPrincipalName = $user.UserPrincipalName
            UserType = $user.UserType
        }
        # Get the groups the user is a member of
        $userMemberOf = Get-MgUserMemberOf -UserId $user.Id | Select-Object * -ExpandProperty additionalProperties
        $userMemberOf | ForEach-Object {
            $group = $_
            $dataGroups += [PSCustomObject]@{
                GroupID = $group.ID
                DisplayName = $group.AdditionalProperties["displayName"]
                Description = $group.AdditionalProperties["description"]
                Mail = $group.AdditionalProperties["mail"]
                SecurityEnabled = $group.AdditionalProperties["securityEnabled"]
                MemberId = $user.ID
                MemberDisplayName = $user.DisplayName
                MemberUserPrincipalName = $user.UserPrincipalName
            }
        }

    } else {
        # Default case: just get the basic user information
        $dataUsers += [PSCustomObject]@{
            UserID = $user.ID
            DisplayName = $user.DisplayName
            UserPrincipalName = $user.UserPrincipalName
            UserType = $user.UserType
        }

    }

}

# Store data at files ...
Write-Verbose -Message "Storing data at files ..."
if ($AllDetails) {
    $dataUsers | Export-Csv -Path $usersFilePath -NoTypeInformation -Force
    $dataGroups | Export-Csv -Path $groupsFilePath -NoTypeInformation -Force
    $dataLicenses | Export-Csv -Path $licensesFilePath -NoTypeInformation -Force
    $dataInactiveMem | Export-Csv -Path $inactiveMemFilePath -NoTypeInformation -Force
    $dataInactiveGue | Export-Csv -Path $inactiveGueFilePath -NoTypeInformation -Force
    $dataSynced | Export-Csv -Path $syncedFilePath -NoTypeInformation -Force

    $dataDetails | ForEach-Object { $_ | Out-File -FilePath $detailsFilePath -Append }

} elseif ($InactiveMembers) {
    $dataInactiveMem | Export-Csv -Path $inactiveMemFilePath -NoTypeInformation -Force

} elseif ($InactiveGuests) {
    $dataInactiveGue | Export-Csv -Path $inactiveGueFilePath -NoTypeInformation -Force

} elseif ($GroupsDetails) {
    $dataUsers | Export-Csv -Path $usersFilePath -NoTypeInformation -Force
    $dataGroups | Export-Csv -Path $groupsFilePath -NoTypeInformation -Force

} else {
    # Default case: just get the basic user information
    $dataUsers | Export-Csv -Path $usersFilePath -NoTypeInformation -Force

}

# Get actual date and time ...
$timeEnd = Get-Date

# Printout date&times ...
Write-Output "***********************************************************"
Write-Output "Started: $($timeStart)"
Write-Output "Finished: $($timeEnd)"
Write-Output "Elapsed time: $($timeEnd - $timeStart)"
