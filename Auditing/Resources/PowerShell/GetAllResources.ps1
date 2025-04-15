<#
.SYNOPSIS
    This script is going through all visible subscriptions and generating inventory.

.DESCRIPTION
    This script is going through all visible subscriptions and generating inventory.

.NOTES
    Author: David Burel (@dafneb)
    Date: April 10, 2025
    Version: 1.1
#>

[CmdletBinding()] # add Common parameter to your script (verbose, ...)
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$DestinationFolder = "inventory",

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [bool]$Details = $false,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [bool]$CompressArchive = $false
)
###################################################################

### Progress bars functions
function Show-RootProgressBar {

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
        Id               = 0
        Activity         = $ActivityName
        Status           = $ObjectName
        PercentComplete  = $progCompleted
    }
    Write-Progress @progParameters    

}

function Hide-RootProgressBar {

    $progParameters = @{
        Id               = 0
        Activity         = 'Nothing'
        Status           = 'Done'
    }
    Write-Progress @progParameters -Completed   

} 

function Show-ChildProgressBar {

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
        [string] $ObjectName,

        [Parameter(Mandatory=$true,
        HelpMessage="BarId of progress bar (has to be higher than 0).")]
        [ValidateRange(1, [int]::MaxValue)]
        [Int32] $BarId,

        [Parameter(Mandatory=$true,
        HelpMessage="ParentId of progress bar (has to be higher than 0).")]
        [ValidateRange(1, [int]::MaxValue)]
        [Int32] $ParentId
    )

    $progCompleted = ($Index/$Max) * 100
    $progParameters = @{
        Id               = $BarId
        ParentId         = $ParentId
        Activity         = $ActivityName
        Status           = $ObjectName
        PercentComplete  = $progCompleted
    }
    Write-Progress @progParameters    

}

function Hide-ChildProgressBar {

    param (
        [Parameter(Mandatory=$true,
        HelpMessage="BarId of progress bar (has to be higher than 0).")]
        [ValidateRange(1, [int]::MaxValue)]
        [Int32] $BarId,

        [Parameter(Mandatory=$true,
        HelpMessage="ParentId of progress bar (has to be higher than 0).")]
        [ValidateRange(1, [int]::MaxValue)]
        [Int32] $ParentId
    )

    $progParameters = @{
        Id               = $BarId
        ParentId         = $ParentId
        Activity         = 'Nothing'
        Status           = 'Done'
    }
    Write-Progress @progParameters -Completed   
}
###################################################################

### Azure functions
function Get-Tenants() {
    [CmdletBinding()]
    param()

    begin {
        Write-Verbose -Message "Getting all visible tenants ..."
        # Reset loop to zero
        $loopTentIndex = 0
    }

    process {
        # Get all visible tenants
        $tenants = Get-AzTenant
        if ($tenants.Count -eq 0) {
            Write-Output -ForegroundColor Red "No tenants found, please check your permissions"
            exit
        }

        $tenants | ForEach-Object {
            $tenantItem = $_
            $loopTentIndex += 1
            # Show progress bar and write verbose message
            Show-RootProgressBar -Index $loopTentIndex -Max $tenants.Count -ActivityName "Tenants" -ObjectName "$($loopTentIndex) / $($tenants.Count) - $($tenantItem.DisplayName)"
            Write-Verbose -Message "Getting tenant $($tenantItem.DisplayName) ..."

            Set-PathsForTenant -TenantId $tenantItem.Id
            Test-PathsForTenant






            Save-DataForTenant
            Clear-DataForTenant
        }
    }

    end {
        Write-Verbose -Message "Finished getting all visible tenants ..."
        Hide-RootProgressBar
    }

}

###################################################################

### Support functions
function Test-Requirements() {

    [CmdletBinding()]
    param()

    Write-Verbose -Message "Checking requirements ..."

    # Check if PowerShell version is 5.1 or higher
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        Write-Verbose -Message "PowerShell version is lower than 7.4, actual version is $($PSVersionTable.PSVersion) ..."
        Write-Output -ForegroundColor Red "PowerShell version 7.4 or higher is required"
        exit
    }

    # Check if module is already installed
    if (-not (Get-Module -Name Az -ListAvailable)) {
        Write-Verbose -Message "Az module not found ..."
        Write-Output -ForegroundColor Red "Az module not found, please install it first"
        Write-Output -ForegroundColor Red "https://learn.microsoft.com/en-us/powershell/azure/new-azureps-module-az"
        exit
    }

    # Check if Az module is loaded
    if (-not (Get-Module -Name Az)) {
        Write-Verbose "Loading Az module ..."
        Import-Module Az
    }

    # Check if the connection was established
    if (-not (Get-AzContext)) {
        Write-Verbose -Message "No connection to Azure found ..."
        Write-Output -ForegroundColor Red "No connection to Azure found, please connect first"
        Write-Output -ForegroundColor Red "Connect-AzAccount"
        exit
    }
}

function Initialize-Variables() {

    [CmdletBinding()]
    param()

    begin {
        Write-Verbose -Message "Initializing variables ..."
    }

    process {
        # Some variables ...
        $script:processDetails = $Details # Request for details ...
        # Definition of lists for data ...
        # Just define them here, they will be filled inside functions
        [string[]]$script:dataInventory = @()
        [string[]]$script:dataDetails = @()
        $script:dataRoles = @()
        $script:dataIps = @()
        $script:dataUrls = @()
        $script:dataOSystems = @()
        $script:dataLanguages = @()
        # Define path to files ...
        # Just define them here, they will be filled inside functions
        $script:folderBase = Get-Location
        $script:folderDest = Join-Path -Path $script:folderBase -ChildPath $DestinationFolder
        $script:folderTenant = $null
        $script:folderSubscription = $null
        $script:fileInventory = $null
        $script:fileDetails = $null
        $script:fileRoles = $null
        $script:fileIps = $null
        $script:fileIpsScan = $null
        $script:fileUrls = $null
        $script:fileUrlsScan = $null
        $script:fileOSystems = $null
        $script:fileLanguages = $null
    }

    end {
        Write-Verbose -Message "Finished initializing variables ..."
    }
}

function Start-Scanning() {

    [CmdletBinding()]
    param()

    begin {
        Write-Verbose -Message "Starting scanning ..."
    }

    process {
        # Check if the destination folder exists
        if (-not (Test-Path -Path $script:folderDest)) {
            Write-Verbose -Message "Destination folder does not exist, creating it..."
            New-Item -Path $script:folderDest -ItemType Directory | Out-Null
        }

        # Get all tenants ...
        Get-Tenants -ErrorAction Stop

    }

    end {
        Write-Verbose -Message "Scan finished ..."
    }
}

function Set-PathsForTenant() {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,
        HelpMessage="Tenant ID.")]
        [ValidateNotNullOrEmpty()]
        [string]$TenantId
    )

    begin {
        Write-Verbose -Message "Setting paths for tenant $($TenantId) ..."
    }

    process {
        # Define path for files and folders
        $script:folderTenant = Join-Path -Path $script:folderDest -ChildPath "$($tenantId)"
        $script:folderSubscription = Join-Path -Path $script:folderTenant -ChildPath "subscriptions"
        $script:fileInventory = Join-Path -Path $script:folderTenant -ChildPath "inventory-tree.txt"
        $script:fileRoles = Join-Path -Path $script:folderTenant -ChildPath "roles.csv"
        $script:fileIps = Join-Path -Path $script:folderTenant -ChildPath "ips.csv"
        $script:fileIpsScan = Join-Path -Path $script:folderTenant -ChildPath "ipscan.txt"
        $script:fileUrls = Join-Path -Path $script:folderTenant -ChildPath "urlscan.csv"
        $script:fileUrlsScan = Join-Path -Path $script:folderTenant -ChildPath "urls.txt"
        $script:fileOSystems = Join-Path -Path $script:folderTenant -ChildPath "os.csv"
        $script:fileLanguages = Join-Path -Path $script:folderTenant -ChildPath "languages.csv"
    }

    end {
        Write-Verbose -Message "Finished setting paths for tenant ..."
    }
}

function Test-PathsForTenant() {

    [CmdletBinding()]
    param()

    begin {
        Write-Verbose -Message "Testing paths for tenant ..."
    }

    process {
        # Check if the tenant folder exists
        if (-not (Test-Path -Path $script:folderTenant)) {
            Write-Verbose -Message "Tenant folder does not exist, creating it..."
            New-Item -Path $script:folderTenant -ItemType Directory | Out-Null
        }

        # Check if the subscription folder exists
        if (-not (Test-Path -Path $script:folderSubscription)) {
            Write-Verbose -Message "Subscription folder does not exist, creating it..."
            New-Item -Path $script:folderSubscription -ItemType Directory | Out-Null
        }

        # Check if file for inventory exists
        if (-not (Test-Path -Path $script:fileInventory)) {
            Write-Verbose -Message "File for inventory does not exist, creating it..."
            New-Item -Path $script:fileInventory -ItemType File | Out-Null
        } else {
            Clear-Content -Path $script:fileInventory
        }

        # Check if file for roles exists
        if (-not (Test-Path -Path $script:fileRoles)) {
            Write-Verbose -Message "File for roles does not exist, creating it..."
            New-Item -Path $script:fileRoles -ItemType File | Out-Null
        } else {
            Clear-Content -Path $script:fileRoles
        }

        # Check if file for IPs exists
        if (-not (Test-Path -Path $script:fileIps)) {
            Write-Verbose -Message "File for IPs does not exist, creating it..."
            New-Item -Path $script:fileIps -ItemType File | Out-Null
        } else {
            Clear-Content -Path $script:fileIps
        }

        # Check if file for IPs scan exists
        if (-not (Test-Path -Path $script:fileIpsScan)) {
            Write-Verbose -Message "File for IPs scan does not exist, creating it..."
            New-Item -Path $script:fileIpsScan -ItemType File | Out-Null
        } else {
            Clear-Content -Path $script:fileIpsScan
        }

        # Check if file for URLs exists
        if (-not (Test-Path -Path $script:fileUrls)) {
            Write-Verbose -Message "File for URLs does not exist, creating it..."
            New-Item -Path $script:fileUrls -ItemType File | Out-Null
        } else {
            Clear-Content -Path $script:fileUrls
        }

        # Check if file for URLs scan exists
        if (-not (Test-Path -Path $script:fileUrlsScan)) {
            Write-Verbose -Message "File for URLs scan does not exist, creating it..."
            New-Item -Path $script:fileUrlsScan -ItemType File | Out-Null
        } else {
            Clear-Content -Path $script:fileUrlsScan
        }

        # Check if file for OS exists
        if (-not (Test-Path -Path $script:fileOSystems)) {
            Write-Verbose -Message "File for OS does not exist, creating it..."
            New-Item -Path $script:fileOSystems -ItemType File | Out-Null
        } else {
            Clear-Content -Path $script:fileOSystems
        }

        # Check if file for languages exists
        if (-not (Test-Path -Path $script:fileLanguages)) {
            Write-Verbose -Message "File for languages does not exist, creating it..."
            New-Item -Path $script:fileLanguages -ItemType File | Out-Null
        } else {
            Clear-Content -Path $script:fileLanguages
        }
    }

    end {
        Write-Verbose -Message "Finished testing paths for tenant ..."
    }
}

function Save-DataForTenant() {

    [CmdletBinding()]
    param()
    
    begin {
        Write-Verbose -Message "Saving data for tenant ..."
    }

    process {
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

    }

    end {
        Write-Verbose -Message "Finished saving data for tenant ..."
    }

}

function Clear-DataForTenant() {

    [CmdletBinding()]
    param()

    begin {
        Write-Verbose -Message "Clearing data for tenant ..."
    }

    process {
        # Clear all data for tenant
        $script:dataInventory = @()
        $script:dataDetails = @()
        $script:dataRoles = @()
        $script:dataIps = @()
        $script:dataUrls = @()
        $script:dataOSystems = @()
        $script:dataLanguages = @()
        # Clear path for files and folders
        $script:folderTenant = $null
        $script:folderSubscription = $null
        $script:fileInventory = $null
        $script:fileDetails = $null
        $script:fileRoles = $null
        $script:fileIps = $null
        $script:fileIpsScan = $null
        $script:fileUrls = $null
        $script:fileUrlsScan = $null
        $script:fileOSystems = $null
        $script:fileLanguages = $null
    }

    end {
        Write-Verbose -Message "Finished clearing data for tenant ..."
    }
}

function Compress-Results() {

    [CmdletBinding()]
    param()

    begin {
        Write-Verbose -Message "Compressing results ..."
    }

    process {
        # Compress results
        if ($CompressArchive) {
            $zipFile = Join-Path -Path $script:folderBase -ChildPath "$($DestinationFolder).zip"
            if (Test-Path -Path $zipFile) {
                Remove-Item -Path $zipFile
            }
            Compress-Archive -Path $script:folderDest -DestinationPath $zipFile
        }
    }

    end {
        Write-Verbose -Message "Finished compressing results ..."
    }
}
###################################################################

###################################################################

# Get actual date and time ...
$timeStart = Get-Date

Write-Output "***********************************************************"
Write-Output "*********** Azure Inventory Script ************************"
Write-Output "*********** Author: David Burel (@dafneb) *****************"

Test-Requirements
Initialize-Variables
Start-Scanning
Compress-Results

# Get actual date and time ...
$timeEnd = Get-Date

# Printout date&times ...
Write-Output "***********************************************************"
Write-Output "Started: $($timeStart)"
Write-Output "Finished: $($timeEnd)"
Write-Output "Elapsed time: $($timeEnd - $timeStart)"

###################################################################
