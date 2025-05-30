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
Write-Output "*********** Applications at Entra Id **********************"
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
$detailsFilePath = Join-Path -Path $caseFolderPath -ChildPath "applications-details.txt"
$applicationsFilePath = Join-Path -Path $caseFolderPath -ChildPath "applications.csv"
$appTokensFilePath = Join-Path -Path $caseFolderPath -ChildPath "applications-tokens.csv"


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

# Check if the applications file already exists
if (-not (Test-Path -Path $applicationsFilePath)) {
    Write-Verbose -Message "Applications file does not exist, creating it..."
    New-Item -ItemType File -Path $applicationsFilePath | Out-Null
} else {
    Write-Verbose -Message "Applications file already exists, clear it..."
    Clear-Content -Path $applicationsFilePath | Out-Null
}

# Chekc if access token file already exists
if (-not (Test-Path -Path $appTokensFilePath)) {
    Write-Verbose -Message "Applications file does not exist, creating it..."
    New-Item -ItemType File -Path $appTokensFilePath | Out-Null
} else {
    Write-Verbose -Message "Applications file already exists, clear it..."
    Clear-Content -Path $appTokensFilePath | Out-Null
}

# Check if the applications details file already exists
if (-not (Test-Path -Path $detailsFilePath)) {
    Write-Verbose -Message "Details file does not exist, creating it..."
    New-Item -ItemType File -Path $detailsFilePath | Out-Null
} else {
    Write-Verbose -Message "Details file already exists, clear it..."
    Clear-Content -Path $detailsFilePath | Out-Null
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
$dataApps = @()
$dataTokens = @()
[string[]]$dataDetails = @()

# Get list of all applications ...
$apps = Get-MgApplication -All
# Loop through each app and get its details
$apps | ForEach-Object {
    $appka = $_
    Write-Verbose -Message "Processing applications: $($appka.DisplayName)"

    # TODO: Add code here to get groups and their details
    "--- Application ---" | Out-File -FilePath $detailsFilePath -Append
    $appka | Format-List | Out-File -FilePath $detailsFilePath -Append
    "--- Application.OptionalClaims ---" | Out-File -FilePath $detailsFilePath -Append
    $appka.OptionalClaims | Format-List | Out-File -FilePath $detailsFilePath -Append
    "--- Application.AuthenticationBehaviors ---" | Out-File -FilePath $detailsFilePath -Append
    $appka.AuthenticationBehaviors | Format-List | Out-File -FilePath $detailsFilePath -Append
    "--- Application.Web ---" | Out-File -FilePath $detailsFilePath -Append
    $appka.Web | Format-List | Out-File -FilePath $detailsFilePath -Append
    "--- Application.Web.ImplicitGrantSettings ---" | Out-File -FilePath $detailsFilePath -Append
    $appka.Web.ImplicitGrantSettings | Format-List | Out-File -FilePath $detailsFilePath -Append
    "------------------------------------------------------" | Out-File -FilePath $detailsFilePath -Append

}

$dataApps | Export-Csv -Path $applicationsFilePath -NoTypeInformation -Force
$dataTokens | Export-Csv -Path $appTokensFilePath -NoTypeInformation -Force
$dataDetails | ForEach-Object { $_ | Out-File -FilePath $detailsFilePath -Append }

# Get actual date and time ...
$timeEnd = Get-Date

# Printout date&times ...
Write-Output "***********************************************************"
Write-Output "Started: $($timeStart)"
Write-Output "Finished: $($timeEnd)"
Write-Output "Elapsed time: $($timeEnd - $timeStart)"
