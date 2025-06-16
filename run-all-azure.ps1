# Define the script's parameters
[CmdletBinding(DefaultParameterSetName = "Default")]
param (
    [Parameter(Mandatory = $true, ParameterSetName = "Default")]
    [ValidateNotNullOrEmpty()]
    [string]$CaseName

)

& ./Auditing/Resources/PowerShell/get-inventory.ps1 -CaseName $CaseName
& ./Auditing/Resources/PowerShell/get-roleassignment.ps1 -CaseName $CaseName
& ./Auditing/Resources/PowerShell/get-networktraffic.ps1 -CaseName $CaseName #-EndTime (Get-Date -Date "2025-05-20T00:00:00") -StartTime (Get-Date -Date "2025-05-20T00:00:00").AddDays(-30)
& ./Auditing/Resources/PowerShell/get-activitylogs.ps1 -CaseName $CaseName #-EndTime (Get-Date -Date "2025-05-20T00:00:00") -StartTime (Get-Date -Date "2025-05-20T00:00:00").AddDays(-30)
