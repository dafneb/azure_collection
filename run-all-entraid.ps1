# Define the script's parameters
[CmdletBinding(DefaultParameterSetName = "Default")]
param (
    [Parameter(Mandatory = $true, ParameterSetName = "Default")]
    [ValidateNotNullOrEmpty()]
    [string]$CaseName

)

& ./Auditing/EntraID/PowerShell/get-entrausers.ps1 -CaseName $CaseName -AllDetails
& ./Auditing/EntraID/PowerShell/get-entragroups.ps1 -CaseName $CaseName
& ./Auditing/EntraID/PowerShell/get-applications.ps1 -CaseName $CaseName
