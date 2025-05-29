# Define the script's parameters
[CmdletBinding(DefaultParameterSetName = "Default")]
param (
    [Parameter(Mandatory = $true, ParameterSetName = "Default")]
    [ValidateNotNullOrEmpty()]
    [string]$CaseName

)

& ./Auditing/Resources/PowerShell/get-inventory.ps1 -CaseName $CaseName
& ./Auditing/Resources/PowerShell/get-roleassignment.ps1 -CaseName $CaseName
& ./Auditing/Resources/PowerShell/get-networktraffic.ps1 -CaseName $CaseName
