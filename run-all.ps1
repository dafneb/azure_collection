& ./Auditing/Resources/PowerShell/get-inventory.ps1 -CaseName "adastra"
& ./Auditing/Resources/PowerShell/get-roleassignment.ps1 -CaseName "adastra"
& ./Auditing/EntraID/PowerShell/get-entrausers.ps1 -CaseName "adastra" -AllDetails -InactiveDays 90
& ./Auditing/EntraID/PowerShell/get-entragroups.ps1 -CaseName "adastra"
& ./Auditing/EntraID/PowerShell/get-applications.ps1 -CaseName "adastra"
