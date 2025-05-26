# This content is part of the MS Learn documentation, I just copy it here for my own reference.
# https://learn.microsoft.com/en-us/powershell/module/az.accounts/connect-azaccount?view=azps-13.3.0#examples

# Login to Azure with concrete TenantId & SubscriptionId ...
Connect-AzAccount -Tenant 'xxxx-xxxx-xxxx-xxxx' -SubscriptionId 'yyyy-yyyy-yyyy-yyyy'

# Login to Azure from Cloud Shell (Azure Portal) ...
Connect-AzAccount -UseDeviceAuthentication

# Login to Azure with credential (username and password) ...
$Credential = Get-Credential
Connect-AzAccount -Credential $Credential

# Login to Azure with a Service Principal (SP) using a certificate's thumbprint ...
$Thumbprint = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
$TenantId = 'yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyy'
$ApplicationId = '00000000-0000-0000-0000-00000000'
Connect-AzAccount -CertificateThumbprint $Thumbprint -ApplicationId $ApplicationId -Tenant $TenantId -ServicePrincipal

# Login to Azure with a Service Principal (SP) using a secret ...
$SecurePassword = Read-Host -Prompt 'Enter a Password' -AsSecureString
$TenantId = 'yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyy'
$ApplicationId = 'zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzz'
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ApplicationId, $SecurePassword
Connect-AzAccount -ServicePrincipal -TenantId $TenantId -Credential $Credential

#----------------------------------------------------------------

# Login to with Microsoft Graph ...
$TenantId = 'yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyy'
Connect-MgGraph -TenantId $TenantId -Scopes 'User.Read.All', 'Group.Read.All', 'Directory.Read.All', 'AuditLog.Read.All', 'GroupMember.Read.All', 'Sites.Read.All'

$TenantId = 'yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyy'
Connect-MgGraph -TenantId $TenantId -Scopes 'User.Read.All', 'Group.Read.All', 'Directory.Read.All', 'AuditLog.Read.All', 'GroupMember.Read.All', 'Sites.Read.All', 'Application.Read.All' -UseDeviceAuthentication

Connect-MgGraph -Scopes 'User.Read.All', 'Group.Read.All', 'Directory.Read.All', 'AuditLog.Read.All', 'GroupMember.Read.All', 'Sites.Read.All', 'Application.Read.All' -UseDeviceAuthentication
