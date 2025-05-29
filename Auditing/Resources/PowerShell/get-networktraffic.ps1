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
Write-Output "*********** Traffic at Azure ******************************"
Write-Output "*********** Author: David Burel (@dafneb) *****************"
Write-Output "***********************************************************"

Write-Verbose -Message "Checking requirements ..."

# Check if PowerShell version is 7.4 or higher
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Verbose -Message "PowerShell version is lower than 7.4, actual version is $($PSVersionTable.PSVersion) ..."
    Write-Warning -Message "PowerShell version 7.4 or higher is required"
    exit
}

# Check if module is already installed
if (-not (Get-Module -Name Az -ListAvailable)) {
    Write-Warning -Message "Az module not found, please install it first"
    exit
}

# Check if Az module is loaded
if (-not (Get-Module -Name Az)) {
    Write-Verbose -Message "Loading Az module ..."
    Import-Module Az -ErrorAction Stop
}

# Check if I am connected to Azure
if (-not (Get-AzContext)) {
    Write-Warning -Message "Not connected to Azure, please connect first"
    exit
}

# Normalize case name to lowercase
$caseFolderName = $CaseName.ToLower()
$caseFolderName = $caseFolderName.Trim()
$caseFolderName = $caseFolderName -replace '[\\/:*?"<>|]', '_'

# Paths for logs
$baseFolderPath = Join-Path -Path (Get-Location) -ChildPath "case"
$caseFolderPath = Join-Path -Path $baseFolderPath -ChildPath "$($caseFolderName)"
$trafficFilePath = Join-Path -Path $caseFolderPath -ChildPath "network-traffic.csv"

Write-Verbose -Message "Checking folders (1/2) ..."

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

# Check if the inventory file already exists
if (-not (Test-Path -Path $trafficFilePath)) {
    Write-Verbose -Message "Traffic file does not exist, creating it..."
    New-Item -ItemType File -Path $trafficFilePath | Out-Null
} else {
    Write-Verbose -Message "Traffic file already exists, clear it..."
    Clear-Content -Path $trafficFilePath | Out-Null
}

Write-Verbose -Message "Listing traffic data from Azure ..."

$dataTraffic = @()
$days = 30 # Define the number of days for which to retrieve traffic data
$endTime = Get-Date -Date "2025-05-20T00:00:00"
$startTime = $endTime.AddDays(-$days) # Adjust the time range as needed

$tenants = Get-AzTenant -ErrorAction SilentlyContinue
if (-not $tenants) {
    Write-Warning -Message "No tenants found, please check your connection"
}
$tenants | ForEach-Object {
    $tenantId = $_.Id
    $tenantName = $_.Name
    Write-Verbose -Message "Processing tenant: $tenantName ($tenantId)"

    # Get all subscriptions for the tenant
    $subscriptions = Get-AzSubscription -TenantId $tenantId -ErrorAction SilentlyContinue
    if (-not $subscriptions) {
        Write-Warning -Message "No subscriptions found for tenant $tenantName ($tenantId)"
    }
    $subscriptions | ForEach-Object {
        $subscriptionId = $_.Id
        $subscriptionName = $_.Name
        Write-Verbose -Message "Processing subscription: $subscriptionName ($subscriptionId)"
        Set-AzContext -SubscriptionId $subscriptionId -TenantId $tenantId -ErrorAction SilentlyContinue | Out-Null
        if (-not (Get-AzContext)) {
            Write-Warning -Message "Failed to set context for subscription $subscriptionName ($subscriptionId)"
            continue
        }

        $resourceGroups = Get-AzResourceGroup -ErrorAction SilentlyContinue
        if (-not $resourceGroups) {
            Write-Warning -Message "No resource groups found for subscription $subscriptionName ($subscriptionId)"
        }
        $resourceGroups | ForEach-Object {
            $resGroup = $_
            Write-Verbose -Message "Processing resource group: $($resGroup.ResourceGroupName)"

            # Get network traffic data for Web Apps
            $webApps = Get-AzWebApp -ResourceGroupName $resGroup.ResourceGroupName -ProgressAction Ignore -ErrorAction SilentlyContinue
            $webApps | ForEach-Object {
                $webApp = $_
                
                $metricIn = Get-AzMetric -ResourceId $webApp.Id -MetricName "BytesReceived" -TimeGrain 01:00:00:00 -StartTime $startTime -EndTime $endTime -ErrorAction SilentlyContinue
                if ($metricIn.Data.Count -gt 0) {
                    $trafficDataIn = @{
                        TenantId = $tenantId
                        TenantName = $tenantName
                        SubscriptionId = $subscriptionId
                        SubscriptionName = $subscriptionName
                        ResourceId = $webApp.Id
                        ResourceType = $webApp.Type
                        ResourceGroup = $resGroup.ResourceGroupName
                        Location = $webApp.Location
                        Kind = $webApp.Kind
                        ResourceName = $webApp.Name
                        Direction = "Inbound"
                    }
                    $amountInTotal = 0
                    $metricIn.Data | ForEach-Object {
                        #$indexIn = $_.TimeStamp.ToString("yyyy-MM-ddTHH:mm:ssZ")
                        $amountIn = $_.Total / 1GB # Convert bytes to GB
                        #$trafficDataIn[$indexIn] = "{0:N8}" -f $amountIn
                        $amountInTotal += $amountIn
                    }
                    $trafficDataIn["TotalAmounts"] = "{0:N8}" -f $amountInTotal
                    $dataTraffic += [PSCustomObject]$trafficDataIn
                }

                $metricOut = Get-AzMetric -ResourceId $webApp.Id -MetricName "BytesSent" -TimeGrain 01:00:00:00 -StartTime $startTime -EndTime $endTime -ErrorAction SilentlyContinue
                if ($metricOut.Data.Count -gt 0) {
                    $trafficDataOut = @{
                        TenantId = $tenantId
                        TenantName = $tenantName
                        SubscriptionId = $subscriptionId
                        SubscriptionName = $subscriptionName
                        ResourceId = $webApp.Id
                        ResourceType = $webApp.Type
                        ResourceGroup = $resGroup.ResourceGroupName
                        Location = $webApp.Location
                        Kind = $webApp.Kind
                        ResourceName = $webApp.Name
                        Direction = "Outbound"
                    }
                    $amountOutTotal = 0
                    $metricOut.Data | ForEach-Object {
                        #$indexOut = $_.TimeStamp.ToString("yyyy-MM-ddTHH:mm:ssZ")
                        $amountOut = $_.Total / 1GB # Convert bytes to GB
                        #$trafficDataOut[$indexOut] = "{0:N8}" -f $amountOut  
                        $amountOutTotal += $amountOut
                    }
                    $trafficDataOut["TotalAmounts"] = "{0:N8}" -f $amountOutTotal
                    $dataTraffic += [PSCustomObject]$trafficDataOut
                }
            }

            # Get network traffic data for Application Gateways
            $appGateways = Get-AzApplicationGateway -ResourceGroupName $resGroup.ResourceGroupName -ProgressAction Ignore -ErrorAction SilentlyContinue
            $appGateways | ForEach-Object {
                $appGateway = $_

                $metricIn = Get-AzMetric -ResourceId $appGateway.Id -MetricName "BytesReceived" -TimeGrain 01:00:00:00 -StartTime $startTime -EndTime $endTime #-ErrorAction SilentlyContinue
                if ($metricIn.Data.Count -gt 0) {
                    $trafficDataIn = @{
                        TenantId = $tenantId
                        TenantName = $tenantName
                        SubscriptionId = $subscriptionId
                        SubscriptionName = $subscriptionName
                        ResourceId = $appGateway.Id
                        ResourceType = $appGateway.Type
                        ResourceGroup = $resGroup.ResourceGroupName
                        Location = $appGateway.Location
                        Kind = $appGateway.Kind
                        ResourceName = $appGateway.Name
                        Direction = "Inbound"
                    }
                    $amountInTotal = 0
                    $metricIn.Data | ForEach-Object {
                        #$indexIn = $_.TimeStamp.ToString("yyyy-MM-ddTHH:mm:ssZ")
                        $amountIn = $_.Total / 1GB # Convert bytes to GB
                        #$trafficDataIn[$indexIn] = "{0:N8}" -f $amountIn
                        $amountInTotal += $amountIn
                    }
                    $trafficDataIn["TotalAmounts"] = "{0:N8}" -f $amountInTotal
                    $dataTraffic += [PSCustomObject]$trafficDataIn
                }

                $metricOut = Get-AzMetric -ResourceId $appGateway.Id -MetricName "BytesSent" -TimeGrain 01:00:00:00 -StartTime $startTime -EndTime $endTime #-ErrorAction SilentlyContinue
                if ($metricOut.Data.Count -gt 0) {
                    $trafficDataOut = @{
                        TenantId = $tenantId
                        TenantName = $tenantName
                        SubscriptionId = $subscriptionId
                        SubscriptionName = $subscriptionName
                        ResourceId = $appGateway.Id
                        ResourceType = $appGateway.Type
                        ResourceGroup = $resGroup.ResourceGroupName
                        Location = $appGateway.Location
                        Kind = $appGateway.Kind
                        ResourceName = $appGateway.Name
                        Direction = "Outbound"
                    }
                    $amountOutTotal = 0
                    $metricOut.Data | ForEach-Object {
                        #$indexIn = $_.TimeStamp.ToString("yyyy-MM-ddTHH:mm:ssZ")
                        $amountOut = $_.Total / 1GB # Convert bytes to GB
                        #$trafficDataIn[$indexIn] = "{0:N8}" -f $amountIn
                        $amountOutTotal += $amountOut
                    }
                    $trafficDataOut["TotalAmounts"] = "{0:N8}" -f $amountOutTotal
                    $dataTraffic += [PSCustomObject]$trafficDataOut
                }
            }

            # Get network traffic data for Virtual Network Gateways
            $virtualGateways = Get-AzVirtualNetworkGateway -ResourceGroupName $resGroup.ResourceGroupName -ProgressAction Ignore -ErrorAction SilentlyContinue
            $virtualGateways | ForEach-Object {
                $vpnGateway = $_

                $metricIn = Get-AzMetric -ResourceId $vpnGateway.Id -MetricName "TunnelIngressBytes" -TimeGrain 01:00:00:00 -StartTime $startTime -EndTime $endTime #-ErrorAction SilentlyContinue
                if ($metricIn.Data.Count -gt 0) {
                    $trafficDataIn = @{
                        TenantId = $tenantId
                        TenantName = $tenantName
                        SubscriptionId = $subscriptionId
                        SubscriptionName = $subscriptionName
                        ResourceId = $vpnGateway.Id
                        ResourceType = $vpnGateway.Type
                        ResourceGroup = $resGroup.ResourceGroupName
                        Location = $vpnGateway.Location
                        Kind = "tunnel" # VPN Gateways are typically of kind "Tunnel"
                        ResourceName = $vpnGateway.Name
                        Direction = "Inbound"
                    }
                    $amountInTotal = 0
                    $metricIn.Data | ForEach-Object {
                        #$indexIn = $_.TimeStamp.ToString("yyyy-MM-ddTHH:mm:ssZ")
                        $amountIn = $_.Total / 1GB # Convert bytes to GB
                        #$trafficDataIn[$indexIn] = "{0:N8}" -f $amountIn
                        $amountInTotal += $amountIn
                    }
                    $trafficDataIn["TotalAmounts"] = "{0:N8}" -f $amountInTotal
                    $dataTraffic += [PSCustomObject]$trafficDataIn
                }

                $metricOut = Get-AzMetric -ResourceId $vpnGateway.Id -MetricName "TunnelEgressBytes" -TimeGrain 01:00:00:00 -StartTime $startTime -EndTime $endTime #-ErrorAction SilentlyContinue
                if ($metricOut.Data.Count -gt 0) {
                    $trafficDataOut = @{
                        TenantId = $tenantId
                        TenantName = $tenantName
                        SubscriptionId = $subscriptionId
                        SubscriptionName = $subscriptionName
                        ResourceId = $vpnGateway.Id
                        ResourceType = $vpnGateway.Type
                        ResourceGroup = $resGroup.ResourceGroupName
                        Location = $vpnGateway.Location
                        Kind = "tunnel" # VPN Gateways are typically of kind "Tunnel"
                        ResourceName = $vpnGateway.Name
                        Direction = "Outbound"
                    }
                    $amountOutTotal = 0
                    $metricOut.Data | ForEach-Object {
                        #$indexIn = $_.TimeStamp.ToString("yyyy-MM-ddTHH:mm:ssZ")
                        $amountOut = $_.Total / 1GB # Convert bytes to GB
                        #$trafficDataIn[$indexIn] = "{0:N8}" -f $amountIn
                        $amountOutTotal += $amountOut
                    }
                    $trafficDataOut["TotalAmounts"] = "{0:N8}" -f $amountOutTotal
                    $dataTraffic += [PSCustomObject]$trafficDataOut
                }

                $metricNat = Get-AzMetric -ResourceId $vpnGateway.Id -MetricName "TunnelNatedBytes" -TimeGrain 01:00:00:00 -StartTime $startTime -EndTime $endTime #-ErrorAction SilentlyContinue
                if ($metricNat.Data.Count -gt 0) {
                    $trafficDataNat = @{
                        TenantId = $tenantId
                        TenantName = $tenantName
                        SubscriptionId = $subscriptionId
                        SubscriptionName = $subscriptionName
                        ResourceId = $vpnGateway.Id
                        ResourceType = $vpnGateway.Type
                        ResourceGroup = $resGroup.ResourceGroupName
                        Location = $vpnGateway.Location
                        Kind = "nat" # VPN Gateways are typically of kind "Tunnel"
                        ResourceName = $vpnGateway.Name
                        Direction = "Nated"
                    }
                    $amountNatTotal = 0
                    $metricNat.Data | ForEach-Object {
                        #$indexIn = $_.TimeStamp.ToString("yyyy-MM-ddTHH:mm:ssZ")
                        $amountNat = $_.Total / 1GB # Convert bytes to GB
                        #$trafficDataIn[$indexIn] = "{0:N8}" -f $amountIn
                        $amountNatTotal += $amountNat
                    }
                    $trafficDataNat["TotalAmounts"] = "{0:N8}" -f $amountNatTotal
                    $dataTraffic += [PSCustomObject]$trafficDataNat
                }

            }

            # Get network traffic data for NAT Gateways
            $natGateways = Get-AzNatGateway -ResourceGroupName $resGroup.ResourceGroupName -ProgressAction Ignore -ErrorAction SilentlyContinue
            $natGateways | ForEach-Object {
                $natGateway = $_

                $metricNat = Get-AzMetric -ResourceId $natGateway.Id -MetricName "ByteCount" -TimeGrain 01:00:00:00 -StartTime $startTime -EndTime $endTime #-ErrorAction SilentlyContinue
                if ($metricNat.Data.Count -gt 0) {
                    $trafficDataNat = @{
                        TenantId = $tenantId
                        TenantName = $tenantName
                        SubscriptionId = $subscriptionId
                        SubscriptionName = $subscriptionName
                        ResourceId = $natGateway.Id
                        ResourceType = $natGateway.Type
                        ResourceGroup = $resGroup.ResourceGroupName
                        Location = $natGateway.Location
                        Kind = "nat"
                        ResourceName = $natGateway.Name
                        Direction = "Nated"
                    }
                    $amountNatTotal = 0
                    $metricNat.Data | ForEach-Object {
                        #$indexIn = $_.TimeStamp.ToString("yyyy-MM-ddTHH:mm:ssZ")
                        $amountNat = $_.Total / 1GB # Convert bytes to GB
                        #$trafficDataIn[$indexIn] = "{0:N8}" -f $amountIn
                        $amountNatTotal += $amountNat
                    }
                    $trafficDataNat["TotalAmounts"] = "{0:N8}" -f $amountNatTotal
                    $dataTraffic += [PSCustomObject]$trafficDataNat
                }

            }

        }

        # Get network traffic data for VPN Gateways
        $vpnGateways = Get-AzVpnGateway -ProgressAction Ignore -ErrorAction SilentlyContinue
        $vpnGateways | ForEach-Object {
            $vpnGateway = $_

            $metricIn = Get-AzMetric -ResourceId $vpnGateway.Id -MetricName "TunnelIngressBytes" -TimeGrain 01:00:00:00 -StartTime $startTime -EndTime $endTime #-ErrorAction SilentlyContinue
            if ($metricIn.Data.Count -gt 0) {
                $trafficDataIn = @{
                    TenantId = $tenantId
                    TenantName = $tenantName
                    SubscriptionId = $subscriptionId
                    SubscriptionName = $subscriptionName
                    ResourceId = $vpnGateway.Id
                    ResourceType = $vpnGateway.Type
                    ResourceGroup = $vpnGateway.ResourceGroup
                    Location = $vpnGateway.Location
                    Kind = "tunnel" # VPN Gateways are typically of kind "Tunnel"
                    ResourceName = $vpnGateway.Name
                    Direction = "Inbound"
                }
                $amountInTotal = 0
                $metricIn.Data | ForEach-Object {
                    #$indexIn = $_.TimeStamp.ToString("yyyy-MM-ddTHH:mm:ssZ")
                    $amountIn = $_.Total / 1GB # Convert bytes to GB
                    #$trafficDataIn[$indexIn] = "{0:N8}" -f $amountIn
                    $amountInTotal += $amountIn
                }
                $trafficDataIn["TotalAmounts"] = "{0:N8}" -f $amountInTotal
                $dataTraffic += [PSCustomObject]$trafficDataIn
            }

            $metricOut = Get-AzMetric -ResourceId $vpnGateway.Id -MetricName "TunnelEgressBytes" -TimeGrain 01:00:00:00 -StartTime $startTime -EndTime $endTime #-ErrorAction SilentlyContinue
            if ($metricOut.Data.Count -gt 0) {
                $trafficDataOut = @{
                    TenantId = $tenantId
                    TenantName = $tenantName
                    SubscriptionId = $subscriptionId
                    SubscriptionName = $subscriptionName
                    ResourceId = $vpnGateway.Id
                    ResourceType = $vpnGateway.Type
                    ResourceGroup = $vpnGateway.ResourceGroup
                    Location = $vpnGateway.Location
                    Kind = "tunnel" # VPN Gateways are typically of kind "Tunnel"
                    ResourceName = $vpnGateway.Name
                    Direction = "Outbound"
                }
                $amountOutTotal = 0
                $metricOut.Data | ForEach-Object {
                    #$indexIn = $_.TimeStamp.ToString("yyyy-MM-ddTHH:mm:ssZ")
                    $amountOut = $_.Total / 1GB # Convert bytes to GB
                    #$trafficDataIn[$indexIn] = "{0:N8}" -f $amountIn
                    $amountOutTotal += $amountOut
                }
                $trafficDataOut["TotalAmounts"] = "{0:N8}" -f $amountOutTotal
                $dataTraffic += [PSCustomObject]$trafficDataOut
            }

            $metricNat = Get-AzMetric -ResourceId $vpnGateway.Id -MetricName "TunnelNatedBytes" -TimeGrain 01:00:00:00 -StartTime $startTime -EndTime $endTime #-ErrorAction SilentlyContinue
            if ($metricNat.Data.Count -gt 0) {
                $trafficDataNat = @{
                    TenantId = $tenantId
                    TenantName = $tenantName
                    SubscriptionId = $subscriptionId
                    SubscriptionName = $subscriptionName
                    ResourceId = $vpnGateway.Id
                    ResourceType = $vpnGateway.Type
                    ResourceGroup = $vpnGateway.ResourceGroup
                    Location = $vpnGateway.Location
                    Kind = "nat" # VPN Gateways are typically of kind "Tunnel"
                    ResourceName = $vpnGateway.Name
                    Direction = "Nated"
                }
                $amountNatTotal = 0
                $metricNat.Data | ForEach-Object {
                    #$indexIn = $_.TimeStamp.ToString("yyyy-MM-ddTHH:mm:ssZ")
                    $amountNat = $_.Total / 1GB # Convert bytes to GB
                    #$trafficDataIn[$indexIn] = "{0:N8}" -f $amountIn
                    $amountNatTotal += $amountNat
                }
                $trafficDataNat["TotalAmounts"] = "{0:N8}" -f $amountNatTotal
                $dataTraffic += [PSCustomObject]$trafficDataNat
            }

        }

    }
}

$dataTraffic | Export-Csv -Path $trafficFilePath -NoTypeInformation -Encoding UTF8 -Force

# Get actual date and time ...
$timeEnd = Get-Date

# Printout date&times ...
Write-Output "***********************************************************"
Write-Output "Started: $($timeStart)"
Write-Output "Finished: $($timeEnd)"
Write-Output "Elapsed time: $($timeEnd - $timeStart)"
