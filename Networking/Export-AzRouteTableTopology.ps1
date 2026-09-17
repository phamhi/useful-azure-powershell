<#
.SYNOPSIS
    Audits Azure Route Tables (UDRs), route hops, blackholed prefixes, and subnet associations.

.DESCRIPTION
    Maps and evaluates User Defined Routes (UDRs) across virtual networks in target subscriptions:
      1. Inspects all Route Tables and their individual route entries.
      2. Validates Next Hop types (VirtualAppliance, VirtualNetworkGateway, VnetLocal, Internet, None).
      3. Identifies Blackholed routes (Next Hop = None) where traffic is silently dropped.
      4. Detects presence or absence of default 0.0.0.0/0 egress routes (NVA/Firewall vs default Azure Internet).
      5. Checks subnet associations, identifying orphaned route tables not bound to any subnet.
      6. Formats an architectural route topology report with CSV export support.

.PARAMETER SubscriptionIds
    Array of Subscription IDs to evaluate. Defaults to all active subscriptions.

.PARAMETER ExportCsvPath
    File path to save the route table audit.

.EXAMPLE
    .\Export-AzRouteTableTopology.ps1 -ExportCsvPath "C:\Reports\AzureUDRTopology.csv"
    Audits all route tables across all subscriptions and exports findings to CSV.

.NOTES
    Required Modules: Az.Accounts, Az.Network
    Permissions: Microsoft.Network/routeTables/read across target scopes.
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
    [string[]]$SubscriptionIds,

    [Parameter(Mandatory = $false)]
    [string]$ExportCsvPath
)

process {
    $context = Get-AzContext
    if (-not $context) {
        throw "No active Azure context. Connect with 'Connect-AzAccount'."
    }

    if ($SubscriptionIds -and $SubscriptionIds.Count -gt 0) {
        $subs = Get-AzSubscription | Where-Object { $SubscriptionIds -contains $_.Id }
    } else {
        $subs = Get-AzSubscription | Where-Object { $_.State -eq 'Enabled' }
    }

    $routeReport = [System.Collections.Generic.List[PSCustomObject]]::new()
    Write-Host "Auditing Route Tables across $($subs.Count) subscription(s)..." -ForegroundColor Cyan

    foreach ($sub in $subs) {
        Set-AzContext -SubscriptionId $sub.Id -ErrorAction SilentlyContinue | Out-Null
        $routeTables = Get-AzRouteTable -ErrorAction SilentlyContinue

        foreach ($rt in $routeTables) {
            $associatedSubnets = if ($rt.Subnets) {
                ($rt.Subnets | ForEach-Object { ($_.Id -split '/')[-3] + '/' + ($_.Id -split '/')[-1] }) -join '; '
            } else {
                'None (Orphaned)'
            }

            $isOrphaned = [string]::IsNullOrEmpty($rt.Subnets) -or $rt.Subnets.Count -eq 0

            # Check routes
            if ($rt.Routes -and $rt.Routes.Count -gt 0) {
                foreach ($r in $rt.Routes) {
                    $isBlackhole = $r.NextHopType -eq 'None'
                    $isDefaultInternetRoute = $r.AddressPrefix -eq '0.0.0.0/0'

                    $notes = [System.Collections.Generic.List[string]]::new()
                    if ($isBlackhole) { $notes.Add("Traffic Blackholed (Next Hop = None)") }
                    if ($isDefaultInternetRoute) { $notes.Add("Default Route (0.0.0.0/0 -> $($r.NextHopType))") }
                    if ($isOrphaned) { $notes.Add("Route table unattached to any subnet") }

                    $routeReport.Add([PSCustomObject]@{
                        SubscriptionId      = $sub.Id
                        ResourceGroup       = $rt.ResourceGroupName
                        RouteTableName      = $rt.Name
                        RouteName           = $r.Name
                        AddressPrefix       = $r.AddressPrefix
                        NextHopType         = $r.NextHopType
                        NextHopIpAddress    = if ($r.NextHopIpAddress) { $r.NextHopIpAddress } else { 'N/A' }
                        DisableBgpRouteProp = $rt.DisableBgpRoutePropagation
                        AssociatedSubnets   = $associatedSubnets
                        StatusFlags         = if ($notes.Count -gt 0) { ($notes -join '; ') } else { 'Standard' }
                    })
                }
            } else {
                # Empty route table
                $routeReport.Add([PSCustomObject]@{
                    SubscriptionId      = $sub.Id
                    ResourceGroup       = $rt.ResourceGroupName
                    RouteTableName      = $rt.Name
                    RouteName           = 'None (Empty Table)'
                    AddressPrefix       = 'N/A'
                    NextHopType         = 'N/A'
                    NextHopIpAddress    = 'N/A'
                    DisableBgpRouteProp = $rt.DisableBgpRoutePropagation
                    AssociatedSubnets   = $associatedSubnets
                    StatusFlags         = 'Empty Route Table (No routes defined)'
                })
            }
        }
    }

    Write-Host "`nRoute Table audit complete ($($routeReport.Count) routes cataloged)." -ForegroundColor Green
    $routeReport | Select-Object RouteTableName, RouteName, AddressPrefix, NextHopType, NextHopIpAddress, StatusFlags | Format-Table -AutoSize

    if ($ExportCsvPath) {
        $parent = Split-Path -Parent $ExportCsvPath
        if ($parent -and -not (Test-Path $parent)) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }
        $routeReport | Export-Csv -Path $ExportCsvPath -NoTypeInformation -Encoding UTF8
        Write-Host "Exported route audit to: $ExportCsvPath" -ForegroundColor Cyan
    }

    return $routeReport
}
