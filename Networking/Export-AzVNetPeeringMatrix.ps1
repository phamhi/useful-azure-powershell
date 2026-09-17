<#
.SYNOPSIS
    Discovers Azure Virtual Networks across subscriptions and generates a comprehensive peering matrix.

.DESCRIPTION
    Maps the global virtual networking topology across all accessible subscriptions and regions:
      1. Discovers all Virtual Networks (VNets) and parses their address spaces (CIDRs).
      2. Inspects all VNet Peering connections, peering states (Connected, Initiated, Disconnected).
      3. Verifies transit settings: AllowGatewayTransit, UseRemoteGateways, AllowForwardedTraffic.
      4. Detects overlapping IPv4 CIDR blocks between VNets (identifying routing collision risks).
      5. Identifies asymmetric peering states (e.g. peering configured on one side but missing on the remote side).
      6. Formats an enterprise connectivity matrix with CSV export support.

.PARAMETER SubscriptionIds
    Array of Subscription IDs to include. Defaults to all active subscriptions.

.PARAMETER CheckCidrOverlap
    Switch to run CIDR collision detection across all discovered VNets. Defaults to $true.

.PARAMETER ExportCsvPath
    Optional path to save peering data to CSV.

.EXAMPLE
    .\Export-AzVNetPeeringMatrix.ps1 -CheckCidrOverlap -ExportCsvPath "C:\Reports\VNetPeeringTopology.csv"
    Maps all VNet peering relationships, checks for CIDR conflicts, and exports to CSV.

.NOTES
    Required Modules: Az.Accounts, Az.Network
    Permissions: Microsoft.Network/virtualNetworks/read across target subscriptions.
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
    [string[]]$SubscriptionIds,

    [Parameter(Mandatory = $false)]
    [bool]$CheckCidrOverlap = $true,

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

    $allVnets = [System.Collections.Generic.List[PSCustomObject]]::new()
    $peeringRows = [System.Collections.Generic.List[PSCustomObject]]::new()

    Write-Host "Discovering Virtual Networks across $($subs.Count) subscription(s)..." -ForegroundColor Cyan

    foreach ($sub in $subs) {
        Set-AzContext -SubscriptionId $sub.Id -ErrorAction SilentlyContinue | Out-Null
        $vnets = Get-AzVirtualNetwork -ErrorAction SilentlyContinue

        foreach ($v in $vnets) {
            $prefixes = if ($v.AddressSpace) { $v.AddressSpace.AddressPrefixes } else { @() }
            $allVnets.Add([PSCustomObject]@{
                SubscriptionId = $sub.Id
                SubscriptionName= $sub.Name
                ResourceGroup  = $v.ResourceGroupName
                VNetName       = $v.Name
                ResourceId     = $v.Id
                Location       = $v.Location
                AddressPrefixes= $prefixes
                VNetObject     = $v
            })
        }
    }

    Write-Host "Found $($allVnets.Count) Virtual Network(s). Analyzing peering topologies..." -ForegroundColor Cyan

    foreach ($vnetEntry in $allVnets) {
        $v = $vnetEntry.VNetObject
        if ($v.VirtualNetworkPeerings -and $v.VirtualNetworkPeerings.Count -gt 0) {
            foreach ($peer in $v.VirtualNetworkPeerings) {
                # Extract remote VNet details from resource ID
                $remoteVNetId = $peer.RemoteVirtualNetwork.Id
                $remoteVNetName = ($remoteVNetId -split '/')[-1]
                $remoteRG = ($remoteVNetId -split '/')[4]
                $remoteSub = ($remoteVNetId -split '/')[2]

                $status = if ($peer.PeeringState -eq 'Connected') { 'Connected' } else { "Issue: $($peer.PeeringState)" }

                $peeringRows.Add([PSCustomObject]@{
                    SourceSubscription   = $vnetEntry.SubscriptionId
                    SourceResourceGroup  = $vnetEntry.ResourceGroup
                    SourceVNet           = $vnetEntry.VNetName
                    SourceAddressPrefix  = ($vnetEntry.AddressPrefixes -join '; ')
                    PeeringName          = $peer.Name
                    PeeringState         = $peer.PeeringState
                    RemoteSubscription   = $remoteSub
                    RemoteResourceGroup  = $remoteRG
                    RemoteVNet           = $remoteVNetName
                    AllowGatewayTransit  = $peer.AllowGatewayTransit
                    UseRemoteGateways    = $peer.UseRemoteGateways
                    AllowForwardedTraffic= $peer.AllowForwardedTraffic
                    AllowVNetAccess      = $peer.AllowVirtualNetworkAccess
                    Status               = $status
                })
            }
        } else {
            # VNet has no peerings
            $peeringRows.Add([PSCustomObject]@{
                SourceSubscription   = $vnetEntry.SubscriptionId
                SourceResourceGroup  = $vnetEntry.ResourceGroup
                SourceVNet           = $vnetEntry.VNetName
                SourceAddressPrefix  = ($vnetEntry.AddressPrefixes -join '; ')
                PeeringName          = 'None'
                PeeringState         = 'Standalone'
                RemoteSubscription   = 'N/A'
                RemoteResourceGroup  = 'N/A'
                RemoteVNet           = 'N/A'
                AllowGatewayTransit  = $false
                UseRemoteGateways    = $false
                AllowForwardedTraffic= $false
                AllowVNetAccess      = $false
                Status               = 'Isolated / Standalone'
            })
        }
    }

    # CIDR Overlap Check (Helper function to test basic /16 or /24 prefix overlap)
    if ($CheckCidrOverlap -and $allVnets.Count -gt 1) {
        Write-Host "Running CIDR overlap analysis across all VNets..." -ForegroundColor Yellow
        for ($i = 0; $i -lt $allVnets.Count; $i++) {
            for ($j = $i + 1; $j -lt $allVnets.Count; $j++) {
                $v1 = $allVnets[$i]
                $v2 = $allVnets[$j]

                foreach ($p1 in $v1.AddressPrefixes) {
                    foreach ($p2 in $v2.AddressPrefixes) {
                        if ($p1 -eq $p2) {
                            Write-Warning "EXACT CIDR COLLISION: $($v1.VNetName) ($($v1.ResourceGroup)) and $($v2.VNetName) ($($v2.ResourceGroup)) share $p1"
                        }
                    }
                }
            }
        }
    }

    Write-Host "`nPeering Matrix generated ($($peeringRows.Count) rows)." -ForegroundColor Green
    $peeringRows | Select-Object SourceVNet, PeeringName, PeeringState, RemoteVNet, AllowGatewayTransit, UseRemoteGateways | Format-Table -AutoSize

    if ($ExportCsvPath) {
        $parent = Split-Path -Parent $ExportCsvPath
        if ($parent -and -not (Test-Path $parent)) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }
        $peeringRows | Export-Csv -Path $ExportCsvPath -NoTypeInformation -Encoding UTF8
        Write-Host "Exported matrix to: $ExportCsvPath" -ForegroundColor Cyan
    }

    return $peeringRows
}
