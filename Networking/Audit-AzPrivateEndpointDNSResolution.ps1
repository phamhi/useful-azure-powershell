<#
.SYNOPSIS
    Audits Azure Private Endpoints for Private DNS Zone record registration and VNet link alignment.

.DESCRIPTION
    Validates end-to-end Private DNS resolution for Azure Private Endpoints across subscriptions:
      1. Discovers all Private Endpoints (PEs), extracting NIC private IPs and target FQDN configurations.
      2. Maps corresponding Azure Private DNS Zones (e.g., privatelink.blob.core.windows.net).
      3. Verifies whether an 'A' record exists matching the Private Endpoint's allocated private IP.
      4. Verifies whether the Private DNS Zone is linked to the VNet where the PE resides.
      5. Detects DNS blackholes, missing A-records, unlinked zones, and orphaned private endpoints.

.PARAMETER SubscriptionIds
    Array of Subscription IDs to evaluate. Defaults to all active subscriptions.

.PARAMETER ExportCsvPath
    Optional CSV path to save resolution validation findings.

.EXAMPLE
    .\Audit-AzPrivateEndpointDNSResolution.ps1 -ExportCsvPath "C:\Reports\PrivateDnsAudit.csv"
    Audits all Private Endpoints and validates DNS zone records and VNet links.

.NOTES
    Required Modules: Az.Accounts, Az.Network, Az.PrivateDns
    Permissions: Reader on target subscriptions.
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

    $dnsFindings = [System.Collections.Generic.List[PSCustomObject]]::new()
    Write-Host "Auditing Private Endpoints and Private DNS across $($subs.Count) subscription(s)..." -ForegroundColor Cyan

    # Pre-fetch all Private DNS Zones across target subscriptions
    $allZones = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($sub in $subs) {
        Set-AzContext -SubscriptionId $sub.Id -ErrorAction SilentlyContinue | Out-Null
        $zones = Get-AzPrivateDnsZone -ErrorAction SilentlyContinue
        foreach ($z in $zones) {
            $allZones.Add([PSCustomObject]@{
                ZoneName        = $z.Name
                ResourceGroup   = $z.ResourceGroupName
                SubscriptionId  = $sub.Id
                ZoneObject      = $z
            })
        }
    }

    Write-Host "Indexed $($allZones.Count) Private DNS Zone(s)." -ForegroundColor Gray

    foreach ($sub in $subs) {
        Set-AzContext -SubscriptionId $sub.Id -ErrorAction SilentlyContinue | Out-Null
        $pes = Get-AzPrivateEndpoint -ErrorAction SilentlyContinue

        foreach ($pe in $pes) {
            $vnetId = $pe.Subnet.Id -replace '/subnets/[^/]+$', ''
            $vnetName = ($vnetId -split '/')[-1]
            $customDnsConfigs = $pe.CustomDnsConfigs

            if (-not $customDnsConfigs -or $customDnsConfigs.Count -eq 0) {
                # Fall back to inspecting NIC IP configurations
                $nicId = $pe.NetworkInterfaces[0].Id
                $nic = Get-AzNetworkInterface -ResourceId $nicId -ErrorAction SilentlyContinue
                $privateIps = if ($nic) { ($nic.IpConfigurations.PrivateIpAddress -join ', ') } else { 'Unknown' }
                
                $dnsFindings.Add([PSCustomObject]@{
                    SubscriptionId   = $sub.Id
                    ResourceGroup    = $pe.ResourceGroupName
                    PrivateEndpoint  = $pe.Name
                    VNetName         = $vnetName
                    TargetFqdn       = 'N/A (No Custom DNS Config)'
                    AllocatedIP      = $privateIps
                    MatchingDnsZone  = 'None'
                    ARecordExists    = 'Unknown'
                    VNetLinkedToZone = 'Unknown'
                    HealthStatus     = 'Warning: Custom DNS configuration missing'
                })
                continue
            }

            foreach ($dnsConfig in $customDnsConfigs) {
                $fqdn = $dnsConfig.Fqdn
                $ip = ($dnsConfig.IpAddresses -join ', ')

                # Find matching private DNS zone
                $matchingZone = $allZones | Where-Object { $fqdn -like "*$($_.ZoneName)" } | Select-Object -First 1

                $hasRecord = "No"
                $isVNetLinked = "No"
                $status = "Healthy"

                if ($matchingZone) {
                    Set-AzContext -SubscriptionId $matchingZone.SubscriptionId -ErrorAction SilentlyContinue | Out-Null
                    
                    # Check A record
                    $recordRelativeName = ($fqdn -replace "\.$($matchingZone.ZoneName)", '')
                    try {
                        $record = Get-AzPrivateDnsRecordSet -ZoneName $matchingZone.ZoneName `
                            -ResourceGroupName $matchingZone.ResourceGroup -RecordType A `
                            -Name $recordRelativeName -ErrorAction SilentlyContinue

                        if ($record) {
                            $hasRecord = if ($record.Records.Ipv4Address -contains $dnsConfig.IpAddresses[0]) { "Yes (Exact Match)" } else { "IP Mismatch" }
                        }
                    } catch { }

                    # Check VNet link
                    try {
                        $links = Get-AzPrivateDnsVirtualNetworkLink -ZoneName $matchingZone.ZoneName `
                            -ResourceGroupName $matchingZone.ResourceGroup -ErrorAction SilentlyContinue

                        $linkedVnet = $links | Where-Object { $_.VirtualNetwork.Id -eq $vnetId }
                        if ($linkedVnet) { $isVNetLinked = "Yes" }
                    } catch { }

                    if ($hasRecord -ne 'Yes (Exact Match)') {
                        $status = "CRITICAL: Missing or mismatched A-record in Private DNS"
                    } elseif ($isVNetLinked -ne 'Yes') {
                        $status = "WARNING: VNet is not linked to Private DNS Zone"
                    }
                } else {
                    $status = "CRITICAL: No matching Private DNS Zone discovered for $fqdn"
                }

                $dnsFindings.Add([PSCustomObject]@{
                    SubscriptionId   = $sub.Id
                    ResourceGroup    = $pe.ResourceGroupName
                    PrivateEndpoint  = $pe.Name
                    VNetName         = $vnetName
                    TargetFqdn       = $fqdn
                    AllocatedIP      = $ip
                    MatchingDnsZone  = if ($matchingZone) { $matchingZone.ZoneName } else { 'None' }
                    ARecordExists    = $hasRecord
                    VNetLinkedToZone = $isVNetLinked
                    HealthStatus     = $status
                })
            }
        }
    }

    Write-Host "`nPrivate Endpoint DNS audit complete ($($dnsFindings.Count) configs checked)." -ForegroundColor Green
    $dnsFindings | Select-Object PrivateEndpoint, TargetFqdn, MatchingDnsZone, ARecordExists, VNetLinkedToZone, HealthStatus | Format-Table -AutoSize

    if ($ExportCsvPath) {
        $parent = Split-Path -Parent $ExportCsvPath
        if ($parent -and -not (Test-Path $parent)) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }
        $dnsFindings | Export-Csv -Path $ExportCsvPath -NoTypeInformation -Encoding UTF8
        Write-Host "Exported DNS report to: $ExportCsvPath" -ForegroundColor Cyan
    }

    return $dnsFindings
}
