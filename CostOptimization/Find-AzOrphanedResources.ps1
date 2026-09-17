<#
.SYNOPSIS
    Discovers, reports, and optionally decommissions orphaned and unattached Azure resources.

.DESCRIPTION
    Traverses one or more Azure subscriptions to identify idle, unattached, and orphaned
    resources that incur unnecessary cloud spend or represent configuration hygiene issues:
      - Unattached Managed Disks (ManagedBy is null)
      - Orphaned Network Interfaces (NICs not attached to VMs or Private Endpoints)
      - Disassociated Public IP Addresses (unallocated to NICs or Gateways)
      - Unassociated Network Security Groups (NSGs not bound to subnets or NICs)
      - Unassociated Route Tables (UDRs not bound to any subnet)
    
    Provides rich structured PSCustomObject output, estimated cost impact, optional HTML/CSV
    reporting with interactive tables, and safe remediation via -Delete and -WhatIf.

.PARAMETER SubscriptionIds
    An optional array of Azure Subscription IDs to scan. Defaults to all accessible subscriptions.

.PARAMETER ResourceTypes
    Filter which orphaned resource types to scan for. Valid values: All, Disks, NICs, PublicIPs, NSGs, RouteTables.
    Default is 'All'.

.PARAMETER ExportCsvPath
    Path to export results as a detailed CSV file.

.PARAMETER ExportHtmlPath
    Path to export a formatted executive HTML report with summary metrics and severity tags.

.PARAMETER Delete
    Switch parameter to delete discovered orphaned resources. Requires -Confirm or -WhatIf validation.

.EXAMPLE
    .\Find-AzOrphanedResources.ps1 -ExportHtmlPath "C:\Reports\OrphanedAzureResources.html"
    Scans all accessible subscriptions and generates a styled HTML report of all orphaned assets.

.EXAMPLE
    .\Find-AzOrphanedResources.ps1 -SubscriptionIds "00000000-0000-0000-0000-000000000000" -ResourceTypes Disks -Delete -WhatIf
    Performs a dry-run check of unattached managed disks in the specified subscription without deleting.

.NOTES
    Required Modules: Az.Accounts, Az.ResourceGraph, Az.Compute, Az.Network, Az.Resources
    Minimum Permissions: Reader on target subscriptions (or Contributor if using -Delete).
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param (
    [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
    [string[]]$SubscriptionIds,

    [Parameter(Mandatory = $false)]
    [ValidateSet('All', 'Disks', 'NICs', 'PublicIPs', 'NSGs', 'RouteTables')]
    [string]$ResourceTypes = 'All',

    [Parameter(Mandatory = $false)]
    [string]$ExportCsvPath,

    [Parameter(Mandatory = $false)]
    [string]$ExportHtmlPath,

    [Parameter(Mandatory = $false)]
    [switch]$Delete
)

process {
    # Ensure active Azure context
    $context = Get-AzContext
    if (-not $context) {
        throw "No active Azure context found. Please run 'Connect-AzAccount' before executing this script."
    }

    Write-Verbose "Connected as: $($context.Account.Id) on Tenant: $($context.Tenant.Id)"

    # Determine subscriptions
    if ($SubscriptionIds -and $SubscriptionIds.Count -gt 0) {
        $targetSubs = Get-AzSubscription | Where-Object { $SubscriptionIds -contains $_.Id }
    } else {
        $targetSubs = Get-AzSubscription | Where-Object { $_.State -eq 'Enabled' }
    }

    if (-not $targetSubs) {
        Write-Warning "No active subscriptions found matching criteria."
        return
    }

    Write-Host "Targeting $($targetSubs.Count) subscription(s)..." -ForegroundColor Cyan
    $discoveredOrphans = [System.Collections.Generic.List[PSCustomObject]]::new()

    # KQL query templates for Azure Resource Graph for ultra-fast scanning across subscriptions
    $subIdList = $targetSubs.Id

    # 1. Unattached Disks
    if ($ResourceTypes -in @('All', 'Disks')) {
        Write-Host "Scanning for unattached Managed Disks..." -ForegroundColor Yellow
        $diskKql = @"
resources
| where type =~ 'microsoft.compute/disks'
| where properties.diskState =~ 'Unattached' or (isnull(managedBy) and properties.diskState !~ 'ActiveSAS')
| project id, name, resourceGroup, subscriptionId, location, skuName = sku.name, diskSizeGB = properties.diskSizeGB, timeCreated = properties.timeCreated
"@
        try {
            $disks = Search-AzGraph -Query $diskKql -Subscription $subIdList -First 5000
            foreach ($d in $disks) {
                # Estimated standard HDD vs SSD monthly cost benchmark per GB ($0.05/GB avg)
                $estMonthlyCost = [math]::Round([double]($d.diskSizeGB * 0.06), 2)
                $discoveredOrphans.Add([PSCustomObject]@{
                    SubscriptionId   = $d.subscriptionId
                    ResourceGroup    = $d.resourceGroup
                    ResourceType     = 'Microsoft.Compute/disks'
                    ResourceName     = $d.name
                    ResourceId       = $d.id
                    Location         = $d.location
                    SizeOrSku        = "$($d.skuName) ($($d.diskSizeGB) GB)"
                    CreatedTime      = $d.timeCreated
                    EstMonthlyCostUSD= $estMonthlyCost
                    Details          = "Unattached Managed Disk. Idle storage cost accumulating."
                })
            }
        } catch {
            Write-Warning "Resource Graph query for disks failed: $($_.Exception.Message)"
        }
    }

    # 2. Orphaned NICs
    if ($ResourceTypes -in @('All', 'NICs')) {
        Write-Host "Scanning for orphaned Network Interfaces..." -ForegroundColor Yellow
        $nicKql = @"
resources
| where type =~ 'microsoft.network/networkinterfaces'
| where isnull(properties.virtualMachine) and isnull(properties.privateEndpoint)
| project id, name, resourceGroup, subscriptionId, location, ipConfigs = properties.ipConfigurations
"@
        try {
            $nics = Search-AzGraph -Query $nicKql -Subscription $subIdList -First 5000
            foreach ($n in $nics) {
                $discoveredOrphans.Add([PSCustomObject]@{
                    SubscriptionId   = $n.subscriptionId
                    ResourceGroup    = $n.resourceGroup
                    ResourceType     = 'Microsoft.Network/networkInterfaces'
                    ResourceName     = $n.name
                    ResourceId       = $n.id
                    Location         = $n.location
                    SizeOrSku        = "Standard NIC"
                    CreatedTime      = "N/A"
                    EstMonthlyCostUSD= 0.00
                    Details          = "NIC unattached to any VM or Private Endpoint."
                })
            }
        } catch {
            Write-Warning "Resource Graph query for NICs failed: $($_.Exception.Message)"
        }
    }

    # 3. Disassociated Public IPs
    if ($ResourceTypes -in @('All', 'PublicIPs')) {
        Write-Host "Scanning for disassociated Public IP Addresses..." -ForegroundColor Yellow
        $pipKql = @"
resources
| where type =~ 'microsoft.network/publicipaddresses'
| where isnull(properties.ipConfiguration) and isnull(properties.natGateway)
| project id, name, resourceGroup, subscriptionId, location, skuName = sku.name, ipAddress = properties.ipAddress
"@
        try {
            $pips = Search-AzGraph -Query $pipKql -Subscription $subIdList -First 5000
            foreach ($p in $pips) {
                # Unassociated Static or Standard Public IPs incur idle charges (~$3.60/month)
                $discoveredOrphans.Add([PSCustomObject]@{
                    SubscriptionId   = $p.subscriptionId
                    ResourceGroup    = $p.resourceGroup
                    ResourceType     = 'Microsoft.Network/publicIPAddresses'
                    ResourceName     = $p.name
                    ResourceId       = $p.id
                    Location         = $p.location
                    SizeOrSku        = "$($p.skuName) (IP: $($p.ipAddress))"
                    CreatedTime      = "N/A"
                    EstMonthlyCostUSD= 3.65
                    Details          = "Unassociated Public IP address. Incurs idle hourly charge."
                })
            }
        } catch {
            Write-Warning "Resource Graph query for Public IPs failed: $($_.Exception.Message)"
        }
    }

    # 4. Empty NSGs
    if ($ResourceTypes -in @('All', 'NSGs')) {
        Write-Host "Scanning for empty Network Security Groups..." -ForegroundColor Yellow
        $nsgKql = @"
resources
| where type =~ 'microsoft.network/networksecuritygroups'
| where array_length(properties.networkInterfaces) == 0 and array_length(properties.subnets) == 0
| project id, name, resourceGroup, subscriptionId, location
"@
        try {
            $nsgs = Search-AzGraph -Query $nsgKql -Subscription $subIdList -First 5000
            foreach ($nsg in $nsgs) {
                $discoveredOrphans.Add([PSCustomObject]@{
                    SubscriptionId   = $nsg.subscriptionId
                    ResourceGroup    = $nsg.resourceGroup
                    ResourceType     = 'Microsoft.Network/networkSecurityGroups'
                    ResourceName     = $nsg.name
                    ResourceId       = $nsg.id
                    Location         = $nsg.location
                    SizeOrSku        = "N/A"
                    CreatedTime      = "N/A"
                    EstMonthlyCostUSD= 0.00
                    Details          = "NSG not bound to any subnet or NIC interface."
                })
            }
        } catch {
            Write-Warning "Resource Graph query for NSGs failed: $($_.Exception.Message)"
        }
    }

    # 5. Unattached Route Tables
    if ($ResourceTypes -in @('All', 'RouteTables')) {
        Write-Host "Scanning for unassociated Route Tables..." -ForegroundColor Yellow
        $rtKql = @"
resources
| where type =~ 'microsoft.network/routetables'
| where array_length(properties.subnets) == 0
| project id, name, resourceGroup, subscriptionId, location
"@
        try {
            $rts = Search-AzGraph -Query $rtKql -Subscription $subIdList -First 5000
            foreach ($rt in $rts) {
                $discoveredOrphans.Add([PSCustomObject]@{
                    SubscriptionId   = $rt.subscriptionId
                    ResourceGroup    = $rt.resourceGroup
                    ResourceType     = 'Microsoft.Network/routeTables'
                    ResourceName     = $rt.name
                    ResourceId       = $rt.id
                    Location         = $rt.location
                    SizeOrSku        = "N/A"
                    CreatedTime      = "N/A"
                    EstMonthlyCostUSD= 0.00
                    Details          = "Route table not associated with any Virtual Network subnet."
                })
            }
        } catch {
            Write-Warning "Resource Graph query for Route Tables failed: $($_.Exception.Message)"
        }
    }

    # Display Summary
    $totalCount = $discoveredOrphans.Count
    $totalEstMonthlyCost = ($discoveredOrphans | Measure-Object -Property EstMonthlyCostUSD -Sum).Sum
    Write-Host "`nScan Complete! Discovered $totalCount orphaned resource(s). Estimated Monthly Waste: `$$totalEstMonthlyCost USD" -ForegroundColor Green

    # Output to Pipeline
    $discoveredOrphans

    # Export to CSV if requested
    if ($ExportCsvPath) {
        $parentDir = Split-Path -Parent $ExportCsvPath
        if ($parentDir -and -not (Test-Path $parentDir)) { New-Item -Path $parentDir -ItemType Directory -Force | Out-Null }
        $discoveredOrphans | Export-Csv -Path $ExportCsvPath -NoTypeInformation -Encoding UTF8
        Write-Host "Exported CSV report to: $ExportCsvPath" -ForegroundColor Cyan
    }

    # Export to styled HTML if requested
    if ($ExportHtmlPath) {
        $parentDir = Split-Path -Parent $ExportHtmlPath
        if ($parentDir -and -not (Test-Path $parentDir)) { New-Item -Path $parentDir -ItemType Directory -Force | Out-Null }

        $htmlHeader = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Azure Orphaned Resources Audit Report</title>
<style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 20px; background-color: #f8fafc; color: #1e293b; }
    h1 { color: #0f172a; margin-bottom: 5px; }
    .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-weight: 600; font-size: 12px; }
    .badge-waste { background-color: #fee2e2; color: #991b1b; }
    .card-container { display: flex; gap: 20px; margin: 20px 0; }
    .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); flex: 1; }
    .card-val { font-size: 28px; font-weight: bold; color: #2563eb; }
    table { width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
    th { background-color: #0284c7; color: white; text-align: left; padding: 12px; font-size: 14px; }
    td { padding: 10px 12px; border-bottom: 1px solid #e2e8f0; font-size: 13px; }
    tr:hover { background-color: #f1f5f9; }
</style>
</head>
<body>
<h1>Azure Orphaned Resources Audit Report</h1>
<p>Generated on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC') | Tenant: $($context.Tenant.Id)</p>
<div class="card-container">
    <div class="card"><div>Total Orphaned Items</div><div class="card-val">$totalCount</div></div>
    <div class="card"><div>Est. Monthly Waste</div><div class="card-val">`$$totalEstMonthlyCost USD</div></div>
    <div class="card"><div>Subscriptions Audited</div><div class="card-val">$($targetSubs.Count)</div></div>
</div>
<table>
<thead>
<tr>
    <th>Subscription</th>
    <th>Resource Group</th>
    <th>Type</th>
    <th>Name</th>
    <th>Location</th>
    <th>Size / SKU</th>
    <th>Est. Cost/Mo</th>
    <th>Finding Details</th>
</tr>
</thead>
<tbody>
"@
        $tableRows = foreach ($item in $discoveredOrphans) {
            "<tr>
                <td>$($item.SubscriptionId)</td>
                <td>$($item.ResourceGroup)</td>
                <td><strong>$($item.ResourceType)</strong></td>
                <td>$($item.ResourceName)</td>
                <td>$($item.Location)</td>
                <td>$($item.SizeOrSku)</td>
                <td><span class='badge badge-waste'>`$$($item.EstMonthlyCostUSD)</span></td>
                <td>$($item.Details)</td>
            </tr>"
        }

        $htmlFooter = @"
</tbody>
</table>
</body>
</html>
"@
        $finalHtml = $htmlHeader + ($tableRows -join "`n") + $htmlFooter
        Set-Content -Path $ExportHtmlPath -Value $finalHtml -Encoding UTF8
        Write-Host "Exported HTML report to: $ExportHtmlPath" -ForegroundColor Cyan
    }

    # Remediation step (Delete)
    if ($Delete -and $discoveredOrphans.Count -gt 0) {
        Write-Host "`nInitiating resource remediation..." -ForegroundColor Red
        foreach ($orphan in $discoveredOrphans) {
            if ($PSCmdlet.ShouldProcess("$($orphan.ResourceType)/$($orphan.ResourceName) in $($orphan.ResourceGroup)", "Delete Orphaned Resource")) {
                try {
                    Write-Host "Deleting $($orphan.ResourceType): $($orphan.ResourceName)..." -ForegroundColor Yellow
                    Remove-AzResource -ResourceId $orphan.ResourceId -Force -ErrorAction Stop | Out-Null
                    Write-Host "Successfully deleted: $($orphan.ResourceName)" -ForegroundColor Green
                } catch {
                    Write-Error "Failed to delete resource $($orphan.ResourceId): $($_.Exception.Message)"
                }
            }
        }
    }
}
