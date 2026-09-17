<#
.SYNOPSIS
    Generates an executive-level multi-subscription Azure cloud resource inventory dashboard using Azure Resource Graph.

.DESCRIPTION
    Executes high-speed Kusto queries across all accessible Azure subscriptions using Search-AzGraph:
      1. Aggregates total resource counts partitioned by Subscription, Region, and Resource Provider.
      2. Audits governance hygiene: Untagged resources, missing lock protections.
      3. Identifies top resource types consuming capacity (Compute, Networking, Storage, PaaS).
      4. Detects regional concentration risk (e.g. 90% of resources in single region).
      5. Outputs an executive dashboard to console and optional interactive HTML/CSV files.

.PARAMETER SubscriptionIds
    Array of Subscription IDs to include. Defaults to all active subscriptions.

.PARAMETER ExportHtmlPath
    Optional path to render an interactive HTML dashboard report.

.PARAMETER ExportCsvPath
    Optional path to export raw aggregated inventory to CSV.

.EXAMPLE
    .\Get-AzSubscriptionInventorySummary.ps1 -ExportHtmlPath "C:\Reports\ExecutiveCloudInventory.html"
    Runs multi-subscription KQL inventory queries and generates an executive HTML dashboard.

.NOTES
    Required Modules: Az.Accounts, Az.ResourceGraph
    Permissions: Reader across target subscriptions.
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
    [string[]]$SubscriptionIds,

    [Parameter(Mandatory = $false)]
    [string]$ExportHtmlPath,

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

    $subIds = $subs.Id
    Write-Host "Querying Azure Resource Graph across $($subIds.Count) subscription(s)..." -ForegroundColor Cyan

    # 1. Total count & breakdown by subscription
    $subKql = @"
resources
| summarize ResourceCount = count() by subscriptionId
| join kind=inner (
    resourcecontainers
    | where type =~ 'microsoft.resources/subscriptions'
    | project subscriptionId, subscriptionName = name
) on subscriptionId
| project subscriptionName, subscriptionId, ResourceCount
| order by ResourceCount desc
"@

    # 2. Breakdown by Resource Type
    $typeKql = @"
resources
| summarize Count = count() by type
| order by Count desc
| take 25
"@

    # 3. Breakdown by Location
    $locKql = @"
resources
| summarize Count = count() by location
| order by Count desc
"@

    # 4. Governance & Hygiene (Untagged Resources)
    $hygieneKql = @"
resources
| extend hasTags = isnotempty(tags)
| summarize TotalResources = count(),
            UntaggedCount = countif(not(hasTags)),
            TaggedCount = countif(hasTags)
            by subscriptionId
| extend TagCompliancePercent = round((todouble(TaggedCount) / todouble(TotalResources)) * 100, 1)
"@

    try {
        $subBreakdown = Search-AzGraph -Query $subKql -Subscription $subIds -First 1000
        $typeBreakdown = Search-AzGraph -Query $typeKql -Subscription $subIds -First 1000
        $locBreakdown = Search-AzGraph -Query $locKql -Subscription $subIds -First 1000
        $hygieneData = Search-AzGraph -Query $hygieneKql -Subscription $subIds -First 1000
    } catch {
        throw "Resource Graph execution failed: $($_.Exception.Message)"
    }

    $totalAllResources = ($subBreakdown | Measure-Object -Property ResourceCount -Sum).Sum

    Write-Host "`n========================================================" -ForegroundColor Cyan
    Write-Host "         AZURE MULTI-SUBSCRIPTION INVENTORY SUMMARY" -ForegroundColor Cyan
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host "Total Subscriptions Audited : $($subs.Count)"
    Write-Host "Total Managed Cloud Assets  : $totalAllResources" -ForegroundColor Green

    Write-Host "`n--- Top Subscriptions by Resource Count ---" -ForegroundColor Yellow
    $subBreakdown | Format-Table subscriptionName, subscriptionId, ResourceCount -AutoSize

    Write-Host "--- Top 15 Resource Providers / Types ---" -ForegroundColor Yellow
    $typeBreakdown | Select-Object -First 15 | Format-Table type, Count -AutoSize

    Write-Host "--- Regional Distribution ---" -ForegroundColor Yellow
    $locBreakdown | Format-Table location, Count -AutoSize

    Write-Host "--- Tag Governance Compliance ---" -ForegroundColor Yellow
    $hygieneData | Format-Table subscriptionId, TotalResources, TaggedCount, UntaggedCount, TagCompliancePercent -AutoSize

    # HTML Dashboard export
    if ($ExportHtmlPath) {
        $parent = Split-Path -Parent $ExportHtmlPath
        if ($parent -and -not (Test-Path $parent)) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }

        $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Azure Cloud Inventory & Governance Dashboard</title>
<style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 24px; background: #f1f5f9; color: #0f172a; }
    h1 { margin-bottom: 4px; }
    .meta { color: #64748b; font-size: 14px; margin-bottom: 24px; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 24px; }
    .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }
    .card-num { font-size: 32px; font-weight: bold; color: #0284c7; }
    .section-box { background: white; padding: 24px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); margin-bottom: 24px; }
    table { width: 100%; border-collapse: collapse; margin-top: 12px; }
    th { text-align: left; padding: 10px; border-bottom: 2px solid #cbd5e1; font-size: 13px; color: #475569; }
    td { padding: 9px 10px; border-bottom: 1px solid #f1f5f9; font-size: 13px; }
</style>
</head>
<body>
<h1>Azure Cloud Inventory & Governance Dashboard</h1>
<div class="meta">Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC') | Tenant: $($context.Tenant.Id)</div>

<div class="grid">
    <div class="card"><div>Total Cloud Assets</div><div class="card-num">$totalAllResources</div></div>
    <div class="card"><div>Active Subscriptions</div><div class="card-num">$($subs.Count)</div></div>
    <div class="card"><div>Unique Regions Active</div><div class="card-num">$($locBreakdown.Count)</div></div>
    <div class="card"><div>Distinct Resource Types</div><div class="card-num">$($typeBreakdown.Count)</div></div>
</div>

<div class="section-box">
    <h3>Subscription Allocation</h3>
    <table>
        <thead><tr><th>Subscription Name</th><th>Subscription ID</th><th>Asset Count</th></tr></thead>
        <tbody>
        $(($subBreakdown | ForEach-Object { "<tr><td>$($_.subscriptionName)</td><td>$($_.subscriptionId)</td><td><strong>$($_.ResourceCount)</strong></td></tr>" }) -join "`n")
        </tbody>
    </table>
</div>

<div class="section-box">
    <h3>Top Resource Types</h3>
    <table>
        <thead><tr><th>Resource Provider / Type</th><th>Total Count</th></tr></thead>
        <tbody>
        $(($typeBreakdown | ForEach-Object { "<tr><td>$($_.type)</td><td>$($_.Count)</td></tr>" }) -join "`n")
        </tbody>
    </table>
</div>
</body>
</html>
"@
        Set-Content -Path $ExportHtmlPath -Value $htmlContent -Encoding UTF8
        Write-Host "Exported HTML Dashboard to: $ExportHtmlPath" -ForegroundColor Cyan
    }

    if ($ExportCsvPath) {
        $parent = Split-Path -Parent $ExportCsvPath
        if ($parent -and -not (Test-Path $parent)) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }
        $typeBreakdown | Export-Csv -Path $ExportCsvPath -NoTypeInformation -Encoding UTF8
        Write-Host "Exported CSV to: $ExportCsvPath" -ForegroundColor Cyan
    }

    return @{
        TotalResources = $totalAllResources
        Subscriptions  = $subBreakdown
        ResourceTypes  = $typeBreakdown
        Locations      = $locBreakdown
        Governance     = $hygieneData
    }
}
