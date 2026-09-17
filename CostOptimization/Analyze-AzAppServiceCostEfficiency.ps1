<#
.SYNOPSIS
    Analyzes Azure App Service Plans for cost efficiency, underutilization, and zero-app waste.

.DESCRIPTION
    Audits App Service Plans (ServerFarms) across one or more subscriptions:
      1. Identifies empty App Service Plans hosting 0 Web Apps or Function Apps.
      2. Queries Azure Monitor metrics over a lookback period (default 7 days) to evaluate
         average and maximum CPU / Memory percentage.
      3. Identifies oversized tiers (e.g. Premium v2/v3, Isolated) running at < 15% average utilization.
      4. Calculates potential monthly cost savings from downscaling or terminating empty plans.
      5. Generates structured output, CSV export, and actionable recommendations.

.PARAMETER SubscriptionIds
    Array of Azure Subscription IDs to inspect. If omitted, checks all accessible subscriptions.

.PARAMETER LookbackDays
    Number of days of metric history to evaluate for CPU and Memory metrics. Default is 7 days.

.PARAMETER LowCpuThresholdPercent
    Percentage threshold below which CPU utilization is flagged as underutilized. Default is 15.

.PARAMETER ExportCsvPath
    Optional file path to output CSV results.

.EXAMPLE
    .\Analyze-AzAppServiceCostEfficiency.ps1 -LookbackDays 14 -ExportCsvPath "C:\Reports\AppServiceWaste.csv"
    Analyzes all App Service Plans over the last 14 days and exports recommendations to CSV.

.NOTES
    Required Modules: Az.Accounts, Az.Websites, Az.Monitor, Az.ResourceGraph
    Permissions: Monitoring Reader, Website Reader on target subscriptions.
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
    [string[]]$SubscriptionIds,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 30)]
    [int]$LookbackDays = 7,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 80)]
    [double]$LowCpuThresholdPercent = 15.0,

    [Parameter(Mandatory = $false)]
    [string]$ExportCsvPath
)

process {
    $context = Get-AzContext
    if (-not $context) {
        throw "No active Azure context. Run 'Connect-AzAccount' first."
    }

    if ($SubscriptionIds -and $SubscriptionIds.Count -gt 0) {
        $subs = Get-AzSubscription | Where-Object { $SubscriptionIds -contains $_.Id }
    } else {
        $subs = Get-AzSubscription | Where-Object { $_.State -eq 'Enabled' }
    }

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    $startTime = (Get-Date).AddDays(-$LookbackDays)
    $endTime = Get-Date

    Write-Host "Analyzing App Service Plans across $($subs.Count) subscription(s) over last $LookbackDays days..." -ForegroundColor Cyan

    foreach ($sub in $subs) {
        Set-AzContext -SubscriptionId $sub.Id -ErrorAction SilentlyContinue | Out-Null
        Write-Host "Checking Subscription: $($sub.Name) ($($sub.Id))..." -ForegroundColor Gray

        $plans = Get-AzAppServicePlan -ErrorAction SilentlyContinue
        if (-not $plans) { continue }

        # Get all web apps in subscription to cross-reference hosted apps
        $webApps = Get-AzWebApp -ErrorAction SilentlyContinue

        foreach ($plan in $plans) {
            $associatedApps = $webApps | Where-Object { $_.ServerFarmId -eq $plan.Id }
            $appCount = if ($associatedApps) { $associatedApps.Count } else { 0 }

            $avgCpu = $null
            $maxCpu = $null
            $avgMemory = $null
            $recommendation = "Optimal"
            $estMonthlyCost = 0.0

            # Estimate base cost per tier
            switch -Wildcard ($plan.Sku.Tier) {
                "Free"        { $estMonthlyCost = 0.0 }
                "Shared"      { $estMonthlyCost = 9.50 }
                "Basic"       { $estMonthlyCost = 55.00 * $plan.Capacity }
                "Standard"    { $estMonthlyCost = 73.00 * $plan.Capacity }
                "PremiumV2"   { $estMonthlyCost = 146.00 * $plan.Capacity }
                "PremiumV3"   { $estMonthlyCost = 135.00 * $plan.Capacity }
                "IsolatedV2"  { $estMonthlyCost = 350.00 * $plan.Capacity }
                Default       { $estMonthlyCost = 50.00 * $plan.Capacity }
            }

            if ($appCount -eq 0) {
                $recommendation = "DELETE - Plan hosts zero applications; idle expense."
            } else {
                # Query Azure Monitor metric data for CPU and Memory
                try {
                    $cpuMetric = Get-AzMetric -ResourceId $plan.Id -MetricName "CpuPercentage" `
                        -StartTime $startTime -EndTime $endTime -TimeGrain ([TimeSpan]::FromHours(1)) `
                        -AggregationType Average, Maximum -ErrorAction Stop

                    $validPoints = $cpuMetric.Data | Where-Object { $null -ne $_.Average }
                    if ($validPoints) {
                        $avgCpu = [math]::Round(($validPoints | Measure-Object -Property Average -Average).Average, 2)
                        $maxCpu = [math]::Round(($validPoints | Measure-Object -Property Maximum -Maximum).Maximum, 2)
                    }

                    $memMetric = Get-AzMetric -ResourceId $plan.Id -MetricName "MemoryPercentage" `
                        -StartTime $startTime -EndTime $endTime -TimeGrain ([TimeSpan]::FromHours(1)) `
                        -AggregationType Average -ErrorAction Stop

                    $validMem = $memMetric.Data | Where-Object { $null -ne $_.Average }
                    if ($validMem) {
                        $avgMemory = [math]::Round(($validMem | Measure-Object -Property Average -Average).Average, 2)
                    }
                } catch {
                    Write-Verbose "Metrics unavailable for plan $($plan.Name): $($_.Exception.Message)"
                }

                if ($null -ne $avgCpu -and $avgCpu -lt $LowCpuThresholdPercent -and $plan.Sku.Tier -notin @('Free', 'Shared', 'Basic')) {
                    $recommendation = "DOWNSCALE - Low avg CPU ($avgCpu%) on $($plan.Sku.Tier). Consider lower SKU or autoscale."
                }
            }

            $results.Add([PSCustomObject]@{
                SubscriptionId      = $sub.Id
                ResourceGroup       = $plan.ResourceGroup
                AppServicePlanName  = $plan.Name
                Location            = $plan.Location
                SkuTier             = $plan.Sku.Tier
                SkuSize             = $plan.Sku.Size
                InstanceCount       = $plan.Capacity
                HostedAppsCount     = $appCount
                AvgCpuPercent       = $avgCpu
                MaxCpuPercent       = $maxCpu
                AvgMemoryPercent    = $avgMemory
                EstMonthlySpendUSD  = [math]::Round($estMonthlyCost, 2)
                Recommendation      = $recommendation
            })
        }
    }

    Write-Host "`nAnalysis complete. Evaluated $($results.Count) App Service Plan(s)." -ForegroundColor Green
    $results | Format-Table -AutoSize

    if ($ExportCsvPath) {
        $parent = Split-Path -Parent $ExportCsvPath
        if ($parent -and -not (Test-Path $parent)) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }
        $results | Export-Csv -Path $ExportCsvPath -NoTypeInformation -Encoding UTF8
        Write-Host "Exported results to: $ExportCsvPath" -ForegroundColor Cyan
    }

    return $results
}
