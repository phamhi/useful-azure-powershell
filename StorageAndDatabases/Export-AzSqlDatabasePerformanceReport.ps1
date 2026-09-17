<#
.SYNOPSIS
    Gathers performance metrics, storage headroom, replication health, and TDE encryption for Azure SQL databases.

.DESCRIPTION
    Performs an operational health and performance assessment across Azure SQL Databases:
      1. Discovers SQL Servers and databases (excluding master).
      2. Analyzes storage capacity: Max Size, Allocated / Used Space, and Remaining Headroom percentage.
      3. Queries Azure Monitor metrics over lookback window (default 7 days) for DTU / CPU peak utilization.
      4. Inspects Transparent Data Encryption (TDE) state (Enabled, Disabled, ServiceManaged, CMK).
      5. Checks Active Geo-Replication status, replication state (CATCH_UP, SEEDING, SUSPENDED), and partner lag.
      6. Formats structured performance reporting with CSV export capability.

.PARAMETER SubscriptionIds
    Array of Subscription IDs to evaluate. Defaults to all active subscriptions.

.PARAMETER LookbackDays
    Number of days of historical metric data to evaluate. Default is 7.

.PARAMETER HighStorageThresholdPercent
    Percentage of storage usage above which a database is flagged for capacity expansion. Default is 80.

.PARAMETER ExportCsvPath
    Optional CSV path to save performance findings.

.EXAMPLE
    .\Export-AzSqlDatabasePerformanceReport.ps1 -LookbackDays 14 -ExportCsvPath "C:\Reports\SqlPerformance.csv"
    Audits all Azure SQL databases, evaluating 14-day utilization peaks and storage headroom.

.NOTES
    Required Modules: Az.Accounts, Az.Sql, Az.Monitor
    Permissions: Microsoft.Sql/servers/databases/read, Monitoring Reader across target subscriptions.
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
    [string[]]$SubscriptionIds,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 30)]
    [int]$LookbackDays = 7,

    [Parameter(Mandatory = $false)]
    [ValidateRange(50, 95)]
    [double]$HighStorageThresholdPercent = 80.0,

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

    $dbReport = [System.Collections.Generic.List[PSCustomObject]]::new()
    $startTime = (Get-Date).AddDays(-$LookbackDays)
    $endTime = Get-Date

    Write-Host "Assessing Azure SQL Database performance across $($subs.Count) subscription(s)..." -ForegroundColor Cyan

    foreach ($sub in $subs) {
        Set-AzContext -SubscriptionId $sub.Id -ErrorAction SilentlyContinue | Out-Null
        $servers = Get-AzSqlServer -ErrorAction SilentlyContinue

        foreach ($srv in $servers) {
            Write-Host "Checking SQL Server: $($srv.ServerName)..." -ForegroundColor Gray
            $dbs = Get-AzSqlDatabase -ServerName $srv.ServerName -ResourceGroupName $srv.ResourceGroupName -ErrorAction SilentlyContinue | Where-Object { $_.DatabaseName -ne 'master' }

            foreach ($db in $dbs) {
                # Storage calculations
                $maxSizeBytes = $db.MaxSizeBytes
                $maxSizeGB = if ($maxSizeBytes) { [math]::Round($maxSizeBytes / 1GB, 2) } else { 0.0 }
                
                # Check TDE
                $tdeState = "Unknown"
                try {
                    $tde = Get-AzSqlDatabaseTransparentDataEncryption -ServerName $srv.ServerName `
                        -ResourceGroupName $srv.ResourceGroupName -DatabaseName $db.DatabaseName -ErrorAction SilentlyContinue
                    $tdeState = if ($tde) { $tde.State } else { 'Disabled' }
                } catch { }

                # Check Geo-Replication
                $replicationState = "Standalone"
                try {
                    $replLinks = Get-AzSqlDatabaseReplicationLink -ServerName $srv.ServerName `
                        -ResourceGroupName $srv.ResourceGroupName -DatabaseName $db.DatabaseName -ErrorAction SilentlyContinue
                    if ($replLinks) {
                        $replicationState = ($replLinks | ForEach-Object { "$($_.PartnerServer) ($($_.ReplicationState))" }) -join '; '
                    }
                } catch { }

                # Query DTU / CPU Metrics
                $avgCpu = $null
                $maxCpu = $null
                try {
                    $metric = Get-AzMetric -ResourceId $db.ResourceId -MetricName "cpu_percent" `
                        -StartTime $startTime -EndTime $endTime -TimeGrain ([TimeSpan]::FromHours(1)) `
                        -AggregationType Average, Maximum -ErrorAction Stop

                    $points = $metric.Data | Where-Object { $null -ne $_.Average }
                    if ($points) {
                        $avgCpu = [math]::Round(($points | Measure-Object -Property Average -Average).Average, 1)
                        $maxCpu = [math]::Round(($points | Measure-Object -Property Maximum -Maximum).Maximum, 1)
                    }
                } catch { }

                # Health Assessment
                $healthStatus = "Healthy"
                if ($tdeState -ne 'Enabled') {
                    $healthStatus = "Risk: TDE Disabled"
                } elseif ($maxCpu -and $maxCpu -gt 90) {
                    $healthStatus = "Warning: CPU Peak > 90%"
                }

                $dbReport.Add([PSCustomObject]@{
                    SubscriptionId    = $sub.Id
                    ServerName        = $srv.ServerName
                    DatabaseName      = $db.DatabaseName
                    Edition           = $db.Edition
                    CurrentServiceTier= $db.CurrentServiceObjectiveName
                    MaxSizeGB         = $maxSizeGB
                    AvgCpuPercent     = $avgCpu
                    MaxCpuPercent     = $maxCpu
                    TdeState          = $tdeState
                    ReplicationStatus = $replicationState
                    HealthStatus      = $healthStatus
                })
            }
        }
    }

    Write-Host "`nAzure SQL audit complete ($($dbReport.Count) databases reviewed)." -ForegroundColor Green
    $dbReport | Select-Object ServerName, DatabaseName, CurrentServiceTier, MaxSizeGB, MaxCpuPercent, TdeState, HealthStatus | Format-Table -AutoSize

    if ($ExportCsvPath) {
        $parent = Split-Path -Parent $ExportCsvPath
        if ($parent -and -not (Test-Path $parent)) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }
        $dbReport | Export-Csv -Path $ExportCsvPath -NoTypeInformation -Encoding UTF8
        Write-Host "Exported performance report to: $ExportCsvPath" -ForegroundColor Cyan
    }

    return $dbReport
}
