<#
.SYNOPSIS
    Audits Azure managed disk snapshots for age hygiene, deleted parent disk lineage, and cost impact.

.DESCRIPTION
    Scans Azure Managed Disk snapshots across specified subscriptions:
      - Calculates snapshot age and identifies snapshots older than a retention threshold.
      - Verifies whether the originating parent source disk still exists in Azure or was deleted.
      - Flags orphaned snapshots where the source VM/disk is long gone.
      - Estimates monthly storage cost based on SKU and allocated disk size.
      - Optionally purges stale snapshots exceeding retention policy using -PurgeStale and -WhatIf.

.PARAMETER SubscriptionIds
    One or more Subscription IDs. Defaults to all active subscriptions.

.PARAMETER AgeDaysThreshold
    Number of days after which a snapshot is classified as 'Stale'. Default is 60.

.PARAMETER PurgeStale
    Switch parameter to delete snapshots older than AgeDaysThreshold. Supports -WhatIf and -Confirm.

.PARAMETER ExportCsvPath
    Path to save a CSV report of snapshot inventory.

.EXAMPLE
    .\Export-AzSnapshotHygieneReport.ps1 -AgeDaysThreshold 90 -ExportCsvPath "C:\Reports\OldSnapshots.csv"
    Finds all snapshots older than 90 days across subscriptions and writes them to a CSV report.

.EXAMPLE
    .\Export-AzSnapshotHygieneReport.ps1 -AgeDaysThreshold 180 -PurgeStale -WhatIf
    Simulates the deletion of snapshots older than 180 days without executing the removal.

.NOTES
    Required Modules: Az.Accounts, Az.Compute, Az.Resources
    Permissions: Microsoft.Compute/snapshots/read (and /delete if PurgeStale is used).
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param (
    [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
    [string[]]$SubscriptionIds,

    [Parameter(Mandatory = $false)]
    [ValidateRange(7, 1000)]
    [int]$AgeDaysThreshold = 60,

    [Parameter(Mandatory = $false)]
    [switch]$PurgeStale,

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

    $snapshotReport = [System.Collections.Generic.List[PSCustomObject]]::new()
    $cutoffDate = (Get-Date).AddDays(-$AgeDaysThreshold)

    Write-Host "Evaluating managed disk snapshots older than $AgeDaysThreshold days across $($subs.Count) subscription(s)..." -ForegroundColor Cyan

    foreach ($sub in $subs) {
        Set-AzContext -SubscriptionId $sub.Id -ErrorAction SilentlyContinue | Out-Null
        $snapshots = Get-AzSnapshot -ErrorAction SilentlyContinue

        if (-not $snapshots) { continue }

        foreach ($snap in $snapshots) {
            $createdDate = $snap.TimeCreated
            $ageDays = if ($createdDate) { [math]::Round(((Get-Date) - $createdDate).TotalDays, 0) } else { 0 }
            $isStale = $ageDays -ge $AgeDaysThreshold

            # Check parent source disk existence
            $parentExists = "Unknown"
            $sourceId = $snap.CreationData.SourceResourceId

            if ($sourceId) {
                try {
                    $parentDisk = Get-AzResource -ResourceId $sourceId -ErrorAction Stop
                    $parentExists = if ($parentDisk) { "Yes" } else { "No" }
                } catch {
                    $parentExists = "No (Deleted)"
                }
            } else {
                $parentExists = "None (Direct/Import)"
            }

            # Estimate cost: Standard HDD snapshot ~ $0.05/GB-month, Premium SSD ~ $0.15/GB-month
            $costPerGB = if ($snap.Sku.Name -match 'Premium') { 0.15 } else { 0.05 }
            $estMonthlyCost = [math]::Round(($snap.DiskSizeBytes / 1GB) * $costPerGB, 2)

            $status = if ($isStale -and $parentExists -eq "No (Deleted)") {
                "Critical: Stale & Parent Deleted"
            } elseif ($isStale) {
                "Warning: Stale (> $AgeDaysThreshold days)"
            } elseif ($parentExists -eq "No (Deleted)") {
                "Notice: Parent Disk Deleted"
            } else {
                "Compliant"
            }

            $entry = [PSCustomObject]@{
                SubscriptionId      = $sub.Id
                ResourceGroup       = $snap.ResourceGroupName
                SnapshotName        = $snap.Name
                Location            = $snap.Location
                Sku                 = $snap.Sku.Name
                DiskSizeGB          = [math]::Round($snap.DiskSizeBytes / 1GB, 1)
                CreatedDate         = $createdDate
                AgeDays             = $ageDays
                SourceResourceId    = $sourceId
                ParentDiskExists    = $parentExists
                EstMonthlySpendUSD  = $estMonthlyCost
                HygieneStatus       = $status
                SnapshotId          = $snap.Id
            }

            $snapshotReport.Add($entry)

            # Purge logic
            if ($PurgeStale -and $isStale) {
                if ($PSCmdlet.ShouldProcess("Snapshot '$($snap.Name)' ($ageDays days old) in RG '$($snap.ResourceGroupName)'", "Delete Stale Snapshot")) {
                    try {
                        Write-Host "Purging snapshot: $($snap.Name)..." -ForegroundColor Yellow
                        Remove-AzSnapshot -ResourceGroupName $snap.ResourceGroupName -SnapshotName $snap.Name -Force -ErrorAction Stop
                        Write-Host "Successfully deleted snapshot $($snap.Name)" -ForegroundColor Green
                    } catch {
                        Write-Error "Failed to delete snapshot $($snap.Name): $($_.Exception.Message)"
                    }
                }
            }
        }
    }

    Write-Host "`nDiscovered $($snapshotReport.Count) snapshot(s). Showing overview:" -ForegroundColor Green
    $snapshotReport | Select-Object SnapshotName, ResourceGroup, AgeDays, ParentDiskExists, EstMonthlySpendUSD, HygieneStatus | Format-Table -AutoSize

    if ($ExportCsvPath) {
        $parent = Split-Path -Parent $ExportCsvPath
        if ($parent -and -not (Test-Path $parent)) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }
        $snapshotReport | Export-Csv -Path $ExportCsvPath -NoTypeInformation -Encoding UTF8
        Write-Host "Exported CSV to: $ExportCsvPath" -ForegroundColor Cyan
    }

    return $snapshotReport
}
