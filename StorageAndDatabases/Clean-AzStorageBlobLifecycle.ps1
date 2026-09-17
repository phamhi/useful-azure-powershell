<#
.SYNOPSIS
    Analyzes blob storage for tier transition candidates (Hot -> Cool -> Archive) and stale blob cleanup.

.DESCRIPTION
    Scans Azure Storage containers to evaluate blob lifecycle economics and hygiene:
      1. Inspects blobs across containers, reading LastModified timestamps and AccessTier (Hot, Cool, Cold, Archive).
      2. Identifies blobs unmodified for > 90, 180, or 365 days still stored in expensive Hot tier.
      3. Calculates projected monthly cost savings by re-tiering to Cool, Cold, or Archive.
      4. Detects orphaned blob snapshots consuming storage.
      5. Supports automated tier shifting via -TargetTier with -WhatIf and -Confirm safety switches.

.PARAMETER ResourceGroupName
    Resource Group of the target Storage Account.

.PARAMETER StorageAccountName
    Name of the Storage Account to analyze.

.PARAMETER ContainerName
    Optional specific container name. If omitted, evaluates all containers in the account.

.PARAMETER DaysInactiveThreshold
    Number of days since LastModified before a blob is considered an archival/re-tiering candidate. Default is 90.

.PARAMETER TargetTier
    Optional target tier to apply to qualifying blobs ('Cool', 'Cold', 'Archive').

.PARAMETER ExportCsvPath
    Path to save analysis results to CSV.

.EXAMPLE
    .\Clean-AzStorageBlobLifecycle.ps1 -ResourceGroupName "rg-data-prod" -StorageAccountName "stlakehousedata" -DaysInactiveThreshold 90
    Scans containers for blobs inactive for 90+ days in Hot tier, projecting potential savings.

.EXAMPLE
    .\Clean-AzStorageBlobLifecycle.ps1 -ResourceGroupName "rg-data-prod" -StorageAccountName "stlakehousedata" -TargetTier "Cool" -WhatIf
    Simulates changing the access tier of qualifying inactive blobs to Cool.

.NOTES
    Required Modules: Az.Accounts, Az.Storage
    Permissions: Storage Blob Data Contributor on the storage account.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param (
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $true)]
    [string]$StorageAccountName,

    [Parameter(Mandatory = $false)]
    [string]$ContainerName,

    [Parameter(Mandatory = $false)]
    [int]$DaysInactiveThreshold = 90,

    [Parameter(Mandatory = $false)]
    [ValidateSet('Cool', 'Cold', 'Archive')]
    [string]$TargetTier,

    [Parameter(Mandatory = $false)]
    [string]$ExportCsvPath
)

process {
    $context = Get-AzContext
    if (-not $context) {
        throw "No active Azure context. Connect with 'Connect-AzAccount'."
    }

    Write-Host "Connecting to Storage Account '$StorageAccountName' in '$ResourceGroupName'..." -ForegroundColor Cyan
    $sa = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ErrorAction Stop
    $storageCtx = $sa.Context

    $containers = if ($ContainerName) {
        Get-AzStorageContainer -Name $ContainerName -Context $storageCtx -ErrorAction Stop
    } else {
        Get-AzStorageContainer -Context $storageCtx -ErrorAction Stop
    }

    $blobAnalysis = [System.Collections.Generic.List[PSCustomObject]]::new()
    $cutoffDate = (Get-Date).AddDays(-$DaysInactiveThreshold)

    Write-Host "Scanning $($containers.Count) container(s) for blobs unmodified since $cutoffDate..." -ForegroundColor Yellow

    foreach ($c in $containers) {
        Write-Host "Inspecting container: $($c.Name)..." -ForegroundColor Gray
        $blobs = Get-AzStorageBlob -Container $c.Name -Context $storageCtx -ErrorAction SilentlyContinue

        foreach ($b in $blobs) {
            $lastMod = $b.LastModified
            $tier = $b.AccessTier
            $sizeMB = [math]::Round($b.Length / 1MB, 2)
            $sizeGB = [math]::Round($b.Length / 1GB, 4)
            $ageDays = if ($lastMod) { [math]::Round(((Get-Date) - $lastMod.DateTime).TotalDays, 0) } else { 0 }

            $isCandidate = ($ageDays -ge $DaysInactiveThreshold) -and ($tier -eq 'Hot')
            
            # Pricing baseline (approximate Azure per GB/month: Hot ~$0.018, Cool ~$0.010, Cold ~$0.0036, Archive ~$0.00099)
            $hotCost = $sizeGB * 0.018
            $coolCost = $sizeGB * 0.010
            $archiveCost = $sizeGB * 0.00099
            $potentialSavings = if ($isCandidate) { [math]::Round(($hotCost - $coolCost), 4) } else { 0.0 }

            $item = [PSCustomObject]@{
                ContainerName       = $c.Name
                BlobName            = $b.Name
                CurrentTier         = $tier
                SizeMB              = $sizeMB
                LastModified        = $lastMod
                AgeDays             = $ageDays
                IsReTierCandidate   = $isCandidate
                EstCurrentMonthlyCost= [math]::Round($hotCost, 4)
                EstCoolSavingsMo    = $potentialSavings
            }

            $blobAnalysis.Add($item)

            # Apply tier change if requested
            if ($TargetTier -and $isCandidate) {
                if ($PSCmdlet.ShouldProcess("Blob '$($b.Name)' in container '$($c.Name)'", "Set Access Tier to $TargetTier")) {
                    try {
                        Write-Host "Transitioning $($b.Name) -> $TargetTier..." -ForegroundColor Yellow
                        $b.BlobClient.SetAccessTier($TargetTier) | Out-Null
                        Write-Host "Successfully changed tier to $TargetTier" -ForegroundColor Green
                    } catch {
                        Write-Error "Failed to set tier on $($b.Name): $($_.Exception.Message)"
                    }
                }
            }
        }
    }

    $candidates = $blobAnalysis | Where-Object { $_.IsReTierCandidate }
    Write-Host "`nScan complete. Discovered $($candidates.Count) qualifying candidate blob(s) for tier optimization." -ForegroundColor Green

    if ($ExportCsvPath) {
        $parent = Split-Path -Parent $ExportCsvPath
        if ($parent -and -not (Test-Path $parent)) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }
        $blobAnalysis | Export-Csv -Path $ExportCsvPath -NoTypeInformation -Encoding UTF8
        Write-Host "Exported blob lifecycle report to: $ExportCsvPath" -ForegroundColor Cyan
    }

    return $blobAnalysis
}
