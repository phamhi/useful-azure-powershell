<#
.SYNOPSIS
    Audits, applies, or removes Azure Management Locks (CanNotDelete, ReadOnly) across resources in bulk.

.DESCRIPTION
    Provides automated governance for Azure Resource Locks to safeguard critical workloads:
      1. Audit Mode: Scans resource groups and resources for existing CanNotDelete or ReadOnly locks,
         evaluating lock coverage and inheritance.
      2. ApplyLock Mode: Enforces locks on production resource groups or critical resources based on
         tagging criteria (e.g. Environment = Production) or naming conventions.
      3. RemoveLock Mode: Safely removes locks to allow scheduled maintenance or decommissioning.
      4. Fully supports -WhatIf and -Confirm to prevent accidental lock changes.
      5. Formats structured audit records and supports CSV reporting.

.PARAMETER Action
    Operational mode: 'Audit', 'ApplyLock', or 'RemoveLock'. Default is 'Audit'.

.PARAMETER LockLevel
    Lock level to apply or target: 'CanNotDelete' or 'ReadOnly'. Default is 'CanNotDelete'.

.PARAMETER SubscriptionIds
    Array of Subscription IDs to evaluate. Defaults to all active subscriptions.

.PARAMETER TagFilter
    Hashtable filter to select target resource groups.
    Example: @{ 'Environment' = 'Production' }

.PARAMETER LockNotes
    Notes to attach to created locks. Default: 'Managed by Enterprise Cloud Governance'.

.PARAMETER ExportCsvPath
    Path to export lock audit results to CSV.

.EXAMPLE
    .\Manage-AzResourceLocksBulk.ps1 -Action Audit -ExportCsvPath "C:\Reports\ResourceLockAudit.csv"
    Audits all management locks across all accessible subscriptions.

.EXAMPLE
    .\Manage-AzResourceLocksBulk.ps1 -Action ApplyLock -LockLevel CanNotDelete -TagFilter @{ 'Environment' = 'Production' } -WhatIf
    Simulates applying CanNotDelete locks to all Production resource groups.

.NOTES
    Required Modules: Az.Accounts, Az.Resources
    Permissions: Microsoft.Authorization/locks/read, Microsoft.Authorization/locks/write, Microsoft.Authorization/locks/delete
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param (
    [Parameter(Mandatory = $false)]
    [ValidateSet('Audit', 'ApplyLock', 'RemoveLock')]
    [string]$Action = 'Audit',

    [Parameter(Mandatory = $false)]
    [ValidateSet('CanNotDelete', 'ReadOnly')]
    [string]$LockLevel = 'CanNotDelete',

    [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
    [string[]]$SubscriptionIds,

    [Parameter(Mandatory = $false)]
    [hashtable]$TagFilter,

    [Parameter(Mandatory = $false)]
    [string]$LockNotes = 'Managed by Enterprise Cloud Governance',

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

    $lockReport = [System.Collections.Generic.List[PSCustomObject]]::new()
    Write-Host "Executing Lock Management in '$Action' mode across $($subs.Count) subscription(s)..." -ForegroundColor Cyan

    foreach ($sub in $subs) {
        Set-AzContext -SubscriptionId $sub.Id -ErrorAction SilentlyContinue | Out-Null
        $rgs = Get-AzResourceGroup -ErrorAction SilentlyContinue

        foreach ($rg in $rgs) {
            # Filter by Tag if specified
            if ($TagFilter) {
                $rgTags = $rg.Tags
                if (-not $rgTags) { continue }
                $matched = $true
                foreach ($k in $TagFilter.Keys) {
                    if (-not $rgTags.ContainsKey($k) -or $rgTags[$k] -ne $TagFilter[$k]) {
                        $matched = $false
                        break
                    }
                }
                if (-not $matched) { continue }
            }

            $existingLocks = Get-AzResourceLock -ResourceGroupName $rg.ResourceGroupName -ErrorAction SilentlyContinue
            $hasTargetLock = ($existingLocks | Where-Object { $_.LockLevel -eq $LockLevel }).Count -gt 0

            $lockNames = if ($existingLocks) { ($existingLocks.Name -join ', ') } else { 'None' }
            $lockLevels = if ($existingLocks) { ($existingLocks.LockLevel -join ', ') } else { 'None' }

            $lockReport.Add([PSCustomObject]@{
                SubscriptionId      = $sub.Id
                ResourceGroupName   = $rg.ResourceGroupName
                Location            = $rg.Location
                ExistingLocks       = $lockNames
                ExistingLockLevels  = $lockLevels
                HasTargetLock       = $hasTargetLock
                Status              = if ($hasTargetLock) { 'Locked' } else { 'Unlocked' }
            })

            # Action: Apply Lock
            if ($Action -eq 'ApplyLock' -and -not $hasTargetLock) {
                $lockName = "lock-$LockLevel-$($rg.ResourceGroupName)"
                if ($PSCmdlet.ShouldProcess("Resource Group '$($rg.ResourceGroupName)'", "Apply $LockLevel lock ($lockName)")) {
                    try {
                        Write-Host "Applying $LockLevel lock to $($rg.ResourceGroupName)..." -ForegroundColor Yellow
                        New-AzResourceLock -LockLevel $LockLevel -LockName $lockName `
                            -ResourceGroupName $rg.ResourceGroupName -LockNotes $LockNotes -Force -ErrorAction Stop | Out-Null
                        Write-Host "Successfully applied lock to $($rg.ResourceGroupName)" -ForegroundColor Green
                    } catch {
                        Write-Error "Failed to apply lock to $($rg.ResourceGroupName): $($_.Exception.Message)"
                    }
                }
            }

            # Action: Remove Lock
            if ($Action -eq 'RemoveLock' -and $hasTargetLock) {
                $locksToRemove = $existingLocks | Where-Object { $_.LockLevel -eq $LockLevel }
                foreach ($l in $locksToRemove) {
                    if ($PSCmdlet.ShouldProcess("Lock '$($l.Name)' on '$($rg.ResourceGroupName)'", "Remove $LockLevel Lock")) {
                        try {
                            Write-Host "Removing lock $($l.Name) from $($rg.ResourceGroupName)..." -ForegroundColor Yellow
                            Remove-AzResourceLock -LockId $l.LockId -Force -ErrorAction Stop | Out-Null
                            Write-Host "Successfully removed lock $($l.Name)" -ForegroundColor Green
                        } catch {
                            Write-Error "Failed to remove lock $($l.Name): $($_.Exception.Message)"
                        }
                    }
                }
            }
        }
    }

    Write-Host "`nLock Management operation complete ($($lockReport.Count) resource groups inspected)." -ForegroundColor Green
    $lockReport | Select-Object ResourceGroupName, ExistingLockLevels, Status | Format-Table -AutoSize

    if ($ExportCsvPath) {
        $parent = Split-Path -Parent $ExportCsvPath
        if ($parent -and -not (Test-Path $parent)) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }
        $lockReport | Export-Csv -Path $ExportCsvPath -NoTypeInformation -Encoding UTF8
        Write-Host "Exported lock audit to: $ExportCsvPath" -ForegroundColor Cyan
    }

    return $lockReport
}
