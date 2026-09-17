<#
.SYNOPSIS
    Identifies and safely decommissions empty or TTL-expired Azure Resource Groups.

.DESCRIPTION
    Scans Resource Groups across subscriptions to locate candidates for decommissioning:
      1. Truly empty resource groups (containing 0 child resources).
      2. Resource groups with expiration or TTL tags (e.g., 'ExpiresOn', 'TTL', 'AutoDeleteAfter')
         where the current timestamp exceeds the configured expiration date.
      3. Checks for Management Locks (CanNotDelete, ReadOnly) on candidate resource groups
         to prevent unauthorized or accidental destructive actions.
      4. Provides safe dry-run preview via -WhatIf and audit manifest generation.

.PARAMETER SubscriptionIds
    Array of Subscription IDs to scan. Defaults to all active subscriptions.

.PARAMETER ExpirationTagNames
    Names of tags that contain expiration timestamps. Defaults to @('ExpiresOn', 'TTL', 'AutoDeleteDate', 'DeleteAfter').

.PARAMETER IncludeEmptyGroups
    Switch parameter to flag resource groups with zero resources as cleanup candidates. Defaults to $true.

.PARAMETER RemoveLocksAndDecommission
    If specified, automatically removes blocking locks before deleting the resource group.
    Requires explicit -Confirm or -WhatIf validation.

.PARAMETER Delete
    Switch to execute resource group deletion.

.EXAMPLE
    .\Clean-AzStaleResourceGroups.ps1 -IncludeEmptyGroups -Delete -WhatIf
    Performs a dry-run check to list empty or expired resource groups that would be removed.

.EXAMPLE
    .\Clean-AzStaleResourceGroups.ps1 -ExpirationTagNames 'DecomDate'
    Scans all resource groups using a custom decommissioning tag name.

.NOTES
    Required Modules: Az.Accounts, Az.Resources
    Permissions: Contributor / Owner on target subscriptions.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param (
    [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
    [string[]]$SubscriptionIds,

    [Parameter(Mandatory = $false)]
    [string[]]$ExpirationTagNames = @('ExpiresOn', 'TTL', 'AutoDeleteDate', 'DeleteAfter'),

    [Parameter(Mandatory = $false)]
    [bool]$IncludeEmptyGroups = $true,

    [Parameter(Mandatory = $false)]
    [switch]$RemoveLocksAndDecommission,

    [Parameter(Mandatory = $false)]
    [switch]$Delete
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

    $candidates = [System.Collections.Generic.List[PSCustomObject]]::new()
    $now = Get-Date

    foreach ($sub in $subs) {
        Set-AzContext -SubscriptionId $sub.Id -ErrorAction SilentlyContinue | Out-Null
        $rgs = Get-AzResourceGroup -ErrorAction SilentlyContinue

        foreach ($rg in $rgs) {
            $resources = Get-AzResource -ResourceGroupName $rg.ResourceGroupName -ErrorAction SilentlyContinue
            $resCount = if ($resources) { $resources.Count } else { 0 }

            $isExpired = $false
            $expirationTagFound = $null
            $expirationDateVal = $null

            # Check tags for TTL / Expiration
            if ($rg.Tags) {
                foreach ($tagName in $ExpirationTagNames) {
                    if ($rg.Tags.ContainsKey($tagName)) {
                        $expirationTagFound = $tagName
                        $tagStr = $rg.Tags[$tagName]
                        [DateTime]$parsedDate = [DateTime]::MinValue
                        if ([DateTime]::TryParse($tagStr, [ref]$parsedDate)) {
                            $expirationDateVal = $parsedDate
                            if ($parsedDate -lt $now) {
                                $isExpired = $true
                            }
                        }
                        break
                    }
                }
            }

            $shouldFlag = ($IncludeEmptyGroups -and $resCount -eq 0) -or $isExpired

            if ($shouldFlag) {
                # Check for management locks
                $locks = Get-AzResourceLock -ResourceGroupName $rg.ResourceGroupName -ErrorAction SilentlyContinue
                $lockTypes = if ($locks) { ($locks.LockLevel -join ', ') } else { 'None' }

                $reason = if ($resCount -eq 0 -and $isExpired) {
                    "Empty (0 resources) and Expired Tag ($expirationTagFound = $expirationDateVal)"
                } elseif ($resCount -eq 0) {
                    "Empty Resource Group (0 child resources)"
                } else {
                    "Expired Tag ($expirationTagFound = $expirationDateVal)"
                }

                $candidates.Add([PSCustomObject]@{
                    SubscriptionId    = $sub.Id
                    ResourceGroupName = $rg.ResourceGroupName
                    Location          = $rg.Location
                    ResourceCount     = $resCount
                    LockStatus        = $lockTypes
                    ExpirationTag     = $expirationTagFound
                    ExpirationDate    = $expirationDateVal
                    Reason            = $reason
                })
            }
        }
    }

    Write-Host "`nDiscovered $($candidates.Count) candidate Resource Group(s) for cleanup." -ForegroundColor Yellow
    $candidates | Format-Table -AutoSize

    if ($Delete -and $candidates.Count -gt 0) {
        foreach ($item in $candidates) {
            if ($item.LockStatus -ne 'None' -and -not $RemoveLocksAndDecommission) {
                Write-Warning "Skipping $($item.ResourceGroupName): Protected by locks ($($item.LockStatus)). Use -RemoveLocksAndDecommission to override."
                continue
            }

            if ($PSCmdlet.ShouldProcess("Resource Group '$($item.ResourceGroupName)' in sub '$($item.SubscriptionId)'", "Decommission Resource Group")) {
                try {
                    Set-AzContext -SubscriptionId $item.SubscriptionId -ErrorAction SilentlyContinue | Out-Null
                    if ($item.LockStatus -ne 'None' -and $RemoveLocksAndDecommission) {
                        Write-Host "Removing locks on $($item.ResourceGroupName)..." -ForegroundColor Yellow
                        $existingLocks = Get-AzResourceLock -ResourceGroupName $item.ResourceGroupName
                        foreach ($l in $existingLocks) {
                            Remove-AzResourceLock -LockId $l.LockId -Force -ErrorAction Stop
                        }
                    }

                    Write-Host "Deleting Resource Group: $($item.ResourceGroupName)..." -ForegroundColor Red
                    Remove-AzResourceGroup -Name $item.ResourceGroupName -Force -AsJob -ErrorAction Stop | Out-Null
                    Write-Host "Deletion job dispatched for $($item.ResourceGroupName)" -ForegroundColor Green
                } catch {
                    Write-Error "Failed to delete RG $($item.ResourceGroupName): $($_.Exception.Message)"
                }
            }
        }
    }

    return $candidates
}
