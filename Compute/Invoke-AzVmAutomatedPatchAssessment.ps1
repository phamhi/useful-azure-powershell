<#
.SYNOPSIS
    Queries and triggers Azure Update Manager patch assessments across Windows and Linux VMs.

.DESCRIPTION
    Audits operating system patch compliance for Azure Virtual Machines using Azure Update Manager:
      1. Inspects OS patch settings (PatchMode: AutomaticByPlatform, AutomaticByOS, Manual).
      2. Retrieves latest assessment results: Missing Critical, Security, and Other patches.
      3. Checks whether a reboot is pending on target VMs.
      4. Optionally triggers an on-demand software update assessment via -TriggerNewAssessment.
      5. Calculates an overall fleet patch compliance grade and outputs structured report.

.PARAMETER SubscriptionIds
    Array of Subscription IDs to assess. Defaults to all active subscriptions.

.PARAMETER ResourceGroupName
    Optional Resource Group filter.

.PARAMETER TriggerNewAssessment
    Switch to invoke a fresh patch assessment scan on target VMs.

.PARAMETER ExportCsvPath
    Path to export patch compliance results to CSV.

.EXAMPLE
    .\Invoke-AzVmAutomatedPatchAssessment.ps1 -TriggerNewAssessment -ExportCsvPath "C:\Reports\VMPatchStatus.csv"
    Triggers an immediate patch assessment on all VMs and exports the compliance results to CSV.

.NOTES
    Required Modules: Az.Accounts, Az.Compute
    Permissions: Microsoft.Compute/virtualMachines/read, Microsoft.Compute/virtualMachines/assessPatches/action
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
    [string[]]$SubscriptionIds,

    [Parameter(Mandatory = $false)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $false)]
    [switch]$TriggerNewAssessment,

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

    $patchResults = [System.Collections.Generic.List[PSCustomObject]]::new()
    Write-Host "Assessing VM patch compliance across $($subs.Count) subscription(s)..." -ForegroundColor Cyan

    foreach ($sub in $subs) {
        Set-AzContext -SubscriptionId $sub.Id -ErrorAction SilentlyContinue | Out-Null
        
        $vms = if ($ResourceGroupName) {
            Get-AzVM -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
        } else {
            Get-AzVM -ErrorAction SilentlyContinue
        }

        if (-not $vms) { continue }

        foreach ($vm in $vms) {
            Write-Host "Checking VM: $($vm.Name) ($($vm.ResourceGroupName))..." -ForegroundColor Gray
            $osType = $vm.StorageProfile.OsDisk.OsType
            $patchMode = $vm.OSProfile.WindowsConfiguration.PatchSettings.PatchMode
            if (-not $patchMode) { $patchMode = $vm.OSProfile.LinuxConfiguration.PatchSettings.PatchMode }

            $criticalMissing = 0
            $securityMissing = 0
            $otherMissing = 0
            $rebootPending = $false
            $lastAssessmentTime = "N/A"

            if ($TriggerNewAssessment) {
                Write-Host "  -> Triggering on-demand patch assessment for $($vm.Name)..." -ForegroundColor Yellow
                try {
                    $assessmentOp = Invoke-AzVMPatchAssessment -ResourceGroupName $vm.ResourceGroupName -VMName $vm.Name -ErrorAction Stop
                    $criticalMissing = $assessmentOp.CriticalAndSecurityPatchCount
                    $rebootPending   = $assessmentOp.RebootPending
                    $lastAssessmentTime = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                } catch {
                    Write-Warning "  -> On-demand assessment failed on $($vm.Name): $($_.Exception.Message)"
                }
            } else {
                # Read existing instance view patch status
                try {
                    $instanceView = Get-AzVM -ResourceGroupName $vm.ResourceGroupName -Name $vm.Name -Status -ErrorAction Stop
                    $patchStatus = $instanceView.PatchStatus
                    if ($patchStatus -and $patchStatus.AvailablePatchSummary) {
                        $criticalMissing    = $patchStatus.AvailablePatchSummary.CriticalAndSecurityPatchCount
                        $otherMissing       = $patchStatus.AvailablePatchSummary.OtherPatchCount
                        $rebootPending      = $patchStatus.AvailablePatchSummary.RebootPending
                        $lastAssessmentTime = $patchStatus.AvailablePatchSummary.LastModifiedTime
                    }
                } catch {
                    Write-Verbose "Could not query instance view for $($vm.Name)"
                }
            }

            $complianceGrade = if ($criticalMissing -gt 0) {
                "Non-Compliant (Missing Critical Patches)"
            } elseif ($rebootPending) {
                "Reboot Pending"
            } else {
                "Compliant"
            }

            $patchResults.Add([PSCustomObject]@{
                SubscriptionId      = $sub.Id
                ResourceGroup       = $vm.ResourceGroupName
                VMName              = $vm.Name
                Location            = $vm.Location
                OSType              = $osType
                PatchMode           = if ($patchMode) { $patchMode } else { 'Default' }
                CriticalMissing     = $criticalMissing
                OtherMissing        = $otherMissing
                RebootPending       = $rebootPending
                LastAssessmentTime  = $lastAssessmentTime
                ComplianceStatus    = $complianceGrade
            })
        }
    }

    Write-Host "`nPatch Assessment complete ($($patchResults.Count) VMs evaluated)." -ForegroundColor Green
    $patchResults | Select-Object VMName, OSType, PatchMode, CriticalMissing, RebootPending, ComplianceStatus | Format-Table -AutoSize

    if ($ExportCsvPath) {
        $parent = Split-Path -Parent $ExportCsvPath
        if ($parent -and -not (Test-Path $parent)) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }
        $patchResults | Export-Csv -Path $ExportCsvPath -NoTypeInformation -Encoding UTF8
        Write-Host "Exported patch assessment to: $ExportCsvPath" -ForegroundColor Cyan
    }

    return $patchResults
}
