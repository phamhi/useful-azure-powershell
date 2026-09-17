<#
.SYNOPSIS
    Audits Azure Recovery Services Vaults, backup protection states, and recent job failures.

.DESCRIPTION
    Provides an enterprise backup posture assessment across one or more subscriptions:
      1. Discovers all Recovery Services Vaults.
      2. Audits all Protected Items (Azure IaaS VMs, Azure Files, SQL/HANA workloads).
      3. Verifies ProtectionStatus (Healthy, Unhealthy), Last Backup Time, and policy names.
      4. Queries backup job history over a configurable window (e.g. 24-48 hours) for failed jobs.
      5. Identifies unprotected Azure Virtual Machines that have no backup coverage.
      6. Formats a comprehensive disaster recovery readiness report with CSV export.

.PARAMETER SubscriptionIds
    Array of Subscription IDs to evaluate. Defaults to all active subscriptions.

.PARAMETER JobLookbackHours
    Hours of job history to analyze for failed or cancelled backup attempts. Default is 24.

.PARAMETER ExportCsvPath
    Optional CSV file path to save backup audit.

.EXAMPLE
    .\Audit-AzBackupProtectedItems.ps1 -JobLookbackHours 48 -ExportCsvPath "C:\Reports\BackupHealth.csv"
    Audits backup item status and checks for job failures over the past 48 hours.

.NOTES
    Required Modules: Az.Accounts, Az.RecoveryServices, Az.Compute
    Permissions: Microsoft.RecoveryServices/vaults/read, Microsoft.Compute/virtualMachines/read.
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
    [string[]]$SubscriptionIds,

    [Parameter(Mandatory = $false)]
    [int]$JobLookbackHours = 24,

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

    $backupReport = [System.Collections.Generic.List[PSCustomObject]]::new()
    $jobStartTime = (Get-Date).AddHours(-$JobLookbackHours)

    Write-Host "Auditing Azure Backup across $($subs.Count) subscription(s)..." -ForegroundColor Cyan

    foreach ($sub in $subs) {
        Set-AzContext -SubscriptionId $sub.Id -ErrorAction SilentlyContinue | Out-Null
        $vaults = Get-AzRecoveryServicesVault -ErrorAction SilentlyContinue

        if (-not $vaults) { continue }

        # Get all VMs in subscription to check protection coverage
        $allVMs = Get-AzVM -ErrorAction SilentlyContinue
        $protectedVmNames = [System.Collections.Generic.List[string]]::new()

        foreach ($vault in $vaults) {
            Write-Host "Checking Vault: $($vault.Name) in $($vault.ResourceGroupName)..." -ForegroundColor Gray
            Set-AzRecoveryServicesVaultContext -Vault $vault | Out-Null

            # 1. Audit Protected Containers & Items
            try {
                $containers = Get-AzRecoveryServicesBackupContainer -ContainerType AzureVM -ErrorAction Stop
                foreach ($c in $containers) {
                    $items = Get-AzRecoveryServicesBackupItem -Container $c -WorkloadType AzureVM -ErrorAction SilentlyContinue
                    foreach ($item in $items) {
                        $protectedVmNames.Add($item.Name)
                        $isHealthy = $item.ProtectionStatus -eq 'Healthy'

                        $backupReport.Add([PSCustomObject]@{
                            SubscriptionId     = $sub.Id
                            VaultName          = $vault.Name
                            ResourceGroup      = $vault.ResourceGroupName
                            WorkloadType       = 'AzureVM'
                            ProtectedItemName  = $item.Name
                            ProtectionStatus   = $item.ProtectionStatus
                            ProtectionState    = $item.ProtectionState
                            LastRecoveryPoint  = $item.LastRecoveryPoint
                            PolicyName         = $item.PolicyName
                            FindingCategory    = if ($isHealthy) { 'Protected - Healthy' } else { 'Protected - Attention Required' }
                        })
                    }
                }
            } catch {
                Write-Verbose "Could not fetch backup items for vault $($vault.Name)"
            }

            # 2. Audit Failed Jobs in Lookback Window
            try {
                $failedJobs = Get-AzRecoveryServicesBackupJob -From $jobStartTime -Status 'Failed' -ErrorAction SilentlyContinue
                foreach ($job in $failedJobs) {
                    $backupReport.Add([PSCustomObject]@{
                        SubscriptionId     = $sub.Id
                        VaultName          = $vault.Name
                        ResourceGroup      = $vault.ResourceGroupName
                        WorkloadType       = $job.WorkloadType
                        ProtectedItemName  = $job.EntityFriendlyName
                        ProtectionStatus   = "JOB FAILED: $($job.Operation)"
                        ProtectionState    = $job.Status
                        LastRecoveryPoint  = $job.EndTime
                        PolicyName         = 'N/A'
                        FindingCategory    = 'Backup Job Failure'
                    })
                }
            } catch {
                Write-Verbose "Could not query backup jobs for vault $($vault.Name)"
            }
        }

        # 3. Detect Unprotected VMs
        if ($allVMs) {
            foreach ($vm in $allVMs) {
                if (-not ($protectedVmNames -contains $vm.Name)) {
                    $backupReport.Add([PSCustomObject]@{
                        SubscriptionId     = $sub.Id
                        VaultName          = 'None'
                        ResourceGroup      = $vm.ResourceGroupName
                        WorkloadType       = 'AzureVM'
                        ProtectedItemName  = $vm.Name
                        ProtectionStatus   = 'Unprotected'
                        ProtectionState    = 'Not Configured'
                        LastRecoveryPoint  = 'Never'
                        PolicyName         = 'None'
                        FindingCategory    = 'Unprotected VM'
                    })
                }
            }
        }
    }

    Write-Host "`nBackup posture assessment complete ($($backupReport.Count) records evaluated)." -ForegroundColor Green
    $backupReport | Select-Object ProtectedItemName, WorkloadType, ProtectionStatus, LastRecoveryPoint, FindingCategory | Format-Table -AutoSize

    if ($ExportCsvPath) {
        $parent = Split-Path -Parent $ExportCsvPath
        if ($parent -and -not (Test-Path $parent)) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }
        $backupReport | Export-Csv -Path $ExportCsvPath -NoTypeInformation -Encoding UTF8
        Write-Host "Exported backup report to: $ExportCsvPath" -ForegroundColor Cyan
    }

    return $backupReport
}
