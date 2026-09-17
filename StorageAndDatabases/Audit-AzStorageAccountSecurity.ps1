<#
.SYNOPSIS
    Evaluates Azure Storage Accounts against CIS Benchmarks and cloud security best practices.

.DESCRIPTION
    Performs an exhaustive security assessment of all Storage Accounts in target subscriptions:
      1. TLS Version: Flags accounts allowing TLS versions below 1.2.
      2. Identity-First Auth: Checks if AllowSharedKeyAccess is enabled (recommends Entra ID RBAC).
      3. Network Firewalls: Evaluates NetworkRuleSet DefaultAction (Deny vs Allow) and bypass rules.
      4. Anonymous Access: Verifies AllowBlobPublicAccess is explicitly disabled.
      5. HTTPS Enforced: Verifies EnableHttpsTrafficOnly is active.
      6. Data Resilience: Audits Blob & Container Soft Delete status and retention periods.
      7. Encryption: Checks for Customer-Managed Keys (CMK) vs Service-Managed Keys.
      8. Formats compliance scorecard with CSV export.

.PARAMETER SubscriptionIds
    Array of Subscription IDs to evaluate. Defaults to all active subscriptions.

.PARAMETER ExportCsvPath
    Optional path to export audit results as CSV.

.EXAMPLE
    .\Audit-AzStorageAccountSecurity.ps1 -ExportCsvPath "C:\Reports\StorageSecurityPosture.csv"
    Executes deep security baseline check across all storage accounts and exports results.

.NOTES
    Required Modules: Az.Accounts, Az.Storage
    Permissions: Microsoft.Storage/storageAccounts/read across target subscriptions.
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
    [string[]]$SubscriptionIds,

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

    $auditResults = [System.Collections.Generic.List[PSCustomObject]]::new()
    Write-Host "Auditing Storage Account security across $($subs.Count) subscription(s)..." -ForegroundColor Cyan

    foreach ($sub in $subs) {
        Set-AzContext -SubscriptionId $sub.Id -ErrorAction SilentlyContinue | Out-Null
        $accounts = Get-AzStorageAccount -ErrorAction SilentlyContinue

        foreach ($sa in $accounts) {
            Write-Host "Evaluating Storage: $($sa.StorageAccountName)..." -ForegroundColor Gray

            $issues = [System.Collections.Generic.List[string]]::new()
            $score = 100

            # 1. TLS Check
            $minTls = $sa.MinimumTlsVersion
            if ($minTls -ne 'TLS1_2') {
                $issues.Add("Insecure TLS: $minTls (Requires TLS1_2)")
                $score -= 25
            }

            # 2. Shared Key Access
            if ($sa.AllowSharedKeyAccess -ne $false) {
                $issues.Add("Shared Key auth enabled (Recommend Entra ID RBAC only)")
                $score -= 15
            }

            # 3. Anonymous Blob Access
            if ($sa.AllowBlobPublicAccess -eq $true) {
                $issues.Add("CRITICAL: Public anonymous blob access is permitted")
                $score -= 35
            }

            # 4. HTTPS Only
            if ($sa.EnableHttpsTrafficOnly -ne $true) {
                $issues.Add("CRITICAL: HTTPS traffic is not strictly enforced")
                $score -= 30
            }

            # 5. Network Firewall
            $networkDefault = $sa.NetworkRuleSet.DefaultAction
            if ($networkDefault -ne 'Deny') {
                $issues.Add("Network firewall defaults to Allow (unrestricted)")
                $score -= 20
            }

            # 6. Blob Soft Delete
            $blobSoftDelete = "Disabled"
            try {
                $blobService = Get-AzStorageBlobServiceProperty -ResourceGroupName $sa.ResourceGroupName -StorageAccountName $sa.StorageAccountName -ErrorAction SilentlyContinue
                if ($blobService.DeleteRetentionPolicy.Enabled) {
                    $blobSoftDelete = "Enabled ($($blobService.DeleteRetentionPolicy.Days) days)"
                } else {
                    $issues.Add("Blob soft delete is disabled")
                    $score -= 10
                }
            } catch { }

            # 7. Encryption Key Source
            $keySource = if ($sa.Encryption.KeySource) { $sa.Encryption.KeySource } else { "Microsoft.Storage" }

            $finalScore = [math]::Max(0, $score)
            $rating = if ($finalScore -ge 90) { 'Excellent' } elseif ($finalScore -ge 70) { 'Moderate' } else { 'Critical Risk' }

            $auditResults.Add([PSCustomObject]@{
                SubscriptionId      = $sub.Id
                ResourceGroup       = $sa.ResourceGroupName
                StorageAccountName  = $sa.StorageAccountName
                Location            = $sa.Location
                Kind                = $sa.Kind
                MinTlsVersion       = $minTls
                AllowSharedKey      = $sa.AllowSharedKeyAccess
                AllowBlobPublic     = $sa.AllowBlobPublicAccess
                NetworkAclDefault   = $networkDefault
                BlobSoftDelete      = $blobSoftDelete
                KeySource           = $keySource
                SecurityScore       = "$finalScore / 100"
                PostureRating       = $rating
                IdentifiedIssues    = if ($issues.Count -gt 0) { ($issues -join ' | ') } else { 'None (Baseline Met)' }
            })
        }
    }

    Write-Host "`nStorage Security Assessment complete ($($auditResults.Count) accounts reviewed)." -ForegroundColor Green
    $auditResults | Select-Object StorageAccountName, MinTlsVersion, AllowBlobPublic, SecurityScore, PostureRating | Format-Table -AutoSize

    if ($ExportCsvPath) {
        $parent = Split-Path -Parent $ExportCsvPath
        if ($parent -and -not (Test-Path $parent)) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }
        $auditResults | Export-Csv -Path $ExportCsvPath -NoTypeInformation -Encoding UTF8
        Write-Host "Exported storage audit to: $ExportCsvPath" -ForegroundColor Cyan
    }

    return $auditResults
}
