<#
.SYNOPSIS
    Audits Azure Key Vaults for expiring or expired SSL/TLS certificates and secrets.

.DESCRIPTION
    Scans Key Vaults across one or more subscriptions to identify certificates and secrets
    approaching expiration or already expired:
      1. Inspects certificate attributes (NotBefore, Expires, Enabled).
      2. Checks certificate auto-renewal lifetime actions (e.g. renewal at 80% lifetime).
      3. Inspects secret expiration attributes.
      4. Calculates remaining days to expiry, classifying by urgency (Expired, Critical, Warning, OK).
      5. Generates structured output with export to CSV/HTML for operational alerting.

.PARAMETER SubscriptionIds
    Array of Subscription IDs to check. Defaults to all active subscriptions.

.PARAMETER DaysThreshold
    Number of days before expiration to trigger a warning status. Default is 30 days.

.PARAMETER IncludeSecrets
    Switch to also inspect expiring Key Vault secrets in addition to certificates.

.PARAMETER ExportCsvPath
    Optional CSV file path for report generation.

.EXAMPLE
    .\Test-AzKeyVaultCertificateExpiry.ps1 -DaysThreshold 45 -IncludeSecrets -ExportCsvPath "C:\Reports\KeyVaultExpirations.csv"
    Audits all certificates and secrets expiring within 45 days and exports findings to CSV.

.NOTES
    Required Modules: Az.Accounts, Az.KeyVault
    Permissions: Key Vault Secrets User / Key Vault Certificates Officer (or access policy with Get, List).
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
    [string[]]$SubscriptionIds,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 365)]
    [int]$DaysThreshold = 30,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeSecrets,

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

    $report = [System.Collections.Generic.List[PSCustomObject]]::new()
    $now = Get-Date

    Write-Host "Auditing Key Vault expiry within $DaysThreshold days across $($subs.Count) subscription(s)..." -ForegroundColor Cyan

    foreach ($sub in $subs) {
        Set-AzContext -SubscriptionId $sub.Id -ErrorAction SilentlyContinue | Out-Null
        $vaults = Get-AzKeyVault -ErrorAction SilentlyContinue

        foreach ($kv in $vaults) {
            Write-Host "Checking Key Vault: $($kv.VaultName)..." -ForegroundColor Gray

            # 1. Certificates
            try {
                $certs = Get-AzKeyVaultCertificate -VaultName $kv.VaultName -ErrorAction Stop
                foreach ($cert in $certs) {
                    $expires = $cert.Expires
                    $daysRemaining = if ($expires) { [math]::Round(($expires - $now).TotalDays, 0) } else { 9999 }
                    $autoRenew = "Not Configured"

                    try {
                        $policy = Get-AzKeyVaultCertificatePolicy -VaultName $kv.VaultName -Name $cert.Name -ErrorAction SilentlyContinue
                        if ($policy.LifetimeActions) {
                            $renewAction = $policy.LifetimeActions | Where-Object { $_.Action -eq 'AutoRenew' }
                            if ($renewAction) {
                                $autoRenew = if ($renewAction.DaysBeforeExpiry) { "AutoRenew ($($renewAction.DaysBeforeExpiry)d before)" } else { "AutoRenew ($($renewAction.LifetimePercentage)%)" }
                            }
                        }
                    } catch { }

                    $status = if (-not $cert.Enabled) {
                        "Disabled"
                    } elseif ($daysRemaining -le 0) {
                        "EXPIRED"
                    } elseif ($daysRemaining -le 14) {
                        "CRITICAL (< 14 days)"
                    } elseif ($daysRemaining -le $DaysThreshold) {
                        "WARNING (< $DaysThreshold days)"
                    } else {
                        "Healthy"
                    }

                    if ($status -ne 'Healthy' -or $DaysThreshold -ge 90) {
                        $report.Add([PSCustomObject]@{
                            SubscriptionId = $sub.Id
                            VaultName      = $kv.VaultName
                            ItemType       = 'Certificate'
                            ItemName       = $cert.Name
                            Enabled        = $cert.Enabled
                            Expires        = $expires
                            DaysRemaining  = $daysRemaining
                            AutoRenewPolicy= $autoRenew
                            Status         = $status
                        })
                    }
                }
            } catch {
                Write-Verbose "Could not read certificates from vault $($kv.VaultName): $($_.Exception.Message)"
            }

            # 2. Secrets (if requested)
            if ($IncludeSecrets) {
                try {
                    $secrets = Get-AzKeyVaultSecret -VaultName $kv.VaultName -ErrorAction Stop
                    foreach ($sec in $secrets) {
                        $expires = $sec.Expires
                        $daysRemaining = if ($expires) { [math]::Round(($expires - $now).TotalDays, 0) } else { 9999 }

                        $status = if (-not $sec.Enabled) {
                            "Disabled"
                        } elseif ($null -eq $expires) {
                            "No Expiration Set"
                        } elseif ($daysRemaining -le 0) {
                            "EXPIRED"
                        } elseif ($daysRemaining -le $DaysThreshold) {
                            "WARNING (< $DaysThreshold days)"
                        } else {
                            "Healthy"
                        }

                        if ($status -in @('EXPIRED', "WARNING (< $DaysThreshold days)")) {
                            $report.Add([PSCustomObject]@{
                                SubscriptionId = $sub.Id
                                VaultName      = $kv.VaultName
                                ItemType       = 'Secret'
                                ItemName       = $sec.Name
                                Enabled        = $sec.Enabled
                                Expires        = $expires
                                DaysRemaining  = $daysRemaining
                                AutoRenewPolicy= 'N/A'
                                Status         = $status
                            })
                        }
                    }
                } catch {
                    Write-Verbose "Could not read secrets from vault $($kv.VaultName): $($_.Exception.Message)"
                }
            }
        }
    }

    Write-Host "`nExpiry audit complete. Discovered $($report.Count) item(s) requiring attention." -ForegroundColor Yellow
    $report | Select-Object VaultName, ItemType, ItemName, DaysRemaining, AutoRenewPolicy, Status | Format-Table -AutoSize

    if ($ExportCsvPath) {
        $parent = Split-Path -Parent $ExportCsvPath
        if ($parent -and -not (Test-Path $parent)) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }
        $report | Export-Csv -Path $ExportCsvPath -NoTypeInformation -Encoding UTF8
        Write-Host "Exported report to: $ExportCsvPath" -ForegroundColor Cyan
    }

    return $report
}
