<#
.SYNOPSIS
    Catalogs Azure Monitor Scheduled Query Rules (Alerts), Action Groups, and evaluates notification health.

.DESCRIPTION
    Extracts and audits alerting infrastructure across Azure subscriptions:
      1. Discovers all Scheduled Query Alert Rules (KQL-based alerts).
      2. Analyzes alert configurations: Query text, Severity, Frequency, Window size, and Thresholds.
      3. Correlates configured Action Groups and extracts notification destinations (Email, Webhook, SMS, LogicApps).
      4. Identifies Broken Alerts (where the configured Action Group no longer exists or was deleted).
      5. Formats an operational alert inventory and runbook catalog with CSV export capability.

.PARAMETER SubscriptionIds
    Array of Subscription IDs to evaluate. Defaults to all active subscriptions.

.PARAMETER ExportCsvPath
    Optional file path to output CSV results.

.EXAMPLE
    .\Export-AzLogAnalyticsQueryAlerts.ps1 -ExportCsvPath "C:\Reports\AlertInventory.csv"
    Extracts all KQL query alerts and action group bindings across subscriptions.

.NOTES
    Required Modules: Az.Accounts, Az.Monitor
    Permissions: Microsoft.Insights/scheduledQueryRules/read, Microsoft.Insights/actionGroups/read.
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

    $alertCatalog = [System.Collections.Generic.List[PSCustomObject]]::new()
    Write-Host "Cataloging Scheduled Query Alerts across $($subs.Count) subscription(s)..." -ForegroundColor Cyan

    foreach ($sub in $subs) {
        Set-AzContext -SubscriptionId $sub.Id -ErrorAction SilentlyContinue | Out-Null
        
        # Pre-fetch action groups in subscription
        $actionGroups = Get-AzActionGroup -ErrorAction SilentlyContinue
        $actionGroupIds = if ($actionGroups) { $actionGroups.Id } else { @() }

        $queryRules = Get-AzScheduledQueryRule -ErrorAction SilentlyContinue
        if (-not $queryRules) { continue }

        foreach ($rule in $queryRules) {
            $associatedActionGroups = $rule.Action
            $actionGroupStatus = "OK"
            $destinations = [System.Collections.Generic.List[string]]::new()

            if ($associatedActionGroups -and $associatedActionGroups.Count -gt 0) {
                foreach ($agId in $associatedActionGroups) {
                    $matchedAg = $actionGroups | Where-Object { $_.Id -eq $agId }
                    if ($matchedAg) {
                        # Summarize receivers
                        if ($matchedAg.EmailReceivers) { $destinations.Add("Email: $($matchedAg.EmailReceivers.EmailAddress -join ', ')") }
                        if ($matchedAg.WebhookReceivers) { $destinations.Add("Webhook: $($matchedAg.WebhookReceivers.Name -join ', ')") }
                        if ($matchedAg.SmsReceivers) { $destinations.Add("SMS: $($matchedAg.SmsReceivers.PhoneNumber -join ', ')") }
                    } else {
                        $actionGroupStatus = "ORPHANED: Action Group resource not found ($agId)"
                    }
                }
            } else {
                $actionGroupStatus = "NO ACTION GROUP ASSIGNED (Silent Alert)"
            }

            $alertCatalog.Add([PSCustomObject]@{
                SubscriptionId      = $sub.Id
                ResourceGroup       = $rule.ResourceGroupName
                AlertRuleName       = $rule.Name
                Enabled             = $rule.Enabled
                Severity            = $rule.Severity
                EvaluationFrequency = $rule.EvaluationFrequency
                WindowSize          = $rule.WindowSize
                QuerySnippet        = if ($rule.Criteria.AllOf[0].Query.Length -gt 100) { $rule.Criteria.AllOf[0].Query.Substring(0, 100) + '...' } else { $rule.Criteria.AllOf[0].Query }
                ActionGroupStatus   = $actionGroupStatus
                NotificationTargets = ($destinations -join ' | ')
            })
        }
    }

    Write-Host "`nCataloged $($alertCatalog.Count) Scheduled Query Alert(s)." -ForegroundColor Green
    $alertCatalog | Select-Object AlertRuleName, Enabled, Severity, ActionGroupStatus, NotificationTargets | Format-Table -AutoSize

    if ($ExportCsvPath) {
        $parent = Split-Path -Parent $ExportCsvPath
        if ($parent -and -not (Test-Path $parent)) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }
        $alertCatalog | Export-Csv -Path $ExportCsvPath -NoTypeInformation -Encoding UTF8
        Write-Host "Exported alerts catalog to: $ExportCsvPath" -ForegroundColor Cyan
    }

    return $alertCatalog
}
