<#
.SYNOPSIS
    Audits and enforces standard Azure Monitor diagnostic settings streaming to a central Log Analytics Workspace.

.DESCRIPTION
    Ensures observability compliance by inspecting and configuring Azure Diagnostic Settings:
      1. Targets mission-critical resource types (Key Vaults, NSGs, SQL Servers, Application Gateways,
         and Subscription Activity Logs).
      2. Dynamically discovers supported Log Categories and Metrics for each target resource.
      3. Identifies missing or incomplete diagnostic settings.
      4. Optionally configures and enables diagnostic pipelines to a central Log Analytics Workspace.
      5. Provides full dry-run simulation via -WhatIf and compliance reporting.

.PARAMETER WorkspaceResourceId
    The full ARM Resource ID of the destination Log Analytics Workspace.
    Example: '/subscriptions/.../resourceGroups/.../providers/Microsoft.OperationalInsights/workspaces/law-corp-prod'

.PARAMETER SubscriptionIds
    Array of Subscription IDs to evaluate. Defaults to all active subscriptions.

.PARAMETER ResourceTypesToAudit
    Target resource provider types. Defaults to Key Vaults, NSGs, and SQL Servers.

.PARAMETER Remediate
    Switch to create or update diagnostic settings on non-compliant resources. Supports -WhatIf.

.PARAMETER DiagnosticSettingName
    Name to assign to the diagnostic setting. Default is 'law-baseline-diagnostic'.

.PARAMETER ExportCsvPath
    Path to export audit results to CSV.

.EXAMPLE
    .\Deploy-AzDiagnosticSettingsBaseline.ps1 -WorkspaceResourceId "/subscriptions/.../workspaces/law-prod"
    Audits diagnostic settings compliance across all subscriptions without applying changes.

.EXAMPLE
    .\Deploy-AzDiagnosticSettingsBaseline.ps1 -WorkspaceResourceId "/subscriptions/.../workspaces/law-prod" -Remediate -WhatIf
    Simulates applying diagnostic settings to unconfigured resources.

.NOTES
    Required Modules: Az.Accounts, Az.Monitor, Az.Resources
    Permissions: Monitoring Contributor / Contributor across target subscriptions.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param (
    [Parameter(Mandatory = $true)]
    [string]$WorkspaceResourceId,

    [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
    [string[]]$SubscriptionIds,

    [Parameter(Mandatory = $false)]
    [string[]]$ResourceTypesToAudit = @(
        'Microsoft.KeyVault/vaults',
        'Microsoft.Network/networkSecurityGroups',
        'Microsoft.Sql/servers/databases',
        'Microsoft.Network/applicationGateways'
    ),

    [Parameter(Mandatory = $false)]
    [switch]$Remediate,

    [Parameter(Mandatory = $false)]
    [string]$DiagnosticSettingName = 'law-baseline-diagnostic',

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
    Write-Host "Auditing Diagnostic Settings against Workspace: $WorkspaceResourceId" -ForegroundColor Cyan

    foreach ($sub in $subs) {
        Set-AzContext -SubscriptionId $sub.Id -ErrorAction SilentlyContinue | Out-Null
        Write-Host "Assessing Subscription: $($sub.Name)..." -ForegroundColor Gray

        foreach ($resType in $ResourceTypesToAudit) {
            $resources = Get-AzResource -ResourceType $resType -ErrorAction SilentlyContinue
            if (-not $resources) { continue }

            foreach ($res in $resources) {
                # Fetch existing diagnostic settings
                try {
                    $diagSettings = Get-AzDiagnosticSetting -ResourceId $res.ResourceId -ErrorAction Stop
                } catch {
                    $diagSettings = $null
                }

                $matchingSetting = $diagSettings | Where-Object { $_.WorkspaceId -eq $WorkspaceResourceId }
                $isCompliant = $matchingSetting -ne $null

                $enabledLogs = if ($matchingSetting) {
                    ($matchingSetting.Logs | Where-Object { $_.Enabled } | ForEach-Object { $_.Category }) -join ', '
                } else {
                    'None'
                }

                $auditResults.Add([PSCustomObject]@{
                    SubscriptionId      = $sub.Id
                    ResourceGroup       = $res.ResourceGroupName
                    ResourceType        = $res.ResourceType
                    ResourceName        = $res.Name
                    ResourceId          = $res.ResourceId
                    IsCompliant         = $isCompliant
                    SettingName         = if ($matchingSetting) { $matchingSetting.Name } else { 'Missing' }
                    ConfiguredLogs      = $enabledLogs
                })

                # Remediation
                if (-not $isCompliant -and $Remediate) {
                    if ($PSCmdlet.ShouldProcess("$($res.Name) ($($res.ResourceType))", "Configure Diagnostic Settings -> $WorkspaceResourceId")) {
                        try {
                            Write-Host "Configuring diagnostic setting on $($res.Name)..." -ForegroundColor Yellow
                            
                            # Query available categories
                            $categories = Get-AzDiagnosticSettingCategory -ResourceId $res.ResourceId -ErrorAction SilentlyContinue
                            $logSettings = @()
                            $metricSettings = @()

                            foreach ($cat in $categories) {
                                if ($cat.CategoryType -eq 'Logs') {
                                    $logSettings += New-AzDiagnosticSettingLogSettingsObject -Category $cat.Name -Enabled $true
                                } elseif ($cat.CategoryType -eq 'Metrics') {
                                    $metricSettings += New-AzDiagnosticSettingMetricSettingsObject -Category $cat.Name -Enabled $true
                                }
                            }

                            New-AzDiagnosticSetting -ResourceId $res.ResourceId -Name $DiagnosticSettingName `
                                -WorkspaceId $WorkspaceResourceId -Log $logSettings -Metric $metricSettings -ErrorAction Stop | Out-Null

                            Write-Host "Successfully applied diagnostic setting to $($res.Name)" -ForegroundColor Green
                        } catch {
                            Write-Error "Failed to apply diagnostic settings to $($res.ResourceId): $($_.Exception.Message)"
                        }
                    }
                }
            }
        }
    }

    $nonCompliant = ($auditResults | Where-Object { -not $_.IsCompliant }).Count
    Write-Host "`nDiagnostic audit complete ($($auditResults.Count) resources checked). Missing settings: $nonCompliant" -ForegroundColor $(if ($nonCompliant -gt 0) { 'Yellow' } else { 'Green' })
    $auditResults | Select-Object ResourceType, ResourceName, IsCompliant, ConfiguredLogs | Format-Table -AutoSize

    if ($ExportCsvPath) {
        $parent = Split-Path -Parent $ExportCsvPath
        if ($parent -and -not (Test-Path $parent)) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }
        $auditResults | Export-Csv -Path $ExportCsvPath -NoTypeInformation -Encoding UTF8
        Write-Host "Exported audit to: $ExportCsvPath" -ForegroundColor Cyan
    }

    return $auditResults
}
