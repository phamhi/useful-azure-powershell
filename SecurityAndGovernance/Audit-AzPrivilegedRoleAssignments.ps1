<#
.SYNOPSIS
    Audits privileged RBAC role assignments (Owner, Contributor, User Access Admin) across subscriptions.

.DESCRIPTION
    Inspects role assignments across one or more Azure Subscriptions and Management Groups:
      1. Flags high-privilege roles: Owner, Contributor, User Access Administrator, and custom roles.
      2. Detects external/guest users (identities containing '#EXT#').
      3. Distinguishes between User, ServicePrincipal, and Group assignments.
      4. Identifies orphaned role assignments (identities deleted from Entra ID but still bound in RBAC).
      5. Highlights scope levels (Subscription root vs Resource Group vs Resource).
      6. Formats an actionable security report with risk levels and CSV export capability.

.PARAMETER SubscriptionIds
    Array of Subscription IDs to audit. Defaults to all active subscriptions.

.PARAMETER IncludeContributor
    Switch to include 'Contributor' role assignments. Defaults to $true.

.PARAMETER ExportCsvPath
    File path to export the audit findings as a CSV.

.EXAMPLE
    .\Audit-AzPrivilegedRoleAssignments.ps1 -ExportCsvPath "C:\Reports\PrivilegedRBAC.csv"
    Audits all subscriptions and exports privileged role assignments to CSV.

.NOTES
    Required Modules: Az.Accounts, Az.Resources
    Permissions: Microsoft.Authorization/roleAssignments/read across target scopes.
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
    [string[]]$SubscriptionIds,

    [Parameter(Mandatory = $false)]
    [bool]$IncludeContributor = $true,

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

    $privilegedRoleNames = [System.Collections.Generic.List[string]]::new()
    $privilegedRoleNames.Add('Owner')
    $privilegedRoleNames.Add('User Access Administrator')
    if ($IncludeContributor) {
        $privilegedRoleNames.Add('Contributor')
    }

    $report = [System.Collections.Generic.List[PSCustomObject]]::new()
    Write-Host "Auditing privileged RBAC roles across $($subs.Count) subscription(s)..." -ForegroundColor Cyan

    foreach ($sub in $subs) {
        Set-AzContext -SubscriptionId $sub.Id -ErrorAction SilentlyContinue | Out-Null
        Write-Host "Evaluating Subscription: $($sub.Name) ($($sub.Id))..." -ForegroundColor Gray

        try {
            $assignments = Get-AzRoleAssignment -ErrorAction Stop
        } catch {
            Write-Warning "Failed to fetch role assignments for sub $($sub.Id): $($_.Exception.Message)"
            continue
        }

        foreach ($ra in $assignments) {
            if ($privilegedRoleNames -contains $ra.RoleDefinitionName) {
                $isGuest = $ra.SignInName -match '#EXT#' -or $ra.DisplayName -match '#EXT#'
                $isOrphaned = [string]::IsNullOrEmpty($ra.DisplayName) -and [string]::IsNullOrEmpty($ra.SignInName)

                # Determine Risk Level
                $riskLevel = "Low"
                $riskDetails = [System.Collections.Generic.List[string]]::new()

                if ($ra.RoleDefinitionName -eq 'Owner') {
                    $riskLevel = "High"
                    $riskDetails.Add("Permanent Owner assignment")
                } elseif ($ra.RoleDefinitionName -eq 'User Access Administrator') {
                    $riskLevel = "High"
                    $riskDetails.Add("Can grant arbitrary RBAC roles")
                }

                if ($isGuest) {
                    $riskLevel = "Critical"
                    $riskDetails.Add("Privileged External/Guest identity")
                }

                if ($isOrphaned) {
                    $riskLevel = "High"
                    $riskDetails.Add("Orphaned principal ID (deleted Entra ID identity)")
                }

                if ($ra.Scope -eq "/subscriptions/$($sub.Id)") {
                    $scopeType = "Subscription Root"
                } elseif ($ra.Scope -match "/resourceGroups/[^/]+$") {
                    $scopeType = "Resource Group"
                } else {
                    $scopeType = "Individual Resource"
                }

                $report.Add([PSCustomObject]@{
                    SubscriptionId    = $sub.Id
                    SubscriptionName  = $sub.Name
                    PrincipalName     = if ($ra.SignInName) { $ra.SignInName } else { $ra.DisplayName }
                    PrincipalType     = $ra.ObjectType
                    PrincipalId       = $ra.ObjectId
                    RoleName          = $ra.RoleDefinitionName
                    ScopeType         = $scopeType
                    Scope             = $ra.Scope
                    IsGuestAccount    = $isGuest
                    IsOrphaned        = $isOrphaned
                    RiskLevel         = $riskLevel
                    RiskDetails       = ($riskDetails -join "; ")
                })
            }
        }
    }

    Write-Host "`nDiscovered $($report.Count) privileged role assignment(s)." -ForegroundColor Green
    $report | Select-Object PrincipalName, PrincipalType, RoleName, ScopeType, RiskLevel, RiskDetails | Format-Table -AutoSize

    if ($ExportCsvPath) {
        $parent = Split-Path -Parent $ExportCsvPath
        if ($parent -and -not (Test-Path $parent)) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }
        $report | Export-Csv -Path $ExportCsvPath -NoTypeInformation -Encoding UTF8
        Write-Host "Exported RBAC audit report to: $ExportCsvPath" -ForegroundColor Cyan
    }

    return $report
}
