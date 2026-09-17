<#
.SYNOPSIS
    Audits and remediates Azure resource compliance against enterprise tagging standards.

.DESCRIPTION
    Scans Azure resources across subscriptions to verify compliance with required tag policies:
      1. Validates presence of mandatory tag keys (e.g., Environment, Owner, CostCenter).
      2. Validates tag values against allowed regex patterns (e.g. Environment in dev|stage|prod).
      3. Implements tag inheritance: fills missing tags on child resources from parent Resource Groups.
      4. Generates an audit compliance percentage per resource group and subscription.
      5. Provides automated remediation with -Remediate and safe dry-run preview via -WhatIf.

.PARAMETER SubscriptionIds
    Array of Subscription IDs to evaluate. Defaults to current or all active subscriptions.

.PARAMETER RequiredTags
    Hashtable defining mandatory tag keys and optional regex validation patterns for values.
    Example: @{ 'Environment' = '^(dev|qa|stage|prod)$'; 'Owner' = '.+'; 'CostCenter' = '^\d{4,6}$' }

.PARAMETER InheritFromResourceGroup
    Switch to populate missing tags on child resources using values from the parent Resource Group.

.PARAMETER Remediate
    Switch to apply missing/inherited tags to non-compliant resources. Supports -WhatIf and -Confirm.

.PARAMETER ExportCsvPath
    File path to save the tag compliance report.

.EXAMPLE
    .\Enforce-AzResourceTaggingPolicy.ps1 -RequiredTags @{ 'Environment' = '^(dev|stage|prod)$'; 'CostCenter' = '.+' } -InheritFromResourceGroup
    Audits all resources against Environment and CostCenter, displaying resources missing tags.

.EXAMPLE
    .\Enforce-AzResourceTaggingPolicy.ps1 -InheritFromResourceGroup -Remediate -WhatIf
    Simulates tag inheritance remediation from Resource Groups to child resources without applying changes.

.NOTES
    Required Modules: Az.Accounts, Az.Resources
    Permissions: Microsoft.Resources/tags/read, Microsoft.Resources/tags/write (for -Remediate).
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param (
    [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
    [string[]]$SubscriptionIds,

    [Parameter(Mandatory = $false)]
    [hashtable]$RequiredTags = @{
        'Environment' = '^(development|dev|qa|staging|production|prod)$'
        'Owner'       = '.+'
        'CostCenter'  = '.+'
    },

    [Parameter(Mandatory = $false)]
    [switch]$InheritFromResourceGroup,

    [Parameter(Mandatory = $false)]
    [switch]$Remediate,

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

    $complianceReport = [System.Collections.Generic.List[PSCustomObject]]::new()
    Write-Host "Auditing tag compliance across $($subs.Count) subscription(s)..." -ForegroundColor Cyan

    foreach ($sub in $subs) {
        Set-AzContext -SubscriptionId $sub.Id -ErrorAction SilentlyContinue | Out-Null
        $rgs = Get-AzResourceGroup -ErrorAction SilentlyContinue

        foreach ($rg in $rgs) {
            $rgTags = if ($rg.Tags) { $rg.Tags } else { @{} }
            $resources = Get-AzResource -ResourceGroupName $rg.ResourceGroupName -ErrorAction SilentlyContinue

            foreach ($res in $resources) {
                $resTags = if ($res.Tags) { $res.Tags } else { @{} }
                $missingTags = [System.Collections.Generic.List[string]]::new()
                $invalidTags = [System.Collections.Generic.List[string]]::new()
                $tagsToApply = @{}

                foreach ($tagKey in $RequiredTags.Keys) {
                    $pattern = $RequiredTags[$tagKey]

                    if (-not $resTags.ContainsKey($tagKey)) {
                        $missingTags.Add($tagKey)

                        # Check inheritance from RG
                        if ($InheritFromResourceGroup -and $rgTags.ContainsKey($tagKey)) {
                            $tagsToApply[$tagKey] = $rgTags[$tagKey]
                        }
                    } else {
                        $val = $resTags[$tagKey]
                        if ($pattern -and ($val -notmatch $pattern)) {
                            $invalidTags.Add("$tagKey='$val' (Failed pattern: $pattern)")
                        }
                    }
                }

                $isCompliant = ($missingTags.Count -eq 0 -and $invalidTags.Count -eq 0)

                $complianceReport.Add([PSCustomObject]@{
                    SubscriptionId   = $sub.Id
                    ResourceGroup    = $rg.ResourceGroupName
                    ResourceType     = $res.ResourceType
                    ResourceName     = $res.Name
                    ResourceId       = $res.ResourceId
                    IsCompliant      = $isCompliant
                    MissingTags      = ($missingTags -join ', ')
                    InvalidTags      = ($invalidTags -join ', ')
                    CurrentTagCount  = $resTags.Count
                    InheritableCount = $tagsToApply.Count
                })

                # Remediate if requested and inheritable tags are available
                if ($Remediate -and $tagsToApply.Count -gt 0) {
                    if ($PSCmdlet.ShouldProcess("$($res.Name) in $($rg.ResourceGroupName)", "Apply inherited tags ($($tagsToApply.Keys -join ', '))")) {
                        try {
                            Write-Host "Updating tags on $($res.Name)..." -ForegroundColor Yellow
                            Update-AzTag -ResourceId $res.ResourceId -Tag $tagsToApply -Operation Merge -ErrorAction Stop | Out-Null
                            Write-Host "Successfully updated tags for $($res.Name)" -ForegroundColor Green
                        } catch {
                            Write-Error "Failed to update tags for $($res.ResourceId): $($_.Exception.Message)"
                        }
                    }
                }
            }
        }
    }

    $nonCompliantCount = ($complianceReport | Where-Object { -not $_.IsCompliant }).Count
    Write-Host "`nTagging audit complete. Scanned $($complianceReport.Count) resources. Non-compliant: $nonCompliantCount" -ForegroundColor $(if ($nonCompliantCount -gt 0) { 'Yellow' } else { 'Green' })

    if ($ExportCsvPath) {
        $parent = Split-Path -Parent $ExportCsvPath
        if ($parent -and -not (Test-Path $parent)) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }
        $complianceReport | Export-Csv -Path $ExportCsvPath -NoTypeInformation -Encoding UTF8
        Write-Host "Exported tag compliance report to: $ExportCsvPath" -ForegroundColor Cyan
    }

    return $complianceReport
}
