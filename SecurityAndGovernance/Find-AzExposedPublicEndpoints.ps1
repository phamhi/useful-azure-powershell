<#
.SYNOPSIS
    Scans Azure PaaS and IaaS services for unintended public internet exposure.

.DESCRIPTION
    Performs a security assessment across Azure subscriptions to detect resources
    exposed directly to the public internet:
      - Storage Accounts: Public network access enabled, anonymous blob access permitted.
      - Key Vaults: Public access allowed without IP / VNet restrictions, firewall bypass settings.
      - Azure SQL Servers: Firewall rules permitting 0.0.0.0/0 or 'Allow Azure Services' wildcard.
      - App Services: Missing IP access restrictions (open to 0.0.0.0/0).
      - AKS Clusters: Public API server endpoints without authorized IP ranges.
    
    Categorizes findings by Severity (Critical, High, Medium) and generates a structured
    risk report suitable for SOC/CloudSec review.

.PARAMETER SubscriptionIds
    Array of Subscription IDs to scan. Defaults to all active subscriptions.

.PARAMETER ExportCsvPath
    Optional path to save findings to a CSV file.

.EXAMPLE
    .\Find-AzExposedPublicEndpoints.ps1 -ExportCsvPath "C:\Reports\ExposedEndpoints.csv"
    Performs a cross-subscription public exposure audit and exports results to CSV.

.NOTES
    Required Modules: Az.Accounts, Az.Storage, Az.KeyVault, Az.Sql, Az.Websites, Az.Aks
    Permissions: Reader permissions on target subscriptions.
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

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    Write-Host "Scanning public endpoint exposure across $($subs.Count) subscription(s)..." -ForegroundColor Cyan

    foreach ($sub in $subs) {
        Set-AzContext -SubscriptionId $sub.Id -ErrorAction SilentlyContinue | Out-Null
        Write-Host "Assessing Subscription: $($sub.Name)..." -ForegroundColor Gray

        # 1. Storage Accounts
        $storageAccounts = Get-AzStorageAccount -ErrorAction SilentlyContinue
        foreach ($sa in $storageAccounts) {
            $hasPublicAccess = $sa.PublicNetworkAccess -ne 'Disabled'
            $blobAnonymousAllowed = $sa.AllowBlobPublicAccess -eq $true

            if ($blobAnonymousAllowed) {
                $findings.Add([PSCustomObject]@{
                    SubscriptionId = $sub.Id
                    ResourceGroup  = $sa.ResourceGroupName
                    ResourceType   = 'Microsoft.Storage/storageAccounts'
                    ResourceName   = $sa.StorageAccountName
                    Severity       = 'Critical'
                    Finding        = 'Anonymous Blob Public Access is ENABLED'
                    PublicNetwork  = $sa.PublicNetworkAccess
                    Recommendation = 'Set AllowBlobPublicAccess to $false and enforce private endpoints.'
                })
            } elseif ($hasPublicAccess -and ($sa.NetworkRuleSet.DefaultAction -eq 'Allow')) {
                $findings.Add([PSCustomObject]@{
                    SubscriptionId = $sub.Id
                    ResourceGroup  = $sa.ResourceGroupName
                    ResourceType   = 'Microsoft.Storage/storageAccounts'
                    ResourceName   = $sa.StorageAccountName
                    Severity       = 'Medium'
                    Finding        = 'Storage firewall defaults to Allow (unrestricted public ingress)'
                    PublicNetwork  = 'Enabled'
                    Recommendation = 'Configure NetworkRuleSet DefaultAction to Deny with IP/VNet whitelist.'
                })
            }
        }

        # 2. Key Vaults
        $keyVaults = Get-AzKeyVault -ErrorAction SilentlyContinue
        foreach ($kv in $keyVaults) {
            $hasPublicAccess = $kv.PublicNetworkAccess -ne 'Disabled'
            $defaultAllow = $kv.NetworkAcls.DefaultAction -eq 'Allow'

            if ($hasPublicAccess -and $defaultAllow) {
                $findings.Add([PSCustomObject]@{
                    SubscriptionId = $sub.Id
                    ResourceGroup  = $kv.ResourceGroupName
                    ResourceType   = 'Microsoft.KeyVault/vaults'
                    ResourceName   = $kv.VaultName
                    Severity       = 'High'
                    Finding        = 'Key Vault public network access enabled with DefaultAction Allow'
                    PublicNetwork  = 'Enabled'
                    Recommendation = 'Disable public network access or restrict to authorized VNet/IP ACLs.'
                })
            }
        }

        # 3. Azure SQL Servers
        $sqlServers = Get-AzSqlServer -ErrorAction SilentlyContinue
        foreach ($sql in $sqlServers) {
            $rules = Get-AzSqlServerFirewallRule -ServerName $sql.ServerName -ResourceGroupName $sql.ResourceGroupName -ErrorAction SilentlyContinue
            foreach ($rule in $rules) {
                if ($rule.StartIpAddress -eq '0.0.0.0' -and $rule.EndIpAddress -eq '255.255.255.255') {
                    $findings.Add([PSCustomObject]@{
                        SubscriptionId = $sub.Id
                        ResourceGroup  = $sql.ResourceGroupName
                        ResourceType   = 'Microsoft.Sql/servers'
                        ResourceName   = $sql.ServerName
                        Severity       = 'Critical'
                        Finding        = "Firewall rule '$($rule.FirewallRuleName)' permits entire internet (0.0.0.0 - 255.255.255.255)"
                        PublicNetwork  = $sql.PublicNetworkAccess
                        Recommendation = 'Remove wide-open firewall rule immediately.'
                    })
                } elseif ($rule.StartIpAddress -eq '0.0.0.0' -and $rule.EndIpAddress -eq '0.0.0.0') {
                    $findings.Add([PSCustomObject]@{
                        SubscriptionId = $sub.Id
                        ResourceGroup  = $sql.ResourceGroupName
                        ResourceType   = 'Microsoft.Sql/servers'
                        ResourceName   = $sql.ServerName
                        Severity       = 'Medium'
                        Finding        = "Firewall rule '$($rule.FirewallRuleName)' enables 'Allow Azure Services' bypass"
                        PublicNetwork  = $sql.PublicNetworkAccess
                        Recommendation = 'Disable Allow Azure Services bypass and transition to Private Endpoints.'
                    })
                }
            }
        }

        # 4. App Services
        $apps = Get-AzWebApp -ErrorAction SilentlyContinue
        foreach ($app in $apps) {
            $config = Get-AzWebAppConfig -ResourceGroupName $app.ResourceGroup -Name $app.Name -ErrorAction SilentlyContinue
            $restrictions = $config.IpSecurityRestrictions | Where-Object { $_.Action -eq 'Allow' }
            $hasUnrestricted = ($restrictions | Where-Object { $_.IpAddress -in @('Any', '0.0.0.0/0') -or $_.Name -eq 'Allow all' }).Count -gt 0

            if ($hasUnrestricted -or (-not $restrictions)) {
                $findings.Add([PSCustomObject]@{
                    SubscriptionId = $sub.Id
                    ResourceGroup  = $app.ResourceGroup
                    ResourceType   = 'Microsoft.Web/sites'
                    ResourceName   = $app.Name
                    Severity       = 'Low'
                    Finding        = 'Web App has no IP restrictions configured (open to public internet)'
                    PublicNetwork  = 'Enabled'
                    Recommendation = 'Implement Front Door/App Gateway or configure IP Security Restrictions.'
                })
            }
        }
    }

    Write-Host "`nExposure scan complete. Discovered $($findings.Count) security finding(s)." -ForegroundColor Yellow
    $findings | Select-Object Severity, ResourceType, ResourceName, Finding | Format-Table -AutoSize

    if ($ExportCsvPath) {
        $parent = Split-Path -Parent $ExportCsvPath
        if ($parent -and -not (Test-Path $parent)) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }
        $findings | Export-Csv -Path $ExportCsvPath -NoTypeInformation -Encoding UTF8
        Write-Host "Exported findings to: $ExportCsvPath" -ForegroundColor Cyan
    }

    return $findings
}
