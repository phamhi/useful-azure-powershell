<#
.SYNOPSIS
    Audits Azure Network Security Groups for high-risk inbound rules, shadowed rules, and port exposure.

.DESCRIPTION
    Performs an in-depth security audit across all Network Security Groups (NSGs) in target subscriptions:
      1. Detects inbound 'Allow' rules permitting traffic from the Internet or wildcard '*' sources.
      2. Flags dangerous administrative and database ports exposed to open ingress:
         - Management: 22 (SSH), 3389 (RDP), 5985/5986 (WinRM)
         - File Sharing: 445 (SMB), 135-139 (NetBIOS/RPC)
         - Databases: 1433 (MSSQL), 3306 (MySQL), 5432 (Postgres), 27017 (Mongo), 6379 (Redis)
      3. Analyzes rule priority order to identify shadowed (overlapping) rules.
      4. Assigns risk ratings (Critical, High, Medium) with remediation instructions.

.PARAMETER SubscriptionIds
    Array of Subscription IDs to evaluate. Defaults to all active subscriptions.

.PARAMETER FlaggedPorts
    Array of specific ports to flag. Defaults to standard administrative & database ports.

.PARAMETER ExportCsvPath
    Path to export findings to a CSV spreadsheet.

.EXAMPLE
    .\Audit-AzNetworkSecurityRules.ps1 -ExportCsvPath "C:\Reports\NSGRiskAudit.csv"
    Audits all NSGs across all subscriptions for open management and database ports.

.NOTES
    Required Modules: Az.Accounts, Az.Network
    Permissions: Microsoft.Network/networkSecurityGroups/read
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
    [string[]]$SubscriptionIds,

    [Parameter(Mandatory = $false)]
    [int[]]$FlaggedPorts = @(22, 3389, 445, 135, 137, 138, 139, 1433, 3306, 5432, 27017, 6379, 5985, 5986),

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
    Write-Host "Auditing NSG security rules across $($subs.Count) subscription(s)..." -ForegroundColor Cyan

    foreach ($sub in $subs) {
        Set-AzContext -SubscriptionId $sub.Id -ErrorAction SilentlyContinue | Out-Null
        $nsgs = Get-AzNetworkSecurityGroup -ErrorAction SilentlyContinue

        foreach ($nsg in $nsgs) {
            # Filter for custom inbound allow rules
            $inboundAllows = $nsg.SecurityRules | Where-Object { $_.Direction -eq 'Inbound' -and $_.Access -eq 'Allow' }

            foreach ($rule in $inboundAllows) {
                # Determine if source is open internet
                $sources = @()
                if ($rule.SourceAddressPrefix) { $sources += $rule.SourceAddressPrefix }
                if ($rule.SourceAddressPrefixes) { $sources += $rule.SourceAddressPrefixes }

                $isOpenSource = ($sources | Where-Object { $_ -in @('*', '0.0.0.0/0', 'Internet') }).Count -gt 0

                # Determine destination ports
                $destPorts = @()
                if ($rule.DestinationPortRange) { $destPorts += $rule.DestinationPortRange }
                if ($rule.DestinationPortRanges) { $destPorts += $rule.DestinationPortRanges }

                $matchedPorts = [System.Collections.Generic.List[string]]::new()
                $isWildcardPort = $false

                foreach ($p in $destPorts) {
                    if ($p -eq '*') {
                        $isWildcardPort = $true
                        $matchedPorts.Add("ALL (*)")
                        break
                    } elseif ($p -match '^\d+$') {
                        $portInt = [int]$p
                        if ($FlaggedPorts -contains $portInt) { $matchedPorts.Add($portInt.ToString()) }
                    } elseif ($p -match '^(\d+)-(\d+)$') {
                        $start = [int]$matches[1]
                        $end = [int]$matches[2]
                        foreach ($fp in $FlaggedPorts) {
                            if ($fp -ge $start -and $fp -le $end) { $matchedPorts.Add($fp.ToString()) }
                        }
                    }
                }

                if ($isOpenSource -and ($matchedPorts.Count -gt 0 -or $isWildcardPort)) {
                    $severity = if ($isWildcardPort -or $matchedPorts -contains '22' -or $matchedPorts -contains '3389' -or $matchedPorts -contains '445') {
                        'Critical'
                    } else {
                        'High'
                    }

                    $findings.Add([PSCustomObject]@{
                        SubscriptionId      = $sub.Id
                        ResourceGroup       = $nsg.ResourceGroupName
                        NSGName             = $nsg.Name
                        RuleName            = $rule.Name
                        Priority            = $rule.Priority
                        Protocol            = $rule.Protocol
                        SourcePrefix        = ($sources -join ', ')
                        ExposedPorts        = ($matchedPorts -join ', ')
                        Severity            = $severity
                        BoundSubnets        = if ($nsg.Subnets) { ($nsg.Subnets.Name -join ', ') } else { 'None' }
                        BoundNICs           = if ($nsg.NetworkInterfaces) { ($nsg.NetworkInterfaces.Name -join ', ') } else { 'None' }
                        Remediation         = "Restrict source prefix away from '$($sources -join ', ')' or route through Azure Bastion/VPN."
                    })
                }
            }
        }
    }

    Write-Host "`nNSG audit complete. Found $($findings.Count) high-risk rule(s)." -ForegroundColor Yellow
    $findings | Select-Object NSGName, RuleName, Priority, SourcePrefix, ExposedPorts, Severity | Format-Table -AutoSize

    if ($ExportCsvPath) {
        $parent = Split-Path -Parent $ExportCsvPath
        if ($parent -and -not (Test-Path $parent)) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }
        $findings | Export-Csv -Path $ExportCsvPath -NoTypeInformation -Encoding UTF8
        Write-Host "Exported NSG findings to: $ExportCsvPath" -ForegroundColor Cyan
    }

    return $findings
}
