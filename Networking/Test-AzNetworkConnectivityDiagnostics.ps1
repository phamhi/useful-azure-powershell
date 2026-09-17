<#
.SYNOPSIS
    Runs comprehensive Azure Network Watcher diagnostics (Connectivity, Next Hop, NSG View).

.DESCRIPTION
    Automates end-to-end network reachability troubleshooting between an Azure VM and a destination:
      1. Executes Network Watcher Connectivity Check to evaluate TCP/HTTP reachability.
      2. Analyzes round-trip latency (Min, Avg, Max in milliseconds).
      3. Determines the Next Hop routing path (VirtualAppliance, VirtualNetwork, Internet, None).
      4. Inspects effective NSG rules to identify specific blocking or allowing rules.
      5. Generates root-cause diagnosis for connection timeouts, routing drops, or security blocks.

.PARAMETER ResourceGroupName
    Resource Group containing the source Virtual Machine.

.PARAMETER SourceVmName
    Name of the source Virtual Machine from which to run diagnostics.

.PARAMETER DestinationAddress
    Target IP address or Fully Qualified Domain Name (FQDN).

.PARAMETER DestinationPort
    Destination TCP port to test (e.g. 443, 22, 1433, 80).

.PARAMETER Protocol
    Protocol to test. Valid values: 'Tcp', 'Http'. Default is 'Tcp'.

.EXAMPLE
    .\Test-AzNetworkConnectivityDiagnostics.ps1 -ResourceGroupName "rg-app-prod" -SourceVmName "vm-web-01" -DestinationAddress "10.200.1.4" -DestinationPort 1433
    Tests TCP connectivity on port 1433 from vm-web-01 to an internal database, pinpointing any NSG or route issues.

.NOTES
    Required Modules: Az.Accounts, Az.Network, Az.Compute
    Prerequisite: Azure Network Watcher must be enabled in the source VM's region. NetworkWatcherAgent extension recommended on VM.
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $true)]
    [string]$SourceVmName,

    [Parameter(Mandatory = $true)]
    [string]$DestinationAddress,

    [Parameter(Mandatory = $true)]
    [int]$DestinationPort,

    [Parameter(Mandatory = $false)]
    [ValidateSet('Tcp', 'Http')]
    [string]$Protocol = 'Tcp'
)

process {
    $context = Get-AzContext
    if (-not $context) {
        throw "No active Azure context. Connect with 'Connect-AzAccount'."
    }

    Write-Host "Fetching details for source VM: $SourceVmName in $ResourceGroupName..." -ForegroundColor Cyan
    $vm = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $SourceVmName -ErrorAction Stop
    $location = $vm.Location

    # Locate Network Watcher in the VM's region
    $watchers = Get-AzNetworkWatcher -ErrorAction Stop
    $nw = $watchers | Where-Object { $_.Location -eq $location }

    if (-not $nw) {
        throw "No Network Watcher instance found in region '$location'. Please enable Network Watcher for this region."
    }

    Write-Host "Using Network Watcher: $($nw.Name) in $($nw.Location)" -ForegroundColor Gray
    Write-Host "Testing connectivity to $DestinationAddress : $DestinationPort via $Protocol..." -ForegroundColor Yellow

    $diagnosticResult = [ordered]@{
        SourceVM             = $SourceVmName
        SourceLocation       = $location
        DestinationAddress   = $DestinationAddress
        DestinationPort      = $DestinationPort
        Protocol             = $Protocol
        ConnectionStatus     = "Unknown"
        AvgLatencyMs         = $null
        NextHopType          = "Unknown"
        NextHopIP            = "N/A"
        NSGEvaluation        = "N/A"
        PrimaryIssue         = "None"
        Recommendation       = ""
    }

    # 1. Next Hop Evaluation
    try {
        Write-Host "Determining Next Hop route..." -ForegroundColor Gray
        $nicId = $vm.NetworkProfile.NetworkInterfaces[0].Id
        $nic = Get-AzNetworkInterface -ResourceId $nicId
        $sourceIp = $nic.IpConfigurations[0].PrivateIpAddress

        $nextHop = Get-AzNetworkWatcherNextHop -NetworkWatcher $nw -TargetVirtualMachineId $vm.Id `
            -SourceIPAddress $sourceIp -DestinationIPAddress $DestinationAddress -ErrorAction Stop

        $diagnosticResult.NextHopType = $nextHop.NextHopType
        $diagnosticResult.NextHopIP   = if ($nextHop.NextHopIpAddress) { $nextHop.NextHopIpAddress } else { 'N/A' }
    } catch {
        Write-Warning "Next Hop evaluation failed: $($_.Exception.Message)"
    }

    # 2. Connection Diagnostics
    try {
        $connTest = Test-AzNetworkWatcherConnectivity -NetworkWatcher $nw -SourceId $vm.Id `
            -DestinationAddress $DestinationAddress -DestinationPort $DestinationPort `
            -Protocol $Protocol -ErrorAction Stop

        $diagnosticResult.ConnectionStatus = $connTest.ConnectionStatus
        $diagnosticResult.AvgLatencyMs     = $connTest.AvgLatencyInMs

        if ($connTest.ConnectionStatus -eq 'Unreachable') {
            $diagnosticResult.PrimaryIssue = "Target Unreachable"
            # Parse hops to identify failure point
            $failedHops = $connTest.Hops | Where-Object { $_.Issues -and $_.Issues.Count -gt 0 }
            if ($failedHops) {
                $issueList = foreach ($h in $failedHops) {
                    $h.Issues | ForEach-Object { "$($_.Type): $($_.Context)" }
                }
                $diagnosticResult.Recommendation = ($issueList -join ' | ')
            } else {
                $diagnosticResult.Recommendation = "Check destination listener status, firewall daemon, or target cloud network."
            }
        } else {
            $diagnosticResult.Recommendation = "Connection successful. Path is clear."
        }
    } catch {
        Write-Warning "Connectivity test failed (Agent extension may be required on VM): $($_.Exception.Message)"
        $diagnosticResult.ConnectionStatus = "AgentCheckFailed"
        $diagnosticResult.Recommendation = "Ensure Azure Network Watcher Agent extension (NetworkWatcherAgentWindows/Linux) is running on the VM."
    }

    # 3. Security Group View
    try {
        Write-Host "Evaluating NSG rules..." -ForegroundColor Gray
        $sgView = Get-AzNetworkWatcherSecurityGroupView -NetworkWatcher $nw -TargetVirtualMachineId $vm.Id -ErrorAction Stop
        $effectiveRules = $sgView.NetworkInterfaces[0].SecurityRuleAssociations.EffectiveSecurityRules
        
        $blockingRules = $effectiveRules | Where-Object {
            $_.Direction -eq 'Outbound' -and $_.Access -eq 'Deny'
        }

        if ($blockingRules) {
            $diagnosticResult.NSGEvaluation = "Outbound Deny rules present: $($blockingRules.Name -join ', ')"
        } else {
            $diagnosticResult.NSGEvaluation = "Outbound NSG rules allow traffic."
        }
    } catch {
        Write-Verbose "Security Group View evaluation failed: $($_.Exception.Message)"
    }

    $resultObj = [PSCustomObject]$diagnosticResult
    Write-Host "`nDiagnostic Summary:" -ForegroundColor Green
    $resultObj | Format-List

    return $resultObj
}
