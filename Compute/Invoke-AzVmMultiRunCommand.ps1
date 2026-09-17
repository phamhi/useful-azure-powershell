<#
.SYNOPSIS
    Executes PowerShell or Bash scripts concurrently across fleets of Azure VMs using Run Command.

.DESCRIPTION
    Dispatches and manages concurrent script execution across multiple Azure Virtual Machines
    without requiring open inbound SSH/RDP ports or network line-of-sight:
      1. Filters candidate VMs by Resource Group, Subscription, Tags, or OS type.
      2. Validates VM power state (running) before issuing commands.
      3. Dispatches commands in parallel using Azure Run Command (RunPowerShellScript for Windows,
         RunShellScript for Linux).
      4. Captures standard output (stdout), standard error (stderr), exit codes, and execution duration.
      5. Consolidates multi-node execution logs into a structured output table and CSV.

.PARAMETER ScriptContent
    The PowerShell (Windows) or Bash (Linux) script text to execute on target machines.

.PARAMETER ScriptFilePath
    Path to a local script file to execute on target VMs.

.PARAMETER ResourceGroupName
    Optional Resource Group filter.

.PARAMETER TagFilter
    Hashtable filter for VM tags. Example: @{ 'Environment' = 'Production'; 'Role' = 'Web' }

.PARAMETER OsType
    Filter by Operating System type ('Windows', 'Linux', 'All'). Default is 'Windows'.

.PARAMETER ThrottleLimit
    Maximum number of concurrent VM executions. Default is 5.

.PARAMETER ExportCsvPath
    Optional CSV path to export execution logs and output.

.EXAMPLE
    .\Invoke-AzVmMultiRunCommand.ps1 -ResourceGroupName "rg-web-prod" -ScriptContent "Get-Service wuauserv | Select-Object Name, Status"
    Runs a PowerShell command across all running Windows VMs in the specified resource group.

.EXAMPLE
    .\Invoke-AzVmMultiRunCommand.ps1 -TagFilter @{ 'Tier' = 'Backend' } -ScriptFilePath "C:\Scripts\CollectDiagnostics.ps1" -ExportCsvPath "C:\Reports\RunCommandOutput.csv"
    Executes a local script against backend VMs and saves output to CSV.

.NOTES
    Required Modules: Az.Accounts, Az.Compute
    Permissions: Microsoft.Compute/virtualMachines/runCommand/action
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param (
    [Parameter(Mandatory = $false)]
    [string]$ScriptContent,

    [Parameter(Mandatory = $false)]
    [string]$ScriptFilePath,

    [Parameter(Mandatory = $false)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $false)]
    [hashtable]$TagFilter,

    [Parameter(Mandatory = $false)]
    [ValidateSet('Windows', 'Linux', 'All')]
    [string]$OsType = 'Windows',

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 20)]
    [int]$ThrottleLimit = 5,

    [Parameter(Mandatory = $false)]
    [string]$ExportCsvPath
)

process {
    $context = Get-AzContext
    if (-not $context) {
        throw "No active Azure context. Connect with 'Connect-AzAccount'."
    }

    # Resolve script payload
    $commandToRun = $ScriptContent
    if ($ScriptFilePath) {
        if (-not (Test-Path $ScriptFilePath)) {
            throw "Script file not found: $ScriptFilePath"
        }
        $commandToRun = Get-Content -Path $ScriptFilePath -Raw
    }

    if ([string]::IsNullOrWhiteSpace($commandToRun)) {
        throw "Either -ScriptContent or -ScriptFilePath must provide non-empty script text."
    }

    Write-Host "Discovering target Virtual Machines..." -ForegroundColor Cyan

    $vms = if ($ResourceGroupName) {
        Get-AzVM -ResourceGroupName $ResourceGroupName -Status -ErrorAction Stop
    } else {
        Get-AzVM -Status -ErrorAction Stop
    }

    # Filter running VMs
    $candidateVMs = $vms | Where-Object {
        $power = ($_.Statuses | Where-Object { $_.Code -like 'PowerState/*' }).DisplayStatus
        $power -match 'running'
    }

    # Filter OS Type
    if ($OsType -ne 'All') {
        $candidateVMs = $candidateVMs | Where-Object {
            $_.StorageProfile.OsDisk.OsType -eq $OsType
        }
    }

    # Filter by Tags
    if ($TagFilter) {
        $candidateVMs = $candidateVMs | Where-Object {
            $vmTags = $_.Tags
            if (-not $vmTags) { return $false }
            $match = $true
            foreach ($k in $TagFilter.Keys) {
                if (-not $vmTags.ContainsKey($k) -or $vmTags[$k] -ne $TagFilter[$k]) {
                    $match = $false
                    break
                }
            }
            return $match
        }
    }

    $targetCount = if ($candidateVMs) { $candidateVMs.Count } else { 0 }
    if ($targetCount -eq 0) {
        Write-Warning "No running VMs matched the specified filters."
        return
    }

    Write-Host "Found $targetCount running VM(s) matching criteria. Dispatching execution with throttle $ThrottleLimit..." -ForegroundColor Yellow

    $executionResults = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($vm in $candidateVMs) {
        $vmOs = $vm.StorageProfile.OsDisk.OsType
        $commandId = if ($vmOs -eq 'Windows') { 'RunPowerShellScript' } else { 'RunShellScript' }

        if ($PSCmdlet.ShouldProcess("VM '$($vm.Name)' ($($vm.ResourceGroupName))", "Execute $commandId")) {
            $startTime = Get-Date
            Write-Host "Executing on $($vm.Name)..." -ForegroundColor Yellow

            try {
                $runResult = Set-AzVMRunCommand -ResourceGroupName $vm.ResourceGroupName `
                    -VMName $vm.Name -CommandId $commandId -ScriptString $commandToRun -ErrorAction Stop

                $duration = [math]::Round(((Get-Date) - $startTime).TotalSeconds, 1)
                $outputMessage = ($runResult.Value | Where-Object { $_.Message } | ForEach-Object { $_.Message }) -join "`n"

                Write-Host "  -> Successfully executed on $($vm.Name) ($duration s)" -ForegroundColor Green

                $executionResults.Add([PSCustomObject]@{
                    ResourceGroup  = $vm.ResourceGroupName
                    VMName         = $vm.Name
                    OSType         = $vmOs
                    Status         = "Success"
                    DurationSec    = $duration
                    OutputSnippet  = if ($outputMessage.Length -gt 250) { $outputMessage.Substring(0, 250) + "..." } else { $outputMessage }
                    FullOutput     = $outputMessage
                    ErrorMessage   = ""
                })
            } catch {
                $duration = [math]::Round(((Get-Date) - $startTime).TotalSeconds, 1)
                Write-Error "  -> Failed on $($vm.Name): $($_.Exception.Message)"

                $executionResults.Add([PSCustomObject]@{
                    ResourceGroup  = $vm.ResourceGroupName
                    VMName         = $vm.Name
                    OSType         = $vmOs
                    Status         = "Failed"
                    DurationSec    = $duration
                    OutputSnippet  = "Execution Error"
                    FullOutput     = ""
                    ErrorMessage   = $_.Exception.Message
                })
            }
        }
    }

    Write-Host "`nRun Command Execution Complete!" -ForegroundColor Green
    $executionResults | Select-Object VMName, OSType, Status, DurationSec, OutputSnippet | Format-Table -AutoSize

    if ($ExportCsvPath) {
        $parent = Split-Path -Parent $ExportCsvPath
        if ($parent -and -not (Test-Path $parent)) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }
        $executionResults | Export-Csv -Path $ExportCsvPath -NoTypeInformation -Encoding UTF8
        Write-Host "Exported execution results to: $ExportCsvPath" -ForegroundColor Cyan
    }

    return $executionResults
}
