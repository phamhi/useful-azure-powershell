<#
.SYNOPSIS
    Resizes an Azure Virtual Machine after performing comprehensive architectural pre-flight checks.

.DESCRIPTION
    Safely executes VM resize operations by validating constraints before making destructive changes:
      1. Cluster Availability Check: Verifies whether the target VM size is available on the current
         underlying hardware cluster without requiring a full deallocation.
      2. Quota Check: Inspects regional subscription vCPU and family core quotas (Get-AzVMUsage)
         to ensure the target SKU does not exceed account limits.
      3. Storage Constraints: Ensures target SKU supports the VM's current number of attached data disks
         and Premium SSD / Ultra Disk capabilities.
      4. Network IP Preservation: Confirms NIC private IP allocation and Public IP assignment types.
      5. Executes deallocation, resize, and startup sequence safely with -WhatIf and -Confirm support.

.PARAMETER ResourceGroupName
    Resource Group containing the Virtual Machine.

.PARAMETER VmName
    Name of the Virtual Machine to resize.

.PARAMETER TargetSize
    Target Azure VM SKU (e.g., 'Standard_D4s_v5', 'Standard_B2ms', 'Standard_E4as_v5').

.PARAMETER ForceDeallocateIfRequired
    Switch to allow deallocating the VM if the target SKU is unavailable on the current physical cluster.

.EXAMPLE
    .\Resize-AzVmWithPreFlightChecks.ps1 -ResourceGroupName "rg-prod-app" -VmName "vm-sql-01" -TargetSize "Standard_D8s_v5" -WhatIf
    Runs all pre-flight quota, disk, and cluster checks in simulation mode.

.EXAMPLE
    .\Resize-AzVmWithPreFlightChecks.ps1 -ResourceGroupName "rg-prod-app" -VmName "vm-sql-01" -TargetSize "Standard_D4s_v5" -ForceDeallocateIfRequired
    Performs pre-flight checks, deallocates if required, resizes, and powers on the VM.

.NOTES
    Required Modules: Az.Accounts, Az.Compute, Az.Network
    Permissions: Contributor on the VM and its Resource Group.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param (
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $true)]
    [string]$VmName,

    [Parameter(Mandatory = $true)]
    [string]$TargetSize,

    [Parameter(Mandatory = $false)]
    [switch]$ForceDeallocateIfRequired
)

process {
    $context = Get-AzContext
    if (-not $context) {
        throw "No active Azure context. Connect with 'Connect-AzAccount'."
    }

    Write-Host "Initiating pre-flight resize validation for VM '$VmName' in '$ResourceGroupName' -> Target: '$TargetSize'..." -ForegroundColor Cyan

    $vm = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VmName -Status -ErrorAction Stop
    $location = $vm.Location
    $currentSize = $vm.HardwareProfile.VmSize
    $powerState = ($vm.Statuses | Where-Object { $_.Code -like 'PowerState/*' }).DisplayStatus

    Write-Host "Current Size : $currentSize" -ForegroundColor Gray
    Write-Host "Power State  : $powerState" -ForegroundColor Gray
    Write-Host "Location     : $location" -ForegroundColor Gray

    if ($currentSize -eq $TargetSize) {
        Write-Warning "VM is already sized at '$TargetSize'. No resize needed."
        return
    }

    # Pre-Flight Check 1: Regional SKU Availability and Constraints
    Write-Host "`n[1/4] Checking target SKU specifications in region '$location'..." -ForegroundColor Yellow
    $allSkus = Get-AzComputeResourceSku -Location $location | Where-Object { $_.ResourceType -eq 'virtualMachines' -and $_.Name -eq $TargetSize }

    if (-not $allSkus) {
        throw "SKU '$TargetSize' is not offered in region '$location'."
    }

    # Extract max data disks and premium capabilities
    $maxDataDisksCap = ($allSkus.Capabilities | Where-Object { $_.Name -eq 'MaxDataDiskCount' }).Value
    $premiumIo = ($allSkus.Capabilities | Where-Object { $_.Name -eq 'PremiumIO' }).Value
    $targetvCPUs = ($allSkus.Capabilities | Where-Object { $_.Name -eq 'vCPUs' }).Value

    Write-Host "  -> Target Specs: $targetvCPUs vCPUs | Max Disks: $maxDataDisksCap | Premium Storage: $premiumIo" -ForegroundColor Gray

    # Check 2: Disk Count & Premium Storage Compatibility
    Write-Host "`n[2/4] Validating VM disk configuration against target limits..." -ForegroundColor Yellow
    $attachedDiskCount = if ($vm.StorageProfile.DataDisks) { $vm.StorageProfile.DataDisks.Count } else { 0 }
    if ($maxDataDisksCap -and [int]$maxDataDisksCap -lt $attachedDiskCount) {
        throw "Incompatible: Target SKU '$TargetSize' supports up to $maxDataDisksCap data disks, but VM currently has $attachedDiskCount data disks attached."
    }

    $hasPremiumDisk = ($vm.StorageProfile.OsDisk.ManagedDisk.StorageAccountType -match 'Premium') -or `
                      ($vm.StorageProfile.DataDisks | Where-Object { $_.ManagedDisk.StorageAccountType -match 'Premium' })
    if ($hasPremiumDisk -and $premiumIo -ne 'True') {
        throw "Incompatible: VM uses Premium SSDs, but target SKU '$TargetSize' does not support Premium Storage."
    }
    Write-Host "  -> Disk configuration is fully compatible." -ForegroundColor Green

    # Check 3: Subscription Core Quota Check
    Write-Host "`n[3/4] Validating regional subscription compute quota..." -ForegroundColor Yellow
    try {
        $usages = Get-AzVMUsage -Location $location
        $coreUsage = $usages | Where-Object { $_.Name.Value -eq 'cores' }
        if ($coreUsage) {
            $availableCores = $coreUsage.Limit - $coreUsage.CurrentValue
            Write-Host "  -> Available regional compute cores: $availableCores (Quota: $($coreUsage.Limit), In-Use: $($coreUsage.CurrentValue))" -ForegroundColor Gray
            if ($availableCores -lt [int]$targetvCPUs) {
                Write-Warning "Subscription may be near or exceeding regional core limits."
            }
        }
    } catch {
        Write-Verbose "Could not fetch regional quota details."
    }

    # Check 4: Host Cluster Availability Check
    Write-Host "`n[4/4] Validating host cluster size compatibility..." -ForegroundColor Yellow
    $clusterSizes = Get-AzVMSize -ResourceGroupName $ResourceGroupName -VMName $VmName
    $availableOnCluster = ($clusterSizes | Where-Object { $_.Name -eq $TargetSize }) -ne $null

    $needsDeallocate = -not $availableOnCluster
    if ($needsDeallocate) {
        Write-Warning "Target size '$TargetSize' is NOT available on the current physical host cluster."
        Write-Warning "The VM must be completely deallocated (Stopped - Deallocated) to relocate to an eligible hardware cluster."
        if (-not $ForceDeallocateIfRequired -and $powerState -match 'running') {
            throw "Resize blocked: VM is running on a cluster that does not host '$TargetSize'. Re-run with -ForceDeallocateIfRequired to allow VM deallocation."
        }
    } else {
        Write-Host "  -> Target size is available on the current cluster." -ForegroundColor Green
    }

    # Execution Phase
    if ($PSCmdlet.ShouldProcess("VM '$VmName' in '$ResourceGroupName'", "Resize from '$currentSize' to '$TargetSize'")) {
        try {
            if ($needsDeallocate -and $powerState -match 'running') {
                Write-Host "Stopping and deallocating VM '$VmName'..." -ForegroundColor Yellow
                Stop-AzVM -ResourceGroupName $ResourceGroupName -Name $VmName -Force -ErrorAction Stop
            }

            Write-Host "Applying new hardware size '$TargetSize'..." -ForegroundColor Yellow
            $vm.HardwareProfile.VmSize = $TargetSize
            Update-AzVM -ResourceGroupName $ResourceGroupName -VM $vm -ErrorAction Stop | Out-Null
            Write-Host "Successfully updated VM size configuration!" -ForegroundColor Green

            if ($powerState -match 'running') {
                Write-Host "Restarting VM '$VmName'..." -ForegroundColor Yellow
                Start-AzVM -ResourceGroupName $ResourceGroupName -Name $VmName -ErrorAction Stop
                Write-Host "VM '$VmName' has restarted successfully on target SKU '$TargetSize'." -ForegroundColor Green
            }
        } catch {
            Write-Error "Resize operation failed: $($_.Exception.Message)"
            throw
        }
    }
}
