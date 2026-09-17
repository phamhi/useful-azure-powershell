<#
.SYNOPSIS
    Creates coordinated point-in-time snapshots of all VM disks and stages copies to Azure Storage.

.DESCRIPTION
    Performs coordinated disk backups for Azure Virtual Machines:
      1. Discovers the OS disk and all attached Data Disks for the target VM.
      2. Creates synchronized Managed Disk Snapshots with standard backup tags
         (SourceVM, SourceDisk, BackupTimestamp, ExpiryDate).
      3. Generates secure read-only Shared Access Signature (SAS) tokens for each snapshot.
      4. Optionally stages snapshots into a target Azure Storage Account container using Azure blob copy.
      5. Generates an architectural backup manifest with SAS expiration tracking.

.PARAMETER ResourceGroupName
    Resource Group of the target Virtual Machine.

.PARAMETER VmName
    Name of the Virtual Machine to backup.

.PARAMETER DestinationStorageAccountName
    Optional Storage Account Name to copy snapshots to.

.PARAMETER DestinationContainerName
    Target blob container name in the destination storage account (default: 'vm-backups').

.PARAMETER RetentionDays
    Number of days for tag-based retention tracking. Default is 30.

.PARAMETER SasDurationHours
    Validity duration in hours for the export SAS tokens. Default is 24 hours.

.EXAMPLE
    .\Backup-AzVmDiskToStorageAccount.ps1 -ResourceGroupName "rg-prod-db" -VmName "vm-db-01" -RetentionDays 14
    Takes coordinated snapshots of all disks on vm-db-01 and outputs the backup manifest.

.EXAMPLE
    .\Backup-AzVmDiskToStorageAccount.ps1 -ResourceGroupName "rg-prod-db" -VmName "vm-db-01" -DestinationStorageAccountName "stbackupsprod" -DestinationContainerName "disks"
    Takes snapshots and stages copies into the specified storage container.

.NOTES
    Required Modules: Az.Accounts, Az.Compute, Az.Storage
    Permissions: Contributor on VM resource group; Storage Blob Data Contributor on destination storage account.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param (
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $true)]
    [string]$VmName,

    [Parameter(Mandatory = $false)]
    [string]$DestinationStorageAccountName,

    [Parameter(Mandatory = $false)]
    [string]$DestinationContainerName = 'vm-backups',

    [Parameter(Mandatory = $false)]
    [int]$RetentionDays = 30,

    [Parameter(Mandatory = $false)]
    [int]$SasDurationHours = 24
)

process {
    $context = Get-AzContext
    if (-not $context) {
        throw "No active Azure context. Connect with 'Connect-AzAccount'."
    }

    Write-Host "Locating VM '$VmName' in '$ResourceGroupName'..." -ForegroundColor Cyan
    $vm = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VmName -ErrorAction Stop
    $location = $vm.Location
    $timestamp = (Get-Date).ToString("yyyyMMdd-HHmmss")
    $expiryDate = (Get-Date).AddDays($RetentionDays).ToString("yyyy-MM-dd")

    $disksToSnapshot = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Add OS Disk
    $disksToSnapshot.Add([PSCustomObject]@{
        DiskType     = 'OS'
        DiskName     = $vm.StorageProfile.OsDisk.Name
        ResourceId   = $vm.StorageProfile.OsDisk.ManagedDisk.Id
        SnapshotName = "$($VmName)-OS-snap-$timestamp"
    })

    # Add Data Disks
    if ($vm.StorageProfile.DataDisks) {
        foreach ($dd in $vm.StorageProfile.DataDisks) {
            $disksToSnapshot.Add([PSCustomObject]@{
                DiskType     = "Data (LUN $($dd.Lun))"
                DiskName     = $dd.Name
                ResourceId   = $dd.ManagedDisk.Id
                SnapshotName = "$($VmName)-Data$($dd.Lun)-snap-$timestamp"
            })
        }
    }

    Write-Host "Identified $($disksToSnapshot.Count) disk(s) for backup." -ForegroundColor Gray
    $manifest = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($diskItem in $disksToSnapshot) {
        if ($PSCmdlet.ShouldProcess("$($diskItem.DiskName) ($($diskItem.DiskType))", "Create Snapshot '$($diskItem.SnapshotName)'")) {
            try {
                Write-Host "Creating snapshot for $($diskItem.DiskName)..." -ForegroundColor Yellow
                $snapConfig = New-AzSnapshotConfig -SourceResourceId $diskItem.ResourceId -Location $location -CreateOption Copy -Tag @{
                    'SourceVM'        = $VmName
                    'SourceDisk'      = $diskItem.DiskName
                    'DiskType'        = $diskItem.DiskType
                    'BackupTimestamp' = $timestamp
                    'ExpiryDate'      = $expiryDate
                    'CreatedBy'       = $context.Account.Id
                }

                $snapshot = New-AzSnapshot -ResourceGroupName $ResourceGroupName -SnapshotName $diskItem.SnapshotName -Snapshot $snapConfig -ErrorAction Stop

                # Grant SAS token
                Write-Host "  -> Generating SAS export URL ($SasDurationHours hours)..." -ForegroundColor Gray
                $sasAccess = Grant-AzSnapshotAccess -ResourceGroupName $ResourceGroupName -SnapshotName $diskItem.SnapshotName `
                    -DurationInSecond ($SasDurationHours * 3600) -Access Read -ErrorAction Stop

                $copyStatus = "N/A"

                # Optional staging copy
                if ($DestinationStorageAccountName) {
                    Write-Host "  -> Initiating async blob copy to '$DestinationStorageAccountName/$DestinationContainerName'..." -ForegroundColor Gray
                    try {
                        $destStorage = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $DestinationStorageAccountName -ErrorAction SilentlyContinue
                        if (-not $destStorage) {
                            $destStorage = Get-AzStorageAccount | Where-Object { $_.StorageAccountName -eq $DestinationStorageAccountName } | Select-Object -First 1
                        }

                        if ($destStorage) {
                            $blobName = "$($diskItem.SnapshotName).vhd"
                            Start-AzStorageBlobCopy -AbsoluteUri $sasAccess.AccessSAS -DestContainer $DestinationContainerName `
                                -DestBlob $blobName -Context $destStorage.Context -ErrorAction Stop | Out-Null
                            $copyStatus = "CopyInitiated: $blobName"
                        } else {
                            $copyStatus = "Failed: Destination Storage Account not found"
                        }
                    } catch {
                        $copyStatus = "CopyError: $($_.Exception.Message)"
                    }
                }

                $manifest.Add([PSCustomObject]@{
                    VMName          = $VmName
                    DiskType        = $diskItem.DiskType
                    OriginalDisk    = $diskItem.DiskName
                    SnapshotName    = $diskItem.SnapshotName
                    SnapshotId      = $snapshot.Id
                    SasExpiryHours  = $SasDurationHours
                    SasUrl          = $sasAccess.AccessSAS
                    StagingStatus   = $copyStatus
                    RetentionExpiry = $expiryDate
                })
            } catch {
                Write-Error "Failed to snapshot $($diskItem.DiskName): $($_.Exception.Message)"
            }
        }
    }

    Write-Host "`nCoordinated disk backup complete!" -ForegroundColor Green
    $manifest | Select-Object VMName, DiskType, SnapshotName, StagingStatus, RetentionExpiry | Format-Table -AutoSize

    return $manifest
}
