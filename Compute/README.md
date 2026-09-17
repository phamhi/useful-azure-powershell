# Compute scripts

PowerShell tools to manage virtual machine patching, safe SKU resizing, coordinated multi-disk backups, and fleet-wide script execution.

## Table of contents
- [Overview](#overview)
- [Scripts](#scripts)
  - [Invoke-AzVmAutomatedPatchAssessment.ps1](#invoke-azvmautomatedpatchassessmentps1)
  - [Resize-AzVmWithPreFlightChecks.ps1](#resize-azvmwithpreflightchecksps1)
  - [Backup-AzVmDiskToStorageAccount.ps1](#backup-azvmdisktostorageaccountps1)
  - [Invoke-AzVmMultiRunCommand.ps1](#invoke-azvmmultiruncommandps1)
- [Required Azure modules](#required-azure-modules)
- [Usage examples](#usage-examples)

## Overview

Virtual machines remain central to enterprise environments. Managing them safely means avoiding surprises during maintenance: checking cluster hardware and regional quota before attempting a resize, backing up all attached data disks together so filesystems remain coherent, verifying update status, and executing commands without opening public management ports.

## Scripts

### Invoke-AzVmAutomatedPatchAssessment.ps1

Queries Azure Update Manager for OS patch status across Windows and Linux virtual machines. Reports missing security and critical updates, pending reboot states, and can trigger on-demand scans.

- **Parameters:**
  - `SubscriptionIds`: Optional list of subscription IDs.
  - `ResourceGroupName`: Optional resource group filter.
  - `TriggerNewAssessment`: Triggers an immediate patch scan on target machines.
  - `ExportCsvPath`: Saves the compliance evaluation to CSV.

### Resize-AzVmWithPreFlightChecks.ps1

Runs pre-flight checks before modifying a virtual machine size. Verifies whether the target size exists on the current physical cluster, checks regional vCPU quota, validates maximum data disk counts, checks premium storage support, and handles required deallocations safely.

- **Parameters:**
  - `ResourceGroupName`: Name of the resource group holding the VM.
  - `VmName`: Name of the virtual machine.
  - `TargetSize`: Desired Azure VM size (for example, `Standard_D4s_v5`).
  - `ForceDeallocateIfRequired`: Allows stopping and deallocating the machine if the target size is unavailable on the current cluster.

### Backup-AzVmDiskToStorageAccount.ps1

Takes point-in-time snapshots of the OS disk and every attached data disk of a virtual machine. Tags snapshots with source machine and expiration metadata, generates read-only SAS access URLs, and optionally stages copies into an Azure Storage container.

- **Parameters:**
  - `ResourceGroupName`: Resource group containing the virtual machine.
  - `VmName`: Name of the virtual machine.
  - `DestinationStorageAccountName`: Optional storage account to receive disk copies.
  - `DestinationContainerName`: Target blob container name (default: `vm-backups`).
  - `RetentionDays`: Expiration period written to snapshot tags (default: 30).
  - `SasDurationHours`: SAS token validity window in hours (default: 24).

### Invoke-AzVmMultiRunCommand.ps1

Executes PowerShell (Windows) or Bash (Linux) scripts across groups of running virtual machines in parallel through the Azure Run Command agent, without needing direct network reachability or open SSH/RDP ports.

- **Parameters:**
  - `ScriptContent`: Script text to run on target machines.
  - `ScriptFilePath`: Path to a local script file to run.
  - `ResourceGroupName`: Optional resource group filter.
  - `TagFilter`: Hashtable of tag key-value pairs to match.
  - `OsType`: Target operating system (`Windows`, `Linux`, `All`). Default is `Windows`.
  - `ThrottleLimit`: Maximum concurrent machines to target at once (default: 5).
  - `ExportCsvPath`: Target path for execution log export.

## Required Azure modules

- `Az.Accounts`
- `Az.Compute`
- `Az.Storage`
- `Az.Network`

## Usage examples

Trigger a patch scan across all machines in a resource group:
```powershell
.\Invoke-AzVmAutomatedPatchAssessment.ps1 -ResourceGroupName "rg-prod-vms" -TriggerNewAssessment -ExportCsvPath "C:\Reports\PatchAudit.csv"
```

Simulate resizing a database server to verify quota and cluster support:
```powershell
.\Resize-AzVmWithPreFlightChecks.ps1 -ResourceGroupName "rg-db-prod" -VmName "vm-db-01" -TargetSize "Standard_E8s_v5" -WhatIf
```

Execute an inventory command across all backend web servers:
```powershell
.\Invoke-AzVmMultiRunCommand.ps1 -TagFilter @{ 'Tier' = 'Web' } -ScriptContent "Get-Service wuauserv | Select-Object Name, Status"
```
