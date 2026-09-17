# Useful Azure PowerShell scripts

A repository of 25 Azure PowerShell automation and governance scripts for infrastructure operations, cost management, security audits, and diagnostics.

## Table of contents
- [Overview](#overview)
- [Design conventions](#design-conventions)
- [Repository layout](#repository-layout)
- [Script catalog](#script-catalog)
  - [Cost optimization](#1-cost-optimization)
  - [Security and governance](#2-security-and-governance)
  - [Networking](#3-networking)
  - [Compute](#4-compute)
  - [Monitoring and backup](#5-monitoring-and-backup)
  - [Storage and databases](#6-storage-and-databases)
  - [Platform operations](#7-platform-operations)
- [Prerequisites and setup](#prerequisites-and-setup)
- [Quick start](#quick-start)
- [License](#license)

## Overview

This repository contains PowerShell scripts that use the `Az` module and Azure Resource Graph (`Search-AzGraph`) to automate routine operational tasks across Azure subscriptions. The scripts target common infrastructure needs such as reclaiming unused resources, checking security baselines, troubleshooting network routing, assessing patch status, and managing resource locks.

## Design conventions

- **Safety checks**: Modifying scripts use `[CmdletBinding(SupportsShouldProcess = $true)]`. You can run them with `-WhatIf` to inspect intended changes without altering resources.
- **Subscription scope**: Scripts accept an optional array of subscription IDs. When omitted, they inspect all active subscriptions in the current context.
- **Structured output**: Commands return `PSCustomObject` instances for pipeline processing, and most scripts provide `-ExportCsvPath` or `-ExportHtmlPath` parameters.
- **Error handling**: Operations run inside `try/catch` blocks with explicit error output to prevent silent failures.
- **Built-in help**: Every script contains standard comment help with parameter definitions and concrete examples.

## Repository layout

Each directory contains a dedicated `README.md` describing its scripts and usage:

```
useful-azure-powershell/
├── CostOptimization/         # Unused disks, idle public IPs, empty app plans, stale groups
├── SecurityAndGovernance/    # Privileged roles, open endpoints, cert expiry, NSG rules, tagging
├── Networking/               # VNet peering matrix, connectivity checks, private DNS, UDRs
├── Compute/                  # Patch audits, safe VM resizing, multi-disk backups, run commands
├── MonitoringAndBackup/      # Diagnostic streaming, backup coverage, alert inventory
├── StorageAndDatabases/      # Storage security baseline, SQL headroom/TDE, blob tiering
└── PlatformOperations/       # Resource Graph inventory summary, management lock automation
```

## Script catalog

### 1. Cost optimization

Detailed documentation: [CostOptimization/README.md](CostOptimization/README.md)

| Script | Description | Key modules |
| :--- | :--- | :--- |
| [`Find-AzOrphanedResources.ps1`](CostOptimization/Find-AzOrphanedResources.ps1) | Finds unattached disks, disconnected NICs, unused public IPs, and empty NSGs. | `Az.ResourceGraph`, `Az.Compute`, `Az.Network` |
| [`Analyze-AzAppServiceCostEfficiency.ps1`](CostOptimization/Analyze-AzAppServiceCostEfficiency.ps1) | Evaluates CPU and memory metrics on App Service Plans to flag idle or oversized tiers. | `Az.Websites`, `Az.Monitor` |
| [`Export-AzSnapshotHygieneReport.ps1`](CostOptimization/Export-AzSnapshotHygieneReport.ps1) | Audits aging disk snapshots and checks whether source disks still exist. | `Az.Compute` |
| [`Clean-AzStaleResourceGroups.ps1`](CostOptimization/Clean-AzStaleResourceGroups.ps1) | Identifies empty groups or groups past their expiration dates. | `Az.Resources` |

### 2. Security and governance

Detailed documentation: [SecurityAndGovernance/README.md](SecurityAndGovernance/README.md)

| Script | Description | Key modules |
| :--- | :--- | :--- |
| [`Audit-AzPrivilegedRoleAssignments.ps1`](SecurityAndGovernance/Audit-AzPrivilegedRoleAssignments.ps1) | Audits Owner, Contributor, and User Access Admin roles, flagging guest accounts and orphaned IDs. | `Az.Resources` |
| [`Find-AzExposedPublicEndpoints.ps1`](SecurityAndGovernance/Find-AzExposedPublicEndpoints.ps1) | Checks for internet-accessible storage blobs, open Key Vaults, and unrestricted SQL firewalls. | `Az.Storage`, `Az.KeyVault`, `Az.Sql`, `Az.Websites` |
| [`Test-AzKeyVaultCertificateExpiry.ps1`](SecurityAndGovernance/Test-AzKeyVaultCertificateExpiry.ps1) | Scans Key Vaults for certificates and secrets expiring within a given window. | `Az.KeyVault` |
| [`Audit-AzNetworkSecurityRules.ps1`](SecurityAndGovernance/Audit-AzNetworkSecurityRules.ps1) | Flags inbound NSG rules allowing unrestricted internet access to management and database ports. | `Az.Network` |
| [`Enforce-AzResourceTaggingPolicy.ps1`](SecurityAndGovernance/Enforce-AzResourceTaggingPolicy.ps1) | Validates resource tags and can inherit missing values from parent resource groups. | `Az.Resources` |

### 3. Networking

Detailed documentation: [Networking/README.md](Networking/README.md)

| Script | Description | Key modules |
| :--- | :--- | :--- |
| [`Export-AzVNetPeeringMatrix.ps1`](Networking/Export-AzVNetPeeringMatrix.ps1) | Maps peering connections, transit configurations, and overlapping IP ranges. | `Az.Network` |
| [`Test-AzNetworkConnectivityDiagnostics.ps1`](Networking/Test-AzNetworkConnectivityDiagnostics.ps1) | Evaluates end-to-end VM reachability, next-hop routing, latency, and NSG rules. | `Az.Network`, `Az.Compute` |
| [`Audit-AzPrivateEndpointDNSResolution.ps1`](Networking/Audit-AzPrivateEndpointDNSResolution.ps1) | Verifies Private Endpoint A-records in Private DNS Zones and confirms VNet links. | `Az.Network`, `Az.PrivateDns` |
| [`Export-AzRouteTableTopology.ps1`](Networking/Export-AzRouteTableTopology.ps1) | Audits user-defined routes across subnets and locates blackholed traffic paths. | `Az.Network` |

### 4. Compute

Detailed documentation: [Compute/README.md](Compute/README.md)

| Script | Description | Key modules |
| :--- | :--- | :--- |
| [`Invoke-AzVmAutomatedPatchAssessment.ps1`](Compute/Invoke-AzVmAutomatedPatchAssessment.ps1) | Reviews OS update status, reboot states, and missing critical patches. | `Az.Compute` |
| [`Resize-AzVmWithPreFlightChecks.ps1`](Compute/Resize-AzVmWithPreFlightChecks.ps1) | Checks cluster size availability, vCPU quota, and disk limits before resizing a VM. | `Az.Compute`, `Az.Network` |
| [`Backup-AzVmDiskToStorageAccount.ps1`](Compute/Backup-AzVmDiskToStorageAccount.ps1) | Creates point-in-time snapshots of all VM disks and generates access SAS tokens. | `Az.Compute`, `Az.Storage` |
| [`Invoke-AzVmMultiRunCommand.ps1`](Compute/Invoke-AzVmMultiRunCommand.ps1) | Executes scripts across multiple running VMs in parallel using Run Command. | `Az.Compute` |

### 5. Monitoring and backup

Detailed documentation: [MonitoringAndBackup/README.md](MonitoringAndBackup/README.md)

| Script | Description | Key modules |
| :--- | :--- | :--- |
| [`Deploy-AzDiagnosticSettingsBaseline.ps1`](MonitoringAndBackup/Deploy-AzDiagnosticSettingsBaseline.ps1) | Configures diagnostic log streaming to Log Analytics across PaaS resources. | `Az.Monitor`, `Az.Resources` |
| [`Audit-AzBackupProtectedItems.ps1`](MonitoringAndBackup/Audit-AzBackupProtectedItems.ps1) | Audits backup vault health, reviews recent job failures, and flags unprotected VMs. | `Az.RecoveryServices`, `Az.Compute` |
| [`Export-AzLogAnalyticsQueryAlerts.ps1`](MonitoringAndBackup/Export-AzLogAnalyticsQueryAlerts.ps1) | Catalogs scheduled query alert rules and verifies linked action groups. | `Az.Monitor` |

### 6. Storage and databases

Detailed documentation: [StorageAndDatabases/README.md](StorageAndDatabases/README.md)

| Script | Description | Key modules |
| :--- | :--- | :--- |
| [`Audit-AzStorageAccountSecurity.ps1`](StorageAndDatabases/Audit-AzStorageAccountSecurity.ps1) | Checks storage configurations for TLS 1.2, shared key status, firewalls, and soft delete. | `Az.Storage` |
| [`Export-AzSqlDatabasePerformanceReport.ps1`](StorageAndDatabases/Export-AzSqlDatabasePerformanceReport.ps1) | Reviews database storage headroom, metric peaks, TDE status, and geo-replication. | `Az.Sql`, `Az.Monitor` |
| [`Clean-AzStorageBlobLifecycle.ps1`](StorageAndDatabases/Clean-AzStorageBlobLifecycle.ps1) | Finds blobs unmodified for 90+ days and estimates savings for moving them to cool tier. | `Az.Storage` |

### 7. Platform operations

Detailed documentation: [PlatformOperations/README.md](PlatformOperations/README.md)

| Script | Description | Key modules |
| :--- | :--- | :--- |
| [`Get-AzSubscriptionInventorySummary.ps1`](PlatformOperations/Get-AzSubscriptionInventorySummary.ps1) | Summarizes resource distribution across regions and subscriptions via Resource Graph. | `Az.ResourceGraph` |
| [`Manage-AzResourceLocksBulk.ps1`](PlatformOperations/Manage-AzResourceLocksBulk.ps1) | Audits, applies, or removes CanNotDelete and ReadOnly management locks in bulk. | `Az.Resources` |

## Prerequisites and setup

### PowerShell version
PowerShell 7 (Core) is recommended for best performance. Windows PowerShell 5.1 is also supported.

### Az module installation
Install the latest `Az` PowerShell module:
```powershell
Install-Module -Name Az -Repository PSGallery -Force -AllowClobber
```

### Authentication
Authenticate with Azure before executing any script:
```powershell
Connect-AzAccount
```

To target a specific directory tenant:
```powershell
Connect-AzAccount -TenantId "00000000-0000-0000-0000-000000000000"
```

## Quick start

Run an orphaned resource scan and export an HTML report:
```powershell
.\CostOptimization\Find-AzOrphanedResources.ps1 -ExportHtmlPath "C:\Reports\OrphanedResources.html"
```

Inspect inbound security rules on all network security groups:
```powershell
.\SecurityAndGovernance\Audit-AzNetworkSecurityRules.ps1 -ExportCsvPath "C:\Reports\NSGRules.csv"
```

Run VM resize pre-checks in test mode:
```powershell
.\Compute\Resize-AzVmWithPreFlightChecks.ps1 -ResourceGroupName "rg-app-prod" -VmName "vm-web-01" -TargetSize "Standard_D4s_v5" -WhatIf
```

