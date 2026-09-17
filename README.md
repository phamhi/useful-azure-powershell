# Useful Azure PowerShell Scripts

A curated collection of 25 enterprise-grade, production-ready PowerShell automation and governance scripts for Microsoft Azure. Built using the modern Azure PowerShell (`Az`) module and Azure Resource Graph (`Search-AzGraph`), these scripts provide platform engineers, cloud architects, and SecOps teams with advanced tooling for cost optimization, security auditing, networking diagnostics, compute management, and governance.

---

## Key Features & Design Standards

Unlike basic one-liner wrappers, every script in this repository adheres to enterprise platform engineering standards:

- **Safety by Default**: Non-read-only scripts implement `[CmdletBinding(SupportsShouldProcess = $true)]` supporting `-WhatIf` (dry-run simulation) and `-Confirm` prompting before making changes.
- **Multi-Subscription & Tenant Scale**: Supports scanning across all active subscriptions or filtering by specific subscription IDs using high-speed Azure Resource Graph queries.
- **Structured Error Handling**: Comprehensive `try/catch` error blocks with terminating and non-terminating controls (`-ErrorAction Stop`).
- **Pipeline & Automation Ready**: Accepts pipeline input (`ValueFromPipeline = $true`), returns structured `[PSCustomObject]` pipelines, and supports optional `-ExportCsvPath` and `-ExportHtmlPath` exports.
- **Comment-Based Help**: Complete documentation for every script including `.SYNOPSIS`, `.DESCRIPTION`, `.PARAMETER`, `.EXAMPLE`, required Az sub-modules, and RBAC permissions.

---

## Repository Structure

```
useful-azure-powershell/
├── CostOptimization/
│   ├── Find-AzOrphanedResources.ps1
│   ├── Analyze-AzAppServiceCostEfficiency.ps1
│   ├── Export-AzSnapshotHygieneReport.ps1
│   └── Clean-AzStaleResourceGroups.ps1
├── SecurityAndGovernance/
│   ├── Audit-AzPrivilegedRoleAssignments.ps1
│   ├── Find-AzExposedPublicEndpoints.ps1
│   ├── Test-AzKeyVaultCertificateExpiry.ps1
│   ├── Audit-AzNetworkSecurityRules.ps1
│   └── Enforce-AzResourceTaggingPolicy.ps1
├── Networking/
│   ├── Export-AzVNetPeeringMatrix.ps1
│   ├── Test-AzNetworkConnectivityDiagnostics.ps1
│   ├── Audit-AzPrivateEndpointDNSResolution.ps1
│   └── Export-AzRouteTableTopology.ps1
├── Compute/
│   ├── Invoke-AzVmAutomatedPatchAssessment.ps1
│   ├── Resize-AzVmWithPreFlightChecks.ps1
│   ├── Backup-AzVmDiskToStorageAccount.ps1
│   └── Invoke-AzVmMultiRunCommand.ps1
├── MonitoringAndBackup/
│   ├── Deploy-AzDiagnosticSettingsBaseline.ps1
│   ├── Audit-AzBackupProtectedItems.ps1
│   └── Export-AzLogAnalyticsQueryAlerts.ps1
├── StorageAndDatabases/
│   ├── Audit-AzStorageAccountSecurity.ps1
│   ├── Export-AzSqlDatabasePerformanceReport.ps1
│   └── Clean-AzStorageBlobLifecycle.ps1
└── PlatformOperations/
    ├── Get-AzSubscriptionInventorySummary.ps1
    └── Manage-AzResourceLocksBulk.ps1
```

---

## Script Catalog

### 1. Cost Optimization & Waste Reclamation

| Script | Description | Key Modules |
| :--- | :--- | :--- |
| [`Find-AzOrphanedResources.ps1`](CostOptimization/Find-AzOrphanedResources.ps1) | Discovers unattached managed disks, orphaned NICs, unallocated public IPs, empty NSGs, and unattached route tables across subscriptions. Generates styled HTML/CSV waste reports with optional `-Delete`. | `Az.ResourceGraph`, `Az.Compute`, `Az.Network` |
| [`Analyze-AzAppServiceCostEfficiency.ps1`](CostOptimization/Analyze-AzAppServiceCostEfficiency.ps1) | Evaluates App Service Plans hosting 0 apps and queries 7-14 day Azure Monitor metrics to flag oversized, underutilized plans (<15% CPU). | `Az.Websites`, `Az.Monitor` |
| [`Export-AzSnapshotHygieneReport.ps1`](CostOptimization/Export-AzSnapshotHygieneReport.ps1) | Audits aging managed disk snapshots (>60 days), checks if parent source disks still exist or have been deleted, and estimates waste. | `Az.Compute` |
| [`Clean-AzStaleResourceGroups.ps1`](CostOptimization/Clean-AzStaleResourceGroups.ps1) | Identifies empty resource groups (0 resources) or groups past their expiration/TTL tags, validates lock status, and assists with retirement. | `Az.Resources` |

### 2. Security, Identity & Governance

| Script | Description | Key Modules |
| :--- | :--- | :--- |
| [`Audit-AzPrivilegedRoleAssignments.ps1`](SecurityAndGovernance/Audit-AzPrivilegedRoleAssignments.ps1) | Audits Owner, Contributor, and User Access Administrator assignments across Management Groups/Subscriptions, flagging guest accounts (`#EXT#`) and orphaned identities. | `Az.Resources` |
| [`Find-AzExposedPublicEndpoints.ps1`](SecurityAndGovernance/Find-AzExposedPublicEndpoints.ps1) | Audits internet-facing exposure across Storage Accounts (blob anonymous access), Key Vaults (firewall bypass), SQL (0.0.0.0/0 rules), App Services, and AKS. | `Az.Storage`, `Az.KeyVault`, `Az.Sql`, `Az.Websites` |
| [`Test-AzKeyVaultCertificateExpiry.ps1`](SecurityAndGovernance/Test-AzKeyVaultCertificateExpiry.ps1) | Scans Key Vaults for SSL/TLS certificates and secrets expiring within a configurable window (e.g. 30/60 days) and verifies auto-renewal policies. | `Az.KeyVault` |
| [`Audit-AzNetworkSecurityRules.ps1`](SecurityAndGovernance/Audit-AzNetworkSecurityRules.ps1) | Detects open inbound rules from `*` or `Internet` to high-risk administrative (22, 3389, 5985) and database ports (1433, 3306, 5432). | `Az.Network` |
| [`Enforce-AzResourceTaggingPolicy.ps1`](SecurityAndGovernance/Enforce-AzResourceTaggingPolicy.ps1) | Validates mandatory tag keys/patterns and remediates non-compliant resources by inheriting tags from parent Resource Groups with audit rollback. | `Az.Resources` |

### 3. Networking & Hybrid Connectivity

| Script | Description | Key Modules |
| :--- | :--- | :--- |
| [`Export-AzVNetPeeringMatrix.ps1`](Networking/Export-AzVNetPeeringMatrix.ps1) | Maps global VNet peering topology, validates gateway transit / remote gateway usage, and identifies IPv4 CIDR address space collisions. | `Az.Network` |
| [`Test-AzNetworkConnectivityDiagnostics.ps1`](Networking/Test-AzNetworkConnectivityDiagnostics.ps1) | Orchestrates Network Watcher connectivity tests, next-hop evaluation, and security group rules to diagnose reachability issues and latency. | `Az.Network`, `Az.Compute` |
| [`Audit-AzPrivateEndpointDNSResolution.ps1`](Networking/Audit-AzPrivateEndpointDNSResolution.ps1) | Audits Private Endpoints against Private DNS Zones to verify A-record registration, allocated private IPs, and VNet zone links. | `Az.Network`, `Az.PrivateDns` |
| [`Export-AzRouteTableTopology.ps1`](Networking/Export-AzRouteTableTopology.ps1) | Audits User Defined Routes (UDRs) and effective route tables across subnets, detecting blackholed paths (`None`) and NVA route anomalies. | `Az.Network` |

### 4. Compute & Virtual Machine Operations

| Script | Description | Key Modules |
| :--- | :--- | :--- |
| [`Invoke-AzVmAutomatedPatchAssessment.ps1`](Compute/Invoke-AzVmAutomatedPatchAssessment.ps1) | Evaluates OS patch status via Azure Update Manager, tracking missing Critical/Security updates, reboot states, and compliance grades. | `Az.Compute` |
| [`Resize-AzVmWithPreFlightChecks.ps1`](Compute/Resize-AzVmWithPreFlightChecks.ps1) | Validates host cluster compatibility, subscription regional core quotas, ephemeral disk limits, and IP reservation safety before resizing VMs. | `Az.Compute`, `Az.Network` |
| [`Backup-AzVmDiskToStorageAccount.ps1`](Compute/Backup-AzVmDiskToStorageAccount.ps1) | Creates coordinated crash-consistent point-in-time snapshots of all attached OS and data disks, generates SAS URLs, and stages copies to Blob Storage. | `Az.Compute`, `Az.Storage` |
| [`Invoke-AzVmMultiRunCommand.ps1`](Compute/Invoke-AzVmMultiRunCommand.ps1) | Executes scripts across fleets of Windows or Linux VMs concurrently via `Invoke-AzVMRunCommand`, capturing exit codes and stdout/stderr. | `Az.Compute` |

### 5. Monitoring, Observability & Backup

| Script | Description | Key Modules |
| :--- | :--- | :--- |
| [`Deploy-AzDiagnosticSettingsBaseline.ps1`](MonitoringAndBackup/Deploy-AzDiagnosticSettingsBaseline.ps1) | Audits and configures Azure Monitor diagnostic streaming for Key Vaults, NSGs, and SQL Databases into a central Log Analytics Workspace. | `Az.Monitor`, `Az.Resources` |
| [`Audit-AzBackupProtectedItems.ps1`](MonitoringAndBackup/Audit-AzBackupProtectedItems.ps1) | Audits Recovery Services Vaults, evaluates backup health and job failures in the last 24h, and identifies unprotected virtual machines. | `Az.RecoveryServices`, `Az.Compute` |
| [`Export-AzLogAnalyticsQueryAlerts.ps1`](MonitoringAndBackup/Export-AzLogAnalyticsQueryAlerts.ps1) | Catalogs KQL Scheduled Query Alert Rules across subscriptions and verifies action group health, flagging broken or orphaned receivers. | `Az.Monitor` |

### 6. Storage & Database Management

| Script | Description | Key Modules |
| :--- | :--- | :--- |
| [`Audit-AzStorageAccountSecurity.ps1`](StorageAndDatabases/Audit-AzStorageAccountSecurity.ps1) | Assesses Storage Accounts against CIS benchmarks: TLS < 1.2, shared key access, network firewalls, public blob access, and soft delete. | `Az.Storage` |
| [`Export-AzSqlDatabasePerformanceReport.ps1`](StorageAndDatabases/Export-AzSqlDatabasePerformanceReport.ps1) | Evaluates Azure SQL database storage headroom, CPU/DTU metric peaks, active geo-replication health, and TDE encryption status. | `Az.Sql`, `Az.Monitor` |
| [`Clean-AzStorageBlobLifecycle.ps1`](StorageAndDatabases/Clean-AzStorageBlobLifecycle.ps1) | Scans containers for blobs inactive for 90+ days in Hot tier, projecting cost savings for transitions to Cool, Cold, or Archive. | `Az.Storage` |

### 7. Cloud Platform & Multi-Subscription Operations

| Script | Description | Key Modules |
| :--- | :--- | :--- |
| [`Get-AzSubscriptionInventorySummary.ps1`](PlatformOperations/Get-AzSubscriptionInventorySummary.ps1) | High-speed multi-subscription inventory aggregation via `Search-AzGraph`, generating an executive posture dashboard with HTML export. | `Az.ResourceGraph` |
| [`Manage-AzResourceLocksBulk.ps1`](PlatformOperations/Manage-AzResourceLocksBulk.ps1) | Audits, applies, or removes `CanNotDelete` and `ReadOnly` management locks across mission-critical resources based on tagging rules. | `Az.Resources` |

---

## Prerequisites & Installation

### 1. PowerShell Version
PowerShell 7.x (Core) is recommended for optimum performance and cross-platform support. Windows PowerShell 5.1 is also supported.

### 2. Azure PowerShell Module (`Az`)
Ensure the `Az` module is installed:
```powershell
Install-Module -Name Az -Repository PSGallery -Force -AllowClobber
```

### 3. Authentication
Connect to your Azure tenant before running any script:
```powershell
# Interactive login
Connect-AzAccount

# Or login to a specific tenant
Connect-AzAccount -TenantId "00000000-0000-0000-0000-000000000000"
```

---

## Quick-Start Examples

### Example 1: Discover All Orphaned Resources & Generate HTML Report
```powershell
.\CostOptimization\Find-AzOrphanedResources.ps1 -ExportHtmlPath "C:\Reports\OrphanedResources.html"
```

### Example 2: Audit High-Risk NSG Inbound Ports
```powershell
.\SecurityAndGovernance\Audit-AzNetworkSecurityRules.ps1 -ExportCsvPath "C:\Reports\NSGRisks.csv"
```

### Example 3: Test Cross-VNet Peering and Address Overlaps
```powershell
.\Networking\Export-AzVNetPeeringMatrix.ps1 -CheckCidrOverlap -ExportCsvPath "C:\Reports\PeeringMatrix.csv"
```

### Example 4: Pre-Flight Check & Resize a Virtual Machine
```powershell
# Run pre-flight checks in simulation mode (-WhatIf)
.\Compute\Resize-AzVmWithPreFlightChecks.ps1 -ResourceGroupName "rg-app-prod" -VmName "vm-app-01" -TargetSize "Standard_D4s_v5" -WhatIf
```

### Example 5: Generate an Executive Cloud Inventory Dashboard
```powershell
.\PlatformOperations\Get-AzSubscriptionInventorySummary.ps1 -ExportHtmlPath "C:\Reports\ExecutiveDashboard.html"
```

---

## License

This project is licensed under the MIT License.
