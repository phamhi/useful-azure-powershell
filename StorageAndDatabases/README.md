# Storage and database scripts

PowerShell tools to audit storage account security against baseline benchmarks, evaluate SQL database utilization, and analyze blob lifecycle tiering.

## Table of contents
- [Overview](#overview)
- [Scripts](#scripts)
  - [Audit-AzStorageAccountSecurity.ps1](#audit-azstorageaccountsecurityps1)
  - [Export-AzSqlDatabasePerformanceReport.ps1](#export-azsqldatabaseperformancereportps1)
  - [Clean-AzStorageBlobLifecycle.ps1](#clean-azstoragebloblifecycleps1)
- [Required Azure modules](#required-azure-modules)
- [Usage examples](#usage-examples)

## Overview

Storage accounts and managed databases house business data. Keeping them secure and cost-efficient requires regular checks: ensuring older TLS protocols and shared keys are disabled, auditing firewall settings, monitoring database capacity headroom, and identifying older blobs stored in expensive access tiers.

## Scripts

### Audit-AzStorageAccountSecurity.ps1

Audits Azure Storage Accounts against common baseline standards. Checks for TLS 1.2 enforcement, shared key access, network firewall default rules, anonymous public blob access, HTTPS enforcement, soft-delete configuration, and key management types.

- **Parameters:**
  - `SubscriptionIds`: Optional list of subscription IDs.
  - `ExportCsvPath`: Saves the scorecard and findings to a CSV file.

### Export-AzSqlDatabasePerformanceReport.ps1

Gathers configuration and utilization data for Azure SQL Databases across servers. Inspects maximum database size, evaluates CPU utilization over a lookback window, checks Transparent Data Encryption (TDE) status, and checks active geo-replication health.

- **Parameters:**
  - `SubscriptionIds`: Optional list of subscription IDs.
  - `LookbackDays`: Number of days of metric history to evaluate (default: 7).
  - `HighStorageThresholdPercent`: Storage percentage used to trigger capacity warnings (default: 80).
  - `ExportCsvPath`: Target path for CSV reporting.

### Clean-AzStorageBlobLifecycle.ps1

Scans blob containers to locate objects that have not been modified within a given number of days. Projects monthly storage cost savings if blobs are moved from Hot to Cool, Cold, or Archive tiers, and can apply tier changes directly.

- **Parameters:**
  - `ResourceGroupName`: Resource group containing the storage account.
  - `StorageAccountName`: Target storage account name.
  - `ContainerName`: Optional container name. Defaults to evaluating all containers.
  - `DaysInactiveThreshold`: Inactivity threshold in days (default: 90).
  - `TargetTier`: Optional tier to apply to qualifying blobs (`Cool`, `Cold`, `Archive`). Supports `-WhatIf`.
  - `ExportCsvPath`: File path for CSV export.

## Required Azure modules

- `Az.Accounts`
- `Az.Storage`
- `Az.Sql`
- `Az.Monitor`

## Usage examples

Audit storage accounts across all subscriptions for security baseline compliance:
```powershell
.\Audit-AzStorageAccountSecurity.ps1 -ExportCsvPath "C:\Reports\StorageSecurity.csv"
```

Report on SQL databases approaching storage limits or experiencing high CPU:
```powershell
.\Export-AzSqlDatabasePerformanceReport.ps1 -LookbackDays 14 -ExportCsvPath "C:\Reports\SqlPerformance.csv"
```

Find blobs untouched for six months and test moving them to cool tier:
```powershell
.\Clean-AzStorageBlobLifecycle.ps1 -ResourceGroupName "rg-data-prod" -StorageAccountName "stbackupsprod" -DaysInactiveThreshold 180 -TargetTier "Cool" -WhatIf
```
