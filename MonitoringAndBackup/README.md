# Monitoring and backup scripts

PowerShell tools to enforce Log Analytics diagnostic streaming, audit Azure Backup vaults, and inventory scheduled query alerts.

## Table of contents
- [Overview](#overview)
- [Scripts](#scripts)
  - [Deploy-AzDiagnosticSettingsBaseline.ps1](#deploy-azdiagnosticsettingsbaselineps1)
  - [Audit-AzBackupProtectedItems.ps1](#audit-azbackupprotecteditemsps1)
  - [Export-AzLogAnalyticsQueryAlerts.ps1](#export-azloganalyticsqueryalertsps1)
- [Required Azure modules](#required-azure-modules)
- [Usage examples](#usage-examples)

## Overview

Reliable observability and data protection require consistent setup across cloud resources. Key Vaults without audit logging leave security teams blind during investigations, unmonitored virtual machines can miss backup windows unnoticed, and alerts that point to deleted action groups fail silently. These scripts inspect diagnostic pipelines, backup protection coverage, and alerting setups.

## Scripts

### Deploy-AzDiagnosticSettingsBaseline.ps1

Audits and configures diagnostic settings to stream audit logs and metrics from Key Vaults, Network Security Groups, Application Gateways, and SQL Databases to a centralized Log Analytics workspace.

- **Parameters:**
  - `WorkspaceResourceId`: Resource ID of the target Log Analytics workspace.
  - `SubscriptionIds`: Optional list of subscription IDs.
  - `ResourceTypesToAudit`: Resource types to check (defaults to Key Vaults, NSGs, and SQL Databases).
  - `Remediate`: Configures missing diagnostic settings on non-compliant resources. Supports `-WhatIf`.
  - `DiagnosticSettingName`: Name assigned to the setting (default: `law-baseline-diagnostic`).
  - `ExportCsvPath`: Saves the compliance evaluation to CSV.

### Audit-AzBackupProtectedItems.ps1

Inspects Recovery Services Vaults across subscriptions. Evaluates the health of protected virtual machines, reviews job history over a recent window for failures, and flags virtual machines that have no backup policy assigned.

- **Parameters:**
  - `SubscriptionIds`: Optional list of subscription IDs.
  - `JobLookbackHours`: Hours of job history to evaluate for failures (default: 24).
  - `ExportCsvPath`: Writes backup status records to CSV.

### Export-AzLogAnalyticsQueryAlerts.ps1

Catalogs KQL-based scheduled query alert rules across subscriptions. Extracts queries, evaluation schedules, and severity levels, and checks whether target action groups still exist.

- **Parameters:**
  - `SubscriptionIds`: Optional list of subscription IDs.
  - `ExportCsvPath`: Target path for CSV export.

## Required Azure modules

- `Az.Accounts`
- `Az.Monitor`
- `Az.RecoveryServices`
- `Az.Compute`
- `Az.Resources`

## Usage examples

Audit diagnostic setting compliance against a central workspace:
```powershell
.\Deploy-AzDiagnosticSettingsBaseline.ps1 -WorkspaceResourceId "/subscriptions/.../workspaces/law-prod" -ExportCsvPath "C:\Reports\DiagnosticAudit.csv"
```

Check backup status and find unprotected machines:
```powershell
.\Audit-AzBackupProtectedItems.ps1 -JobLookbackHours 48 -ExportCsvPath "C:\Reports\BackupHealth.csv"
```

Catalog scheduled query rules and locate broken action groups:
```powershell
.\Export-AzLogAnalyticsQueryAlerts.ps1 -ExportCsvPath "C:\Reports\AlertInventory.csv"
```
