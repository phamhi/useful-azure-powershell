# Platform operations scripts

PowerShell tools for multi-subscription inventory reporting and resource lock governance.

## Table of contents
- [Overview](#overview)
- [Scripts](#scripts)
  - [Get-AzSubscriptionInventorySummary.ps1](#get-azsubscriptioninventorysummaryps1)
  - [Manage-AzResourceLocksBulk.ps1](#manage-azresourcelocksbulkps1)
- [Required Azure modules](#required-azure-modules)
- [Usage examples](#usage-examples)

## Overview

Platform engineers responsible for multiple Azure subscriptions need quick ways to survey broad cloud estates and apply guardrails. These scripts summarize asset counts and geographic distribution via Azure Resource Graph, evaluate tag completeness, and enforce management locks across production resources to prevent accidental deletion.

## Scripts

### Get-AzSubscriptionInventorySummary.ps1

Runs fast KQL queries via Azure Resource Graph across accessible subscriptions. Summarizes resource counts by subscription, provider type, and region, and calculates tag compliance percentages. Can generate an HTML dashboard.

- **Parameters:**
  - `SubscriptionIds`: Optional list of subscription IDs.
  - `ExportHtmlPath`: Generates a standalone HTML dashboard.
  - `ExportCsvPath`: Saves the provider distribution to CSV.

### Manage-AzResourceLocksBulk.ps1

Audits, applies, or removes Azure Management Locks (`CanNotDelete`, `ReadOnly`) across resource groups. Filters targets by tag (for example, `Environment = Production`) and provides a safe simulation mode.

- **Parameters:**
  - `Action`: Operation mode (`Audit`, `ApplyLock`, `RemoveLock`). Default is `Audit`.
  - `LockLevel`: Target lock type (`CanNotDelete`, `ReadOnly`). Default is `CanNotDelete`.
  - `SubscriptionIds`: Optional list of subscription IDs.
  - `TagFilter`: Hashtable of tag key-value pairs to target.
  - `LockNotes`: Informational note attached to newly created locks.
  - `ExportCsvPath`: Target path for CSV reporting.

## Required Azure modules

- `Az.Accounts`
- `Az.ResourceGraph`
- `Az.Resources`

## Usage examples

Generate an executive HTML dashboard of all cloud resources:
```powershell
.\Get-AzSubscriptionInventorySummary.ps1 -ExportHtmlPath "C:\Reports\CloudSummary.html"
```

Audit management locks across all production resource groups:
```powershell
.\Manage-AzResourceLocksBulk.ps1 -Action Audit -TagFilter @{ 'Environment' = 'Production' }
```

Test applying CanNotDelete locks to production groups:
```powershell
.\Manage-AzResourceLocksBulk.ps1 -Action ApplyLock -LockLevel CanNotDelete -TagFilter @{ 'Environment' = 'Production' } -WhatIf
```
