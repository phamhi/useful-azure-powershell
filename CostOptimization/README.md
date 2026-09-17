# Cost optimization scripts

PowerShell tools to locate and reclaim unused or over-provisioned Azure resources across subscriptions.

## Table of contents
- [Overview](#overview)
- [Scripts](#scripts)
  - [Find-AzOrphanedResources.ps1](#find-azorphanedresourcesps1)
  - [Analyze-AzAppServiceCostEfficiency.ps1](#analyze-azappservicecostefficiencyps1)
  - [Export-AzSnapshotHygieneReport.ps1](#export-azsnapshothygienereportps1)
  - [Clean-AzStaleResourceGroups.ps1](#clean-azstaleresourcegroupsps1)
- [Required Azure modules](#required-azure-modules)
- [Usage examples](#usage-examples)

## Overview

Cloud bills often carry costs from abandoned infrastructure: disks left behind after deleting a virtual machine, network interfaces never reattached, empty app service plans running in premium tiers, and expired temporary resource groups. These scripts query Azure Resource Graph and Azure Monitor to identify waste, estimate cost impact, and clean up unneeded items safely.

## Scripts

### Find-AzOrphanedResources.ps1

Scans subscriptions for unattached managed disks, disconnected network interfaces, unallocated public IP addresses, empty network security groups, and route tables with no subnet associations.

- **Parameters:**
  - `SubscriptionIds`: Optional list of subscription IDs to scan. Defaults to all active subscriptions.
  - `ResourceTypes`: Resource filter (`All`, `Disks`, `NICs`, `PublicIPs`, `NSGs`, `RouteTables`). Default is `All`.
  - `ExportCsvPath`: Writes raw records to a CSV file.
  - `ExportHtmlPath`: Builds a standalone HTML report with a summary table and cost estimates.
  - `Delete`: Deletes identified items. Supports `-WhatIf` and prompts for confirmation before removing resources.

### Analyze-AzAppServiceCostEfficiency.ps1

Audits App Service Plans across subscriptions to find plans hosting zero web apps or functions, and evaluates CPU and memory metrics over a rolling window.

- **Parameters:**
  - `SubscriptionIds`: Optional list of subscription IDs.
  - `LookbackDays`: Historical metric window in days (default: 7).
  - `LowCpuThresholdPercent`: Utilization percentage below which an active plan is flagged as oversized (default: 15).
  - `ExportCsvPath`: Target path for CSV export.

### Export-AzSnapshotHygieneReport.ps1

Audits managed disk snapshots older than a configurable number of days. Checks whether the original parent disk still exists in Azure or has been removed, and estimates monthly retention expenses.

- **Parameters:**
  - `SubscriptionIds`: Optional list of subscription IDs.
  - `AgeDaysThreshold`: Snapshot age threshold in days (default: 60).
  - `PurgeStale`: Switch to delete snapshots older than the threshold. Supports `-WhatIf`.
  - `ExportCsvPath`: Output path for CSV reporting.

### Clean-AzStaleResourceGroups.ps1

Finds empty resource groups and groups carrying expiration or TTL tags whose date has passed. Checks for management locks before taking action.

- **Parameters:**
  - `SubscriptionIds`: Optional list of subscription IDs.
  - `ExpirationTagNames`: Tag names checked for dates (default: `ExpiresOn`, `TTL`, `AutoDeleteDate`, `DeleteAfter`).
  - `IncludeEmptyGroups`: Identifies groups with zero resources (default: `$true`).
  - `RemoveLocksAndDecommission`: Removes blocking locks before deletion. Requires confirmation or `-WhatIf`.
  - `Delete`: Removes candidate resource groups.

## Required Azure modules

- `Az.Accounts`
- `Az.ResourceGraph`
- `Az.Compute`
- `Az.Network`
- `Az.Websites`
- `Az.Monitor`
- `Az.Resources`

## Usage examples

Generate an HTML report of all orphaned assets across subscriptions:
```powershell
.\Find-AzOrphanedResources.ps1 -ExportHtmlPath "C:\Reports\OrphanedAssets.html"
```

Find underused App Service Plans over the last two weeks:
```powershell
.\Analyze-AzAppServiceCostEfficiency.ps1 -LookbackDays 14 -ExportCsvPath "C:\Reports\AppServiceAudit.csv"
```

Preview removal of disk snapshots older than 90 days:
```powershell
.\Export-AzSnapshotHygieneReport.ps1 -AgeDaysThreshold 90 -PurgeStale -WhatIf
```
