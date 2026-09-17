# Security and governance scripts

PowerShell tools to audit access permissions, discover exposed network endpoints, check certificate lifecycles, and enforce organizational resource tags.

## Table of contents
- [Overview](#overview)
- [Scripts](#scripts)
  - [Audit-AzPrivilegedRoleAssignments.ps1](#audit-azprivilegedroleassignmentsps1)
  - [Find-AzExposedPublicEndpoints.ps1](#find-azexposedpublicendpointsps1)
  - [Test-AzKeyVaultCertificateExpiry.ps1](#test-azkeyvaultcertificateexpiryps1)
  - [Audit-AzNetworkSecurityRules.ps1](#audit-aznetworksecurityrulesps1)
  - [Enforce-AzResourceTaggingPolicy.ps1](#enforce-azresourcetaggingpolicyps1)
- [Required Azure modules](#required-azure-modules)
- [Usage examples](#usage-examples)

## Overview

Maintaining security across multiple Azure subscriptions requires checking who holds elevated roles, ensuring databases and storage accounts do not sit open to the internet, and preventing expired certificates from disrupting workloads. The scripts in this directory audit role assignments, internet exposure, SSL/TLS certificates, and tagging policies.

## Scripts

### Audit-AzPrivilegedRoleAssignments.ps1

Audits high-privilege Azure RBAC roles (Owner, User Access Administrator, Contributor) across subscriptions and management groups. Flags external guest users (`#EXT#`) and identities deleted from Entra ID that still have role bindings.

- **Parameters:**
  - `SubscriptionIds`: Optional list of subscription IDs.
  - `IncludeContributor`: Include Contributor assignments in the scan (default: `$true`).
  - `ExportCsvPath`: Writes findings to a CSV file.

### Find-AzExposedPublicEndpoints.ps1

Scans PaaS and IaaS services to detect resources accessible directly from the public internet. Checks for anonymous blob access on storage accounts, open Key Vault firewalls, SQL firewall rules permitting all internet IPs (`0.0.0.0` to `255.255.255.255`), and App Services lacking IP restrictions.

- **Parameters:**
  - `SubscriptionIds`: Optional list of subscription IDs.
  - `ExportCsvPath`: Saves exposure findings to a CSV spreadsheet.

### Test-AzKeyVaultCertificateExpiry.ps1

Iterates through Key Vaults to audit SSL/TLS certificates and secrets nearing expiration or already expired. Checks if auto-renewal policies exist for managed certificates.

- **Parameters:**
  - `SubscriptionIds`: Optional list of subscription IDs.
  - `DaysThreshold`: Days remaining before expiration to trigger a warning (default: 30).
  - `IncludeSecrets`: Switch to check secret expiration dates alongside certificates.
  - `ExportCsvPath`: Target path for CSV reporting.

### Audit-AzNetworkSecurityRules.ps1

Evaluates Network Security Group rules to detect inbound `Allow` rules open to wildcard `*` or `Internet` sources on sensitive ports, including SSH (22), RDP (3389), SMB (445), and databases (1433, 3306, 5432).

- **Parameters:**
  - `SubscriptionIds`: Optional list of subscription IDs.
  - `FlaggedPorts`: Array of ports to check. Defaults to standard remote management and database ports.
  - `ExportCsvPath`: File path to output results.

### Enforce-AzResourceTaggingPolicy.ps1

Validates resource tags against defined naming schemas and regular expressions. Can populate missing tags on child resources by inheriting values from their parent Resource Group.

- **Parameters:**
  - `SubscriptionIds`: Optional list of subscription IDs.
  - `RequiredTags`: Hashtable of tag keys and optional regex validation patterns for tag values.
  - `InheritFromResourceGroup`: Pulls missing tag values from parent Resource Groups.
  - `Remediate`: Applies tags to non-compliant resources. Supports `-WhatIf`.
  - `ExportCsvPath`: Path for compliance CSV export.

## Required Azure modules

- `Az.Accounts`
- `Az.Resources`
- `Az.Storage`
- `Az.KeyVault`
- `Az.Sql`
- `Az.Websites`
- `Az.Network`

## Usage examples

Find all external guest users with Owner or Contributor roles:
```powershell
.\Audit-AzPrivilegedRoleAssignments.ps1 -ExportCsvPath "C:\Reports\PrivilegedRoles.csv"
```

Find certificates expiring within the next 45 days:
```powershell
.\Test-AzKeyVaultCertificateExpiry.ps1 -DaysThreshold 45 -IncludeSecrets -ExportCsvPath "C:\Reports\ExpiringCerts.csv"
```

Inherit missing tags from resource groups in test mode:
```powershell
.\Enforce-AzResourceTaggingPolicy.ps1 -InheritFromResourceGroup -Remediate -WhatIf
```
