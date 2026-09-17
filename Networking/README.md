# Networking scripts

PowerShell tools to map virtual network peering, diagnose connectivity hops, audit private endpoint DNS resolution, and inspect route tables.

## Table of contents
- [Overview](#overview)
- [Scripts](#scripts)
  - [Export-AzVNetPeeringMatrix.ps1](#export-azvnetpeeringmatrixps1)
  - [Test-AzNetworkConnectivityDiagnostics.ps1](#test-aznetworkconnectivitydiagnosticsps1)
  - [Audit-AzPrivateEndpointDNSResolution.ps1](#audit-azprivateendpointdnsresolutionps1)
  - [Export-AzRouteTableTopology.ps1](#export-azroutetabletopologyps1)
- [Required Azure modules](#required-azure-modules)
- [Usage examples](#usage-examples)

## Overview

Azure virtual network architectures grow complex as teams connect multiple subscriptions through hub-and-spoke models, private endpoints, and network virtual appliances. These scripts help verify peering connections, check for overlapping IP addresses, test end-to-end traffic flows, ensure private DNS zones link correctly to subnets, and find blackholed routes.

## Scripts

### Export-AzVNetPeeringMatrix.ps1

Maps virtual networks across subscriptions and regions into a unified connectivity table. Evaluates peering status, gateway transit settings, and checks for overlapping IPv4 address spaces.

- **Parameters:**
  - `SubscriptionIds`: Optional list of subscription IDs.
  - `CheckCidrOverlap`: Checks whether any two VNets share identical address prefixes (default: `$true`).
  - `ExportCsvPath`: Saves the peering matrix to a CSV file.

### Test-AzNetworkConnectivityDiagnostics.ps1

Automates Azure Network Watcher to test reachability between a source virtual machine and a destination IP or host. Evaluates packet transmission, round-trip latency, next-hop route choices, and effective network security group rules.

- **Parameters:**
  - `ResourceGroupName`: Name of the resource group holding the source virtual machine.
  - `SourceVmName`: Name of the source virtual machine.
  - `DestinationAddress`: Target IP address or domain name.
  - `DestinationPort`: Target TCP port number.
  - `Protocol`: Network protocol (`Tcp` or `Http`, default: `Tcp`).

### Audit-AzPrivateEndpointDNSResolution.ps1

Verifies that private endpoints register correct A-records in corresponding Private DNS Zones, and confirms that host virtual networks link to those zones.

- **Parameters:**
  - `SubscriptionIds`: Optional list of subscription IDs.
  - `ExportCsvPath`: Saves the validation output to CSV.

### Export-AzRouteTableTopology.ps1

Extracts user-defined routes across subnets. Identifies routes whose next hop is set to `None` (blackholed traffic), maps appliance routes, and flags route tables that are not attached to any subnet.

- **Parameters:**
  - `SubscriptionIds`: Optional list of subscription IDs.
  - `ExportCsvPath`: Writes the routing inventory to a CSV file.

## Required Azure modules

- `Az.Accounts`
- `Az.Network`
- `Az.Compute`
- `Az.PrivateDns`

## Usage examples

Export a complete peering matrix and detect IP collisions:
```powershell
.\Export-AzVNetPeeringMatrix.ps1 -CheckCidrOverlap -ExportCsvPath "C:\Reports\PeeringTopology.csv"
```

Diagnose connection problems between an application server and a database:
```powershell
.\Test-AzNetworkConnectivityDiagnostics.ps1 -ResourceGroupName "rg-app-prod" -SourceVmName "vm-web-01" -DestinationAddress "10.200.1.4" -DestinationPort 1433
```

Validate private endpoint DNS registration across all subscriptions:
```powershell
.\Audit-AzPrivateEndpointDNSResolution.ps1 -ExportCsvPath "C:\Reports\PrivateDnsValidation.csv"
```
