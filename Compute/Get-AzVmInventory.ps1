<#
.SYNOPSIS
    Retrieves Azure VM inventory with power state and sizing info.
#>
function Get-AzVmInventory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$ResourceGroupName
    )
    Write-Output "Querying Azure Virtual Machines inventory on dev branch..."
}
