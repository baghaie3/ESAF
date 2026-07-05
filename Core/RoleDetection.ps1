# Core\RoleDetection.ps1
function Get-ESAFHostRole {
    [CmdletBinding()]
    param()

    $role = "Unknown"

    try {
        $dcRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS"
        if (Test-Path $dcRegPath) {
            $role = "DomainController"
        }
        else {
            $cs = Get-CimInstance Win32_ComputerSystem

            if ($cs.PartOfDomain -eq $true) {
                if ($cs.DomainRole -in 3,4) {
                    $role = "MemberServer"
                }
                elseif ($cs.DomainRole -in 2) {
                    $role = "DomainJoinedWorkstation"
                }
                else {
                    $role = "DomainJoinedUnknown"
                }
            }
            else {
                if ($cs.Role -like "*Workstation*") {
                    $role = "StandaloneWorkstation"
                }
                else {
                    $role = "StandaloneServer"
                }
            }
        }
    }
    catch {
        $role = "Unknown"
    }

    return $role
}
