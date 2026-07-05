function Get-ESAFSystemRoles {
    $roles = @()

    try {
        $cs = Get-CimInstance Win32_ComputerSystem

        if ($cs.DomainRole -ge 4) {
            $roles += "Domain Controller"
        }
        elseif ($cs.PartOfDomain) {
            $roles += "Member Server or Domain-Joined Client"
        }
        else {
            $roles += "Workgroup System"
        }

        $features = Get-WindowsFeature -ErrorAction SilentlyContinue

        if ($features) {
            if (($features | Where-Object { $_.Name -eq "DNS" -and $_.InstallState -eq "Installed" })) {
                $roles += "DNS Server"
            }
            if (($features | Where-Object { $_.Name -eq "Web-Server" -and $_.InstallState -eq "Installed" })) {
                $roles += "IIS Web Server"
            }
            if (($features | Where-Object { $_.Name -eq "FS-FileServer" -and $_.InstallState -eq "Installed" })) {
                $roles += "File Server"
            }
            if (($features | Where-Object { $_.Name -eq "AD-Domain-Services" -and $_.InstallState -eq "Installed" })) {
                $roles += "Active Directory Domain Services"
            }
        }
    }
    catch {
        $roles += "Unknown"
    }

    return $roles | Select-Object -Unique
}
