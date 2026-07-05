# Core\Menu.ps1
function Show-ESAFMainMenu {
    param(
        [string]$HostRole
    )

    Write-Host ""
    Write-Host "================ ESAF Main Menu ================"
    Write-Host "Host Role: $HostRole"
    Write-Host "==============================================="
    Write-Host ""

    switch ($HostRole) {
        "DomainController" {
            Write-Host "1) Full DC Security Assessment"
            Write-Host "2) Identity & Privileged Groups Audit (DC)"
            Write-Host "3) Network & Protocol Hardening (DC)"
            Write-Host "4) Custom Module Selection"
        }
        "MemberServer" {
            Write-Host "1) Full Server Security Assessment"
            Write-Host "2) Identity & Local Privilege Audit"
            Write-Host "3) Network & Protocol Hardening"
            Write-Host "4) Custom Module Selection"
        }
        default {
            Write-Host "1) Full Workstation Security Assessment"
            Write-Host "2) Identity & Local Privilege Audit"
            Write-Host "3) Network & Protocol Hardening"
            Write-Host "4) Custom Module Selection"
        }
    }

    Write-Host ""
    $choice = Read-Host "Select an option"
    return $choice
}

function Show-ESAFCustomModuleSelection {
    $availableModules = @(
        "Firewall",
        "LocalSecurity",
        "Services",
        "NetworkSecurity",
        "IdentityAudit",
        "ActiveDirectoryAudit"
    )

    Write-Host ""
    Write-Host "Available Modules:"
    $i = 1
    foreach ($m in $availableModules) {
        Write-Host "$i) $m"
        $i++
    }
    Write-Host ""
    $sel = Read-Host "Enter module numbers separated by comma (e.g. 1,3,5)"

    $indices = $sel -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' }
    $selected = @()
    foreach ($idx in $indices) {
        $pos = [int]$idx - 1
        if ($pos -ge 0 -and $pos -lt $availableModules.Count) {
            $selected += $availableModules[$pos]
        }
    }

    return $selected
}
