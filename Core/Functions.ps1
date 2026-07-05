function Test-ESAFAdmin {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Start-ESAFAutoElevation {
    if (-not (Test-ESAFAdmin)) {
        Write-Host "[*] PowerShell is not running as Administrator. Requesting elevation..." -ForegroundColor Yellow

        $scriptPath = $MyInvocation.PSCommandPath
        $arguments = "-ExecutionPolicy Bypass -File `"$scriptPath`""

        Start-Process powershell.exe -Verb RunAs -ArgumentList $arguments
        exit
    }
}

function New-ESAFReportFolder {
    param(
        [string]$BasePath = "C:\SECURITYREPORTS",
        [string]$SystemName = $env:COMPUTERNAME
    )

    if (-not (Test-Path $BasePath)) {
        New-Item -Path $BasePath -ItemType Directory -Force | Out-Null
    }

    $timestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
    $reportPath = Join-Path $BasePath "$timestamp`_$SystemName"
    $evidencePath = Join-Path $reportPath "Evidence"

    New-Item -Path $reportPath -ItemType Directory -Force | Out-Null
    New-Item -Path $evidencePath -ItemType Directory -Force | Out-Null

    return [PSCustomObject]@{
        BasePath     = $BasePath
        ReportPath   = $reportPath
        EvidencePath = $evidencePath
        Timestamp    = $timestamp
        SystemName   = $SystemName
    }
}
