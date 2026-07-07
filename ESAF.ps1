param(
    [switch]$NonInteractive
)

$ErrorActionPreference = "Stop"

# ----------------------------
# Resolve ESAF root
# ----------------------------
$scriptPath = $MyInvocation.ScriptName
if ([string]::IsNullOrWhiteSpace($scriptPath)) {
    if ($PSCommandPath) {
        $scriptPath = $PSCommandPath
    } elseif ($PSScriptRoot) {
        $scriptPath = Join-Path $PSScriptRoot "ESAF.ps1"
    } else {
        $scriptPath = Join-Path (Get-Location).Path "ESAF.ps1"
    }
}

$script:ESAFRoot = Split-Path -Parent $scriptPath
$corePath        = Join-Path $script:ESAFRoot "Core"
$modulesPath     = Join-Path $script:ESAFRoot "Modules"

Write-Host "ESAFRoot   : $script:ESAFRoot"   -ForegroundColor DarkGray
Write-Host "CorePath   : $corePath"          -ForegroundColor DarkGray
Write-Host "ModulesPath: $modulesPath"       -ForegroundColor DarkGray

# ----------------------------
# Dot-source Core & Modules
# ----------------------------
$filesToDotSource = @(
    (Join-Path $modulesPath "Common.ps1"),
    (Join-Path $corePath    "Functions.ps1"),
    (Join-Path $corePath    "RoleDetection.ps1"),
    (Join-Path $corePath    "Menu.ps1"),
    (Join-Path $corePath    "Orchestrator.ps1"),
    (Join-Path $corePath    "Reporting.ps1"),
    (Join-Path $modulesPath "Firewall.ps1"),
    (Join-Path $modulesPath "LocalSecurity.ps1"),
    (Join-Path $modulesPath "Services.ps1"),
    (Join-Path $modulesPath "NetworkSecurity.ps1"),
    (Join-Path $modulesPath "IdentityAudit.ps1"),
    (Join-Path $modulesPath "ActiveDirectoryAudit.ps1"),
    (Join-Path $modulesPath "PasswordPolicy.ps1")
)

foreach ($f in $filesToDotSource) {
    if (-not (Test-Path $f)) {
        Write-Host "[!] Missing file: $f" -ForegroundColor Red
        continue
    }
    . $f
}

# ----------------------------
# Banner
# ----------------------------
Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  ESAF - Enterprise Security Assessment Framework" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# ----------------------------
# Host Role Selection
# ----------------------------
$hostRole = $null

if (-not $NonInteractive) {
    Write-Host "[?] Select target host role:" -ForegroundColor Cyan
    Write-Host "    1) Domain Controller"
    Write-Host "    2) Member Server"
    Write-Host "    3) Workstation"
    Write-Host "    4) IIS Server"
    Write-Host "    5) File Server"
    $roleChoice = Read-Host "Enter choice (1-5)"

    switch ($roleChoice) {
        "1" { $hostRole = "DomainController" }
        "2" { $hostRole = "MemberServer" }
        "3" { $hostRole = "DomainJoinedWorkstation" }
        "4" { $hostRole = "IISServer" }
        "5" { $hostRole = "FileServer" }
        default {
            Write-Host "[!] Invalid choice. Defaulting to MemberServer." -ForegroundColor Yellow
            $hostRole = "MemberServer"
        }
    }
}
else {
    $detectedRole = Get-ESAFHostRole
    if ([string]::IsNullOrWhiteSpace($detectedRole) -or $detectedRole -eq "Unknown") {
        Write-Host "[!] Host role unknown in NonInteractive mode. Defaulting to MemberServer." -ForegroundColor Yellow
        $hostRole = "MemberServer"
    }
    else {
        $hostRole = $detectedRole
    }
}

Write-Host "[*] Using host role: $hostRole" -ForegroundColor Green

# ----------------------------
# Report Root
# ----------------------------
$reportRoot = "C:\SECURITYREPORTS"

if (-not (Test-Path $reportRoot)) {
    New-Item -ItemType Directory -Path $reportRoot | Out-Null
}

$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$hostname  = $env:COMPUTERNAME

$runFolder      = Join-Path $reportRoot "${timestamp}_${hostname}"
$evidenceFolder = Join-Path $runFolder "Evidence"

New-Item -ItemType Directory -Path $runFolder      | Out-Null
New-Item -ItemType Directory -Path $evidenceFolder | Out-Null

Write-Host "[*] Run folder   : $runFolder"      -ForegroundColor Cyan
Write-Host "[*] Evidence path: $evidenceFolder" -ForegroundColor Cyan

# ----------------------------
# Menu / Scan Mode
# ----------------------------
$scanMode        = "Full"
$selectedModules = @()

$baselineModules = @(
    "Firewall",
    "LocalSecurity",
    "Services",
    "NetworkSecurity",
    "PasswordPolicy"
)

$roleSpecificModulesMap = @{
    "DomainController"       = @("IdentityAudit", "ActiveDirectoryAudit")
    "MemberServer"           = @()
    "DomainJoinedWorkstation"= @()
    "IISServer"              = @()
    "FileServer"             = @()
}

if (-not $NonInteractive) {
    Write-Host ""
    Write-Host "================ ESAF Main Menu ================" -ForegroundColor Cyan
    Write-Host "1) Full Report"
    Write-Host "2) Server Report"
    Write-Host "3) Baseline Report"
    Write-Host "4) Custom Module Selection"
    Write-Host "================================================" -ForegroundColor Cyan

    $menuChoice = Read-Host "Select an option"

    switch ($menuChoice) {
        "1" {
            $scanMode = "Full"
            $selectedModules = @($baselineModules)
            if ($roleSpecificModulesMap.ContainsKey($hostRole)) {
                $selectedModules += $roleSpecificModulesMap[$hostRole]
            }
        }
        "2" {
            $scanMode = "ServerReport"
            $selectedModules = @($baselineModules)
            if ($roleSpecificModulesMap.ContainsKey($hostRole)) {
                $selectedModules += $roleSpecificModulesMap[$hostRole]
            }
        }
        "3" {
            $scanMode = "Baseline"
            $selectedModules = @($baselineModules)
        }
        "4" {
            $scanMode = "Custom"

            $availableModules = @($baselineModules)
            if ($roleSpecificModulesMap.ContainsKey($hostRole)) {
                $availableModules += $roleSpecificModulesMap[$hostRole]
            }

            Write-Host ""
            Write-Host "Available Modules:" -ForegroundColor Cyan
            for ($i = 0; $i -lt $availableModules.Count; $i++) {
                Write-Host ("{0}) {1}" -f ($i + 1), $availableModules[$i])
            }

            $selectionInput = Read-Host "Select module numbers separated by commas (e.g. 1,3,5)"
            $selectedIndices = $selectionInput.Split(',') | ForEach-Object {
                $trimmed = $_.Trim()
                if ($trimmed -match '^\d+$') { [int]$trimmed - 1 }
            }

            foreach ($index in $selectedIndices) {
                if ($index -ge 0 -and $index -lt $availableModules.Count) {
                    $selectedModules += $availableModules[$index]
                }
            }

            $selectedModules = $selectedModules | Select-Object -Unique
        }
        default {
            Write-Host "[!] Invalid menu choice, defaulting to Full scan." -ForegroundColor Yellow
            $scanMode = "Full"
            $selectedModules = @($baselineModules)
            if ($roleSpecificModulesMap.ContainsKey($hostRole)) {
                $selectedModules += $roleSpecificModulesMap[$hostRole]
            }
        }
    }
}
else {
    $scanMode = "Full"
    $selectedModules = @($baselineModules)
    if ($roleSpecificModulesMap.ContainsKey($hostRole)) {
        $selectedModules += $roleSpecificModulesMap[$hostRole]
    }
}

Write-Host ""
Write-Host "[*] Scan mode   : $scanMode" -ForegroundColor Cyan
Write-Host "[*] Modules     : $($selectedModules -join ', ')" -ForegroundColor Cyan
Write-Host ""

# ----------------------------
# Orchestrator
# ----------------------------
$findings = @()

try {
    $findings = Invoke-ESAFOrchestrator `
        -ScanType        $scanMode `
        -SelectedModules $selectedModules `
        -SystemRoles     $null `
        -EvidencePath    $evidenceFolder `
        -HostRole        $hostRole
}
catch {
    Write-Host "[!] Orchestrator failed: $($_.Exception.Message)" -ForegroundColor Red
}

# ----------------------------
# Report Paths
# ----------------------------
$htmlReportPath = Join-Path $runFolder "Assessment_Report.html"
$jsonReportPath = Join-Path $runFolder "Assessment_Report.json"
$csvReportPath  = Join-Path $runFolder "Assessment_Report.csv"
$txtReportPath  = Join-Path $runFolder "Assessment_Report.txt"

# ----------------------------
# Reporting Calls
# ----------------------------
try {
    Export-ESAFHtmlReport -Findings $findings -Path $htmlReportPath -Roles $hostRole -SystemName $hostname -ScanType $scanMode
}
catch {
    Write-Host "[!] Failed to generate HTML report: $($_.Exception.Message)" -ForegroundColor Red
}

try {
    Export-ESAFJsonReport -Findings $findings -Path $jsonReportPath
}
catch {
    Write-Host "[!] Failed to generate JSON report: $($_.Exception.Message)" -ForegroundColor Red
}

try {
    Export-ESAFCsvReport -Findings $findings -Path $csvReportPath
}
catch {
    Write-Host "[!] Failed to generate CSV report: $($_.Exception.Message)" -ForegroundColor Red
}

try {
    Export-ESAFTxtSummary -Findings $findings -Path $txtReportPath -Roles $hostRole -SystemName $hostname -ScanType $scanMode
}
catch {
    Write-Host "[!] Failed to generate TXT summary report: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""
Write-Host "================ Assessment Completed ================" -ForegroundColor Green
Write-Host "HTML report : $htmlReportPath"
Write-Host "JSON report : $jsonReportPath"
Write-Host "CSV report  : $csvReportPath"
Write-Host "TXT summary : $txtReportPath"
Write-Host "Evidence    : $evidenceFolder"
Write-Host "Run folder  : $runFolder"
Write-Host "======================================================" -ForegroundColor Green
Write-Host ""

if (-not $NonInteractive) {
    $openChoice = Read-Host "Open HTML report now? (Y/N)"
    if ($openChoice -match '^(Y|y)') {
        Invoke-Item $htmlReportPath
    }
}
