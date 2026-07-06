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
    (Join-Path $corePath    "RoleDetection.ps1"),
    (Join-Path $corePath    "Menu.ps1"),
    (Join-Path $corePath    "Orchestrator.ps1"),
    (Join-Path $corePath    "Reporting.ps1"),
    (Join-Path $modulesPath "Firewall.ps1"),
    (Join-Path $modulesPath "LocalSecurity.ps1"),
    (Join-Path $modulesPath "Services.ps1"),
    (Join-Path $modulesPath "NetworkSecurity.ps1"),
    (Join-Path $modulesPath "IdentityAudit.ps1")
    (Join-Path $modulesPath "ActiveDirectoryAudit.ps1")

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
# Host Role Detection
# ----------------------------
$hostRole = Get-ESAFHostRole
Write-Host "[*] Detected host role: $hostRole" -ForegroundColor Cyan

if ($hostRole -eq "Unknown" -and -not $NonInteractive) {
    Write-Host "[?] Unable to determine host role automatically." -ForegroundColor Yellow
    Write-Host "    1) Domain Controller"
    Write-Host "    2) Member Server"
    Write-Host "    3) Workstation"
    $roleChoice = Read-Host "Enter choice (1-3)"

    switch ($roleChoice) {
        "1" { $hostRole = "DomainController" }
        "2" { $hostRole = "MemberServer" }
        "3" { $hostRole = "DomainJoinedWorkstation" }
        default {
            Write-Host "[!] Invalid choice. Defaulting to MemberServer." -ForegroundColor Yellow
            $hostRole = "MemberServer"
        }
    }
}
elseif ($hostRole -eq "Unknown" -and $NonInteractive) {
    Write-Host "[!] Host role unknown in NonInteractive mode. Defaulting to MemberServer." -ForegroundColor Yellow
    $hostRole = "MemberServer"
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

if (-not $NonInteractive) {
    $menuChoice = Show-ESAFMainMenu -HostRole $hostRole

    switch ($menuChoice) {
        "1" { $scanMode = "Full";       $selectedModules = @() }
        "2" { $scanMode = "RoleBased";  $selectedModules = @("IdentityAudit") }
        "3" { $scanMode = "RoleBased";  $selectedModules = @("NetworkSecurity") }
        "4" { $scanMode = "Custom";     $selectedModules = Show-ESAFCustomModuleSelection }
        default {
            Write-Host "[!] Invalid menu choice, defaulting to Full scan." -ForegroundColor Yellow
            $scanMode = "Full"
        }
    }
}

Write-Host ""
Write-Host "[*] Scan mode   : $scanMode" -ForegroundColor Cyan
Write-Host ""

# ----------------------------
# Orchestrator
# ----------------------------
$findings = @()

try {
    $findings = Invoke-ESAFOrchestrator `
        -ScanType       $scanMode `
        -SelectedModules $selectedModules `
        -SystemRoles    $null `
        -EvidencePath   $evidenceFolder `
        -HostRole       $hostRole
}
catch {
    Write-Host "[!] Orchestrator failed: $($_.Exception.Message)" -ForegroundColor Red
}

# ----------------------------
# Report Paths
# ----------------------------
$htmlReportPath = Join-Path $runFolder "DC_Assessment.html"
$jsonReportPath = Join-Path $runFolder "DC_Assessment.json"
$csvReportPath  = Join-Path $runFolder "DC_Assessment.csv"
$txtReportPath  = Join-Path $runFolder "DC_Assessment.txt"

# ----------------------------
# Reporting Calls (Fixed)
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
