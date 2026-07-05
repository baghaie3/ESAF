$ErrorActionPreference = "Stop"

# Load Core Files
. "$PSScriptRoot\Core\Functions.ps1"
. "$PSScriptRoot\Core\RoleDetection.ps1"
. "$PSScriptRoot\Core\Reporting.ps1"
. "$PSScriptRoot\Core\Menu.ps1"

# Load Module Helpers
. "$PSScriptRoot\Modules\Common.ps1"

# Load Assessment Modules
. "$PSScriptRoot\Modules\Firewall.ps1"

# Ensure Admin Mode
Start-ESAFAutoElevation

Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "      ESAF - Security Assessment     " -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan

# 1. Detect Roles first (Quietly)
$roles = Get-ESAFSystemRoles

# 2. Get User Input
$selection = Show-ESAFMainMenu

$scanType = "Quick"
switch ($selection) {
    "1" { $scanType = "Quick" }
    "2" { $scanType = "Full" }
    "3" { $scanType = "Role-Based" }
    "4" { 
        $customChoice = Show-ESAFCustomModuleMenu
        if ($customChoice -eq "2") { exit }
        $scanType = "Custom"
    }
    "5" { 
        Write-Host "[*] Exiting..." -ForegroundColor Yellow
        exit 
    }
}

# 3. Create Report Folder ONLY after choice is confirmed, injecting ScanType
$reportInfo = New-ESAFReportFolder -BasePath "C:\SECURITYREPORTS" -SystemName "$($env:COMPUTERNAME)_$scanType"
Write-Host "[+] Report folder created: $($reportInfo.ReportPath)" -ForegroundColor Green
Write-Host "[+] Detected System Roles: $($roles -join ', ')" -ForegroundColor Green

# 4. Run Assessments
$allFindings = @()

Write-Host "[*] Executing Firewall Diagnostic module..." -ForegroundColor Yellow
$allFindings += Invoke-ESAFFirewallAssessment -EvidencePath $reportInfo.EvidencePath

# 5. Export Reports with scan-type in file name
$jsonPath = Join-Path $reportInfo.ReportPath "ESAF_$($scanType)_Assessment.json"
$csvPath  = Join-Path $reportInfo.ReportPath "ESAF_$($scanType)_Assessment.csv"
$htmlPath = Join-Path $reportInfo.ReportPath "ESAF_$($scanType)_Assessment.html"

Export-ESAFJsonReport -Findings $allFindings -Path $jsonPath
Export-ESAFCsvReport -Findings $allFindings -Path $csvPath
Export-ESAFHtmlReport -Findings $allFindings -Path $htmlPath -Roles $roles -SystemName $env:COMPUTERNAME -ScanType $scanType

Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "[+] JSON: $jsonPath" -ForegroundColor Green
Write-Host "[+] CSV:  $csvPath" -ForegroundColor Green
Write-Host "[+] HTML: $htmlPath" -ForegroundColor Green
Write-Host "[+] Done! Total findings: $($allFindings.Count)" -ForegroundColor Cyan
