function Invoke-ESAFOrchestrator {
    param(
        [string]$ScanType,
        [array]$SelectedModules, # برای حالت Custom
        [array]$SystemRoles,     # برای حالت Role-Based
        [string]$EvidencePath
    )

    Write-Host "[*] Initializing ESAF Orchestrator..." -ForegroundColor Cyan
    Write-Host "[*] Scan Mode: $ScanType" -ForegroundColor Cyan
    
    $allFindings = @()

    # تعریف ماژول‌های موجود و متادیتای آن‌ها برای نگاشت نقش‌ها
    # این هشت‌تیبل مشخص می‌کند هر ماژول به چه نقش‌هایی مرتبط است
    $moduleRegistry = @{
        "Firewall" = @{
            ScriptPath = "Modules\Firewall.ps1"
            CmdletName = "Invoke-ESAFFirewallAssessment"
            Roles      = @("Any") # روی همه سیستم‌ها اجرا می‌شود
        }
        "LocalSecurity" = @{
            ScriptPath = "Modules\LocalSecurity.ps1"
            CmdletName = "Invoke-ESAFLocalSecurityAssessment"
            Roles      = @("Any") # روی همه سیستم‌ها اجرا می‌شود
        }
        "Services" = @{
            ScriptPath = "Modules\Services.ps1"
            CmdletName = "Invoke-ESAFServicesAssessment"
            Roles      = @("Any") # روی همه سیستم‌ها اجرا می‌شود
        }
        # در آینده ماژول‌های اختصاصی مثل IIS یا AD اینجا اضافه می‌شوند:
        # "IIS" = @{ ScriptPath = "Modules\IIS.ps1"; CmdletName = "Invoke-ESAFIisAssessment"; Roles = @("Web Server (IIS)") }
    }

    # تعیین لیست نهایی ماژول‌هایی که باید اجرا شوند
    $modulesToRun = @()

    switch ($ScanType) {
        "Full" {
            $modulesToRun = $moduleRegistry.Keys
        }
        "Role-Based" {
            # انتخاب ماژول‌هایی که نقش آن‌ها "Any" است یا با نقش‌های سیستم مطابقت دارد
            foreach ($modName in $moduleRegistry.Keys) {
                $modRoles = $moduleRegistry[$modName].Roles
                if ($modRoles -contains "Any") {
                    $modulesToRun += $modName
                } else {
                    # بررسی اشتراک نقش‌های سیستم با نقش‌های ماژول
                    $match = $SystemRoles | Where-Object { $modRoles -contains $_ }
                    if ($match) {
                        $modulesToRun += $modName
                    }
                }
            }
        }
        "Custom" {
            $modulesToRun = $SelectedModules
        }
    }

    Write-Host "[*] Queued Modules: $($modulesToRun -join ', ')" -ForegroundColor Yellow

    # اجرای ماژول‌ها به صورت پویا
    foreach ($moduleName in $modulesToRun) {
        if ($moduleRegistry.ContainsKey($moduleName)) {
            $modInfo = $moduleRegistry[$moduleName]
            $scriptFullPath = Join-Path $PSScriptRoot "..\" | Join-Path -ChildPath $modInfo.ScriptPath
            
            if (Test-Path $scriptFullPath) {
                Write-Host "[>] Running Module: $moduleName..." -ForegroundColor Green
                
                # لود کردن ماژول در Session فعلی
                . $scriptFullPath

                # فراخوانی تابع ماژول به صورت پویا همراه با ارسال مسیر Evidence
                $params = @{ EvidencePath = $EvidencePath }
                $moduleFindings = & $modInfo.CmdletName @params
                
                if ($moduleFindings) {
                    Write-Host "[+] Module $moduleName returned $($moduleFindings.Count) findings." -ForegroundColor Green
                    $allFindings += $moduleFindings
                } else {
                    Write-Host "[-] Module $moduleName returned 0 findings." -ForegroundColor Gray
                }
            } else {
                Write-Warning "Module script not found: $scriptFullPath"
            }
        }
    }

    return $allFindings
}
