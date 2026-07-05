function Invoke-ESAFFirewallAssessment {
    param(
        [string]$EvidencePath
    )

    $findings = @()

    try {
        # 1. جمع‌آوری داده از Get-NetFirewallProfile
        $profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
        
        # 2. جمع‌آوری داده از Netsh
        $netshOutput = netsh advfirewall show allprofiles state | Out-String
        
        # 3. بررسی وضعیت سرویس
        $mpsSvc = Get-Service -Name MpsSvc -ErrorAction SilentlyContinue
        $serviceState = if ($mpsSvc) { "$($mpsSvc.Name) is $($mpsSvc.Status) (StartType: $($mpsSvc.StartType))" } else { "MpsSvc NOT FOUND" }

        # تعریف نگاشت دقیق برای حل ناهماهنگی نام‌ها در ویندوز
        # دامین = Domain | پرایوت = Private (رجیستری: StandardProfile، پاورشل: Standard) | پابلیک = Public
        $profileConfigs = @(
            @{
                DisplayName  = "Domain"
                CmdletName   = "Domain"
                RegistryName = "DomainProfile"
                NetshPattern = "Domain"
            },
            @{
                DisplayName  = "Private"
                CmdletName   = "Standard"  # در پاورشل نام اصلی پروفایل پرایوت Standard است
                RegistryName = "StandardProfile"
                NetshPattern = "Private"
            },
            @{
                DisplayName  = "Public"
                CmdletName   = "Public"
                RegistryName = "PublicProfile"
                NetshPattern = "Public"
            }
        )

        # 4. بررسی رجیستری GPO Policy
        $gpoRegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall"
        $gpoEvidence = ""
        $gpoStates = @{}

        if (Test-Path $gpoRegistryPath) {
            $gpoEvidence += "GPO Registry Policies Found:`n"
            foreach ($config in $profileConfigs) {
                $targetPath = Join-Path $gpoRegistryPath $config.RegistryName
                if (Test-Path $targetPath) {
                    $enableVal = Get-ItemProperty -Path $targetPath -Name "EnableFirewall" -ErrorAction SilentlyContinue
                    if ($enableVal) {
                        $gpoStates[$config.DisplayName] = [bool]$enableVal.EnableFirewall
                        $gpoEvidence += "- GPO $($config.DisplayName): EnableFirewall = $($enableVal.EnableFirewall)`n"
                    } else {
                        $gpoStates[$config.DisplayName] = $null
                    }
                } else {
                    $gpoStates[$config.DisplayName] = $null
                }
            }
        } else {
            $gpoEvidence = "No Centralized GPO Firewall Registry settings found under HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall`n"
            foreach ($config in $profileConfigs) { $gpoStates[$config.DisplayName] = $null }
        }

        # ذخیره شواهد خام برای مستندسازی
        if ($EvidencePath) {
            $rawLog = "=== SERVICE STATE ===`n$serviceState`n`n=== NETSH OUTPUT ===`n$netshOutput`n`n=== GPO REGISTRY ===`n$gpoEvidence"
            if ($profiles) {
                $rawLog += "`n=== CMDLET PROFILES ===`n" + ($profiles | Format-List | Out-String)
            }
            $rawLog | Out-File -FilePath (Join-Path $EvidencePath "Firewall_Diagnostic_Evidence.txt") -Encoding UTF8
        }

        # پردازش و اعتبارسنجی تک‌تک پروفایل‌ها
        foreach ($config in $profileConfigs) {
            $pName = $config.DisplayName

            # الف) بررسی وضعیت از خروجی Netsh
            $netshEnabled = $null
            # الگو: پیدا کردن فایروال متناظر با الگوی NetshPattern و گرفتن وضعیت خط بعد از آن
            if ($netshOutput -match "(?i)$($config.NetshPattern)\s+Profile\s+Settings:\s*`r?`n(?:.+`r?`n)*?State\s+(ON|OFF)") {
                $netshEnabled = ($matches[1] -eq "ON")
            } elseif ($netshOutput -match "(?i)$($config.NetshPattern).*?State\s+(ON|OFF)") {
                # الگوی کمکی در صورتی که ساختار خروجی ساده‌تر باشد
                $netshEnabled = ($matches[1] -eq "ON")
            }

            # ب) بررسی وضعیت از Cmdlet پاورشل (تطبیق با نام بومی Standard یا نام نمایشی)
            $cmdletProfile = $profiles | Where-Object { $_.Name -eq $config.CmdletName -or $_.Name -eq $pName }
            $cmdletEnabled = if ($cmdletProfile) { $cmdletProfile.Enabled } else { $null }

            # ج) بررسی وضعیت اعمال شده از GPO
            $gpoEnabled = $gpoStates[$pName]

            # د) منطق نهایی بررسی وضعیت فعال بودن فایروال
            $isEffectiveEnabled = $false
            if ($gpoEnabled -eq $true) {
                $isEffectiveEnabled = $true
            } elseif ($netshEnabled -eq $true) {
                $isEffectiveEnabled = $true
            } elseif ($cmdletEnabled -eq $true -and $gpoEnabled -ne $false) {
                $isEffectiveEnabled = $true
            }

            # تهیه شواهد متنی برای این پروفایل
            $evidenceSummary = @"
Profile Analyzed: $pName (Mapped Standard Name: $($config.CmdletName))
- Netsh State: $(if ($null -ne $netshEnabled) { if ($netshEnabled) {"ON"} else {"OFF"} } else {"Unknown"})
- Cmdlet State: $(if ($null -ne $cmdletEnabled) { $cmdletEnabled } else {"Unknown"})
- GPO Registry Enforced: $(if ($null -ne $gpoEnabled) { $gpoEnabled } else {"Not Configured"})
- Firewall Service Running: $(if ($mpsSvc -and $mpsSvc.Status -eq "Running") {"Yes"} else {"No"})
"@

            if ($isEffectiveEnabled) {
                $findings += New-ESAFFinding `
                    -FindingID "FW-INFO-$($pName.ToUpper())-001" `
                    -Category "Firewall" `
                    -Title "Firewall profile is active ($pName)" `
                    -Severity "Informational" `
                    -AffectedComponent $pName `
                    -Description "The Windows Firewall $pName profile is verified as active and enforcing policies." `
                    -Evidence $evidenceSummary `
                    -Impact "Informational finding. Host protection active." `
                    -Recommendation "No action required." `
                    -Reference "Microsoft Security Baseline - Defender Firewall" `
                    -Status "Informational"
            }
            else {
                $severity = "Medium"
                $rec = "Enable the $pName firewall profile using local Group Policy, active GPO, or PowerShell."
                if ($mpsSvc -and $mpsSvc.Status -ne "Running") {
                    $severity = "High"
                    $rec = "The firewall service is stopped. Start the MpsSvc service and ensure it is set to Automatic startup."
                }

                $findings += New-ESAFFinding `
                    -FindingID "FW-WARN-$($pName.ToUpper())-001" `
                    -Category "Firewall" `
                    -Title "Firewall profile disabled ($pName)" `
                    -Severity $severity `
                    -AffectedComponent $pName `
                    -Description "All diagnostic indicators (Netsh, Cmdlets, Registry) show the $pName firewall profile is inactive." `
                    -Evidence $evidenceSummary `
                    -Impact "Disabling host-based firewalls permits unrestricted lateral network connections, exposing services to unauthorized network access." `
                    -Recommendation $rec `
                    -Reference "Microsoft Security Baseline - Defender Firewall" `
                    -Status "Open"
            }
        }

    }
    catch {
        $findings += New-ESAFFinding `
            -FindingID "FW-ERR-001" `
            -Category "Firewall" `
            -Title "Firewall diagnostic failed" `
            -Severity "Medium" `
            -AffectedComponent "Windows Defender Firewall" `
            -Description "An unexpected error occurred during execution." `
            -Evidence $_.Exception.Message `
            -Impact "Visibility reduced." `
            -Recommendation "Investigate PowerShell host errors and check administrative rights." `
            -Reference "Internal Framework Validation" `
            -Status "Open"
    }

    return $findings
}
