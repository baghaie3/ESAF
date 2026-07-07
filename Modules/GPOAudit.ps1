function Invoke-ESAFGPOAuditAssessment {
    [CmdletBinding()]
    param(
        [string]$EvidencePath,
        [string]$HostRole = "MemberServer"
    )

    $findings = @()

    # تابع کمکی برای ثبت یافته‌ها با حفظ سازگاری با سیستم گزارش‌دهی ESAF
    function Add-GPOFinding {
        param(
            [string]$FindingID,
            [string]$Category,
            [string]$Title,
            [string]$Severity,
            [string]$AffectedComponent,
            [string]$Description,
            [string]$Evidence,
            [string]$Impact,
            [string]$Recommendation,
            [string]$Standard = "Microsoft Security Baseline",
            [string]$Reference = "Group Policy Security Review",
            [string]$Status = "Open"
        )

        $script:findings += New-ESAFFinding `
            -FindingID $FindingID `
            -Category $Category `
            -Title $Title `
            -Severity $Severity `
            -AffectedComponent $AffectedComponent `
            -Description $Description `
            -Evidence $Evidence `
            -Impact $Impact `
            -Recommendation $Recommendation `
            -Standard $Standard `
            -Reference $Reference `
            -Status $Status
    }

    # تابع کمکی برای پارس کردن فایل‌های GptTmpl.inf (فرمت شبیه به INI)
    function ConvertFrom-InfFile {
        param([string]$FilePath)
        if (-not (Test-Path $FilePath)) { return $null }
        
        $ini = @{}
        $section = ""
        foreach ($line in Get-Content $FilePath) {
            $line = $line.Trim()
            if ($line -match '^\[(.*)\]$') {
                $section = $Matches[1].Trim()
                $ini[$section] = @{}
            }
            elseif ($line -match '^([^=]+)=(.*)$' -and $section -ne "") {
                $key = $Matches[1].Trim()
                $value = $Matches[2].Trim()
                $ini[$section][$key] = $value
            }
        }
        return $ini
    }

    # ۱. بررسی لود شدن ماژول GroupPolicy و ActiveDirectory
    try {
        Import-Module GroupPolicy -ErrorAction Stop
        Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch {
        Add-GPOFinding `
            -FindingID "GPO-MODULE-001" `
            -Category "Active Directory GPO" `
            -Title "Required Active Directory / GroupPolicy modules are not available" `
            -Severity "High" `
            -AffectedComponent "Group Policy Module" `
            -Description "The GroupPolicy or ActiveDirectory PowerShell module could not be loaded." `
            -Evidence $_.Exception.Message `
            -Impact "GPO configuration checks, deep template audits, and delegation analysis cannot be performed." `
            -Recommendation "Install Remote Server Administration Tools (RSAT) on this system." `
            -Standard "Internal ESAF Validation" `
            -Reference "GroupPolicy module dependency"
        return $script:findings
    }

    # ۲. بررسی اتصال به اکتیو دایرکتوری
    try {
        $domain = Get-ADDomain -ErrorAction Stop
        $domainName = $domain.DNSRoot
        $gpos = Get-GPO -All -ErrorAction Stop
    }
    catch {
        Add-GPOFinding `
            -FindingID "GPO-CONNECT-001" `
            -Category "Active Directory GPO" `
            -Title "Unable to query Group Policy Objects" `
            -Severity "High" `
            -AffectedComponent "Group Policy Objects" `
            -Description "The assessment could not retrieve GPO metadata from the domain controller." `
            -Evidence $_.Exception.Message `
            -Impact "GPO assessments could not be completed." `
            -Recommendation "Ensure domain connectivity and verify that the current context has read access to SYSVOL and GPO objects." `
            -Standard "Internal ESAF Validation" `
            -Reference "Domain discovery dependency"
        return $script:findings
    }

    $sysvolPoliciesPath = "\\$domainName\sysvol\$domainName\Policies"

    $gpoLookup = @{}
    foreach ($g in $gpos) {
        $gpoLookup[$g.Id.ToString("B").ToUpper()] = $g.DisplayName
    }

    # ۳. ممیزی عمیق (Deep Audit) الگوهای امنیتی (GptTmpl.inf) در SYSVOL
    if (Test-Path $sysvolPoliciesPath) {
        $gptFiles = Get-ChildItem -Path $sysvolPoliciesPath -Recurse -Filter "GptTmpl.inf" -ErrorAction SilentlyContinue
        
        $weakPasswords = @()
        $weakLockouts = @()
        $riskyURAs = @()
        $weakAuditPolicies = @()

        # تعریف مقادیر مرجع Baseline امنیتی (بر اساس Microsoft Security Baseline)
        $minPasswordLengthBaseline = 14
        $maxPasswordAgeBaseline = 60 # روز
        $minPasswordAgeBaseline = 1   # روز
        $passwordHistoryBaseline = 24 # تعداد پسوردهای ذخیره شده قبلی
        $lockoutThresholdBaseline = 10 # حداکثر تلاش‌های ناموفق مجاز

        # لیست نگاشت SIDهای پرریسک به نام‌های متداول جهت ممیزی URA
        $dangerousSids = @(
            "S-1-1-0",       # Everyone
            "S-1-5-32-546",  # Guests
            "S-1-5-11",      # Authenticated Users (در جاهای بسیار حساس)
            "S-1-5-32-547"   # Power Users
        )

        foreach ($file in $gptFiles) {
            $gpoGuid = [regex]::Match($file.FullName, '\{[0-9A-Fa-f-]{36}\}').Value.ToUpper()
            # پیدا کردن نام نمایشی GPO از روی لیست لود شده قبلی
            $gpoName = $gpoLookup[$gpoGuid]
            if (-not $gpoName) { $gpoName = $gpoGuid }

            $infData = ConvertFrom-InfFile -FilePath $file.FullName
            if ($null -eq $infData) { continue }

            # الف) ممیزی تنظیمات پسورد و اکانت [System Access]
            if ($infData.ContainsKey("System Access")) {
                $sysAccess = $infData["System Access"]
                
                # بررسی طول پسورد
                if ($sysAccess.ContainsKey("MinimumPasswordLength")) {
                    $val = [int]$sysAccess["MinimumPasswordLength"]
                    if ($val -lt $minPasswordLengthBaseline) {
                        $weakPasswords += [PSCustomObject]@{
                            GPOName   = $gpoName
                            GPOGuid   = $gpoGuid
                            Setting   = "MinimumPasswordLength"
                            Value     = $val
                            Threshold = ">= $minPasswordLengthBaseline"
                        }
                    }
                }
                # بررسی انقضای پسورد
                if ($sysAccess.ContainsKey("MaximumPasswordAge")) {
                    $val = [int]$sysAccess["MaximumPasswordAge"]
                    if ($val -gt $maxPasswordAgeBaseline -or $val -eq -1) {
                        $weakPasswords += [PSCustomObject]@{
                            GPOName   = $gpoName
                            GPOGuid   = $gpoGuid
                            Setting   = "MaximumPasswordAge"
                            Value     = $val
                            Threshold = "<= $maxPasswordAgeBaseline"
                        }
                    }
                }
                # بررسی تاریخچه پسورد
                if ($sysAccess.ContainsKey("PasswordHistorySize")) {
                    $val = [int]$sysAccess["PasswordHistorySize"]
                    if ($val -lt $passwordHistoryBaseline) {
                        $weakPasswords += [PSCustomObject]@{
                            GPOName   = $gpoName
                            GPOGuid   = $gpoGuid
                            Setting   = "PasswordHistorySize"
                            Value     = $val
                            Threshold = ">= $passwordHistoryBaseline"
                        }
                    }
                }
                # بررسی قفل شدن حساب کاربری (Account Lockout)
                if ($sysAccess.ContainsKey("LockoutBadCount")) {
                    $val = [int]$sysAccess["LockoutBadCount"]
                    if ($val -gt $lockoutThresholdBaseline -or $val -eq 0) {
                        $weakLockouts += [PSCustomObject]@{
                            GPOName   = $gpoName
                            GPOGuid   = $gpoGuid
                            Setting   = "LockoutBadCount"
                            Value     = $val
                            Threshold = "<= $lockoutThresholdBaseline"
                        }
                    }
                }
            }

            # ب) ممیزی واگذاری حقوق کاربران [Privilege Rights] (User Rights Assignment)
            if ($infData.ContainsKey("Privilege Rights")) {
                $privRights = $infData["Privilege Rights"]
                
                # امتیازات حیاتی و حساس از نظر نفوذ
                $sensitivePrivileges = @(
                    "SeDebugPrivilege",                  # اشکال‌زدایی برنامه‌ها (دور زدن LSASS)
                    "SeEnableDelegationPrivilege",       # فعال‌سازی جعل هویت در کربروس
                    "SeTakeOwnershipPrivilege",          # مالکیت فایل‌ها و آبجکت‌ها
                    "SeLoadDriverPrivilege",             # لود کردن درایورهای مخرب kernel-mode
                    "SeBackupPrivilege",                 # بکاپ‌گیری (امکان خواندن مستقیم SAM/NTDS.dit)
                    "SeRestorePrivilege",                # بازیابی فایل‌ها (نوشتن روی فایل‌های سیستمی)
                    "SeTcbPrivilege"                     # عمل به عنوان بخشی از سیستم‌عامل
                )

                foreach ($priv in $sensitivePrivileges) {
                    if ($privRights.ContainsKey($priv)) {
                        $assignedTrustees = $privRights[$priv] -split ','
                        foreach ($trustee in $assignedTrustees) {
                            $cleanTrustee = $trustee.Trim().Trim('*')
                            # اگر گروه غیرمجاز/عمومی به این حق حساس دسترسی داشت
                            if ($dangerousSids -contains $cleanTrustee) {
                                $riskyURAs += [PSCustomObject]@{
                                    GPOName   = $gpoName
                                    GPOGuid   = $gpoGuid
                                    Privilege = $priv
                                    Trustee   = $cleanTrustee
                                }
                            }
                        }
                    }
                }
            }

            # ج) ممیزی Event Audit Policies (سیاست‌های ممیزی وقایع)
            if ($infData.ContainsKey("Event Audit")) {
                $eventAudit = $infData["Event Audit"]
                # ۱ به معنای Success، ۲ به معنای Failure و ۳ به معنای هر دو است.
                $criticalAudits = @(
                    "AuditAccountLogon",
                    "AuditAccountManage",
                    "AuditDSAccess",
                    "AuditPolicyChange",
                    "AuditSystemEvents"
                )

                foreach ($audit in $criticalAudits) {
                    if ($eventAudit.ContainsKey($audit)) {
                        $val = [int]$eventAudit[$audit]
                        if ($val -eq 0) {
                            $weakAuditPolicies += [PSCustomObject]@{
                                GPOName       = $gpoName
                                GPOGuid       = $gpoGuid
                                AuditCategory = $audit
                                Status        = "Disabled (0)"
                            }
                        }
                    } else {
                        $weakAuditPolicies += [PSCustomObject]@{
                            GPOName       = $gpoName
                            GPOGuid       = $gpoGuid
                            AuditCategory = $audit
                            Status        = "Not Configured"
                        }
                    }
                }
            }
        }

        # ثبت یافته‌های حاصل از تحلیل عمیق الگوها
        if ($weakPasswords.Count -gt 0) {
            $evidenceText = $weakPasswords | Format-Table -AutoSize | Out-String
            $affectedGpos = ($weakPasswords.GPOName | Select-Object -Unique) -join ", "

            Add-GPOFinding `
                -FindingID "GPO-DEEP-PASSWORD-POLICY-001" `
                -Category "Active Directory GPO" `
                -Title "Weak Password Policy Configuration detected in GPOs" `
                -Severity "Medium" `
                -AffectedComponent "GPOs: $affectedGpos" `
                -Description "One or more GPOs contain password complexity/length settings that are weaker than Microsoft Security Baselines." `
                -Evidence $evidenceText `
                -Impact "Weak password requirements ease brute-force and credential spraying attacks within the domain environment." `
                -Recommendation "Align Domain GPOs and Fine-Grained Password Policies with Microsoft Security Baseline requirements (min 14 characters, enforce history)."
        }

        if ($weakLockouts.Count -gt 0) {
            $evidenceText = $weakLockouts | Format-Table -AutoSize | Out-String
            $affectedGpos = ($weakLockouts.GPOName | Select-Object -Unique) -join ", "

            Add-GPOFinding `
                -FindingID "GPO-DEEP-LOCKOUT-POLICY-001" `
                -Category "Active Directory GPO" `
                -Title "Insecure Account Lockout Threshold configured in GPOs" `
                -Severity "Medium" `
                -AffectedComponent "GPOs: $affectedGpos" `
                -Description "GPOs were found configuring an excessive or disabled Account Lockout Threshold." `
                -Evidence $evidenceText `
                -Impact "An attacker can execute infinite brute force or dictionary attacks without risking account lockout." `
                -Recommendation "Enforce an account lockout threshold of 10 or fewer bad attempts to prevent automated online password guessing."
        }

        if ($riskyURAs.Count -gt 0) {
            $evidenceText = $riskyURAs | Format-Table -AutoSize | Out-String
            $affectedGpos = ($riskyURAs.GPOName | Select-Object -Unique) -join ", "

            Add-GPOFinding `
                -FindingID "GPO-DEEP-URA-RISK-001" `
                -Category "Active Directory GPO" `
                -Title "Risky User Rights Assignments (URA) identified" `
                -Severity "High" `
                -AffectedComponent "GPOs: $affectedGpos" `
                -Description "Sensitive privileges (such as SeDebugPrivilege or SeEnableDelegationPrivilege) are assigned to unprivileged or generic security identifiers (SIDs)." `
                -Evidence $evidenceText `
                -Impact "Allows malicious or compromised domain users to escalate privileges, dump credentials from memory, or perform Active Directory delegation attacks." `
                -Recommendation "Restrict sensitive User Rights Assignments to native administrative groups (e.g., Domain Admins, SYSTEM) and remove generic SIDs like Everyone or Guests."
        }

        if ($weakAuditPolicies.Count -gt 0) {
            $evidenceText = $weakAuditPolicies | Format-Table -AutoSize | Out-String
            $affectedGpos = ($weakAuditPolicies.GPOName | Select-Object -Unique) -join ", "

            Add-GPOFinding `
                -FindingID "GPO-DEEP-AUDIT-POLICY-001" `
                -Category "Active Directory GPO" `
                -Title "Disabled or unconfigured critical audit policies in GPOs" `
                -Severity "Medium" `
                -AffectedComponent "GPOs: $affectedGpos" `
                -Description "Critical security logging/auditing policies are either explicitly disabled or not configured in security templates." `
                -Evidence $evidenceText `
                -Impact "Reduces security visibility, preventing SIEM solutions and security teams from detecting privilege escalations, lateral movement, or unauthorized Active Directory changes." `
                -Recommendation "Configure Domain Audit Policies to audit Success and Failure for logon, account management, DS access, and system event categories."
        }
    }

    # ۴. بررسی GPP Cpassword (پسوردهای هاردکد شده در SYSVOL)
    try {
        if (Test-Path $sysvolPoliciesPath) {
            $gppFiles = Get-ChildItem -Path $sysvolPoliciesPath -Recurse -Include *.xml -ErrorAction SilentlyContinue
            $compromisedGpps = @()
            
            foreach ($file in $gppFiles) {
                if (Select-String -Path $file.FullName -Pattern "cpassword=" -Quiet) {
                    $compromisedGpps += [PSCustomObject]@{
                        GPOPath  = $file.FullName
                        GPOName  = $file.Directory.Parent.Parent.Name # GUID جی‌پی‌او
                        FileName = $file.Name
                    }
                }
            }

            if ($compromisedGpps.Count -gt 0) {
                $evidence = $compromisedGpps | Out-String
                Add-GPOFinding `
                    -FindingID "GPO-GPPC-PASSWORD-001" `
                    -Category "Active Directory GPO" `
                    -Title "Hardcoded passwords found in Group Policy Preferences (cpassword)" `
                    -Severity "Critical" `
                    -AffectedComponent "Group Policy Preferences" `
                    -Description "One or more GPP XML configuration files contain 'cpassword' attributes. Microsoft encrypts these using a publicly known AES key, allowing immediate decryption of these passwords." `
                    -Evidence $evidence `
                    -Impact "Attackers can decrypt these passwords instantly, resulting in local administrator or domain user credentials compromise." `
                    -Recommendation "Remove the password configurations from GPP, rotate the compromised accounts' passwords, and apply MS14-025 patch." `
                    -Standard "MS14-025 / CIS Benchmark" `
                    -Reference "https://support.microsoft.com/en-us/topic/kb2962486"
            }
        }
    }
    catch {}

    # ۵. ممیزی دسترسی‌ها و Delegation روی GPOها (شناسایی آسیب‌پذیری‌های تغییر یا تخریب GPO)
    try {
        $riskyDelegations = @()
        
        foreach ($gpo in $gpos) {
            $gpoReportXml = [xml](Get-GPOReport -Guid $gpo.Id -ReportType Xml -ErrorAction SilentlyContinue)
            if ($null -ne $gpoReportXml) {
                $trustees = $gpoReportXml.GPO.SecurityDescriptor.Permissions.Trustee
                foreach ($trustee in $trustees) {
                    $trusteeName = $trustee.Name
                    $permissionType = $trustee.PermissionType
                    
                    if ($trusteeName -notmatch "Domain Admins|Enterprise Admins|SYSTEM|Domain Controllers|Enterprise Domain Controllers|Creator Owner" -and 
                        $permissionType -match "Edit|FullControl|Custom") {
                        
                        $riskyDelegations += [PSCustomObject]@{
                            GPOName      = $gpo.DisplayName
                            GPOGuid      = $gpo.Id
                            Trustee      = $trusteeName
                            Permission   = $permissionType
                        }
                    }
                }
            }
        }

        if ($riskyDelegations.Count -gt 0) {
            $evidence = $riskyDelegations | Out-String
            Add-GPOFinding `
                -FindingID "GPO-DELEGATION-RISK-001" `
                -Category "Active Directory GPO" `
                -Title "Non-privileged trustees have modify permissions on GPOs" `
                -Severity "High" `
                -AffectedComponent "GPO Delegation" `
                -Description "Non-privileged accounts or groups have edit or full control permissions on GPOs. If compromised, an attacker can modify GPOs to execute code on all target systems." `
                -Evidence $evidence `
                -Impact "High risk of lateral movement and privilege escalation by modifying policies applied to domain controllers or critical servers." `
                -Recommendation "Revoke edit/write permissions for non-privileged accounts on GPOs. Enforce strict administrative delegation tiering." `
                -Standard "Microsoft Securing Active Directory" `
                -Reference "Active Directory GPO security delegation guidance"
        }
    }
    catch {}

    # ۶. بررسی GPP Registry Preferences مخرب یا ضعیف
    try {
        if (Test-Path $sysvolPoliciesPath) {
            # فایل Registry.xml تنظیمات رجیستری GPP را نگه می‌دارد
            $gppRegistryFiles = Get-ChildItem -Path $sysvolPoliciesPath -Recurse -Filter "Registry.xml" -ErrorAction SilentlyContinue
            $weakRegSettings = @()

            foreach ($file in $gppRegistryFiles) {
                $gpoGuid = [regex]::Match($file.FullName, '\{[0-9A-Fa-f-]{36}\}').Value.ToUpper()
                $gpoName = $gpoLookup[$gpoGuid]
                if (-not $gpoName) { $gpoName = $gpoGuid }

                [xml]$xml = Get-Content $file.FullName -ErrorAction SilentlyContinue
                if ($xml) {
                    # جستجو برای تنظیمات دستکاری شده رجیستری (مانند غیرفعال کردن UAC یا فایروال)
                    $regProperties = $xml.SelectNodes("//Registry")
                    foreach ($prop in $regProperties) {
                        $key = $prop.Properties.key
                        $name = $prop.Properties.name
                        $value = $prop.Properties.value

                        # بررسی غیرفعال‌سازی UAC (ConsentPromptBehaviorAdmin = 0 یا EnableLUA = 0)
                        if ($key -match "Microsoft\\Windows\\CurrentVersion\\Policies\\System" -and 
                            ($name -eq "EnableLUA" -or $name -eq "ConsentPromptBehaviorAdmin") -and $value -eq "0") {
                            $weakRegSettings += [PSCustomObject]@{
                                GPOName  = $gpoName
                                GPOGuid  = $gpoGuid
                                Setting  = "UAC Disabled ($name)"
                                Key      = $key
                            }
                        }

                        # بررسی غیرفعال‌سازی فایروال ویندوز
                        if ($key -match "System\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy" -and 
                            $name -eq "EnableFirewall" -and $value -eq "0") {
                            $weakRegSettings += [PSCustomObject]@{
                                GPOName  = $gpoName
                                GPOGuid  = $gpoGuid
                                Setting  = "Firewall Disabled (EnableFirewall)"
                                Key      = $key
                            }
                        }
                    }
                }
            }

            if ($weakRegSettings.Count -gt 0) {
                $evidenceText = $weakRegSettings | Format-Table -AutoSize | Out-String
                $affectedGpos = ($weakRegSettings.GPOName | Select-Object -Unique) -join ", "

                Add-GPOFinding `
                    -FindingID "GPO-DEEP-REGISTRY-RISK-001" `
                    -Category "Active Directory GPO" `
                    -Title "Insecure Registry Preferences Configured via GPP" `
                    -Severity "High" `
                    -AffectedComponent "GPOs: $affectedGpos" `
                    -Description "Security-critical registry settings (like disabling UAC or turning off the Windows Firewall) have been explicitly deployed through Group Policy Preferences Registry.xml." `
                    -Evidence $evidenceText `
                    -Impact "Weakens host security policies across all target systems, leaving them vulnerable to malware execution and remote network scanning." `
                    -Recommendation "Revoke policies that weaken default security baselines. Enforce Windows Firewall and UAC settings through standard Administrative Templates."
            }
        }
    }
    catch {}

    # ۷. بررسی GPOهای خالی (Empty GPOs) و GPOهای بدون لینک فعال (Unlinked GPOs)
    try {
        $unlinkedGpos = @()
        $emptyGpos = @()

        foreach ($gpo in $gpos) {
            # ۱. بررسی خالی بودن GPO
            if ($gpo.User.Enabled -eq $false -and $gpo.Computer.Enabled -eq $false) {
                $emptyGpos += [PSCustomObject]@{
                    DisplayName = $gpo.DisplayName
                    Id          = $gpo.Id
                    Status      = "Both User and Computer configuration settings disabled"
                }
            }

            # ۲. بررسی بدون لینک بودن (بوسیله دریافت گزارش XML)
            $reportXml = [xml](Get-GPOReport -Guid $gpo.Id -ReportType Xml -ErrorAction SilentlyContinue)
            if ($null -ne $reportXml) {
                $links = $reportXml.GPO.LinksTo
                if ($null -eq $links -or $links.Count -eq 0) {
                    $unlinkedGpos += [PSCustomObject]@{
                        DisplayName = $gpo.DisplayName
                        Id          = $gpo.Id
                    }
                }
            }
        }

        if ($emptyGpos.Count -gt 0) {
            Add-GPOFinding `
                -FindingID "GPO-EMPTY-001" `
                -Category "Active Directory GPO" `
                -Title "Empty or completely disabled GPOs detected" `
                -Severity "Low" `
                -AffectedComponent "GPO Hygiene" `
                -Description "GPOs were identified that have both computer and user configurations disabled or contain no settings." `
                -Evidence ($emptyGpos | Out-String) `
                -Impact "Creates administrative overhead and slows down GPO processing times without providing any security value." `
                -Recommendation "Review these empty GPOs and delete them if they are no longer required." `
                -Standard "Active Directory Cleanup Operations" `
                -Reference "Active Directory optimization guidelines"
        }

        if ($unlinkedGpos.Count -gt 0) {
            Add-GPOFinding `
                -FindingID "GPO-UNLINKED-001" `
                -Category "Active Directory GPO" `
                -Title "Unlinked GPOs present in the domain" `
                -Severity "Info" `
                -AffectedComponent "GPO Hygiene" `
                -Description "GPOs exist in the domain but are not linked to any Site, Domain, or OU." `
                -Evidence ($unlinkedGpos | Out-String) `
                -Impact "Unlinked GPOs are inactive. They may contain legacy settings that could accidentally be applied if linked, or represent leftover configurations." `
                -Recommendation "Review the unlinked GPOs. If they are obsolete, back them up and delete them." `
                -Standard "Active Directory Cleanup Operations" `
                -Reference "Active Directory optimization guidelines"
        }
    }
    catch {}

    return $script:findings
}
