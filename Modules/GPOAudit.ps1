function Invoke-ESAFGPOAuditAssessment {
    [CmdletBinding()]
    param(
        [string]$EvidencePath,
        [string]$HostRole = "MemberServer"
    )

    $findings = @()

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

    # ۱. بررسی لود شدن ماژول GroupPolicy
    try {
        Import-Module GroupPolicy -ErrorAction Stop
    }
    catch {
        Add-GPOFinding `
            -FindingID "GPO-MODULE-001" `
            -Category "Active Directory GPO" `
            -Title "GroupPolicy PowerShell module is not available" `
            -Severity "High" `
            -AffectedComponent "Group Policy Module" `
            -Description "The GroupPolicy PowerShell module could not be loaded." `
            -Evidence $_.Exception.Message `
            -Impact "GPO configuration checks and delegation audits cannot be performed." `
            -Recommendation "Install Remote Server Administration Tools (RSAT) Group Policy Management Tools on this system." `
            -Standard "Internal ESAF Validation" `
            -Reference "GroupPolicy module dependency"
        return $script:findings
    }

    # ۲. بررسی اتصال به اکتیو دایرکتوری و دریافت لیست GPOها
    try {
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

    # ۳. بررسی GPP Cpassword (پسوردهای هاردکد شده در SYSVOL)
    try {
        # بررسی فیزیکی پوشه Policies در SYSVOL برای پیدا کردن پسوردهای ذخیره شده در فایل‌های XML پیکربندی (GPP)
        $domainName = (Get-ADDomain).DNSRoot
        $sysvolPoliciesPath = "\\$domainName\sysvol\$domainName\Policies"
        
        if (Test-Path $sysvolPoliciesPath) {
            $gppFiles = Get-ChildItem -Path $sysvolPoliciesPath -Recurse -Include *.xml -ErrorAction SilentlyContinue
            $compromisedGpps = @()
            
            foreach ($file in $gppFiles) {
                if (Select-String -Path $file.FullName -Pattern "cpassword=" -Quiet) {
                    $compromisedGpps += [PSCustomObject]@{
                        GPOPath  = $file.FullName
                        GPOName  = $file.Directory.Parent.Parent.Name # دریافت GUID جی‌پی‌او
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

    # ۴. ممیزی دسترسی‌ها و Delegation روی GPOها (شناسایی آسیب‌پذیری‌های تغییر یا تخریب GPO)
    try {
        $riskyDelegations = @()
        
        foreach ($gpo in $gpos) {
            # دریافت اطلاعات دسترسی‌های امنیتی هر GPO
            $gpoReportXml = [xml](Get-GPOReport -Guid $gpo.Id -ReportType Xml -ErrorAction SilentlyContinue)
            if ($null -ne $gpoReportXml) {
                # تحلیل تگ‌های SecurityDescriptor در XML خروجی گزارش GPO
                $trustees = $gpoReportXml.GPO.SecurityDescriptor.Permissions.Trustee
                foreach ($trustee in $trustees) {
                    $trusteeName = $trustee.Name
                    $permissionType = $trustee.PermissionType
                    
                    # فیلتر کردن دسترسی‌های خطرناک برای گروه‌های غیرامن
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

    # ۵. بررسی GPOهای خالی (Empty GPOs) و GPOهای بدون لینک فعال (Unlinked GPOs)
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
