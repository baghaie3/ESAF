function Invoke-ESAFPasswordPolicyAssessment {
    <#
    .SYNOPSIS
        Audits Windows Password Policy settings and generates structured ESAF findings.
    #>
    [CmdletBinding()]
    param(
        [string]$EvidencePath
    )

    $findings = @()
    $evidenceLog = "Password Policy Security Audit`n"
    $evidenceLog += "=============================`n`n"

    try {
        # اجرای دستور net accounts برای استخراج سیاست‌های پایه سیستم
        $netAccounts = net accounts | Out-String
        $evidenceLog += "Raw net accounts output:`n$netAccounts`n"

        # ۱. بررسی طول رمز عبور (Minimum password length)
        $minLength = 0
        if ($netAccounts -match "Minimum password length:\s+(\d+)") {
            $minLength = [int]$matches[1]
        }

        if ($minLength -lt 14) {
            $findings += New-ESAFFinding `
                -FindingID "SEC-PASS-LEN-001" `
                -Category "Password Policy" `
                -Title "Weak Minimum Password Length Policy" `
                -Severity "Medium" `
                -AffectedComponent "Password Policy" `
                -Description "The minimum password length is configured to $minLength characters, which is below the recommended enterprise baseline of 14 characters." `
                -Evidence "Minimum password length detected: $minLength characters." `
                -Impact "Short passwords are highly vulnerable to brute-force, dictionary-based, and password-spraying attacks." `
                -Recommendation "Configure the minimum password length to at least 14 characters via Group Policy or Local Security Policy." `
                -Standard "CIS Microsoft Windows Server Benchmark" `
                -Reference "Password Policy Configuration Guide" `
                -Status "Open"
        }

        # ۲. بررسی دوره تناوب تغییر رمز عبور (Maximum password age)
        $maxAge = 0
        if ($netAccounts -match "Maximum password age \(days\):\s+(\d+)") {
            $maxAge = [int]$matches[1]
        }

        if ($maxAge -eq 0 -or $maxAge -gt 90) {
            $findings += New-ESAFFinding `
                -FindingID "SEC-PASS-AGE-001" `
                -Category "Password Policy" `
                -Title "Improper Maximum Password Age Policy" `
                -Severity "Medium" `
                -AffectedComponent "Password Policy" `
                -Description "Maximum password age is configured to $maxAge days. Setting it to unlimited (0) or too high allows compromise to persist." `
                -Evidence "Maximum password age: $maxAge days." `
                -Impact "If user credentials are leaked or compromised, they can be used indefinitely without periodic forced changes." `
                -Recommendation "Configure the maximum password age to between 30 and 90 days." `
                -Standard "CIS Microsoft Windows Server Benchmark" `
                -Reference "Maximum Password Age Policy" `
                -Status "Open"
        }

        # ۳. بررسی تاریخچه رمز عبور (Password history)
        $historyLen = 0
        if ($netAccounts -match "Length of password history maintained:\s+(\d+)") {
            $historyLen = [int]$matches[1]
        }

        if ($historyLen -lt 24) {
            $findings += New-ESAFFinding `
                -FindingID "SEC-PASS-HIST-001" `
                -Category "Password Policy" `
                -Title "Insufficient Password History Maintained" `
                -Severity "Low" `
                -AffectedComponent "Password Policy" `
                -Description "Password history is configured to remember only $historyLen passwords." `
                -Evidence "Password history length: $historyLen" `
                -Impact "Users can quickly cycle back to their favorite weak passwords, bypassing the password rotation policy." `
                -Recommendation "Configure Password History to remember at least 24 passwords." `
                -Standard "CIS Microsoft Windows Server Benchmark" `
                -Reference "Password History Policy Guide" `
                -Status "Open"
        }

        # ذخیره‌سازی شواهد در صورت تعریف مسیر خروجی
        if ($EvidencePath) {
            $evidenceLog | Out-File -FilePath (Join-Path $EvidencePath "PasswordPolicy_Evidence.txt") -Encoding UTF8
        }

    }
    catch {
        $findings += New-ESAFFinding `
            -FindingID "SEC-PASS-ERR-001" `
            -Category "Password Policy" `
            -Title "Password Policy assessment execution failed" `
            -Severity "Medium" `
            -AffectedComponent "Password Policy Audit" `
            -Description "The password policy assessment module encountered an exception during execution." `
            -Evidence $_.Exception.Message `
            -Impact "Visibility into password policy configurations is limited." `
            -Recommendation "Check current account permissions and execution context." `
            -Standard "Internal ESAF Validation" `
            -Reference "Password policy troubleshooting" `
            -Status "Open"
    }

    return $findings
}
