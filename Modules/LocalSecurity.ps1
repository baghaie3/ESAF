function Invoke-ESAFLocalSecurityAssessment {
    param(
        [string]$EvidencePath
    )

    $findings = @()
    $evidenceLog = ""

    try {
        # LAPS
        $lapsInstalled = $false
        $lapsEvidence = "LAPS Check:`n"

        $lapsDllLegacy = Test-Path "C:\Program Files\LAPS\CSE\AdmPwd.dll"
        $lapsRegModern = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS" -ErrorAction SilentlyContinue

        if ($lapsDllLegacy -or $lapsRegModern) {
            $lapsInstalled = $true
            $lapsEvidence += "- LAPS state: LAPS/Windows LAPS configuration detected.`n"
        } else {
            $lapsEvidence += "- LAPS state: NOT DETECTED (No legacy DLL or modern registry key found).`n"
        }

        $evidenceLog += $lapsEvidence + "`n"

        if (-not $lapsInstalled) {
            $findings += New-ESAFFinding `
                -FindingID "SEC-LOCAL-LAPS-001" `
                -Category "Local Security" `
                -Title "Windows LAPS is not installed or configured" `
                -Severity "High" `
                -AffectedComponent "LAPS" `
                -Description "Local administrator password management via Microsoft LAPS was not detected on this system." `
                -Evidence $lapsEvidence `
                -Impact "Without LAPS, local administrator passwords may remain static or reused across systems, increasing the risk of credential theft and lateral movement." `
                -Recommendation "Deploy and configure Microsoft LAPS (or Windows LAPS where supported) to randomize and securely manage local administrator passwords." `
                -Standard "CIS Microsoft Windows Server Benchmark" `
                -Reference "Microsoft LAPS documentation" `
                -Status "Open"
        }

        # Guest Account
        $guestAccount = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
        $guestEvidence = "Guest Account Check:`n"

        if ($guestAccount) {
            $guestEvidence += "- Account Enabled: $($guestAccount.Enabled)`n"
            $evidenceLog += $guestEvidence + "`n"

            if ($guestAccount.Enabled -eq $true) {
                $findings += New-ESAFFinding `
                    -FindingID "SEC-LOCAL-GUEST-001" `
                    -Category "Local Security" `
                    -Title "Built-in Guest Account is Enabled" `
                    -Severity "High" `
                    -AffectedComponent "Local Users" `
                    -Description "The built-in Guest account is enabled on this system." `
                    -Evidence $guestEvidence `
                    -Impact "An enabled Guest account increases the risk of unauthorized local or network access and weakens identity accountability." `
                    -Recommendation "Disable the built-in Guest account through Local Users and Groups or Group Policy." `
                    -Standard "CIS Microsoft Windows Server Benchmark" `
                    -Reference "Guest account status security policy" `
                    -Status "Open"
            }
        }

        # Password Policy
        $netAccounts = net accounts | Out-String
        $evidenceLog += "Local Password Policy (net accounts):`n$netAccounts`n"

        $minPasswordLength = 0
        if ($netAccounts -match "Minimum password length:\s+(\d+)") {
            $minPasswordLength = [int]$matches[1]
        }

        $lockoutThreshold = "Never"
        if ($netAccounts -match "Lockout threshold:\s+(\w+)") {
            $lockoutThreshold = $matches[1]
        }

        if ($minPasswordLength -lt 14) {
            $findings += New-ESAFFinding `
                -FindingID "SEC-LOCAL-PASS-001" `
                -Category "Local Security" `
                -Title "Weak Minimum Password Length Policy" `
                -Severity "Medium" `
                -AffectedComponent "Password Policy" `
                -Description "The minimum password length is configured to $minPasswordLength characters, below the recommended enterprise baseline." `
                -Evidence "Minimum password length detected: $minPasswordLength characters." `
                -Impact "Short passwords are more vulnerable to brute-force, password spraying, and dictionary-based attacks." `
                -Recommendation "Set the minimum password length to at least 14 characters through Local Security Policy or Group Policy." `
                -Standard "CIS Microsoft Windows Server Benchmark" `
                -Reference "Password policy minimum length guidance" `
                -Status "Open"
        }

        $lockoutBad = $false
        if ($lockoutThreshold -eq "Never") {
            $lockoutBad = $true
        } else {
            $thresholdInt = 0
            if ([int]::TryParse($lockoutThreshold, [ref]$thresholdInt)) {
                if ($thresholdInt -eq 0 -or $thresholdInt -gt 10) {
                    $lockoutBad = $true
                }
            }
        }

        if ($lockoutBad) {
            $findings += New-ESAFFinding `
                -FindingID "SEC-LOCAL-LOCK-001" `
                -Category "Local Security" `
                -Title "Account Lockout Threshold Not Properly Configured" `
                -Severity "Medium" `
                -AffectedComponent "Account Lockout Policy" `
                -Description "The account lockout threshold is set to '$lockoutThreshold', which does not align with recommended hardening guidance." `
                -Evidence "Lockout threshold detected: $lockoutThreshold" `
                -Impact "Improper lockout configuration can allow repeated password guessing attempts against local accounts." `
                -Recommendation "Configure Account Lockout Threshold to a secure value such as 5 or 10 invalid attempts." `
                -Standard "CIS Microsoft Windows Server Benchmark" `
                -Reference "Account lockout policy guidance" `
                -Status "Open"
        }

        if ($EvidencePath) {
            $evidenceLog | Out-File -FilePath (Join-Path $EvidencePath "LocalSecurity_Evidence.txt") -Encoding UTF8
        }
    }
    catch {
        $findings += New-ESAFFinding `
            -FindingID "SEC-LOCAL-ERR-001" `
            -Category "Local Security" `
            -Title "Local Security assessment execution failed" `
            -Severity "Medium" `
            -AffectedComponent "Local Security Policy" `
            -Description "The local security assessment module encountered an exception during execution." `
            -Evidence $_.Exception.Message `
            -Impact "Visibility into local account and password policy security posture is incomplete." `
            -Recommendation "Review module execution errors, permissions, and command availability." `
            -Standard "Internal ESAF Validation" `
            -Reference "Local security module troubleshooting" `
            -Status "Open"
    }

    return $findings
}
