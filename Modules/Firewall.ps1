function Invoke-ESAFFirewallAssessment {
    param(
        [string]$EvidencePath
    )

    $findings = @()
    $evidenceLog = ""

    try {
        $profiles = @(
            @{ PSName = "Domain";  NetshName = "Domain Profile";  GpoName = "DomainProfile";  RegistryValue = 1 }
            @{ PSName = "Private"; NetshName = "Private Profile"; GpoName = "StandardProfile"; RegistryValue = 1 }
            @{ PSName = "Public";  NetshName = "Public Profile";  GpoName = "PublicProfile";  RegistryValue = 1 }
        )

        $fwProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
        $netshOutput = netsh advfirewall show allprofiles | Out-String
        $mpsSvc = Get-Service -Name "MpsSvc" -ErrorAction SilentlyContinue

        $gpoBasePaths = @(
            "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall",
            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\WindowsFirewall"
        )

        $evidenceLog += "Windows Defender Firewall Assessment`n"
        $evidenceLog += "Service Check:`n"
        if ($mpsSvc) {
            $evidenceLog += "- MpsSvc Status: $($mpsSvc.Status)`n"
            $evidenceLog += "- MpsSvc StartType: $((Get-CimInstance Win32_Service -Filter "Name='MpsSvc'" -ErrorAction SilentlyContinue).StartMode)`n`n"
        } else {
            $evidenceLog += "- MpsSvc service not found.`n`n"
        }

        foreach ($profile in $profiles) {
            $profileName = $profile.PSName
            $netshName   = $profile.NetshName
            $gpoName     = $profile.GpoName

            $psEnabled = $null
            $netshEnabled = $null
            $gpoEnabled = $null

            $psProfile = $fwProfiles | Where-Object { $_.Name -eq $profileName }
            if ($psProfile) {
                $psEnabled = [bool]$psProfile.Enabled
            }

            if ($netshOutput -match "(?s)$([regex]::Escape($netshName)).*?State\s+([A-Z]+)") {
                $netshState = $matches[1]
                $netshEnabled = ($netshState -eq "ON")
            }

            foreach ($basePath in $gpoBasePaths) {
                $fullPath = Join-Path $basePath $gpoName
                if (Test-Path $fullPath) {
                    $regValue = Get-ItemProperty -Path $fullPath -Name "EnableFirewall" -ErrorAction SilentlyContinue
                    if ($null -ne $regValue) {
                        $gpoEnabled = ($regValue.EnableFirewall -eq 1)
                        break
                    }
                }
            }

            $profileEvidence = "Profile: $profileName`n"
            $profileEvidence += "- PowerShell(Get-NetFirewallProfile): $psEnabled`n"
            $profileEvidence += "- netsh advfirewall: $netshEnabled`n"
            $profileEvidence += "- GPO/Registry Policy: $gpoEnabled`n"
            if ($mpsSvc) {
                $profileEvidence += "- MpsSvc Service Status: $($mpsSvc.Status)`n"
            }

            $evidenceLog += $profileEvidence + "`n"

            $isProtected = $false

            if ($gpoEnabled -eq $true) {
                $isProtected = $true
            }
            elseif ($psEnabled -eq $true -or $netshEnabled -eq $true) {
                $isProtected = $true
            }

            if (-not $isProtected) {
                $findings += New-ESAFFinding `
                    -FindingID "SEC-FW-$($profileName.ToUpper())-001" `
                    -Category "Firewall" `
                    -Title "Windows Defender Firewall appears disabled for $profileName profile" `
                    -Severity "High" `
                    -AffectedComponent "Windows Defender Firewall - $profileName Profile" `
                    -Description "The $profileName firewall profile appears to be disabled or not effectively enforced based on PowerShell, netsh, and policy/registry validation." `
                    -Evidence $profileEvidence `
                    -Impact "A disabled firewall profile increases exposure to unauthorized inbound and lateral network access, weakening host-based segmentation and attack resistance." `
                    -Recommendation "Enable Windows Defender Firewall for the $profileName profile and ensure enforcement through Group Policy where applicable." `
                    -Standard "CIS Microsoft Windows Server Benchmark" `
                    -Reference "Windows Defender Firewall configuration guidance" `
                    -Status "Open"
            }
        }

        if ($mpsSvc -and $mpsSvc.Status -ne "Running") {
            $findings += New-ESAFFinding `
                -FindingID "SEC-FW-SVC-001" `
                -Category "Firewall" `
                -Title "Windows Defender Firewall service is not running" `
                -Severity "High" `
                -AffectedComponent "MpsSvc" `
                -Description "The Windows Defender Firewall service (MpsSvc) is not running." `
                -Evidence "MpsSvc Status: $($mpsSvc.Status)" `
                -Impact "If the firewall service is not running, firewall policy enforcement may fail or become inconsistent." `
                -Recommendation "Set the Windows Defender Firewall service startup type appropriately and ensure the service is running." `
                -Standard "CIS Microsoft Windows Server Benchmark" `
                -Reference "Windows Defender Firewall configuration guidance" `
                -Status "Open"
        }

        if ($EvidencePath) {
            $evidenceLog | Out-File -FilePath (Join-Path $EvidencePath "Firewall_Evidence.txt") -Encoding UTF8
        }
    }
    catch {
        $findings += New-ESAFFinding `
            -FindingID "SEC-FW-ERR-001" `
            -Category "Firewall" `
            -Title "Firewall assessment execution failed" `
            -Severity "Medium" `
            -AffectedComponent "Windows Defender Firewall" `
            -Description "The firewall assessment module encountered an exception during execution." `
            -Evidence $_.Exception.Message `
            -Impact "Firewall posture could not be fully assessed, reducing overall visibility." `
            -Recommendation "Review execution errors, permissions, and firewall-related cmdlet availability." `
            -Standard "Internal ESAF Validation" `
            -Reference "Firewall module execution troubleshooting" `
            -Status "Open"
    }

    return $findings
}
