# Modules\IdentityAudit.ps1

function Invoke-ESAFIdentityAuditAssessment {
    param(
        [string]$EvidencePath,
        [string]$HostRole = "MemberServer"
    )

    $findings = @()

    try {
        if ([string]::IsNullOrWhiteSpace($EvidencePath)) {
            if ($PSScriptRoot) {
                $esafRoot = Split-Path -Parent $PSScriptRoot
                $EvidencePath = Join-Path -Path $esafRoot -ChildPath "Evidence"
            }
            else {
                $EvidencePath = Join-Path -Path (Get-Location).Path -ChildPath "Evidence"
            }
        }

        if (-not (Test-Path -Path $EvidencePath)) {
            New-Item -ItemType Directory -Path $EvidencePath -Force | Out-Null
        }

        $identityEvidencePath = Join-Path -Path $EvidencePath -ChildPath "IdentityAudit"

        if (-not (Test-Path -Path $identityEvidencePath)) {
            New-Item -ItemType Directory -Path $identityEvidencePath -Force | Out-Null
        }

        if ($HostRole -eq "DomainController") {
            if (Get-Module -ListAvailable -Name ActiveDirectory) {
                Import-Module ActiveDirectory -ErrorAction SilentlyContinue

                $domainAdminsFile     = Join-Path -Path $identityEvidencePath -ChildPath "DomainAdmins.txt"
                $enterpriseAdminsFile = Join-Path -Path $identityEvidencePath -ChildPath "EnterpriseAdmins.txt"
                $adminsFile           = Join-Path -Path $identityEvidencePath -ChildPath "Administrators_AD.txt"

                try {
                    $daMembers = @(Get-ADGroupMember "Domain Admins" -ErrorAction Stop)

                    $daMembers |
                        Select-Object Name, SamAccountName, objectClass |
                        Out-File -FilePath $domainAdminsFile -Encoding UTF8

                    if ($daMembers.Count -gt 1) {
                        $findings += New-ESAFFinding `
                            -FindingID "ID-DC-DA-001" `
                            -Category "Identity & Access" `
                            -Title "Multiple accounts in Domain Admins group" `
                            -Severity "High" `
                            -AffectedComponent "Active Directory" `
                            -Description "The Domain Admins group contains multiple members, increasing the risk of privileged account misuse." `
                            -Evidence (Get-Content -Path $domainAdminsFile -Raw) `
                            -Impact "Compromise of any Domain Admin account can lead to full forest compromise." `
                            -Recommendation "Limit Domain Admins membership to the minimum necessary accounts, implement tiered administration and PAM." `
                            -Standard "Microsoft Security Baseline" `
                            -Reference "https://learn.microsoft.com/windows-server/identity/securing-privileged-access" `
                            -Status "Open"
                    }
                }
                catch {
                    $findings += New-ESAFFinding `
                        -FindingID "ID-DC-DA-ERR" `
                        -Category "Identity & Access" `
                        -Title "Failed to enumerate Domain Admins group" `
                        -Severity "Medium" `
                        -AffectedComponent "Active Directory" `
                        -Description "The assessment could not enumerate members of the Domain Admins group." `
                        -Evidence $_.Exception.Message `
                        -Impact "Privileged group exposure could not be fully assessed." `
                        -Recommendation "Verify AD tools, permissions, and connectivity on the domain controller." `
                        -Standard "Microsoft Security Baseline" `
                        -Reference "Get-ADGroupMember documentation" `
                        -Status "Open"
                }

                try {
                    $eaMembers = @(Get-ADGroupMember "Enterprise Admins" -ErrorAction Stop)

                    $eaMembers |
                        Select-Object Name, SamAccountName, objectClass |
                        Out-File -FilePath $enterpriseAdminsFile -Encoding UTF8

                    if ($eaMembers.Count -gt 0) {
                        $findings += New-ESAFFinding `
                            -FindingID "ID-DC-EA-001" `
                            -Category "Identity & Access" `
                            -Title "Enterprise Admins group has active members" `
                            -Severity "High" `
                            -AffectedComponent "Active Directory" `
                            -Description "The Enterprise Admins group has active members, which have high-impact privileges across the forest." `
                            -Evidence (Get-Content -Path $enterpriseAdminsFile -Raw) `
                            -Impact "Compromise of Enterprise Admins accounts can lead to complete forest compromise and cross-domain attacks." `
                            -Recommendation "Restrict Enterprise Admins membership, consider temporary elevation through PAM solutions." `
                            -Standard "Microsoft Security Baseline" `
                            -Reference "https://learn.microsoft.com/windows-server/identity/securing-privileged-access" `
                            -Status "Open"
                    }
                }
                catch {
                    $findings += New-ESAFFinding `
                        -FindingID "ID-DC-EA-ERR" `
                        -Category "Identity & Access" `
                        -Title "Failed to enumerate Enterprise Admins group" `
                        -Severity "Medium" `
                        -AffectedComponent "Active Directory" `
                        -Description "The assessment could not enumerate members of the Enterprise Admins group." `
                        -Evidence $_.Exception.Message `
                        -Impact "Privileged group exposure could not be fully assessed." `
                        -Recommendation "Verify AD tools, permissions, and connectivity on the domain controller." `
                        -Standard "Microsoft Security Baseline" `
                        -Reference "Get-ADGroupMember documentation" `
                        -Status "Open"
                }

                try {
                    $admMembers = @(Get-ADGroupMember "Administrators" -ErrorAction Stop)

                    $admMembers |
                        Select-Object Name, SamAccountName, objectClass |
                        Out-File -FilePath $adminsFile -Encoding UTF8

                    if ($admMembers.Count -gt 0) {
                        $findings += New-ESAFFinding `
                            -FindingID "ID-DC-ADM-001" `
                            -Category "Identity & Access" `
                            -Title "Administrators group in Active Directory has members" `
                            -Severity "Medium" `
                            -AffectedComponent "Active Directory" `
                            -Description "The Administrators group in Active Directory contains members that may have elevated privileges." `
                            -Evidence (Get-Content -Path $adminsFile -Raw) `
                            -Impact "Misconfigured membership can increase the attack surface for privileged roles." `
                            -Recommendation "Review Administrators group membership and ensure it aligns with least privilege principles." `
                            -Standard "Microsoft Security Baseline" `
                            -Reference "https://learn.microsoft.com/windows-server/identity/securing-privileged-access" `
                            -Status "Open"
                    }
                }
                catch {
                    $findings += New-ESAFFinding `
                        -FindingID "ID-DC-ADM-ERR" `
                        -Category "Identity & Access" `
                        -Title "Failed to enumerate Administrators group in AD" `
                        -Severity "Low" `
                        -AffectedComponent "Active Directory" `
                        -Description "The assessment could not enumerate members of the Administrators group in Active Directory." `
                        -Evidence $_.Exception.Message `
                        -Impact "Some privileged roles may not be fully assessed." `
                        -Recommendation "Verify AD tools, permissions, and connectivity on the domain controller." `
                        -Standard "Microsoft Security Baseline" `
                        -Reference "Get-ADGroupMember documentation" `
                        -Status "Open"
                }
            }
            else {
                $findings += New-ESAFFinding `
                    -FindingID "ID-DC-ADMOD-001" `
                    -Category "Identity & Access" `
                    -Title "ActiveDirectory PowerShell module not available" `
                    -Severity "Medium" `
                    -AffectedComponent "Active Directory" `
                    -Description "The ActiveDirectory module is not available on this domain controller, limiting AD-based identity assessment." `
                    -Evidence "Get-Module -ListAvailable ActiveDirectory returned no results." `
                    -Impact "Privileged group membership in the domain cannot be fully audited." `
                    -Recommendation "Install RSAT/ActiveDirectory module on the domain controller or management server." `
                    -Standard "Microsoft Security Baseline" `
                    -Reference "https://learn.microsoft.com/powershell/module/activedirectory/" `
                    -Status "Open"
            }
        }
        else {
            $uacRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            $uacInfoFile = Join-Path -Path $identityEvidencePath -ChildPath "UACPolicy.txt"

            $enableLUA = $null
            $consentPromptBehaviorAdmin = $null
            $promptOnSecureDesktop = $null
            $filterAdministratorToken = $null

            if (Test-Path -Path $uacRegPath) {
                $uac = Get-ItemProperty -Path $uacRegPath

                $enableLUA = $uac.EnableLUA
                $consentPromptBehaviorAdmin = $uac.ConsentPromptBehaviorAdmin
                $promptOnSecureDesktop = $uac.PromptOnSecureDesktop
                $filterAdministratorToken = $uac.FilterAdministratorToken

@"
UAC Policy Check:
- HostRole: $HostRole
- EnableLUA: $enableLUA
- ConsentPromptBehaviorAdmin: $consentPromptBehaviorAdmin
- PromptOnSecureDesktop: $promptOnSecureDesktop
- FilterAdministratorToken: $filterAdministratorToken
"@ | Out-File -FilePath $uacInfoFile -Encoding UTF8

                if ($enableLUA -ne 1 -or $promptOnSecureDesktop -ne 1) {
                    $findings += New-ESAFFinding `
                        -FindingID "ID-UAC-001" `
                        -Category "Identity & Access" `
                        -Title "UAC is not configured to enforce secure desktop prompts" `
                        -Severity "Medium" `
                        -AffectedComponent "UAC" `
                        -Description "User Account Control is not fully enforcing secure prompts on the secure desktop." `
                        -Evidence (Get-Content -Path $uacInfoFile -Raw) `
                        -Impact "Elevation prompts may be more susceptible to UI spoofing and social engineering." `
                        -Recommendation "Enable UAC with secure desktop prompts for administrators and users." `
                        -Standard "Microsoft Security Baseline" `
                        -Reference "https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation" `
                        -Status "Open"
                }
            }
            else {
                $findings += New-ESAFFinding `
                    -FindingID "ID-UAC-REG-ERR" `
                    -Category "Identity & Access" `
                    -Title "UAC registry policy path not found" `
                    -Severity "Low" `
                    -AffectedComponent "UAC" `
                    -Description "The expected UAC policy registry path was not found." `
                    -Evidence "Registry path not found: $uacRegPath" `
                    -Impact "UAC configuration could not be assessed." `
                    -Recommendation "Verify the operating system version and registry accessibility." `
                    -Standard "Microsoft Security Baseline" `
                    -Reference "UAC policy registry settings" `
                    -Status "Open"
            }
        }
    }
    catch {
        $findings += New-ESAFFinding `
            -FindingID "ID-AUDIT-ERR-001" `
            -Category "Identity & Access" `
            -Title "Identity audit module execution failed" `
            -Severity "Medium" `
            -AffectedComponent "IdentityAudit Module" `
            -Description "The IdentityAudit module encountered an unexpected execution error." `
            -Evidence $_.Exception.Message `
            -Impact "Identity and access security posture could not be fully assessed." `
            -Recommendation "Verify EvidencePath initialization, module parameters, permissions, and PowerShell prerequisites." `
            -Standard "Internal ESAF Validation" `
            -Reference "IdentityAudit module error handling" `
            -Status "Open"
    }

    return $findings
}
