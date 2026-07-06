function Invoke-ESAFActiveDirectoryAuditAssessment {
    [CmdletBinding()]
    param()

    $findings = @()

    function Add-ADFinding {
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
            [string]$Reference = "Active Directory Security Review",
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

    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch {
        Add-ADFinding `
            -FindingID "AD-MODULE-001" `
            -Category "Identity & Access" `
            -Title "ActiveDirectory PowerShell module is not available" `
            -Severity "High" `
            -AffectedComponent "Active Directory Module" `
            -Description "The ActiveDirectory PowerShell module could not be loaded." `
            -Evidence $_.Exception.Message `
            -Impact "Active Directory security checks cannot be completed, reducing assessment coverage." `
            -Recommendation "Install RSAT Active Directory tools or run the assessment on a system with the ActiveDirectory module available." `
            -Standard "Internal ESAF Validation" `
            -Reference "ActiveDirectory module dependency"
        return $script:findings
    }

    try {
        $domain = Get-ADDomain -ErrorAction Stop
        $forest = Get-ADForest -ErrorAction Stop
    }
    catch {
        Add-ADFinding `
            -FindingID "AD-CONNECT-001" `
            -Category "Identity & Access" `
            -Title "Unable to query Active Directory domain or forest metadata" `
            -Severity "High" `
            -AffectedComponent "Active Directory" `
            -Description "The assessment could not retrieve core domain or forest information." `
            -Evidence $_.Exception.Message `
            -Impact "Domain-level security validation could not be fully completed." `
            -Recommendation "Run the assessment from a domain-joined system with sufficient privileges and connectivity to a domain controller." `
            -Standard "Internal ESAF Validation" `
            -Reference "Domain discovery dependency"
        return $script:findings
    }

    try {
        if ($forest.ForestMode -match "2008|2003") {
            Add-ADFinding `
                -FindingID "AD-FORESTMODE-001" `
                -Category "Identity & Access" `
                -Title "Forest functional level is below modern recommended baseline" `
                -Severity "Medium" `
                -AffectedComponent "Forest Functional Level" `
                -Description "The forest functional level appears older than modern security baselines recommend." `
                -Evidence "ForestMode: $($forest.ForestMode)" `
                -Impact "Legacy functional levels may limit modern security capabilities and indicate technical debt." `
                -Recommendation "Review compatibility requirements and raise the forest functional level where operationally feasible." `
                -Reference "Microsoft forest functional level guidance"
        }
    }
    catch {}

    try {
        if ($domain.DomainMode -match "2008|2003") {
            Add-ADFinding `
                -FindingID "AD-DOMAINMODE-001" `
                -Category "Identity & Access" `
                -Title "Domain functional level is below modern recommended baseline" `
                -Severity "Medium" `
                -AffectedComponent "Domain Functional Level" `
                -Description "The domain functional level appears older than modern security baselines recommend." `
                -Evidence "DomainMode: $($domain.DomainMode)" `
                -Impact "Older domain modes may prevent deployment of newer identity protections and hardening controls." `
                -Recommendation "Review compatibility requirements and raise the domain functional level where feasible." `
                -Reference "Microsoft domain functional level guidance"
        }
    }
    catch {}

    try {
        $dcs = Get-ADDomainController -Filter * -ErrorAction Stop
        if (($dcs | Measure-Object).Count -eq 0) {
            Add-ADFinding `
                -FindingID "AD-DC-001" `
                -Category "Identity & Access" `
                -Title "No domain controllers were returned by directory query" `
                -Severity "High" `
                -AffectedComponent "Domain Controllers" `
                -Description "The assessment did not receive any domain controller objects from Active Directory." `
                -Evidence "Get-ADDomainController returned zero objects." `
                -Impact "This may indicate connectivity, permissions, or directory health issues affecting domain operations." `
                -Recommendation "Validate domain controller availability, DNS health, and permissions used for the assessment." `
                -Reference "Active Directory domain controller inventory"
        }
    }
    catch {
        Add-ADFinding `
            -FindingID "AD-DC-002" `
            -Category "Identity & Access" `
            -Title "Failed to enumerate domain controllers" `
            -Severity "Medium" `
            -AffectedComponent "Domain Controllers" `
            -Description "The assessment could not enumerate domain controllers." `
            -Evidence $_.Exception.Message `
            -Impact "Domain controller inventory and related checks may be incomplete." `
            -Recommendation "Verify directory connectivity and permissions for domain controller enumeration." `
            -Reference "Active Directory domain controller inventory"
    }

    try {
        $fsmoEvidence = @(
            "PDCEmulator: $($domain.PDCEmulator)"
            "RIDMaster: $($domain.RIDMaster)"
            "InfrastructureMaster: $($domain.InfrastructureMaster)"
            "DomainNamingMaster: $($forest.DomainNamingMaster)"
            "SchemaMaster: $($forest.SchemaMaster)"
        ) -join [Environment]::NewLine

        $uniqueFsmo = @(
            $domain.PDCEmulator
            $domain.RIDMaster
            $domain.InfrastructureMaster
            $forest.DomainNamingMaster
            $forest.SchemaMaster
        ) | Where-Object { $_ } | Select-Object -Unique

        if ($uniqueFsmo.Count -eq 1) {
            Add-ADFinding `
                -FindingID "AD-FSMO-001" `
                -Category "Identity & Access" `
                -Title "All FSMO roles are concentrated on a single domain controller" `
                -Severity "Low" `
                -AffectedComponent "FSMO Roles" `
                -Description "All Flexible Single Master Operation roles appear assigned to a single server." `
                -Evidence $fsmoEvidence `
                -Impact "Operational concentration may increase resilience risk if the role holder becomes unavailable." `
                -Recommendation "Review whether FSMO role distribution aligns with resilience and operational requirements." `
                -Reference "FSMO placement review"
        }
    }
    catch {}

    $privilegedGroups = @(
        @{ Name = "Domain Admins";       Id = "AD-GRP-DA-001"; Severity = "High"   },
        @{ Name = "Enterprise Admins";   Id = "AD-GRP-EA-001"; Severity = "High"   },
        @{ Name = "Schema Admins";       Id = "AD-GRP-SA-001"; Severity = "High"   },
        @{ Name = "Administrators";      Id = "AD-GRP-ADM-001"; Severity = "Medium" },
        @{ Name = "Account Operators";   Id = "AD-GRP-AO-001"; Severity = "Medium" },
        @{ Name = "Server Operators";    Id = "AD-GRP-SO-001"; Severity = "Medium" },
        @{ Name = "Backup Operators";    Id = "AD-GRP-BO-001"; Severity = "Medium" },
        @{ Name = "Print Operators";     Id = "AD-GRP-PO-001"; Severity = "Low"    }
    )

    foreach ($group in $privilegedGroups) {
        try {
            $members = Get-ADGroupMember -Identity $group.Name -Recursive -ErrorAction Stop
            if (($members | Measure-Object).Count -gt 0) {
                $evidence = $members | Select-Object Name, SamAccountName, objectClass | Out-String
                Add-ADFinding `
                    -FindingID $group.Id `
                    -Category "Identity & Access" `
                    -Title "$($group.Name) group contains members" `
                    -Severity $group.Severity `
                    -AffectedComponent "Active Directory Privileged Groups" `
                    -Description "The privileged group '$($group.Name)' contains one or more members." `
                    -Evidence $evidence `
                    -Impact "Compromise or misuse of privileged group members can lead to elevated access and broader domain compromise." `
                    -Recommendation "Review membership of privileged groups and restrict assignments to the minimum necessary accounts." `
                    -Reference "Privileged group membership review"
            }
        }
        catch {
            Add-ADFinding `
                -FindingID "$($group.Id)-ERR" `
                -Category "Identity & Access" `
                -Title "Failed to enumerate members of $($group.Name)" `
                -Severity "Low" `
                -AffectedComponent "Active Directory Privileged Groups" `
                -Description "The assessment could not enumerate the members of a privileged Active Directory group." `
                -Evidence $_.Exception.Message `
                -Impact "Privileged group visibility is incomplete." `
                -Recommendation "Verify permissions and group existence, then rerun the assessment." `
                -Reference "Privileged group membership review"
        }
    }

    try {
        $preAuthDisabled = Get-ADUser -LDAPFilter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" -Properties SamAccountName,userAccountControl -ErrorAction Stop
        foreach ($user in $preAuthDisabled) {
            Add-ADFinding `
                -FindingID "AD-KRB-PREAUTH-001" `
                -Category "Identity & Access" `
                -Title "Kerberos pre-authentication is disabled for an account" `
                -Severity "High" `
                -AffectedComponent "Kerberos" `
                -Description "An account was identified with Kerberos pre-authentication disabled." `
                -Evidence "SamAccountName: $($user.SamAccountName)`nUserAccountControl: $($user.userAccountControl)" `
                -Impact "Accounts without pre-authentication are more susceptible to offline password-guessing attacks such as AS-REP roasting." `
                -Recommendation "Re-enable Kerberos pre-authentication unless a specific and documented business requirement exists." `
                -Reference "Kerberos pre-authentication hardening"
        }
    }
    catch {}

    try {
        $spnUsers = Get-ADUser -LDAPFilter "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))" -Properties SamAccountName,ServicePrincipalName,PasswordNeverExpires -ErrorAction Stop
        foreach ($user in $spnUsers) {
            Add-ADFinding `
                -FindingID "AD-SPN-001" `
                -Category "Identity & Access" `
                -Title "User account with SPN configured may be kerberoastable" `
                -Severity "Medium" `
                -AffectedComponent "Service Accounts" `
                -Description "A user account with one or more SPNs was identified." `
                -Evidence ("SamAccountName: {0}`nSPNs:`n{1}" -f $user.SamAccountName, (($user.ServicePrincipalName | Out-String).Trim())) `
                -Impact "Service accounts with SPNs may be targeted for Kerberoasting if they use weak passwords or lack managed rotation." `
                -Recommendation "Use strong randomly generated passwords, prefer gMSA where possible, and review necessity of each SPN." `
                -Reference "Kerberoasting exposure review"
        }
    }
    catch {}

    try {
        $pwdNeverExpires = Get-ADUser -Filter { PasswordNeverExpires -eq $true -and Enabled -eq $true } -Properties SamAccountName,PasswordNeverExpires,AdminCount -ErrorAction Stop
        foreach ($user in $pwdNeverExpires) {
            $severity = if ($user.AdminCount -eq 1) { "High" } else { "Medium" }

            Add-ADFinding `
                -FindingID "AD-PWD-NEVEREXPIRES-001" `
                -Category "Identity & Access" `
                -Title "Enabled account has password set to never expire" `
                -Severity $severity `
                -AffectedComponent "User Accounts" `
                -Description "An enabled account was identified with a non-expiring password." `
                -Evidence "SamAccountName: $($user.SamAccountName)`nAdminCount: $($user.AdminCount)" `
                -Impact "Non-expiring passwords increase credential persistence risk, especially for privileged identities." `
                -Recommendation "Require password rotation for standard accounts and migrate eligible service identities to managed service accounts." `
                -Reference "Password lifecycle hardening"
        }
    }
    catch {}

    try {
        $inactivePrivileged = Get-ADUser -Filter { Enabled -eq $true -and AdminCount -eq 1 } -Properties SamAccountName,LastLogonDate -ErrorAction Stop |
            Where-Object { $_.LastLogonDate -and $_.LastLogonDate -lt (Get-Date).AddDays(-90) }

        foreach ($user in $inactivePrivileged) {
            Add-ADFinding `
                -FindingID "AD-ADMIN-INACTIVE-001" `
                -Category "Identity & Access" `
                -Title "Privileged account appears inactive" `
                -Severity "Medium" `
                -AffectedComponent "Privileged Accounts" `
                -Description "A privileged account appears not to have logged on recently." `
                -Evidence "SamAccountName: $($user.SamAccountName)`nLastLogonDate: $($user.LastLogonDate)" `
                -Impact "Inactive privileged accounts increase attack surface and may remain unnoticed if compromised." `
                -Recommendation "Review and disable or remove dormant privileged accounts that are no longer operationally required." `
                -Reference "Privileged account hygiene"
        }
    }
    catch {}

    try {
        $unconstrained = Get-ADComputer -LDAPFilter "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" -Properties DNSHostName,userAccountControl -ErrorAction Stop
        foreach ($computer in $unconstrained) {
            Add-ADFinding `
                -FindingID "AD-DELEG-UNCONSTRAINED-001" `
                -Category "Identity & Access" `
                -Title "Computer account has unconstrained delegation enabled" `
                -Severity "High" `
                -AffectedComponent "Delegation" `
                -Description "A computer account was identified with unconstrained delegation enabled." `
                -Evidence "DNSHostName: $($computer.DNSHostName)`nUserAccountControl: $($computer.userAccountControl)" `
                -Impact "Unconstrained delegation can allow theft and replay of high-value Kerberos tickets, increasing lateral movement risk." `
                -Recommendation "Eliminate unconstrained delegation where possible and migrate to constrained or resource-based constrained delegation." `
                -Reference "Kerberos delegation hardening"
        }
    }
    catch {}

    try {
        $constrained = Get-ADObject -LDAPFilter "(&(msDS-AllowedToDelegateTo=*)(|(objectClass=user)(objectClass=computer)))" -Properties msDS-AllowedToDelegateTo,sAMAccountName,dNSHostName,objectClass -ErrorAction Stop
        foreach ($obj in $constrained) {
            $name = if ($obj.sAMAccountName) { $obj.sAMAccountName } elseif ($obj.dNSHostName) { $obj.dNSHostName } else { $obj.DistinguishedName }
            Add-ADFinding `
                -FindingID "AD-DELEG-CONSTRAINED-001" `
                -Category "Identity & Access" `
                -Title "Account has constrained delegation configured" `
                -Severity "Medium" `
                -AffectedComponent "Delegation" `
                -Description "An account was identified with constrained delegation configured." `
                -Evidence ("Name: {0}`nObjectClass: {1}`nAllowedToDelegateTo:`n{2}" -f $name, $obj.objectClass, (($obj.'msDS-AllowedToDelegateTo' | Out-String).Trim())) `
                -Impact "Constrained delegation reduces exposure relative to unconstrained delegation but still requires strict review and scoping." `
                -Recommendation "Validate business justification, ensure minimal scope, and monitor these accounts closely." `
                -Reference "Kerberos delegation hardening"
        }
    }
    catch {}

    try {
        $rbcdObjects = Get-ADObject -LDAPFilter "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)" -Properties msDS-AllowedToActOnBehalfOfOtherIdentity,sAMAccountName,dNSHostName,objectClass -ErrorAction Stop
        foreach ($obj in $rbcdObjects) {
            $name = if ($obj.sAMAccountName) { $obj.sAMAccountName } elseif ($obj.dNSHostName) { $obj.dNSHostName } else { $obj.DistinguishedName }
            Add-ADFinding `
                -FindingID "AD-DELEG-RBCD-001" `
                -Category "Identity & Access" `
                -Title "Object configured for resource-based constrained delegation" `
                -Severity "Medium" `
                -AffectedComponent "Delegation" `
                -Description "An object was identified with resource-based constrained delegation configuration." `
                -Evidence "Name: $name`nObjectClass: $($obj.objectClass)" `
                -Impact "RBCD can be secure when properly controlled, but unexpected entries may indicate attack paths or misconfiguration." `
                -Recommendation "Review principals allowed for RBCD and confirm explicit business need and ownership." `
                -Reference "Resource-based constrained delegation review"
        }
    }
    catch {}

    try {
        $trusts = Get-ADTrust -Filter * -ErrorAction Stop
        foreach ($trust in $trusts) {
            Add-ADFinding `
                -FindingID "AD-TRUST-001" `
                -Category "Identity & Access" `
                -Title "Active Directory trust relationship detected" `
                -Severity "Info" `
                -AffectedComponent "Trusts" `
                -Description "A trust relationship exists and should be reviewed as part of identity boundary management." `
                -Evidence ($trust | Select-Object Name,Source,Target,Direction,IntraForest,ForestTransitive,SelectiveAuthentication,SIDFilteringQuarantined | Out-String) `
                -Impact "Trusts expand authentication boundaries and may introduce lateral movement paths if not tightly governed." `
                -Recommendation "Review trust necessity, authentication scope, SID filtering, and selective authentication settings." `
                -Reference "AD trust review"
        }
    }
    catch {}

    try {
        $maq = (Get-ADDomain -ErrorAction Stop).'ms-DS-MachineAccountQuota'
        if ($null -ne $maq -and $maq -gt 0) {
            Add-ADFinding `
                -FindingID "AD-MAQ-001" `
                -Category "Identity & Access" `
                -Title "MachineAccountQuota allows non-admin computer joins" `
                -Severity "Medium" `
                -AffectedComponent "Domain Configuration" `
                -Description "The domain permits users to join computer accounts to the domain based on MachineAccountQuota." `
                -Evidence "ms-DS-MachineAccountQuota: $maq" `
                -Impact "Attackers with standard domain user access may create computer accounts that can be abused in certain privilege escalation and delegation scenarios." `
                -Recommendation "Set MachineAccountQuota to 0 unless there is a controlled operational requirement." `
                -Reference "MachineAccountQuota hardening"
        }
    }
    catch {}

    try {
        $optionalFeatures = Get-ADOptionalFeature -Filter * -ErrorAction Stop
        $recycleBin = $optionalFeatures | Where-Object { $_.Name -match "Recycle Bin" }
        if (-not $recycleBin) {
            Add-ADFinding `
                -FindingID "AD-RECYCLEBIN-001" `
                -Category "Identity & Access" `
                -Title "Active Directory Recycle Bin status could not be confirmed" `
                -Severity "Low" `
                -AffectedComponent "Active Directory Recovery" `
                -Description "The assessment could not confirm the Active Directory Recycle Bin state." `
                -Evidence "No Recycle Bin optional feature object was returned." `
                -Impact "Recovery readiness for deleted directory objects may be unclear." `
                -Recommendation "Confirm whether the AD Recycle Bin is enabled and align with recovery requirements." `
                -Reference "Active Directory recovery readiness"
        }
    }
    catch {}

    try {
        $adminSdHolderDn = "CN=AdminSDHolder,CN=System,$($domain.DistinguishedName)"
        $acl = Get-Acl -Path ("AD:\\" + $adminSdHolderDn) -ErrorAction Stop
        $suspiciousRights = $acl.Access | Where-Object {
            $_.IdentityReference -notmatch "Domain Admins|Enterprise Admins|Administrators|SYSTEM" -and
            (
                $_.ActiveDirectoryRights.ToString() -match "GenericAll|GenericWrite|WriteDacl|WriteOwner|AllExtendedRights"
            )
        }

        foreach ($ace in $suspiciousRights) {
            Add-ADFinding `
                -FindingID "AD-ACL-ADMINSDHOLDER-001" `
                -Category "Identity & Access" `
                -Title "Potentially dangerous delegated rights on AdminSDHolder" `
                -Severity "High" `
                -AffectedComponent "AdminSDHolder ACL" `
                -Description "A non-standard principal appears to have powerful rights on AdminSDHolder." `
                -Evidence ($ace | Format-List * | Out-String) `
                -Impact "Malicious or unintended control of AdminSDHolder can propagate privileged ACLs to protected accounts and groups." `
                -Recommendation "Review and remove unauthorized ACEs from AdminSDHolder and validate delegated administration boundaries." `
                -Reference "AdminSDHolder ACL review"
        }
    }
    catch {}

    try {
        $domainAcl = Get-Acl -Path ("AD:\\" + $domain.DistinguishedName) -ErrorAction Stop
        $suspiciousDomainAces = $domainAcl.Access | Where-Object {
            $_.IdentityReference -notmatch "Domain Admins|Enterprise Admins|Administrators|SYSTEM|Authenticated Users|Everyone" -and
            (
                $_.ActiveDirectoryRights.ToString() -match "GenericAll|GenericWrite|WriteDacl|WriteOwner|AllExtendedRights"
            )
        }

        foreach ($ace in $suspiciousDomainAces) {
            Add-ADFinding `
                -FindingID "AD-ACL-DOMAINROOT-001" `
                -Category "Identity & Access" `
                -Title "Potentially dangerous delegated rights on domain root object" `
                -Severity "High" `
                -AffectedComponent "Domain Root ACL" `
                -Description "A non-standard principal appears to have powerful rights on the domain root object." `
                -Evidence ($ace | Format-List * | Out-String) `
                -Impact "Excessive rights on the domain root can enable broad directory compromise or stealthy privilege escalation." `
                -Recommendation "Review delegated ACEs on the domain root and restrict powerful rights to explicitly authorized principals only." `
                -Reference "Domain root ACL review"
        }
    }
    catch {}

    try {
        $psoList = Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction Stop
        foreach ($pso in $psoList) {
            if ($pso.MinPasswordLength -lt 14 -or $pso.LockoutThreshold -eq 0) {
                Add-ADFinding `
                    -FindingID "AD-PSO-001" `
                    -Category "Identity & Access" `
                    -Title "Fine-grained password policy appears weaker than recommended baseline" `
                    -Severity "Medium" `
                    -AffectedComponent "Fine-Grained Password Policy" `
                    -Description "A fine-grained password policy was identified with potentially weak settings." `
                    -Evidence ($pso | Select-Object Name,Precedence,MinPasswordLength,LockoutThreshold,MaxPasswordAge | Out-String) `
                    -Impact "Weak password policy settings may reduce resilience against password guessing and brute-force attacks." `
                    -Recommendation "Review PSO settings and align them with current enterprise password and lockout standards." `
                    -Reference "Fine-grained password policy review"
            }
        }
    }
    catch {}

    try {
        $ldapSigning = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -ErrorAction SilentlyContinue
        $ldapServerIntegrity = $ldapSigning."LDAPServerIntegrity"
        if ($null -eq $ldapServerIntegrity -or $ldapServerIntegrity -lt 2) {
            Add-ADFinding `
                -FindingID "AD-LDAPSIGN-001" `
                -Category "Identity & Access" `
                -Title "LDAP signing may not be fully enforced on the domain controller" `
                -Severity "High" `
                -AffectedComponent "LDAP Security" `
                -Description "LDAP signing does not appear to be fully enforced based on current registry state." `
                -Evidence "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity = $ldapServerIntegrity" `
                -Impact "Unsigned LDAP traffic can increase exposure to relay and tampering attacks." `
                -Recommendation "Enforce LDAP signing through directory service policy and validate compatibility before broad rollout." `
                -Reference "LDAP signing hardening"
        }
    }
    catch {}

    try {
        $channelBinding = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -ErrorAction SilentlyContinue
        $cbtValue = $channelBinding."LdapEnforceChannelBinding"
        if ($null -eq $cbtValue -or $cbtValue -lt 1) {
            Add-ADFinding `
                -FindingID "AD-LDAPCBT-001" `
                -Category "Identity & Access" `
                -Title "LDAP channel binding may not be enforced" `
                -Severity "Medium" `
                -AffectedComponent "LDAP Security" `
                -Description "LDAP channel binding does not appear enforced based on current registry state." `
                -Evidence "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LdapEnforceChannelBinding = $cbtValue" `
                -Impact "Missing channel binding enforcement can reduce resistance to certain NTLM relay scenarios involving LDAP." `
                -Recommendation "Review and enforce LDAP channel binding according to supported client and application requirements." `
                -Reference "LDAP channel binding hardening"
        }
    }
    catch {}

    return $script:findings
}
