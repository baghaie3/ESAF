function Invoke-ESAFNetworkSecurityAssessment {
    param(
        [string]$EvidencePath
    )

    $findings = @()
    $evidenceLog = "Network Security Assessment`n`n"

    try {
        # --------------------------------------------------
        # SMBv1 Check
        # --------------------------------------------------
        $smbEvidence = "SMBv1 Check:`n"
        $smbServerEnabled = $null
        $smbOptionalFeatureEnabled = $null

        try {
            $smbConfig = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
            if ($null -ne $smbConfig) {
                $smbServerEnabled = $smbConfig.EnableSMB1Protocol
                $smbEvidence += "- Get-SmbServerConfiguration EnableSMB1Protocol: $smbServerEnabled`n"
            } else {
                $smbEvidence += "- Get-SmbServerConfiguration unavailable or returned null.`n"
            }
        } catch {
            $smbEvidence += "- Get-SmbServerConfiguration failed: $($_.Exception.Message)`n"
        }

        try {
            $smbFeature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
            if ($null -ne $smbFeature) {
                $smbOptionalFeatureEnabled = $smbFeature.State
                $smbEvidence += "- SMB1 Optional Feature State: $smbOptionalFeatureEnabled`n"
            } else {
                $smbEvidence += "- SMB1 optional feature info unavailable.`n"
            }
        } catch {
            $smbEvidence += "- Get-WindowsOptionalFeature failed: $($_.Exception.Message)`n"
        }

        $evidenceLog += $smbEvidence + "`n"

        $smbv1Enabled = $false
        if ($smbServerEnabled -eq $true) { $smbv1Enabled = $true }
        if ($smbOptionalFeatureEnabled -match "Enabled") { $smbv1Enabled = $true }

        if ($smbv1Enabled) {
            $findings += New-ESAFFinding `
                -FindingID "SEC-NET-SMB1-001" `
                -Category "Network Security" `
                -Title "SMBv1 is enabled" `
                -Severity "High" `
                -AffectedComponent "SMBv1" `
                -Description "The deprecated SMBv1 protocol appears to be enabled on the system." `
                -Evidence $smbEvidence `
                -Impact "SMBv1 is obsolete and vulnerable to multiple well-known attacks, including wormable exploitation and lateral movement." `
                -Recommendation "Disable SMBv1 on the system and verify that dependent legacy applications are migrated to SMBv2 or SMBv3." `
                -Standard "CIS Microsoft Windows Server Benchmark" `
                -Reference "SMBv1 deprecation and removal guidance" `
                -Status "Open"
        }

        # --------------------------------------------------
        # SCHANNEL Protocol Checks
        # --------------------------------------------------
        $protocolChecks = @(
            @{
                Name = "SSL 2.0"
                RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server"
                Standard = "CIS Microsoft Windows Server Benchmark"
                Reference = "SSL 2.0 deprecation guidance"
                Severity = "High"
            },
            @{
                Name = "SSL 3.0"
                RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server"
                Standard = "CIS Microsoft Windows Server Benchmark"
                Reference = "SSL 3.0 deprecation guidance"
                Severity = "High"
            },
            @{
                Name = "TLS 1.0"
                RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server"
                Standard = "CIS Microsoft Windows Server Benchmark"
                Reference = "TLS 1.0 deprecation guidance"
                Severity = "Medium"
            },
            @{
                Name = "TLS 1.1"
                RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server"
                Standard = "CIS Microsoft Windows Server Benchmark"
                Reference = "TLS 1.1 deprecation guidance"
                Severity = "Medium"
            }
        )

        foreach ($proto in $protocolChecks) {
            $protoEvidence = "$($proto.Name) Check:`n"
            $enabled = $null
            $disabledByDefault = $null

            if (Test-Path $proto.RegPath) {
                $reg = Get-ItemProperty -Path $proto.RegPath -ErrorAction SilentlyContinue
                $enabled = $reg.Enabled
                $disabledByDefault = $reg.DisabledByDefault

                $protoEvidence += "- Registry Path: $($proto.RegPath)`n"
                $protoEvidence += "- Enabled: $enabled`n"
                $protoEvidence += "- DisabledByDefault: $disabledByDefault`n"
            }
            else {
                $protoEvidence += "- Registry Path not found: $($proto.RegPath)`n"
                $protoEvidence += "- This may indicate default OS behavior or unconfigured policy.`n"
            }

            $evidenceLog += $protoEvidence + "`n"

            $protocolEnabled = $false

            if (Test-Path $proto.RegPath) {
                if ($enabled -eq 1) {
                    $protocolEnabled = $true
                }
                elseif ($null -eq $enabled -and $disabledByDefault -ne 1) {
                    $protocolEnabled = $true
                }
            }

            if ($protocolEnabled) {
                $findingIdSafe = ($proto.Name -replace '[^A-Za-z0-9]', '').ToUpper()

                $findings += New-ESAFFinding `
                    -FindingID "SEC-NET-$findingIdSafe-001" `
                    -Category "Network Security" `
                    -Title "$($proto.Name) is enabled" `
                    -Severity $proto.Severity `
                    -AffectedComponent $proto.Name `
                    -Description "The legacy cryptographic protocol $($proto.Name) appears to be enabled for SCHANNEL server-side communications." `
                    -Evidence $protoEvidence `
                    -Impact "Legacy protocols expose the system to downgrade attacks, weak cipher negotiation, and non-compliance with modern security baselines." `
                    -Recommendation "Disable $($proto.Name) for server-side SCHANNEL and enforce modern protocol versions such as TLS 1.2 and TLS 1.3 where supported." `
                    -Standard $proto.Standard `
                    -Reference $proto.Reference `
                    -Status "Open"
            }
        }

        # --------------------------------------------------
        # LLMNR Check
        # --------------------------------------------------
        $llmnrEvidence = "LLMNR Check:`n"
        $llmnrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
        $llmnrValue = $null

        if (Test-Path $llmnrPath) {
            $llmnrReg = Get-ItemProperty -Path $llmnrPath -ErrorAction SilentlyContinue
            $llmnrValue = $llmnrReg.EnableMulticast
            $llmnrEvidence += "- Registry Path: $llmnrPath`n"
            $llmnrEvidence += "- EnableMulticast: $llmnrValue`n"
        }
        else {
            $llmnrEvidence += "- Registry Path not found: $llmnrPath`n"
            $llmnrEvidence += "- Policy may be unconfigured; LLMNR may still be enabled by default depending on system baseline.`n"
        }

        $evidenceLog += $llmnrEvidence + "`n"

        $llmnrEnabled = $true
        if (Test-Path $llmnrPath) {
            if ($llmnrValue -eq 0) {
                $llmnrEnabled = $false
            }
        }

        if ($llmnrEnabled) {
            $findings += New-ESAFFinding `
                -FindingID "SEC-NET-LLMNR-001" `
                -Category "Network Security" `
                -Title "LLMNR appears enabled or not explicitly disabled" `
                -Severity "Medium" `
                -AffectedComponent "LLMNR" `
                -Description "Link-Local Multicast Name Resolution (LLMNR) does not appear to be explicitly disabled through policy." `
                -Evidence $llmnrEvidence `
                -Impact "LLMNR can be abused in local network poisoning attacks to capture NTLM challenge-response traffic and support credential relay scenarios." `
                -Recommendation "Disable LLMNR through Group Policy by setting 'Turn Off Multicast Name Resolution' appropriately." `
                -Standard "CIS Microsoft Windows Server Benchmark" `
                -Reference "LLMNR hardening guidance" `
                -Status "Open"
        }

        # --------------------------------------------------
        # NetBIOS over TCP/IP Check
        # --------------------------------------------------
        $netbiosEvidence = "NetBIOS over TCP/IP Check:`n"

        try {
            $adapters = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled = True" -ErrorAction SilentlyContinue

            foreach ($adapter in $adapters) {
                $netbiosOption = $adapter.TcpipNetbiosOptions
                $desc = $adapter.Description

                $netbiosEvidence += "- Adapter: $desc | TcpipNetbiosOptions: $netbiosOption`n"

                # 0 = Use DHCP setting
                # 1 = Enable NetBIOS
                # 2 = Disable NetBIOS
                if ($netbiosOption -ne 2) {
                    $findings += New-ESAFFinding `
                        -FindingID "SEC-NET-NETBIOS-001" `
                        -Category "Network Security" `
                        -Title "NetBIOS over TCP/IP is enabled or not explicitly disabled" `
                        -Severity "Medium" `
                        -AffectedComponent $desc `
                        -Description "NetBIOS over TCP/IP is enabled or inherits non-hardened behavior on one or more active network adapters." `
                        -Evidence "Adapter: $desc | TcpipNetbiosOptions: $netbiosOption" `
                        -Impact "NetBIOS can assist network reconnaissance, name service abuse, and credential capture techniques in flat or weakly segmented environments." `
                        -Recommendation "Disable NetBIOS over TCP/IP on all applicable network adapters unless a legacy dependency requires it." `
                        -Standard "CIS Microsoft Windows Server Benchmark" `
                        -Reference "NetBIOS over TCP IP hardening guidance" `
                        -Status "Open"
                }
            }
        }
        catch {
            $netbiosEvidence += "- NetBIOS check failed: $($_.Exception.Message)`n"
        }

        $evidenceLog += $netbiosEvidence + "`n"

        if ($EvidencePath) {
            $evidenceLog | Out-File -FilePath (Join-Path $EvidencePath "NetworkSecurity_Evidence.txt") -Encoding UTF8
        }
    }
    catch {
        $findings += New-ESAFFinding `
            -FindingID "SEC-NET-ERR-001" `
            -Category "Network Security" `
            -Title "Network security assessment execution failed" `
            -Severity "Medium" `
            -AffectedComponent "Network Security Module" `
            -Description "The network security module encountered an exception during execution." `
            -Evidence $_.Exception.Message `
            -Impact "Visibility into legacy protocol and name resolution hardening is incomplete." `
            -Recommendation "Review registry access, SMB feature availability, and adapter query methods." `
            -Standard "Internal ESAF Validation" `
            -Reference "Network security module troubleshooting" `
            -Status "Open"
    }

    return $findings
}
