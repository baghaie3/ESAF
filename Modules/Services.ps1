function Invoke-ESAFServicesAssessment {
    param(
        [string]$EvidencePath
    )

    $findings = @()
    $evidenceLog = "Unnecessary/Risk-prone Services Analysis:`n"

    $riskyServices = @(
        @{
            Name = "Spooler"
            Severity = "Medium"
            Reason = "Print Spooler is frequently associated with privilege escalation and remote code execution risk when not required."
            Standard = "Microsoft Security Baseline"
            Reference = "Print Spooler security guidance"
        },
        @{
            Name = "RemoteRegistry"
            Severity = "Medium"
            Reason = "Remote Registry allows remote modification of registry settings and should typically be disabled."
            Standard = "CIS Microsoft Windows Server Benchmark"
            Reference = "Remote Registry service hardening guidance"
        },
        @{
            Name = "TlntSvr"
            Severity = "High"
            Reason = "Telnet Server transmits credentials and session data in cleartext and is considered insecure."
            Standard = "CIS Microsoft Windows Server Benchmark"
            Reference = "Telnet Server insecure cleartext protocol guidance"
        },
        @{
            Name = "wuauserv"
            Severity = "Low"
            Reason = "Windows Update service is disabled, which can prevent timely installation of security updates."
            Standard = "Microsoft Security Baseline"
            Reference = "Windows Update security servicing guidance"
        }
    )

    try {
        foreach ($svcConfig in $riskyServices) {
            $svc = Get-Service -Name $svcConfig.Name -ErrorAction SilentlyContinue
            if ($svc) {
                $svcCim = Get-CimInstance -ClassName Win32_Service -Filter "Name='$($svcConfig.Name)'" -ErrorAction SilentlyContinue
                $startMode = if ($svcCim) { $svcCim.StartMode } else { "Unknown" }

                $evidenceLog += "- Service: $($svc.Name) | Status: $($svc.Status) | StartMode: $startMode`n"

                $trigger = $false
                if ($svcConfig.Name -eq "wuauserv") {
                    if ($startMode -eq "Disabled") { $trigger = $true }
                } else {
                    if ($startMode -ne "Disabled" -or $svc.Status -eq "Running") { $trigger = $true }
                }

                if ($trigger) {
                    $findings += New-ESAFFinding `
                        -FindingID "SEC-SVC-$($svcConfig.Name.ToUpper())-001" `
                        -Category "Services" `
                        -Title "Potentially Insecure Service State: $($svcConfig.Name)" `
                        -Severity $svcConfig.Severity `
                        -AffectedComponent $svcConfig.Name `
                        -Description "The service '$($svcConfig.Name)' was found in state '$($svc.Status)' with startup mode '$startMode'. $($svcConfig.Reason)" `
                        -Evidence "Service status: $($svc.Status)`nStartup Mode: $startMode" `
                        -Impact "Unnecessary or insecure services increase attack surface and may aid lateral movement, privilege escalation, or persistence." `
                        -Recommendation "Review business need for '$($svcConfig.Name)'. Disable it if not required, or configure it according to hardening guidance." `
                        -Standard $svcConfig.Standard `
                        -Reference $svcConfig.Reference `
                        -Status "Open"
                }
            }
        }

        if ($EvidencePath) {
            $evidenceLog | Out-File -FilePath (Join-Path $EvidencePath "Services_Evidence.txt") -Encoding UTF8
        }
    }
    catch {
        $findings += New-ESAFFinding `
            -FindingID "SEC-SVC-ERR-001" `
            -Category "Services" `
            -Title "Services assessment failed" `
            -Severity "Medium" `
            -AffectedComponent "Services Subsystem" `
            -Description "The services assessment module encountered an exception during execution." `
            -Evidence $_.Exception.Message `
            -Impact "Assessment coverage for unnecessary or risky services is incomplete." `
            -Recommendation "Review local permissions, CIM/WMI availability, and service query behavior." `
            -Standard "Internal ESAF Validation" `
            -Reference "Services module troubleshooting" `
            -Status "Open"
    }

    return $findings
}
