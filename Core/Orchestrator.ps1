# Core\Orchestrator.ps1
function Invoke-ESAFOrchestrator {
    param(
        [ValidateSet("Full","RoleBased","Custom")]
        [string]$ScanType,

        [array]$SelectedModules,

        [array]$SystemRoles,

        [string]$EvidencePath,

        [string]$HostRole
    )

    $allFindings = @()

    $moduleRegistry = @{
        Firewall = @{
            Script = { Invoke-ESAFFirewallAssessment -EvidencePath $EvidencePath }
            Roles  = @("MemberServer","DomainJoinedWorkstation","StandaloneServer","StandaloneWorkstation")
        }
        LocalSecurity = @{
            Script = { Invoke-ESAFLocalSecurityAssessment -EvidencePath $EvidencePath }
            Roles  = @("MemberServer","DomainJoinedWorkstation","StandaloneServer","StandaloneWorkstation")
        }
        Services = @{
            Script = { Invoke-ESAFServicesAssessment -EvidencePath $EvidencePath }
            Roles  = @("MemberServer","StandaloneServer")
        }
        NetworkSecurity = @{
            Script = { Invoke-ESAFNetworkSecurityAssessment -EvidencePath $EvidencePath }
            Roles  = @("DomainController","MemberServer","DomainJoinedWorkstation","StandaloneServer","StandaloneWorkstation")
        }
        IdentityAudit = @{
            Script = { Invoke-ESAFIdentityAuditAssessment -EvidencePath $EvidencePath -HostRole $HostRole }
            Roles  = @("DomainController","MemberServer","DomainJoinedWorkstation","StandaloneServer","StandaloneWorkstation")
        }
        ActiveDirectoryAudit = @{
            Script = { Invoke-ESAFActiveDirectoryAuditAssessment -EvidencePath $EvidencePath }
            Roles  = @("DomainController")
        }
    }

    $modulesToRun = @()

    switch ($ScanType) {
        "Full" {
            foreach ($moduleName in $moduleRegistry.Keys) {
                $moduleRoles = $moduleRegistry[$moduleName].Roles
                if ($moduleRoles -contains $HostRole) {
                    $modulesToRun += $moduleName
                }
            }
        }

        "RoleBased" {
            foreach ($moduleName in $moduleRegistry.Keys) {
                $moduleRoles = $moduleRegistry[$moduleName].Roles
                if ($moduleRoles -contains $HostRole -or $moduleRoles -contains "All") {
                    if ($SelectedModules -and $SelectedModules.Count -gt 0) {
                        if ($SelectedModules -contains $moduleName) {
                            $modulesToRun += $moduleName
                        }
                    }
                    else {
                        $modulesToRun += $moduleName
                    }
                }
            }
        }

        "Custom" {
            $modulesToRun = $SelectedModules
        }
    }

    $modulesToRun = $modulesToRun | Sort-Object -Unique

    foreach ($moduleName in $modulesToRun) {
        try {
            Write-Host "[*] Running module: $moduleName" -ForegroundColor Cyan
            $result = & $moduleRegistry[$moduleName].Script

            if ($result) {
                $allFindings += $result
            }
        }
        catch {
            $allFindings += New-ESAFFinding `
                -FindingID "SEC-ORCH-$($moduleName.ToUpper())-001" `
                -Category "Execution" `
                -Title "Module execution failed: $moduleName" `
                -Severity "Medium" `
                -AffectedComponent $moduleName `
                -Description "The orchestrator failed while executing module '$moduleName'." `
                -Evidence $_.Exception.Message `
                -Impact "Assessment coverage is incomplete because one of the modules did not run successfully." `
                -Recommendation "Review the module code, dependencies, permissions, and runtime environment." `
                -Standard "Internal ESAF Validation" `
                -Reference "Orchestrator module execution handling" `
                -Status "Open"
        }
    }

    return $allFindings
}
