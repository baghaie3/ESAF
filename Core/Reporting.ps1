function Export-ESAFJsonReport {
    param(
        [array]$Findings,
        [string]$Path
    )

    $Findings | ConvertTo-Json -Depth 6 | Out-File -FilePath $Path -Encoding UTF8
}

function Export-ESAFCsvReport {
    param(
        [array]$Findings,
        [string]$Path
    )

    $Findings | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
}

function Export-ESAFHtmlReport {
    param(
        [array]$Findings,
        [string]$Path,
        [array]$Roles,
        [string]$SystemName,
        [string]$ScanType
    )

    $reportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    $criticalCount = ($Findings | Where-Object { $_.Severity -eq "Critical" } | Measure-Object).Count
    $highCount     = ($Findings | Where-Object { $_.Severity -eq "High" } | Measure-Object).Count
    $mediumCount   = ($Findings | Where-Object { $_.Severity -eq "Medium" } | Measure-Object).Count
    $lowCount      = ($Findings | Where-Object { $_.Severity -eq "Low" } | Measure-Object).Count
    $infoCount     = ($Findings | Where-Object { $_.Severity -eq "Info" } | Measure-Object).Count
    $totalCount    = ($Findings | Measure-Object).Count

    $executiveSummary = ""
    if ($criticalCount -gt 0 -or $highCount -gt 0) {
        $executiveSummary = "The assessment identified significant security issues requiring prioritized remediation. Immediate attention is recommended for Critical and High severity findings."
    }
    elseif ($mediumCount -gt 0) {
        $executiveSummary = "The assessment identified moderate security weaknesses. Remediation should be planned to reduce attack surface and improve baseline compliance."
    }
    elseif ($lowCount -gt 0 -or $infoCount -gt 0) {
        $executiveSummary = "The assessment identified minor issues and informational observations. Addressing these findings will improve operational security posture and hardening consistency."
    }
    else {
        $executiveSummary = "No security findings were identified during this assessment. The evaluated system appears aligned with the currently implemented checks and baseline expectations."
    }

    $rows = foreach ($finding in $Findings) {
        $severityClass = switch ($finding.Severity) {
            "Critical" { "sev-critical" }
            "High"     { "sev-high" }
            "Medium"   { "sev-medium" }
            "Low"      { "sev-low" }
            "Info"     { "sev-info" }
            default    { "" }
        }

        @"
<tr class="$severityClass">
    <td>$($finding.FindingID)</td>
    <td>$($finding.Category)</td>
    <td>$($finding.Title)</td>
    <td>$($finding.Severity)</td>
    <td>$($finding.AffectedComponent)</td>
    <td>$($finding.Standard)</td>
    <td>$($finding.Reference)</td>
    <td><pre>$($finding.Description)</pre></td>
    <td><pre>$($finding.Evidence)</pre></td>
    <td><pre>$($finding.Impact)</pre></td>
    <td><pre>$($finding.Recommendation)</pre></td>
    <td>$($finding.Status)</td>
</tr>
"@
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ESAF Security Report</title>
    <style>
        body {
            font-family: Segoe UI, Arial, sans-serif;
            background-color: #f4f7fb;
            color: #1f2937;
            margin: 0;
            padding: 0;
        }
        .container {
            width: 96%;
            margin: 2px auto;
            background: #ffffff;
            border-radius: 10px;
            box-shadow: 0 4px 16px rgba(0,0,0,0.08);
            padding: 1px;
        }
        h1, h2, h3, p {
            margin-top: 0;
            color: #0f172a;
            margin-bottom: 2px;
        }
        .meta, .summary, .exec-summary {
            margin-bottom: 4px;
            padding: 2px;
            border-radius: 8px;
        }
        .meta {
            background: #e0f2fe;
        }
        .summary {
            background: #f8fafc;
            border: 1px solid #e5e7eb;
        }
        .exec-summary {
            background: #eef6ff;
            border-left: 5px solid #2563eb;
        }
        .badge {
            display: inline-block;
            margin: 4px 8px 4px 0;
            padding: 8px 12px;
            border-radius: 20px;
            color: white;
            font-weight: bold;
            font-size: 13px;
        }
        .critical { background: #7f1d1d; }
        .high     { background: #dc2626; }
        .medium   { background: #f59e0b; color: #111827; }
        .low      { background: #2563eb; }
        .info     { background: #6b7280; }
        .total    { background: #111827; }
        table {
            width: 100%;
            border-collapse: collapse;
            table-layout: fixed;
            font-size: 13px;
        }
        th, td {
            border: 1px solid #d1d5db;
            padding: 10px;
            text-align: left;
            vertical-align: top;
            word-wrap: break-word;
            overflow-wrap: break-word;
        }
        th {
            background-color: #1e3a8a;
            color: white;
            position: sticky;
            top: 0;
        }
        tr:nth-child(even) {
            background-color: #f9fafb;
        }
        .sev-critical { background-color: #fee2e2 !important; }
        .sev-high     { background-color: #fecaca !important; }
        .sev-medium   { background-color: #fef3c7 !important; }
        .sev-low      { background-color: #dbeafe !important; }
        .sev-info     { background-color: #e5e7eb !important; }
        pre {
            white-space: pre-wrap;
            word-wrap: break-word;
            margin: 0;
            font-family: Consolas, monospace;
            font-size: 12px;
        }
        .footer {
            margin-top: 20px;
            font-size: 12px;
            color: #6b7280;
            text-align: right;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Enterprise Security Assessment Framework (ESAF)</h1>

        <div class="meta">
            <h3>Assessment Metadata</h3>
            <p><strong>System Name:</strong> $SystemName</p>
            <p><strong>Scan Type:</strong> $ScanType</p>
            <p><strong>Detected Roles:</strong> $($Roles -join ', ')</p>
            <p><strong>Report Generated:</strong> $reportDate</p>
        </div>

        <div class="exec-summary">
            <h3>Executive Summary</h3>
            <p>$executiveSummary</p>
        </div>

        <div class="summary">
            <h3>Severity Summary</h3>
            <span class="badge critical">Critical: $($criticalCount)</span>
            <span class="badge high">High: $($highCount)</span>
            <span class="badge medium">Medium: $($mediumCount)</span>
            <span class="badge low">Low: $($lowCount)</span>
            <span class="badge info">Info: $($infoCount)</span>
            <span class="badge total">Total: $($totalCount)</span>
        </div>

        <h3>Detailed Findings</h3>
        <table>
            <thead>
                <tr>
                    <th>Finding ID</th>
                    <th>Category</th>
                    <th>Title</th>
                    <th>Severity</th>
                    <th>Affected Component</th>
                    <th>Standard</th>
                    <th>Reference</th>
                    <th>Description</th>
                    <th>Evidence</th>
                    <th>Impact</th>
                    <th>Recommendation</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                $($rows -join "`n")
            </tbody>
        </table>

        <div class="footer">
            ESAF Report | Generated with Enterprise Security Assessment Framework by Kb7200
        </div>
    </div>
</body>
</html>
"@

    $html | Out-File -FilePath $Path -Encoding UTF8
}

function Export-ESAFTxtSummary {
    param(
        [array]$Findings,
        [string]$Path,
        [array]$Roles,
        [string]$SystemName,
        [string]$ScanType
    )

    $reportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    $criticalCount = ($Findings | Where-Object { $_.Severity -eq "Critical" }).Count
    $highCount     = ($Findings | Where-Object { $_.Severity -eq "High" }).Count
    $mediumCount   = ($Findings | Where-Object { $_.Severity -eq "Medium" }).Count
    $lowCount      = ($Findings | Where-Object { $_.Severity -eq "Low" }).Count
    $infoCount     = ($Findings | Where-Object { $_.Severity -eq "Info" }).Count
    $totalCount    = $Findings.Count

    $lines = @()
    $lines += "Enterprise Security Assessment Framework (ESAF)"
    $lines += "================================================"
    $lines += ""
    $lines += "System Name      : $SystemName"
    $lines += "Scan Type        : $ScanType"
    $lines += "Detected Roles   : $($Roles -join ', ')"
    $lines += "Report Generated : $reportDate"
    $lines += ""
    $lines += "Severity Summary"
    $lines += "----------------"
    $lines += "Critical : $criticalCount"
    $lines += "High     : $highCount"
    $lines += "Medium   : $mediumCount"
    $lines += "Low      : $lowCount"
    $lines += "Info     : $infoCount"
    $lines += "Total    : $totalCount"
    $lines += ""
    $lines += "Detailed Findings"
    $lines += "-----------------"

    foreach ($f in $Findings) {
        $lines += ""
        $lines += "Finding ID         : $($f.FindingID)"
        $lines += "Category           : $($f.Category)"
        $lines += "Title              : $($f.Title)"
        $lines += "Severity           : $($f.Severity)"
        $lines += "Affected Component : $($f.AffectedComponent)"
        $lines += "Standard           : $($f.Standard)"
        $lines += "Reference          : $($f.Reference)"
        $lines += "Status             : $($f.Status)"
        $lines += "Description        : $($f.Description)"
        $lines += "Evidence           : $($f.Evidence)"
        $lines += "Impact             : $($f.Impact)"
        $lines += "Recommendation     : $($f.Recommendation)"
        $lines += "------------------------------------------------"
    }

    $lines | Out-File -FilePath $Path -Encoding UTF8
}
