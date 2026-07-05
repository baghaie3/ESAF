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

    $criticalCount      = [int](($Findings | Where-Object { $_.Severity -eq "Critical" }) | Measure-Object).Count
    $highCount          = [int](($Findings | Where-Object { $_.Severity -eq "High" }) | Measure-Object).Count
    $mediumCount        = [int](($Findings | Where-Object { $_.Severity -eq "Medium" }) | Measure-Object).Count
    $lowCount           = [int](($Findings | Where-Object { $_.Severity -eq "Low" }) | Measure-Object).Count
    $informationalCount = [int](($Findings | Where-Object { $_.Severity -eq "Informational" }) | Measure-Object).Count

    $severitySummaryHtml = @"
<span class="badge critical">Critical: $($criticalCount)</span>
<span class="badge high">High: $($highCount)</span>
<span class="badge medium">Medium: $($mediumCount)</span>
<span class="badge low">Low: $($lowCount)</span>
<span class="badge informational">Informational: $($informationalCount)</span>
"@

    $rows = foreach ($finding in $Findings) {
        $severityClass = if ($finding.Severity) { $finding.Severity.ToLower() } else { "informational" }

        @"
<tr class="row-$severityClass">
    <td style="font-weight: bold;">$($finding.FindingID)</td>
    <td>$($finding.Category)</td>
    <td>$($finding.Title)</td>
    <td><span class="badge $severityClass">$($finding.Severity)</span></td>
    <td>$($finding.AffectedComponent)</td>
    <td>$($finding.Description)</td>
    <td><pre>$([System.Web.HttpUtility]::HtmlEncode([string]$finding.Evidence))</pre></td>
    <td>$($finding.Impact)</td>
    <td>$($finding.Recommendation)</td>
    <td>$($finding.Reference)</td>
    <td>$($finding.Status)</td>
</tr>
"@
    }

    $html = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>ESAF Assessment Report - $($ScanType)</title>
    <style>
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            margin: 25px;
            background-color: #f4f6f9;
            color: #333;
        }
        h1, h2 {
            color: #0f2c59;
        }
        .summary {
            background: #ffffff;
            border-left: 5px solid #0f2c59;
            padding: 20px;
            margin-bottom: 25px;
            border-radius: 4px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            color: #ffffff;
            font-weight: bold;
            font-size: 11px;
            text-transform: uppercase;
            margin-right: 5px;
            margin-bottom: 5px;
        }
        .critical { background-color: #991b1b; }
        .high { background-color: #dc2626; }
        .medium { background-color: #d97706; }
        .low { background-color: #2563eb; }
        .informational { background-color: #4b5563; }

        table {
            border-collapse: collapse;
            width: 100%;
            background: #ffffff;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            margin-top: 15px;
        }
        th, td {
            border: 1px solid #e5e7eb;
            padding: 12px;
            text-align: left;
            vertical-align: top;
            font-size: 13px;
        }
        th {
            background-color: #0f2c59;
            color: #ffffff;
        }
        .row-critical { background-color: #fef2f2; }
        .row-high { background-color: #fff5f5; }
        .row-medium { background-color: #fffbeb; }
        .row-low { background-color: #eff6ff; }
        .row-informational { background-color: #f9fafb; }

        pre {
            white-space: pre-wrap;
            word-wrap: break-word;
            font-size: 11px;
            margin: 0;
            background: #27272a;
            color: #a7f3d0;
            padding: 8px;
            border-radius: 4px;
            max-height: 200px;
            overflow-y: auto;
        }
    </style>
</head>
<body>
    <h1>Enterprise Security Assessment Framework (ESAF)</h1>
    <div class="summary">
        <h2>Executive Summary</h2>
        <p><strong>System Name:</strong> $($SystemName)</p>
        <p><strong>Scan Mode:</strong> $($ScanType)</p>
        <p><strong>Detected Roles:</strong> $($Roles -join ", ")</p>
        <p><strong>Report Timestamp:</strong> $(Get-Date)</p>
        <hr style="border: 0; border-top: 1px solid #e5e7eb; margin: 15px 0;">
        <strong>Severity Summary:</strong><br><br>
        $severitySummaryHtml
    </div>

    <h2>Detailed Findings Table</h2>
    <table>
        <thead>
            <tr>
                <th>Finding ID</th>
                <th>Category</th>
                <th>Title</th>
                <th>Severity</th>
                <th>Component</th>
                <th>Description</th>
                <th>Evidence</th>
                <th>Impact</th>
                <th>Recommendation</th>
                <th>Reference</th>
                <th>Status</th>
            </tr>
        </thead>
        <tbody>
            $($rows -join "`n")
        </tbody>
    </table>
</body>
</html>
"@

    [System.IO.File]::WriteAllText($Path, $html, [System.Text.UTF8Encoding]::new($false))
}
1