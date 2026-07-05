function New-ESAFFinding {
    param(
        [string]$FindingID,
        [string]$Category,
        [string]$Title,
        [ValidateSet("Informational","Low","Medium","High","Critical")]
        [string]$Severity,
        [string]$AffectedComponent,
        [string]$Description,
        [string]$Evidence,
        [string]$Impact,
        [string]$Recommendation,
        [string]$Reference,
        [string]$Status = "Open"
    )

    return [PSCustomObject]@{
        FindingID         = $FindingID
        Category          = $Category
        Title             = $Title
        Severity          = $Severity
        AffectedComponent = $AffectedComponent
        Description       = $Description
        Evidence          = $Evidence
        Impact            = $Impact
        Recommendation    = $Recommendation
        Reference         = $Reference
        Status            = $Status
    }
}
