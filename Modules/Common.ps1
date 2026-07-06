function New-ESAFFinding {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FindingID,

        [Parameter(Mandatory = $true)]
        [string]$Category,

        [Parameter(Mandatory = $true)]
        [string]$Title,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Critical","High","Medium","Low","Info")]
        [string]$Severity,

        [Parameter(Mandatory = $true)]
        [string]$AffectedComponent,

        [Parameter(Mandatory = $true)]
        [string]$Description,

        [Parameter(Mandatory = $true)]
        [string]$Evidence,

        [Parameter(Mandatory = $true)]
        [string]$Impact,

        [Parameter(Mandatory = $true)]
        [string]$Recommendation,

        [Parameter(Mandatory = $false)]
        [string]$Standard = "Not Specified",

        [Parameter(Mandatory = $false)]
        [string]$Reference = "Not Specified",

        [Parameter(Mandatory = $true)]
        [string]$Status
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
        Standard          = $Standard
        Reference         = $Reference
        Status            = $Status
    }
}
