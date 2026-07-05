function Show-ESAFMainMenu {
    Write-Host ""
    Write-Host "=========== ESAF Main Menu ===========" -ForegroundColor Cyan
    Write-Host "1. Quick Assessment"
    Write-Host "2. Full Assessment"
    Write-Host "3. Role-based Assessment"
    Write-Host "4. Custom Assessment"
    Write-Host "5. Exit"
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host ""

    do {
        $choice = Read-Host "Select an option (1-5)"
    } while ($choice -notin @("1","2","3","4","5"))

    return $choice
}

function Show-ESAFCustomModuleMenu {
    Write-Host ""
    Write-Host "======= ESAF Custom Assessment =======" -ForegroundColor Cyan
    Write-Host "1. Firewall"
    Write-Host "2. Back"
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host ""

    do {
        $choice = Read-Host "Select an option (1-2)"
    } while ($choice -notin @("1","2"))

    return $choice
}
