# =========================================
# SCAN ONLINE SANS API - CISA KEV
# =========================================

$KevUrl = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

function Get-InstalledSoftware {

    $paths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    $results = @()

    foreach ($path in $paths) {
        Get-ItemProperty -Path $path -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.DisplayName) {
                $results += [pscustomobject]@{
                    Name    = $_.DisplayName.Trim()
                    Version = $_.DisplayVersion
                }
            }
        }
    }

    return $results | Sort-Object Name, Version -Unique
}

Write-Host "=== SCAN DES VULNERABILITES EXPLOITEES (CISA KEV) ===" -ForegroundColor Cyan

# -------------------------
# Chargement logiciels
# -------------------------
$Installed = Get-InstalledSoftware
Write-Host ("Logiciels detectes : {0}" -f $Installed.Count)

# -------------------------
# Chargement KEV
# -------------------------
Write-Host "Telechargement base CISA KEV..."
$KevData = Invoke-RestMethod -Uri $KevUrl -Method Get
$KevList = $KevData.vulnerabilities

Write-Host ("Vulnerabilites exploitees connues : {0}" -f $KevList.Count)

# -------------------------
# Matching heuristique
# -------------------------
$Findings = @()

foreach ($app in $Installed) {

    foreach ($kev in $KevList) {

        # matching large volontaire
        if ($app.Name -match [regex]::Escape($kev.product)) {

            $Findings += [pscustomobject]@{
                Software   = $app.Name
                Version    = $app.Version
                CVE        = $kev.cveID
                Vendor     = $kev.vendorProject
                Product    = $kev.product
                DateAdded  = $kev.dateAdded
                Ransomware = $kev.knownRansomwareCampaignUse
                Description = $kev.shortDescription
                Action     = $kev.requiredAction
            }
        }
    }
}

# -------------------------
# Export
# -------------------------
$OutDir = Join-Path $PSScriptRoot "VulnReport"
if (-not (Test-Path $OutDir)) {
    New-Item -ItemType Directory -Path $OutDir | Out-Null
}

if ($Findings.Count -gt 0) {

    $Findings |
        Sort-Object DateAdded -Descending |
        Export-Csv "$OutDir\kev_exploited_vulnerabilities.csv" `
            -NoTypeInformation -Encoding UTF8

    Write-Host "`n!!! VULNERABILITES EXPLOITEES DETECTEES !!!" -ForegroundColor Red
    Write-Host ("Total : {0}" -f $Findings.Count)
    Write-Host "Rapport : $OutDir\kev_exploited_vulnerabilities.csv"

} else {
    Write-Host "`nAucune vulnerabilite exploitee detectee via KEV"
}

Write-Host "=== SCAN TERMINE ===" -ForegroundColor Green
