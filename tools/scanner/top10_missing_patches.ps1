<#
.SYNOPSIS
    Lists the top 10 missing patches on a Windows machine, prioritised by severity.

.DESCRIPTION
    This script uses the PSWindowsUpdate module (if available) to scan for missing
    Windows and Microsoft updates, then outputs the top 10 missing patches ordered by:
        1. Security severity (Critical > Important > Moderate > Low > Other)
        2. Whether a reboot is required
        3. Title

    It is designed as a lightweight "prioritised patch gap" view for SMEs as part of
    a vulnerability & patch management toolkit.

    Output:
      - A CSV file containing the top 10 missing patches and their key details.
      - Summary output to the console.

.PARAMETER OutputPath
    Path to the CSV file to write. The directory will be created if it does not exist.
    Default: .\reports\top10_missing_patches.csv

.EXAMPLE
    .\top10_missing_patches.ps1

.EXAMPLE
    .\top10_missing_patches.ps1 -OutputPath .\reports\server01_top10_missing_patches.csv
#>

[CmdletBinding()]
param(
    [string]
    $OutputPath = ".\reports\top10_missing_patches.csv"
)

Write-Verbose "Checking for PSWindowsUpdate module..."

try {
    Import-Module PSWindowsUpdate -ErrorAction SilentlyContinue | Out-Null
} catch {
    Write-Verbose "PSWindowsUpdate import failed: $_"
}

if (-not (Get-Module -Name PSWindowsUpdate)) {
    Write-Error "PSWindowsUpdate module not found. Install PSWindowsUpdate (e.g. via PSGallery) to use this script."
    Write-Host "Hint: Install-Module PSWindowsUpdate -Scope AllUsers"
    exit 1
}

Write-Verbose "Querying missing updates using Get-WindowsUpdate..."

try {
    # Retrieve missing (not installed) updates excluding drivers
    $updates = Get-WindowsUpdate -MicrosoftUpdate -IgnoreReboot -NotCategory "Drivers" -IsInstalled:$false -ErrorAction Stop
} catch {
    Write-Error "Failed to query missing updates via Get-WindowsUpdate: $_"
    exit 1
}

if (-not $updates -or $updates.Count -eq 0) {
    Write-Host "No missing updates detected for this computer."
    exit 0
}

Write-Verbose "Processing $(($updates).Count) missing updates..."

# Map severity to a numeric rank for prioritisation
function Get-SeverityRank {
    param(
        [string] $Severity
    )

    switch -Regex ($Severity) {
        "Critical"  { return 1 }
        "Important" { return 2 }
        "Moderate"  { return 3 }
        "Low"       { return 4 }
        default     { return 5 }
    }
}

# Enrich update objects with priority fields
$processed = $updates | ForEach-Object {
    $kb = $_.KB
    if (-not $kb -and $_.Title -match "KB(\d{6,})") {
        $kb = $matches[1]
    }

    $severity = $_.MsrcSeverity
    $sevRank  = Get-SeverityRank -Severity $severity

    # Consider classification or Title to flag security updates
    $isSecurity = $false
    if ($_.Title -match "Security Update" -or $_.Title -match "Security") {
        $isSecurity = $true
    }

    [PSCustomObject]@{
        ComputerName        = $env:COMPUTERNAME
        KB                  = $kb
        Title               = $_.Title
        MsrcSeverity        = $severity
        SeverityRank        = $sevRank
        IsSecurityUpdate    = $isSecurity
        Category            = $_.Category
        RebootRequired      = $_.RebootRequired
        IsDownloaded        = $_.IsDownloaded
        IsInstalled         = $_.IsInstalled
        Size                = $_.Size
        LastDeploymentChangeTime = $_.LastDeploymentChangeTime
    }
}

# Sort: highest priority first (lowest SeverityRank), then reboot-required, then title
$top10 = $processed |
    Sort-Object SeverityRank, @{ Expression = { -[int]($_.RebootRequired -eq $true) } }, Title |
    Select-Object -First 10

if (-not $top10 -or $top10.Count -eq 0) {
    Write-Host "No updates returned after prioritisation."
    exit 0
}

# Ensure output folder exists
$fullPath = [System.IO.Path]::GetFullPath($OutputPath)
$directory = [System.IO.Path]::GetDirectoryName($fullPath)
if (-not [string]::IsNullOrWhiteSpace($directory) -and -not (Test-Path $directory)) {
    New-Item -Path $directory -ItemType Directory -Force | Out-Null
}

Write-Verbose "Writing top 10 missing patches to $fullPath"

$top10 |
    Select-Object ComputerName, KB, Title, MsrcSeverity, IsSecurityUpdate, Category, `
                  RebootRequired, IsDownloaded, IsInstalled, Size, LastDeploymentChangeTime |
    Export-Csv -Path $fullPath -NoTypeInformation -Encoding UTF8

Write-Host "Top 10 missing patches written to: $fullPath"
Write-Host ""

Write-Host "Summary for $($env:COMPUTERNAME):"
foreach ($item in $top10) {
    Write-Host ("- {0} ({1}) | Severity: {2} | RebootRequired: {3}" -f `
        $item.KB, $item.Title, $item.MsrcSeverity, $item.RebootRequired)
}
