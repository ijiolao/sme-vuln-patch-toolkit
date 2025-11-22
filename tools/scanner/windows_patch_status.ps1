<#
.SYNOPSIS
    Collects Windows patch status for the local machine: OS version, missing updates, and pending reboot state.

.DESCRIPTION
    This script is intended for SMEs as part of a vulnerability & patch management toolkit.
    It gathers:
      - Basic OS information (caption, version, build)
      - Count of missing updates (using PSWindowsUpdate if available)
      - Pending reboot status (based on common Windows indicators)

    Output:
      - A CSV file summarising patch status for the local machine.

.PARAMETER OutputPath
    Path to the CSV report to write. If the folder does not exist, it will be created.

.EXAMPLE
    .\windows_patch_status.ps1

.EXAMPLE
    .\windows_patch_status.ps1 -OutputPath .\reports\windows_patch_status.csv
#>

[CmdletBinding()]
param(
    [string]
    $OutputPath = ".\reports\windows_patch_status.csv"
)

function Test-PendingReboot {
    <#
    .SYNOPSIS
        Checks common locations to determine if a reboot is pending.
    #>
    [CmdletBinding()]
    param()

    $isPending = $false

    # 1. PendingFileRenameOperations (general indicator)
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
    if (Test-Path $regPath) {
        $value = (Get-ItemProperty -Path $regPath -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue)
        if ($null -ne $value.PendingFileRenameOperations) {
            $isPending = $true
        }
    }

    # 2. Windows Update auto-reboot required
    $wuPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
    if (Test-Path $wuPath) {
        $isPending = $true
    }

    # 3. CBS reboot pending
    $cbsPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
    if (Test-Path $cbsPath) {
        $isPending = $true
    }

    return $isPending
}

Write-Verbose "Collecting OS information..."

try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
} catch {
    Write-Warning "Unable to get OS information: $_"
    $os = $null
}

$computerName = $env:COMPUTERNAME
$osCaption    = if ($os) { $os.Caption } else { $null }
$osVersion    = if ($os) { $os.Version } else { $null }
$osBuild      = if ($os) { $os.BuildNumber } else { $null }
$lastBoot     = if ($os) { $os.LastBootUpTime } else { $null }

Write-Verbose "Checking pending reboot status..."
$pendingReboot = Test-PendingReboot

# Defaults in case PSWindowsUpdate is not present
$missingCount           = $null
$criticalMissingCount   = $null
$securityMissingCount   = $null
$sampleUpdates          = $null
$pswuNote               = $null

Write-Verbose "Attempting to load PSWindowsUpdate for missing patch enumeration..."

try {
    Import-Module PSWindowsUpdate -ErrorAction SilentlyContinue | Out-Null
} catch {
    Write-Verbose "PSWindowsUpdate module not available."
}

if (Get-Module -Name PSWindowsUpdate) {
    try {
        # Get list of available updates (not installed)
        $updates = Get-WindowsUpdate -MicrosoftUpdate -IgnoreReboot -NotCategory "Drivers" -IsInstalled:$false -ErrorAction SilentlyContinue

        if ($updates) {
            $missingCount = $updates.Count
            $criticalMissingCount = ($updates | Where-Object { $_.MsrcSeverity -eq 'Critical' }).Count
            $securityMissingCount = ($updates | Where-Object { $_.MsrcSeverity -eq 'Important' -or $_.MsrcSeverity -eq 'Moderate' }).Count

            # Take a few sample titles
            $sampleUpdates = ($updates | Select-Object -First 5 | ForEach-Object { $_.KB + ' - ' + $_.Title }) -join "; "
        } else {
            $missingCount = 0
            $criticalMissingCount = 0
            $securityMissingCount = 0
        }
    } catch {
        Write-Warning "Error querying missing updates via PSWindowsUpdate: $_"
        $pswuNote = "PSWindowsUpdate installed but query failed. See console output."
    }
} else {
    $pswuNote = "PSWindowsUpdate module not found. Missing update count not available. Install PSWindowsUpdate to enable this feature."
}

# Ensure target directory exists
$fullPath = [System.IO.Path]::GetFullPath($OutputPath)
$directory = [System.IO.Path]::GetDirectoryName($fullPath)
if (-not [string]::IsNullOrWhiteSpace($directory) -and -not (Test-Path $directory)) {
    Write-Verbose "Creating directory $directory"
    New-Item -Path $directory -ItemType Directory -Force | Out-Null
}

$result = [PSCustomObject]@{
    ComputerName            = $computerName
    OSCaption               = $osCaption
    OSVersion               = $osVersion
    OSBuild                 = $osBuild
    LastBootUpTime          = $lastBoot
    PendingReboot           = $pendingReboot
    MissingUpdateCount      = $missingCount
    CriticalMissingCount    = $criticalMissingCount
    SecurityMissingCount    = $securityMissingCount
    SampleMissingUpdates    = $sampleUpdates
    PSWindowsUpdateNote     = $pswuNote
    ReportGeneratedUtc      = (Get-Date).ToUniversalTime().ToString("s") + "Z"
}

Write-Verbose "Writing output to $fullPath"
$result | Export-Csv -Path $fullPath -NoTypeInformation -Encoding UTF8

Write-Host "Windows patch status report written to: $fullPath"
Write-Host "Computer: $computerName"
Write-Host "Pending reboot: $pendingReboot"
if ($missingCount -ne $null) {
    Write-Host "Missing updates: $missingCount (Critical: $criticalMissingCount, Security: $securityMissingCount)"
} else {
    Write-Host "Missing updates: Unknown (PSWindowsUpdate not installed)."
}
