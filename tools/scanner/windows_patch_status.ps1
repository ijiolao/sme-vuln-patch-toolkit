<#
.SYNOPSIS
    Collects Windows patch status for one or more machines: OS version, missing updates, and pending reboot state.

.DESCRIPTION
    This script is intended for SMEs as part of a vulnerability & patch management toolkit.
    It can run:
      - Locally on the current machine, or
      - Remotely against one or more targets using PowerShell remoting (Invoke-Command).

    For each target, it gathers:
      - Basic OS information (caption, version, build)
      - Count of missing updates (using PSWindowsUpdate if available on the target)
      - Pending reboot status (based on common Windows indicators)

    Output:
      - A CSV file summarising patch status for each target machine.

.PARAMETER ComputerName
    One or more computer names to query. Defaults to the local machine if not specified.

.PARAMETER Credential
    Optional credentials to use for remote connections.

.PARAMETER OutputPath
    Path to the CSV report to write. If the folder does not exist, it will be created.

.EXAMPLE
    # Local only
    .\windows_patch_status.ps1

.EXAMPLE
    # Multiple remote servers, with explicit output path
    .\windows_patch_status.ps1 -ComputerName "SERVER1","SERVER2" -OutputPath .\reports\patch_status.csv

.EXAMPLE
    # Use alternate credentials for remote servers
    $cred = Get-Credential
    .\windows_patch_status.ps1 -ComputerName "SERVER1","SERVER2" -Credential $cred
#>

[CmdletBinding()]
param(
    [string[]]
    $ComputerName = $env:COMPUTERNAME,

    [Parameter()]
    [System.Management.Automation.PSCredential]
    $Credential,

    [string]
    $OutputPath = ".\reports\windows_patch_status.csv"
)

function Test-PendingRebootLocal {
    <#
    .SYNOPSIS
        Checks common locations on the local machine to determine if a reboot is pending.
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

# ScriptBlock to be executed locally and remotely
$patchStatusScriptBlock = {
    param()

    function Test-PendingRebootInner {
        [CmdletBinding()]
        param()

        $isPending = $false

        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
        if (Test-Path $regPath) {
            $value = (Get-ItemProperty -Path $regPath -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue)
            if ($null -ne $value.PendingFileRenameOperations) {
                $isPending = $true
            }
        }

        $wuPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
        if (Test-Path $wuPath) {
            $isPending = $true
        }

        $cbsPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
        if (Test-Path $cbsPath) {
            $isPending = $true
        }

        return $isPending
    }

    $computerName = $env:COMPUTERNAME

    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    } catch {
        Write-Warning "[$computerName] Unable to get OS information: $_"
        $os = $null
    }

    $osCaption    = if ($os) { $os.Caption } else { $null }
    $osVersion    = if ($os) { $os.Version } else { $null }
    $osBuild      = if ($os) { $os.BuildNumber } else { $null }
    $lastBoot     = if ($os) { $os.LastBootUpTime } else { $null }

    $pendingReboot = Test-PendingRebootInner

    # Defaults in case PSWindowsUpdate is not present
    $missingCount           = $null
    $criticalMissingCount   = $null
    $securityMissingCount   = $null
    $sampleUpdates          = $null
    $pswuNote               = $null

    try {
        Import-Module PSWindowsUpdate -ErrorAction SilentlyContinue | Out-Null
    } catch {
        Write-Verbose "[$computerName] PSWindowsUpdate module not available."
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
            Write-Warning "[$computerName] Error querying missing updates via PSWindowsUpdate: $_"
            $pswuNote = "PSWindowsUpdate installed but query failed. See console output."
        }
    } else {
        $pswuNote = "PSWindowsUpdate module not found on target. Missing update count not available."
    }

    [PSCustomObject]@{
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
}

# Collect results for all targets
$results = @()

foreach ($comp in $ComputerName) {
    if ([string]::IsNullOrWhiteSpace($comp)) { continue }

    # Normalise: if target is local host, run locally to avoid remoting overhead
    $isLocal =
        ($comp -eq ".") -or
        ($comp -eq "localhost") -or
        ($comp -ieq $env:COMPUTERNAME)

    if ($isLocal) {
        Write-Verbose "Collecting patch status locally for [$($env:COMPUTERNAME)]..."
        $result = & $patchStatusScriptBlock
        if ($result) { $results += $result }
    }
    else {
        Write-Verbose "Collecting patch status remotely for [$comp] using Invoke-Command..."

        try {
            if ($PSBoundParameters.ContainsKey("Credential") -and $null -ne $Credential) {
                $remoteResult = Invoke-Command -ComputerName $comp -Credential $Credential -ScriptBlock $patchStatusScriptBlock -ErrorAction Stop
            } else {
                $remoteResult = Invoke-Command -ComputerName $comp -ScriptBlock $patchStatusScriptBlock -ErrorAction Stop
            }

            if ($remoteResult) { $results += $remoteResult }
        } catch {
            Write-Warning "Failed to query patch status for [$comp]: $_"
            $results += [PSCustomObject]@{
                ComputerName            = $comp
                OSCaption               = $null
                OSVersion               = $null
                OSBuild                 = $null
                LastBootUpTime          = $null
                PendingReboot           = $null
                MissingUpdateCount      = $null
                CriticalMissingCount    = $null
                SecurityMissingCount    = $null
                SampleMissingUpdates    = $null
                PSWindowsUpdateNote     = "Failed to connect or execute script: $_"
                ReportGeneratedUtc      = (Get-Date).ToUniversalTime().ToString("s") + "Z"
            }
        }
    }
}

# Ensure target directory exists
$fullPath = [System.IO.Path]::GetFullPath($OutputPath)
$directory = [System.IO.Path]::GetDirectoryName($fullPath)
if (-not [string]::IsNullOrWhiteSpace($directory) -and -not (Test-Path $directory)) {
    Write-Verbose "Creating directory $directory"
    New-Item -Path $directory -ItemType Directory -Force | Out-Null
}

if ($results.Count -gt 0) {
    $results | Export-Csv -Path $fullPath -NoTypeInformation -Encoding UTF8
    Write-Host "Windows patch status report written to: $fullPath"
    foreach ($r in $results) {
        Write-Host "Computer: $($r.ComputerName)  Pending reboot: $($r.PendingReboot)  Missing updates: $($r.MissingUpdateCount)"
    }
} else {
    Write-Warning "No results collected. Check connectivity and parameters."
}
