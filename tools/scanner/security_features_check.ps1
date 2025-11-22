<#
.SYNOPSIS
    Checks key Windows security features on one or more machines:
    ASLR, DEP, SMB signing, and RDP / NLA state.

.DESCRIPTION
    This script is designed for SMEs as part of a security baseline / hardening toolkit.
    It can run:
      - Locally on the current machine, or
      - Remotely against one or more targets using PowerShell remoting (Invoke-Command).

    For each target, it collects the following high-level configuration signals:

      - ASLR (Address Space Layout Randomization) system mitigation state
      - DEP (Data Execution Prevention) system mitigation state
      - SMB signing requirements (client & server)
      - RDP (Remote Desktop) enabled/disabled
      - RDP Network Level Authentication (NLA) required or not

    Output:
      - A CSV with one row per computer summarising security feature states
      - Human-readable summary to the console

.PARAMETER ComputerName
    One or more computer names to query. Defaults to the local computer.

.PARAMETER Credential
    Optional credentials to use for remote connections.

.PARAMETER OutputPath
    Path to the CSV report to write. If the folder does not exist, it will be created.
    Default: .\reports\security_features_check.csv

.EXAMPLE
    # Local only
    .\security_features_check.ps1

.EXAMPLE
    # Multiple remote servers
    .\security_features_check.ps1 -ComputerName "SERVER1","SERVER2"

.EXAMPLE
    # With alternate credentials
    $cred = Get-Credential
    .\security_features_check.ps1 -ComputerName "SERVER1","SERVER2" -Credential $cred `
        -OutputPath .\reports\sec_features_all.csv
#>

[CmdletBinding()]
param(
    [string[]]
    $ComputerName = $env:COMPUTERNAME,

    [Parameter()]
    [System.Management.Automation.PSCredential]
    $Credential,

    [string]
    $OutputPath = ".\reports\security_features_check.csv"
)

$ErrorActionPreference = "Stop"

# Scriptblock to execute locally or remotely
$securityCheckScriptBlock = {
    param()

    function Get-ASLRAndDEPStateInner {
        [CmdletBinding()]
        param()

        $aslrEnabled  = $null
        $depEnabled   = $null
        $aslrDetails  = $null
        $depDetails   = $null
        $note         = $null

        if (Get-Command Get-ProcessMitigation -ErrorAction SilentlyContinue) {
            try {
                $mit = Get-ProcessMitigation -System

                if ($mit -and $mit.ASLR) {
                    $aslrEnabled = $false
                    if ($mit.ASLR.ForceRelocateImages -eq "ON" -or
                        $mit.ASLR.HighEntropy -eq "ON" -or
                        $mit.ASLR.BottomUp -eq "ON") {
                        $aslrEnabled = $true
                    }
                    $aslrDetails = $mit.ASLR | Out-String
                } else {
                    $note = "Get-ProcessMitigation returned no ASLR data."
                }

                if ($mit -and $mit.DEP) {
                    $depEnabled = $mit.DEP.Enable -eq "ON"
                    $depDetails = $mit.DEP | Out-String
                } else {
                    $note = ($note + " ") + "Get-ProcessMitigation returned no DEP data."
                }
            }
            catch {
                $note = "Get-ProcessMitigation failed: $($_.Exception.Message)"
            }
        }
        else {
            $note = "Get-ProcessMitigation is not available on this OS/PowerShell version."
        }

        [PSCustomObject]@{
            ASLR_Enabled   = $aslrEnabled
            DEP_Enabled    = $depEnabled
            ASLR_Details   = $aslrDetails
            DEP_Details    = $depDetails
            MitigationNote = $note
        }
    }

    function Get-SmbSigningStateInner {
        [CmdletBinding()]
        param()

        $serverKey = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
        $clientKey = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"

        $serverRequire = $null
        $serverEnable  = $null
        $clientRequire = $null
        $clientEnable  = $null

        if (Test-Path $serverKey) {
            $srv = Get-ItemProperty -Path $serverKey -ErrorAction SilentlyContinue
            if ($srv) {
                $serverRequire = $srv.RequireSecuritySignature
                $serverEnable  = $srv.EnableSecuritySignature
            }
        }

        if (Test-Path $clientKey) {
            $cli = Get-ItemProperty -Path $clientKey -ErrorAction SilentlyContinue
            if ($cli) {
                $clientRequire = $cli.RequireSecuritySignature
                $clientEnable  = $cli.EnableSecuritySignature
            }
        }

        $srvReqBool = if ($null -ne $serverRequire) { [bool]([int]$serverRequire) } else { $null }
        $srvEnBool  = if ($null -ne $serverEnable)  { [bool]([int]$serverEnable) }  else { $null }
        $cliReqBool = if ($null -ne $clientRequire) { [bool]([int]$clientRequire) } else { $null }
        $cliEnBool  = if ($null -ne $clientEnable)  { [bool]([int]$clientEnable) }  else { $null }

        [PSCustomObject]@{
            SMB_Server_RequireSigning = $srvReqBool
            SMB_Server_EnableSigning  = $srvEnBool
            SMB_Client_RequireSigning = $cliReqBool
            SMB_Client_EnableSigning  = $cliEnBool
        }
    }

    function Get-RdpStateInner {
        [CmdletBinding()]
        param()

        $rdpKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
        $nlaKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"

        $rdpEnabled  = $null
        $nlaRequired = $null

        if (Test-Path $rdpKey) {
            $ts = Get-ItemProperty -Path $rdpKey -ErrorAction SilentlyContinue
            if ($ts -and ($ts.PSObject.Properties.Name -contains "fDenyTSConnections")) {
                $rdpEnabled = ([int]$ts.fDenyTSConnections -eq 0)
            }
        }

        if (Test-Path $nlaKey) {
            $nla = Get-ItemProperty -Path $nlaKey -ErrorAction SilentlyContinue
            if ($nla -and ($nla.PSObject.Properties.Name -contains "UserAuthentication")) {
                $nlaRequired = ([int]$nla.UserAuthentication -eq 1)
            }
        }

        [PSCustomObject]@{
            RDP_Enabled      = $rdpEnabled
            RDP_NLA_Required = $nlaRequired
        }
    }

    $mitigation = Get-ASLRAndDEPStateInner
    $smb        = Get-SmbSigningStateInner
    $rdp        = Get-RdpStateInner

    [PSCustomObject]@{
        ComputerName              = $env:COMPUTERNAME

        ASLR_Enabled              = $mitigation.ASLR_Enabled
        DEP_Enabled               = $mitigation.DEP_Enabled
        ASLR_Details              = $mitigation.ASLR_Details
        DEP_Details               = $mitigation.DEP_Details
        MitigationNote            = $mitigation.MitigationNote

        SMB_Server_RequireSigning = $smb.SMB_Server_RequireSigning
        SMB_Server_EnableSigning  = $smb.SMB_Server_EnableSigning
        SMB_Client_RequireSigning = $smb.SMB_Client_RequireSigning
        SMB_Client_EnableSigning  = $smb.SMB_Client_EnableSigning

        RDP_Enabled               = $rdp.RDP_Enabled
        RDP_NLA_Required          = $rdp.RDP_NLA_Required

        ReportGeneratedUtc        = (Get-Date).ToUniversalTime().ToString("s") + "Z"
    }
}

Write-Verbose "Collecting security feature state..."

$results = @()

foreach ($comp in $ComputerName) {
    if ([string]::IsNullOrWhiteSpace($comp)) { continue }

    $isLocal =
        ($comp -eq ".") -or
        ($comp -eq "localhost") -or
        ($comp -ieq $env:COMPUTERNAME)

    if ($isLocal) {
        Write-Verbose "Running security feature check locally on [$($env:COMPUTERNAME)]..."
        try {
            $res = & $securityCheckScriptBlock
            if ($res) { $results += $res }
        } catch {
            Write-Warning "Failed to collect security features for local host: $_"
        }
    }
    else {
        Write-Verbose "Running security feature check remotely on [$comp] via Invoke-Command..."
        try {
            if ($PSBoundParameters.ContainsKey("Credential") -and $null -ne $Credential) {
                $remoteRes = Invoke-Command -ComputerName $comp -Credential $Credential -ScriptBlock $securityCheckScriptBlock -ErrorAction Stop
            } else {
                $remoteRes = Invoke-Command -ComputerName $comp -ScriptBlock $securityCheckScriptBlock -ErrorAction Stop
            }
            if ($remoteRes) { $results += $remoteRes }
        } catch {
            Write-Warning "Failed to collect security features for [$comp]: $_"
            $results += [PSCustomObject]@{
                ComputerName              = $comp
                ASLR_Enabled              = $null
                DEP_Enabled               = $null
                ASLR_Details              = $null
                DEP_Details               = $null
                MitigationNote            = "Error: $($_.Exception.Message)"

                SMB_Server_RequireSigning = $null
                SMB_Server_EnableSigning  = $null
                SMB_Client_RequireSigning = $null
                SMB_Client_EnableSigning  = $null

                RDP_Enabled               = $null
                RDP_NLA_Required          = $null

                ReportGeneratedUtc        = (Get-Date).ToUniversalTime().ToString("s") + "Z"
            }
        }
    }
}

# Ensure output directory exists
$fullPath  = [System.IO.Path]::GetFullPath($OutputPath)
$directory = [System.IO.Path]::GetDirectoryName($fullPath)
if (-not [string]::IsNullOrWhiteSpace($directory) -and -not (Test-Path $directory)) {
    New-Item -Path $directory -ItemType Directory -Force | Out-Null
}

if ($results.Count -gt 0) {
    $results | Export-Csv -Path $fullPath -NoTypeInformation -Encoding UTF8

    Write-Host "Security features check report written to: $fullPath"
    Write-Host ""
    foreach ($r in $results) {
        Write-Host "Summary for $($r.ComputerName):"
        Write-Host ("- ASLR Enabled:               {0}" -f $r.ASLR_Enabled)
        Write-Host ("- DEP Enabled:                {0}" -f $r.DEP_Enabled)
        Write-Host ("- SMB Server Require Signing: {0}" -f $r.SMB_Server_RequireSigning)
        Write-Host ("- SMB Client Require Signing: {0}" -f $r.SMB_Client_RequireSigning)
        Write-Host ("- RDP Enabled:                {0}" -f $r.RDP_Enabled)
        Write-Host ("- RDP NLA Required:           {0}" -f $r.RDP_NLA_Required)
        Write-Host ""
    }
} else {
    Write-Warning "No results collected. Check connectivity and parameters."
}
