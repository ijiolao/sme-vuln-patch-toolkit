<#
.SYNOPSIS
    One-click orchestrator for the Vulnerability & Patch Readiness toolkit.

.DESCRIPTION
    This script is a simple control panel for SMEs to run the Windows-focused
    components of the vulnerability & patch suite.

    It performs:
      1. Patch status scan (local or remote)
      2. Patch status report generation (Markdown + HTML)
      3. Top 10 missing patches (local)
      4. Security features check (ASLR, DEP, SMB signing, RDP)

    Output is written into a timestamped folder under .\reports\YYYY-MM-DD_HHmmss\

.PARAMETER ComputerName
    One or more computers for remote scanning.
    Defaults to the local machine.

.PARAMETER Credential
    Optional credential for remote queries.

.PARAMETER OutputRoot
    Root folder for storing run results.

.PARAMETER SkipPatchStatus
    Skip Windows patch status scanning.

.PARAMETER SkipPatchReports
    Skip generating patch status reports.

.PARAMETER SkipTop10
    Skip Top 10 missing patches.

.PARAMETER SkipSecurityFeatures
    Skip ASLR/DEP/SMB/RDP checks.

.EXAMPLE
    .\un_vuln_patch_suite.ps1

.EXAMPLE
    $cred = Get-Credential
    .\un_vuln_patch_suite.ps1 -ComputerName SERVER01,SERVER02 -Credential $cred

#>

[CmdletBinding()]
param(
    [string[]] $ComputerName = $env:COMPUTERNAME,
    [System.Management.Automation.PSCredential] $Credential,
    [string] $OutputRoot = ".\reports",

    [switch] $SkipPatchStatus,
    [switch] $SkipPatchReports,
    [switch] $SkipTop10,
    [switch] $SkipSecurityFeatures
)

$ErrorActionPreference = "Stop"

function Get-ScriptPath {
    if ($PSCommandPath) { return $PSCommandPath }
    elseif ($MyInvocation.MyCommand.Path) { return $MyInvocation.MyCommand.Path }
    else { throw "Unable to determine script location." }
}

$scriptDir = Split-Path -Parent (Get-ScriptPath)

# Child scripts
$windowsPatchStatusScript  = Join-Path $scriptDir "windows_patch_status.ps1"
$windowsPatchReportScript  = Join-Path $scriptDir "windows_patch_status_report.ps1"
$top10MissingPatchesScript = Join-Path $scriptDir "top10_missing_patches.ps1"
$securityFeaturesScript    = Join-Path $scriptDir "security_features_check.ps1"

# Output paths
$timestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
$runRoot   = Join-Path (Resolve-Path $OutputRoot) $timestamp

Write-Host "=== Vulnerability & Patch Suite Orchestrator ==="
Write-Host "Run folder : $runRoot"
Write-Host "Targets    : $($ComputerName -join ', ')"
Write-Host ""

New-Item -Path $runRoot -ItemType Directory -Force | Out-Null

# Credential splatting
$credSplat = @{}
if ($PSBoundParameters.ContainsKey("Credential") -and $Credential) {
    $credSplat.Credential = $Credential
}

# ----------------------------
# 1. PATCH STATUS SCAN
# ----------------------------
$patchStatusCsv          = Join-Path $runRoot "windows_patch_status_all.csv"
$patchStatusReportMdPath = Join-Path $runRoot "windows_patch_status_report.md"
$patchStatusReportHtml   = Join-Path $runRoot "windows_patch_status_report.html"

if (-not $SkipPatchStatus) {
    Write-Host "[1/4] Running Windows patch status scan..."

    if (-not (Test-Path $windowsPatchStatusScript)) {
        Write-Warning "Script not found: windows_patch_status.ps1"
    }
    else {
        $splat = @{
            ComputerName = $ComputerName
            OutputPath   = $patchStatusCsv
        }
        if ($credSplat.Credential) { $splat.Credential = $credSplat.Credential }

        try {
            & $windowsPatchStatusScript @splat
        }
        catch {
            Write-Warning "Patch status scan failed: $_"
        }
    }
}
else {
    Write-Host "[1/4] Skipped."
}

# ----------------------------
# 2. PATCH STATUS REPORTS
# ----------------------------
if (-not $SkipPatchReports) {
    Write-Host "[2/4] Generating patch status reports..."

    if (-not (Test-Path $windowsPatchReportScript)) {
        Write-Warning "Script not found: windows_patch_status_report.ps1"
    }
    elseif (-not (Test-Path $patchStatusCsv)) {
        Write-Warning "Missing patch status CSV, cannot generate report."
    }
    else {
        try {
            & $windowsPatchReportScript `
                -InputPath $patchStatusCsv `
                -MarkdownOutputPath $patchStatusReportMdPath `
                -HtmlOutputPath $patchStatusReportHtml
        }
        catch {
            Write-Warning "Patch report generation failed: $_"
        }
    }
}
else {
    Write-Host "[2/4] Skipped."
}

# ----------------------------
# 3. TOP 10 MISSING PATCHES (LOCAL)
# ----------------------------
$top10Csv = Join-Path $runRoot "top10_missing_patches_local.csv"

if (-not $SkipTop10) {
    Write-Host "[3/4] Running Top 10 missing patches..."

    if (-not (Test-Path $top10MissingPatchesScript)) {
        Write-Warning "Script not found: top10_missing_patches.ps1"
    }
    else {
        try {
            & $top10MissingPatchesScript -OutputPath $top10Csv
        }
        catch {
            Write-Warning "Top 10 missing patches failed: $_"
        }
    }
}
else {
    Write-Host "[3/4] Skipped."
}

# ----------------------------
# 4. SECURITY FEATURES CHECK
# ----------------------------
$securityFeaturesCsv = Join-Path $runRoot "security_features_check_all.csv"

if (-not $SkipSecurityFeatures) {
    Write-Host "[4/4] Running security features check..."

    if (-not (Test-Path $securityFeaturesScript)) {
        Write-Warning "Script not found: security_features_check.ps1"
    }
    else {
        $splatSec = @{
            ComputerName = $ComputerName
            OutputPath   = $securityFeaturesCsv
        }
        if ($credSplat.Credential) { $splatSec.CredCredential = $credSplat.Credential }

        try {
            & $securityFeaturesScript @splatSec
        }
        catch {
            Write-Warning "Security features check failed: $_"
        }
    }
}
else {
    Write-Host "[4/4] Skipped."
}

Write-Host ""
Write-Host "=== Run Completed ==="
Write-Host "Output folder: $runRoot"
Write-Host ""
