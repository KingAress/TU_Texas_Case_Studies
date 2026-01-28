
<#
.SYNOPSIS
    A PowerShell script to scan for common antivirus software on a Windows system.
.DESCRIPTION
    This script will check if Windows Defender is active and scan for other common antivirus software installations.
#>

function CheckIfWinDefenderActive {
    [CmdletBinding(DefaultParameterSetName='WinDefender')]
    param(
        [string]$ComputerName = $env:COMPUTERNAME
    )

    Write-Host "Checking if Windows Defender is Active..."
    Get-MpComputerStatus | Select-Object AMServiceEnabled, AntispywareEnabled, AntivirusEnabled
}

function DetectingThreats {
    [CmdletBinding(DefaultParameterSetName='QuickScan')]
    param(
        [ValidateSet("QuickScan", "FullScan", "CustomScan")]
        [string]$ScanType = "QuickScan",

        [string]$PathToScan = ""
    )

    Write-Host "Detecting Threats..."

    switch ($ScanType) {
        "QuickScan" {
            $scanResult = Start-MpScan -ScanType QuickScan
        }
        "FullScan" {
            $scanResult = Start-MpScan -ScanType FullScan
        }
        "CustomScan" {
            $scanResult = Start-MpScan -ScanType CustomScan -ScanPath $PathToScan
        }
    }

    return $scanResult
}

function ScanForAntivirusSoftware {
    $antivirusList = @(
        "Avast Antivirus",
        "AVG Antivirus",
        "Bitdefender Antivirus",
        "Kaspersky Anti-Virus",
        "Norton AntiVirus",
        "McAfee Total Protection",
        "ESET NOD32 Antivirus",
        "Trend Micro Maximum Security",
        "Sophos Home",
        "Webroot SecureAnywhere"
    )

    $foundAntivirus = @()

    foreach ($av in $antivirusList) {
        $installedSoftware = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*$av*" }
        if ($installedSoftware) {
            $foundAntivirus += $installedSoftware.Name
        }
    }

    return $foundAntivirus
}

#This function requires administrative privileges to run successfully. This will disable real-time protection in Windows Defender.
# Realtime protect does automatically turn back on after a short period of time.
# TemperProtect is something that you would want to disable if you are running certain scripts or applications that may be flagged as malicious by Windows Defender.
# But you cant disable TemperProtect via PowerShell, only RealTimeProtection.
function disableRealTimeProtection{
   $user = [System.Security.Principal.WindowsIdentity]::GetCurrent()
   $principal = New-Object System.Security.Principal.WindowsPrincipal($user)
  if ($principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
       Set-MpPreference -DisableRealtimeMonitoring $true
       Write-Host "Real-time protection has been disabled."
   } else {
       Write-Host "This script must be run as an administrator to disable real-time protection."
   }
}

function Show-Help {
    Write-Host "Usage: .\Anti-Virus.ps1"
    Write-Host "This script checks Windows Defender status, detects threats, and scans for other antivirus software."
    Write-Host ""
    Write-Host "Functions:"
    Write-Host "  CheckIfWinDefenderActive - Checks if Windows Defender is active."
    Write-Host "  DetectingThreats - Scans for threats using Windows Defender."
    Write-Host "  ScanForAntivirusSoftware - Scans for common antivirus software installations."
}


Show-Help
Write-Host "Checking Windows Defender Status..."
$defenderStatus = CheckIfWinDefenderActive

Write-Host "`nWindows Defender Status:"
$defenderStatus | Format-List

$threats = DetectingThreats
if ($threats) {
    Write-Host "`nDetected Threats:"
    $threats | Format-Table -AutoSize
} else {
    Write-Host "`nNo threats detected."
}

Read-Host "`nWhat option would you like to do for scanning threats? (QuickScan, FullScan, CustomScan)"
$scanOption = Read-Host "Enter your choice"
if ($scanOption -eq "CustomScan") {
    $pathToScan = Read-Host "Enter the path to scan"
    DetectingThreats -ScanType $scanOption -PathToScan $pathToScan
} else {
    DetectingThreats -ScanType $scanOption
}


Write-Host "`nScanning for other Antivirus Software..."
$antivirusSoftware = ScanForAntivirusSoftware

if ($antivirusSoftware.Count -gt 0) {
    Write-Host "Found the following Antivirus Software:"
    $antivirusSoftware | ForEach-Object { Write-Host "- $_" }
} else {
    Write-Host "No additional Antivirus Software found."
}
