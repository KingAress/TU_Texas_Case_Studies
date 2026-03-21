<#
.SYNOPSIS
    This script audits systems for misconfigurations of security settings.
.DESCRIPTION

.PARAMETER Path
    The file or directory path to set access control on.

.PARAMETER Identity
    The user or group identity to set permissions for.
.PARAMETER Rights
    The specific rights to assign (e.g., Read, Write, FullControl) to the specified identity on a folder or file.
.EXAMPLE
    .\System_Security.ps1 -Path "C:\MyFolder" -Identity "DOMAIN\User" -AccessType "Allow" -Rights "Read"

.NOTES
 This script requires administrative privileges to run successfully.
 This script will also replace existing access rules for the specified identity on the target path and replace it with the new ones.
#>

function Test-SMBv1Enabled {
  try {
    $feat = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
    return ($feat.State -eq 'Enabled' -or $feat.State -eq 'EnablePending')
  } catch {
    return $false
  }
}
