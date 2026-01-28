<#
.SYNOPSIS
    This script configures system security settings.
.DESCRIPTION
    The script allows administrators to set various security parameters on a Windows machine,
    This script is going to use Set-Acl and get-acl, created the script the so that i can understand System.Security.AccessControl better.

.PARAMETER Path
    The file or directory path to set access control on.

.PARAMETER Identity
    The user or group identity to set permissions for.
.PARAMETER AccessType
    The type of access control (Allow or Deny).

.PARAMETER Rights
    The specific rights to assign (e.g., Read, Write, FullControl) to the specified identity on a folder or file.
.EXAMPLE
    .\System_Security.ps1 -Path "C:\MyFolder" -Identity "DOMAIN\User" -AccessType "Allow" -Rights "Read"

.NOTES
 This script requires administrative privileges to run successfully.
 This script will also replace existing access rules for the specified identity on the target path and replace it with the new ones.
#>

function Set-AccessControl
{
    param (
        [Parameter(Mandatory=$true)]
        [string]$Path,

        [Parameter(Mandatory=$true)]
        [string]$Identity,

        [Parameter(Mandatory=$true)]
        [string]$AccessType,

        [Parameter(Mandatory=$true)]
        [string[]]$Rights
    )

    $RightsMap = @{
        "Read"          = [System.Security.AccessControl.FileSystemRights]::Read
        "Write"         = [System.Security.AccessControl.FileSystemRights]::Write
        "Modify"        = [System.Security.AccessControl.FileSystemRights]::Modify
        "FullControl"   = [System.Security.AccessControl.FileSystemRights]::FullControl
        "ReadAndExecute"= [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
        "ListDirectory" = [System.Security.AccessControl.FileSystemRights]::ListDirectory
        "ExecuteFile"   = [System.Security.AccessControl.FileSystemRights]::ExecuteFile
        "Traverse"      = [System.Security.AccessControl.FileSystemRights]::Traverse
    }

    $AccessTypeMap = @{
        "Allow" = [System.Security.AccessControl.AccessControlType]::Allow
        "Deny"  = [System.Security.AccessControl.AccessControlType]::Deny
    }


    $NetRights = 0
    $ErrorRights = @()

    foreach ($right in $Rights)
    {
        $StripRight = $right.Trim()

        if ($RightsMap.ContainsKey($StripRight))
        {
            $NetRights = $NetRights -bor $RightsMap[$StripRight]
        } else
        {
            $ErrorRights += $right
        }
    }

    if ($ErrorRights.Count -gt 0)
    {
        Write-Error "The following Rights are invalid: $($ErrorRights -join ', '). Valid options are: $($RightsMap.Keys -join ', ')"
        return
    }

    if (-not $AccessTypeMap.ContainsKey($AccessType))
    {
        Write-Error "Invalid Access Type specified: '$AccessType'. Must be 'Allow' or 'Deny'"
        return
    }
    $NetAccessType = $AccessTypeMap[$AccessType]

    $Inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $Propagation = [System.Security.AccessControl.PropagationFlags]::None

    try
    {
        if (-not (Test-Path -Path $Path))
        {
            Write-Error "Path does not exist: $Path"
            return
        }

        Write-Host "Setting access control on $Path for $Identity with $Rights rights as $AccessType"
        $acl = Get-Acl -Path $Path

        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $Identity,
            $NetRights,
            $Inheritance,
            $Propagation,
            $NetAccessType
        )

        $acl.SetAccessRule($accessRule)

        Set-Acl -Path $Path -AclObject $acl
        Write-Host "Access control set successfully on $Path for $Identity"

    } catch
    {
        Write-Error "Failed to set access control on '$Path': $($_.Exception.Message)"
    }
}

function Show-Help
{
    Write-Host "Usage: .\System_Security.ps1 -SettingName <Name> -SettingValue <Value>"
    Write-Host "Example: .\System_Security.ps1 -SettingName 'EnableFirewall' -SettingValue 'True'"
}

$TargetPath = Read-Host -Prompt "Enter the target file or directory path"
$User = Read-Host -Prompt "Enter the user or group identity (e.g., 'DOMAIN\User' or 'BUILTIN\Administrators')"
$SelectedRightsInput = Read-Host -Prompt "Enter the rights to assign (comma-separated, e.g., Read, Write, FullControl)"
$SelectedAccessType = Read-Host -Prompt "Selected Access Type (e.g., Allow or Deny)"

$SelectedRights = $SelectedRightsInput -split ',' | ForEach-Object { $_.Trim() }

Set-AccessControl -Path $TargetPath -Identity $User -AccessType $SelectedAccessType -Rights $SelectedRights
