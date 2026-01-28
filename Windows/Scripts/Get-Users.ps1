
<#
.SYNOPSIS
    Get a user and list the groups they are a member of (Domain or Local).
#>

function Get-TargetSID
{
    param(
        [string]$UserName,
        [ValidateSet("Domain","Local")]
        [string]$UserType,
        [string]$Domain = $env:USERDOMAIN
    )

    if ($UserType -eq 'Local')
    {
        $localUser = Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue
        if (-not $localUser)
        { throw "Local user '$UserName' not found." 
        }
        return $localUser.SID
    } else
    {
        $adUser = Get-ADUser -Identity $UserName -Server $Domain -Properties SID -ErrorAction SilentlyContinue
        if (-not $adUser)
        { throw "Domain user '$UserName' not found in domain '$Domain'." 
        }
        return $adUser.SID
    }
}

function Get-Groups
{
    param(
        [string]$UserName,
        [ValidateSet("Domain","Local")]
        [string]$UserType,
        [string]$Domain = $env:USERDOMAIN
    )

    try
    {
        $targetSid = Get-TargetSID -UserName $UserName -UserType $UserType -Domain $Domain
    } catch
    {
        Write-Error $_
        return @()
    }

    if ($UserType -eq 'Domain')
    {
        # Domain groups via AD
        try
        {
            $adGroups = Get-ADPrincipalGroupMembership -Identity $UserName -Server $Domain -ErrorAction Stop
            return $adGroups | Select-Object -ExpandProperty Name
        } catch
        {
            Write-Warning "Unable to enumerate domain groups for ${UserName}: ${_}"
            return @()
        }
    }

    # Local user: iterate local groups and match by SID (works for local and domain accounts that are local group members)
    $matched = @()
    foreach ($grp in Get-LocalGroup)
    {
        try
        {
            $members = Get-LocalGroupMember -Group $grp.Name -ErrorAction Stop
            foreach ($m in $members)
            {
                # Some members may not have SID property (rare)
                if ($m.PSObject.Properties.Match('SID').Count -gt 0)
                {
                    if ($m.SID -eq $targetSid)
                    {
                        $matched += $grp.Name
                        break
                    }
                } else
                {
                    $leaf = ($m.Name -split '\\')[-1]
                    if ($leaf -ieq $UserName)
                    {
                        $matched += $grp.Name
                        break
                    }
                }
            }
        } catch
        {
        }
    }

    return $matched
}

function Show-UserGroups
{
    param(
        [string]$UserName,
        [ValidateSet("Domain","Local")]
        [string]$UserType,
        [string]$Domain = $env:USERDOMAIN
    )

    Write-Host "User: $UserName"
    Write-Host "Type: $UserType"
    Write-Host "Groups:"

    $groups = Get-Groups -UserName $UserName -UserType $UserType -Domain $Domain

    if (-not $groups -or $groups.Count -eq 0)
    {
        Write-Host "  <no groups found or unable to enumerate groups>"
        return
    }

    foreach ($g in $groups)
    {
        Write-Host "- $g"
    }
}

$username = Read-Host "Enter the username"
$userType = Read-Host "Enter user type (Domain or Local)"

Show-UserGroups -UserName $username -UserType $userType
