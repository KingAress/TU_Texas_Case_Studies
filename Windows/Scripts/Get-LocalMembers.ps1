<#
.SYNOPSIS
    Retrieves local group members on a Windows machine.
.PARAMETER GroupName
    The name of the local group to retrieve members from.
    defaults to "Administrators" if not specified.
.PARAMETER IncludeDisabled
    Switch to include disabled user accounts in the results.
.PARAMETER OutputFormat
    Specifies the output format: "Table", "List", or "Json".
    defaults to "Table".
    #>

param (
    [string]$GroupName = "Administrators",
    [switch]$IncludeDisabled,
    [ValidateSet("Table", "List", "Json")]
    [string]$OutputFormat = "Table"
)

function Get-LocalGroupMembers
{
    param (
        [string ]$GroupName,
        [switch]$IncludeDisabled
    )
    try
    {
        $input = 'Enter Group Name (default is "Administrators") '
        $GroupName = Read-Host -Prompt $input
        $group = [ADSI]"WinNT://$env:COMPUTERNAME/$GroupName,group"
        $members = @()


        foreach ($member in $group.Invoke("Members"))
        {
            $obj = New-Object PSObject
            $obj | Add-Member -MemberType NoteProperty -Name "Name" -Value $member.GetType().InvokeMember("Name", 'GetProperty', $null, $member, $null)
            $obj | Add-Member -MemberType NoteProperty -Name "Class" -Value $member.GetType().InvokeMember("Class", 'GetProperty', $null, $member, $null)

            if ($obj.Class -eq "User")
            {
                $user = [ADSI]$member.Path
                $isDisabled = ($user.UserFlags.Value -band 0x2) -ne 0
                $obj | Add-Member -MemberType NoteProperty -Name "Disabled" -Value $isDisabled

                if (-not $IncludeDisabled.IsPresent -and $isDisabled)
                {
                    continue
                }
            }

            $members += $obj
        }

        switch ($OutputFormat)
        {
            "Table"
            { $members | Format-Table -AutoSize
            }
            "List"
            { $members | Format-List
            }
            "Json"
            { $members | ConvertTo-Json -Depth 3
            }
        }

    } catch
    {
        Show-Help
        Write-Error "An error occurred while retrieving local group members: $_"
    }
}

function  get-LocalUser
{
    param(
        [string] $user,
        [ValidateSet("Table", "List", "Json")]
        [string]$OutputFormat = "Table"
    )
    try
    {
        $input = 'Enter a user (e.g., "Administrator")'
        $user = Read-Host -Prompt $input
        $obj = New-Object PSObject
        $localUser = [ADSI]"WinNT://$env:COMPUTERNAME/$user,user"
        $obj | Add-Member -MemberType NoteProperty -Name "Name" -Value $localUser.Name
        $obj | Add-Member -MemberType NoteProperty -Name "FullName" -Value $localUser.FullName
        $obj | Add-Member -MemberType NoteProperty -Name "Description" -Value $localUser.Description
        $obj | Add-Member -MemberType NoteProperty -Name "Disabled" -Value ( ($localUser.UserFlags.Value -band 0x2) -ne 0 )
        $obj | Add-Member -MemberType NoteProperty -Name "PasswordExpired" -Value $localUser.PasswordExpired
        $obj | Add-Member -MemberType NoteProperty -Name "LastLogin" -Value $localUser.LastLogin
        Write-Host $localUser.LastLogin


        switch ($OutputFormat)
        {
            "Table"
            { $obj | Format-Table -AutoSize
            }
            "List"
            { $obj | Format-List
            }
            "Json"
            { $obj | ConvertTo-Json -Depth 3
            }
        }

    } catch
    {
        Show-Help
        Write-Error "An error occurred while retrieving local user: $_ "
    }

}



function Show-Help
{
    Write-Host "Usage: .\Get-LocalMembers.ps1 [-GroupName <string>] [-IncludeDisabled] [-OutputFormat <Table|List|Json>]"
    Write-Host ""
    Write-Host "Parameters:"
    Write-Host "  -GroupName        The name of the local group to retrieve members from. Default is 'Administrators'."
    Write-Host "  -IncludeDisabled  Include disabled user accounts in the results."
    Write-Host "  -OutputFormat     Specifies the output format: 'Table', 'List', or 'Json'. Default is 'Table'."
}


get-LocalUser -user $user  -OutputFormat $OutputFormat
