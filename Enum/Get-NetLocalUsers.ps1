function Get-NetLocalUsers {

<#
    
    .SYNOPSIS

        Simple Cmdlet function that enumerate local user of a computer within a domain

    .DESCRIPTION

        It uses System.DirectoryServices.DirectoryEntry with WinNT in order to connect to remote system (or local)
        then list all users or specified ones, and return an array of PSCustomObject where users properties are stored

    .PARAMETER Identities

        User(s) to find

    .PARAMETER Properties

        Specific Property(ies) to return

    .PARAMETER ComputerName

        Target computer to list users, default = $env:COMPUTERNAME

    .PARAMETER Credential

        Alternate PSCredential to use

    .EXAMPLE

        Get-NetLocalUser -Verbose

    .EXAMPLE 

        Get-NetLocalUser -ComputerName DC01

    .EXAMPLE

        $pass = ConvertTo-SecureString -AsPlainText -Force "metallica123!"
        C:\PS>$cred = New-Object System.Management.Automation.PSCredential -ArgumentList "TESTLAB\bobby",$pass
        C:\PS>Get-NetLocalUser -Credential $cred

    .LINK
        
        https://www.lepide.com/how-to/list-all-user-accounts-on-a-windows-system-using-powershell.html

#>

    [OutputType([System.Object[]], [System.Management.Automation.PSCustomObject])]
    [CmdletBinding()]

    param (

        [Parameter(Mandatory=$false, Position=0, ValueFromPipeline=$true)]
        [Alias("Identity", "User", "Users")]
        [String[]]
        $Identities,

        [Parameter(Mandatory=$false, Position=1, ValueFromPipeline=$true)]
        [Alias("Property")]
        [String[]]
        $Properties,

        [Parameter(Mandatory=$false, Position=2, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerName = $env:COMPUTERNAME,

        [Parameter(Mandatory=$false, Position=3, ValueFromPipeline=$false)]
        [System.Management.Automation.CredentialAttribute()]
        [System.Management.Automation.PSCredential]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    PROCESS {

        try {

            if ($PSBoundParameters["Credential"]) {

                Write-Verbose "[Get-NetLocalUsers] Using alternate PSCredential"
                $ADSIObject = New-Object System.DirectoryServices.DirectoryEntry -ArgumentList "WinNT://$ComputerName", $Credential.GetNetworkCredential().UserName, $Credential.GetNetworkCredential().Password
            } else {

                $ADSIObject = New-Object System.DirectoryServices.DirectoryEntry -ArgumentList "WinNT://$ComputerName"
            }
        } catch {

            Write-Verbose "[Get-NetLocalUsers] Error while requesting $_"
            return
        }

        $ADSIUsers = ($ADSIObject.Children | Where-Object {$_.SchemaClassName -eq 'user'})
        $Users = @()
        
        foreach ($user in $ADSIUsers) {

            $psObject = New-Object System.Management.Automation.PSObject -Property @{

                "UserFlags" = $user.UserFlags -as [System.String];
                "MaxStorage" = $user.MaxStorage -as [System.String];
                "PasswordAge" = $user.PasswordAge -as [System.String];
                "PasswordExpired" = $user.PasswordExpired -as [System.String];
                "FullName" = $user.FullName -as [System.String];
                "Description" = $user.Description -as [System.String];
                "BadPasswordAttempts" = $user.BadPasswordAttempts -as [System.String];
                "HomeDirectory" = $user.HomeDirectory -as [System.String];
                "LoginScript" = $user.LoginScript -as [System.String];
                "Profile" = $user.Profile -as [System.String];
                "Parameters" = $user.Parameters -as [System.String];
                "PrimaryGroupID" = $user.PrimaryGroupID -as [System.String];
                "Name" = $user.Name -as [System.String];
                "MinPasswordLength" = $user.MinPasswordLength -as [System.String];
                "MaxPasswordAge" = $user.MaxPasswordAge -as [System.String];
                "MinPasswordAge" = $user.MinPasswordAge -as [System.String];
                "PasswordHistoryLength" = $user.PasswordHistoryLength -as [System.String];
                "AutoUnlockInterval" = $user.AutoUnlockInterval -as [System.String];
                "LockoutObservationInterval" = $user.LockoutObservationInterval -as [System.String];
                "MaxBadPasswordsAllowed" = $user.MaxBadPasswordsAllowed -as [System.String];
                "objectSid" = (New-Object System.Security.Principal.SecurityIdentifier ($user.objectSid[0],0)).Value -as [System.String];
                "AuthenticationType" = $user.AuthenticationType -as [System.String];
                "Children" = $user.Children -as [System.String];
                "Guid" = $user.Guid -as [System.String];
                "NativeGuid" = $user.NativeGuid -as [System.String];
                "Path" = $user.Path -as [System.String];
            }

            if ($PSBoundParameters["Identities"]) {

                foreach ($Identity in $Identities) {

                    if ($psObject.Name -like $Identity) {

                        $Users += $psObject
                    }
                }
            } else {

                $Users += $psObject
            }
        }
    }

    END {

        if ($PSBoundParameters["Properties"]) {

            return ($Users | Select-Object -Property $Properties | Format-List)
        } else {

            return $Users
        }
    }
}
