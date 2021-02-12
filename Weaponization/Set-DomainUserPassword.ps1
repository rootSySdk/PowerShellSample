#require -Version 2

function Get-Domain {

<#

    .SYNOPSIS

        Returns the domain object for the current (or specified) domain.

        Author: Will Schroeder (@harmj0y)  
        License: BSD 3-Clause  
        Required Dependencies: None  

    .DESCRIPTION

        Returns a System.DirectoryServices.ActiveDirectory.Domain object for the current
        domain or the domain specified with -Domain X.

    .PARAMETER Domain

        Specifies the domain name to query for, defaults to the current domain.

    .PARAMETER Credential

        A [System.Management.Automation.PSCredential] object of alternate credentials
        for connection to the target domain.

    .EXAMPLE

        Get-Domain -Domain testlab.local

    .EXAMPLE

        $SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
        $Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
        Get-Domain -Credential $Cred

    .LINK

        http://social.technet.microsoft.com/Forums/scriptcenter/en-US/0c5b3f83-e528-4d49-92a4-dee31f4b481c/finding-the-dn-of-the-the-domain-without-admodule-in-powershell?forum=ITCG

#>

    [OutputType([System.DirectoryServices.ActiveDirectory.Domain])]
    [CmdletBinding()]

    Param(

        [Parameter(Mandatory=$false, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Parameter(Mandatory=$false, Position=1, ValueFromPipeline=$true)]
        [System.Management.Automation.CredentialAttribute()]
        [System.Management.Automation.PSCredential]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    PROCESS {

        if ($PSBoundParameters['Credential']) {

            Write-Verbose '[Get-Domain] Using alternate credentials for Get-Domain'

            if ($PSBoundParameters['Domain']) {

                $TargetDomain = $Domain
            }
            else {

                # if no domain is supplied, extract the logon domain from the PSCredential passed
                $TargetDomain = $Credential.GetNetworkCredential().Domain
                if ($TargetDomain -ne "") {

                    Write-Verbose "[Get-Domain] Extracted domain '$TargetDomain' from -Credential"
                } else {

                    $TargetDomain = $env:USERDNSDOMAIN
                    Write-Verbose "[Get-Domain] Extracted domain '$TargetDomain' from environment variable"
                }
            }

            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $TargetDomain, $Credential.UserName, $Credential.GetNetworkCredential().Password)

            try {

                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            catch {

                Write-Verbose "[Get-Domain] The specified domain '$TargetDomain' does not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid: $_"
            }
        } elseif ($PSBoundParameters['Domain']) {

            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain)

            try {

                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            catch {

                Write-Verbose "[Get-Domain] The specified domain '$Domain' does not exist, could not be contacted, or there isn't an existing trust : $_"
            }
        } else {

            try {

                [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            }
            catch {

                Write-Verbose "[Get-Domain] Error retrieving the current domain: $_"
            }
        }
    }
}

function Invoke-DomainSearcher {

<#

    .SYNOPISIS

        The purpose of this function is to search for object withing the Active Directory using LDAP queries.

    .DESCRIPTION

        From a filter provided by the users with the parameter -Filter, an instance of the DirectorySearcher
        .NET class is created, raw object are returned.

    .PARAMETER Filter

        LDAP filter for research.

    .PARAMETER Domain

        Specifies the domain name to query for, defaults to the current domain.

    .PARAMETER Credential

        Alternate PSCredential to use during research.

    .EXAMPLE

        Invoke-DomainSearcher -Filter "(samAccountName=*bobby*)" # search for bobby user or groupe

#>

    [OutputType([System.DirectoryServices.SearchResultCollection])]
    [CmdletBinding()]

    Param (

        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Filter,

        [Parameter(Mandatory=$false, Position=1, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Parameter(Mandatory=$false, Position=3, ValueFromPipeline=$true)]
        [System.Management.Automation.CredentialAttribute()]
        [System.Management.Automation.PSCredential]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    BEGIN {

        $commonArgs = @{}
        if ($PSBoundParameters["Domain"]) {$commonArgs["Domain"] = $Domain}
        if ($PSBoundParameters["Credential"]) {$commonArgs["Credential"] = $Credential}

        $domainObj = Get-Domain @commonArgs
        $PDC = $domainObj.PdcRoleOwner.Name
    }

    PROCESS {

        try {

            $SearchString = "LDAP://"
            $SearchString += $PDC + "/"
            $DistinguishedName = "DC=$($domainObj.Name.Replace('.',	',DC='))"
            $SearchString += $DistinguishedName
            Write-Verbose "[Invoke-DomainSearcher] Search base: $SearchString"
            if ($PSBoundParameters['Credential']) {

                $Searcher = New-Object System.DirectoryServices.DirectorySearcher(New-Object System.DirectoryServices.DirectoryEntry $SearchString, $Credential.GetNetworkCredential().UserName, $Credential.GetNetworkCredential().Password)
            } else {

                $Searcher = New-Object System.DirectoryServices.DirectorySearcher(New-Object System.DirectoryServices.DirectoryEntry $SearchString)
            }
            $objDomain = New-Object System.DirectoryServices.DirectoryEntry
            $Searcher.SearchRoot = $objDomain
            $Searcher.Filter = $Filter
            $result = $Searcher.FindAll()
        } catch {

            Write-Verbose "[Invoke-DomainSearcher] Error while research $_"
        }
        
    }

    END {

        $Searcher.Dispose()

        return $result
    }
}

function Get-DomainUser {

<#

    .SYNOPSIS
    
        This function return a specific user object.

    .DESCRIPTION

        This function research given user by searching through LDAP.

    .PARAMETER UserIdentity

        Target identity/Identities to search for in the AD.

    .PARAMETER Domain

        Specifies the domain name to query for, defaults to the current domain.

    .PARAMETER Credential

        Alternate PSCredential to use during research.

    .EXAMPLE

        Get-DomainUser -Identity bobby

#>

    [OutputType([System.Object[]], [System.DirectoryServices.SearchRresult], [System.Management.Automation.PSCustomObject])]
    [OutputType('PowerShellSample.User')]
    [CmdletBinding()]

    param (

        [Parameter(Mandatory=$false, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("Identity")]
        [String]
        $UserIdentity,

        [Parameter(Mandatory=$false, Position=4, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        
        [Parameter(Mandatory=$false, Position=6, ValueFromPipeline=$true)]
        [Management.Automation.CredentialAttribute()]
        [Management.Automation.PSCredential]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    
    BEGIN {

        $arguments = @{}

        if ($PSBoundParameters["Domain"]) {$arguments["Domain"] = $Domain}
        if ($PSBoundParameters["Credential"]) {$arguments["Credential"] = $Credential}
    }

    PROCESS {

        if ($PSBoundParameters["UserIdentity"]) {

            if ($UserIdentity.Split("-").Count -eq 8) {

                $Filter = "(&(samAccountType=805306368)(objectSid=$UserIdentity))"
            } elseif ($UserIdentity.Contains("LDAP://")) {

                $Filter = "(&(samAccountType=805306368)(distinguishedName=$($UserIdentity.Replace('LDAP://', ''))))"
            } elseif ($UserIdentity.Contains(",") -and $UserIdentity.Contains("DC=")) {

                $Filter = "(&(samAccountType=805306368)(distinguishedName=$UserIdentity)$finalFilter)"
            } else {

                $Filter = "(&(samAccountType=805306368)(|(cn=$UserIdentity)(name=$UserIdentity)(samAccountName=$UserIdentity)))"
            }
        } else {

            $Filter = "(&(samAccountType=805306368))"
        }

        Write-Verbose "[Get-DomainUser] LDAP filter: $Filter"

        $results = Invoke-DomainSearcher @arguments -Filter $Filter

        $users = @()

        foreach ($result in $results) {

            $psObject = New-Object System.Management.Automation.PSObject -Property @{
            
                "logoncount" = $result.Properties.logoncount -as [System.String];
                "codepage" = $result.Properties.codepage -as [System.String];
                "objectcategory" = $result.Properties.objectcategory -as [System.String];
                "dscorepropagationdata" = $result.Properties.dscorepropagationdata -as [System.String];
                "usnchanged" = $result.Properties.usnchanged -as [System.String];
                "instancetype" = $result.Properties.instancetype -as [System.String];
                "name" = $result.Properties.name -as [System.String];
                "badpasswordtime" = $result.Properties.badpasswordtime -as [System.String];
                "pwdlastset" = $result.Properties.pwdlastset -as [System.String];
                "objectclass" = $result.Properties.objectclass ;
                "badpwdcount" = $result.Properties.badpwdcount -as [System.String];
                "samaccounttype" = $result.Properties.samaccounttype -as [System.String];
                "lastlogontimestamp" = $result.Properties.lastlogontimestamp -as [System.String];
                "usncreated" = $result.Properties.usncreated -as [System.String];
                "memberof" = $result.Properties.memberof ;
                "whencreated" = $result.Properties.whencreated -as [System.String];
                "adspath" = $result.Properties.adspath -as [System.String];
                "useraccountcontrol" = $result.Properties.useraccountcontrol -as [System.String];
                "cn" = $result.Properties.cn -as [System.String];
                "countrycode" = $result.Properties.countrycode -as [System.String];
                "primarygroupid" = $result.Properties.primarygroupid -as [System.String];
                "whenchanged" = $result.Properties.whenchanged -as [System.String];
                "lastlogon" = $result.Properties.lastlogon -as [System.String];
                "distinguishedname" = $result.Properties.distinguishedname -as [System.String];
                "samaccountname" = $result.Properties.samaccountname -as [System.String];
                "sid" = (New-Object System.Security.Principal.SecurityIdentifier ($result.Properties.objectsid[0], 0)).Value
                "lastlogoff" = $result.Properties.lastlogoff -as [System.String];
                "accountexpires" = $result.Properties.accountexpires -as [System.String]; 
            }

            $psObject.psObject.TypeNames.Insert(0, "PowerShellSample.User")
            $users += $psObject
        }
    }

    END {

        return $users
    }
}

function Set-DomainUserPassword {

<#

    .SYNOPISIS

        This function goal is to change a user's password via ADSI.

    .DESCRIPTION

        This function mount the ADSI path of a user provided by the parameter Identities, and invoke the method SetPassword().

    .PARAMETER Identities

        Target identity/identities to change the password.

    .PARAMETER AccountPassword

        The new password to set.

    .PARAMETER Domain

        Specifies the domain name to query for, defaults to the current domain.

    .PARAMETER Credential

        Alternate PSCredential to use during research.

    .EXAMPLE


#>

    [OutputType([System.Boolean])]
    [CmdletBinding()]

    param (

        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("Identity")]
        [String[]]
        $Identities,

        [Parameter(Mandatory=$true, Position=1, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $AccountPassword,

        [Parameter(Mandatory=$false, Position=2, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Parameter(Mandatory=$false, Position=3, ValueFromPipeline=$false)]
        [System.Management.Automation.CredentialAttribute()]
        [System.Management.Automation.PSCredential]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    BEGIN {

        $arguments = @{}

        if ($PSBoundParameters["Domain"]) {$arguments["Domain"] = $Domain}
        if ($PSBoundParameters["Credential"]) {$arguments["Credential"] = $Credential}

        $users = Get-DomainUser -UserIdentity $Identity @arguments
    }

    PROCESS {

        foreach ($user in $users) {

            if ($PSBoundParameters["Credential"]) {

                $ADSIObject = New-Object System.DirectoryServices.DirectoryEntry($user.adspath, $Credential.GetNetworkCredential().UserName, $Credential.GetNetworkCredential().Password)
            } else {

                $ADSIObject = New-Object System.DirectoryServices.DirectoryEntry($user.adspath)
            }

            try {

                $ADSIObject.PSBase.Invoke("SetPassword", $AccountPassword)
                $ADSIObject.CommitChanges()

                Write-Verbose "[Set-DomainUserPassword] Password change was a success"
                $returnValue = $true
            } catch {

                $returnValue = $false
            }
        }
    }

    END {

        return $returnValue
    }
}
