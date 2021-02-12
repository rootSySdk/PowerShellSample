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

function Get-DomainObject {

<#

    .SYNOPISIS

        The purpose of this function is to search for a specific AD object given with the parameter -Identities

    .DESCRIPTION

        This function create a LDAP filter from the object identity given, then it searches with Invoke-DomainSearcher
        the object and return a PSCustomObject where some of the properties are stored.

    .PARAMETER Identities

        Target identity/Identities to search for in the AD.

    .PARAMETER Domain

        Specifies the domain name to query for, defaults to the current domain.

    .PARAMETER Credential

        Alternate PSCredential to use during research.

    .EXAMPLE

        Get-DomainObject -Identity Bobby


#>

    [OutputType([System.Management.Automation.PSCustomObject[]])]
    [CmdletBinding()]

    param (

        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("Identity")]
        [String[]]
        $Identities,

        [Parameter(Mandatory=$false, Position=1, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Parameter(Mandatory=$false, Position=2, ValueFromPipeline=$false)]
        [System.Management.Automation.CredentialAttribute()]
        [System.Management.Automation.PSCredential]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    BEGIN {

        $arguments = @{}

        if ($PSBoundParameters["Domain"]) {$arguments["Domain"] = $Domain}
        if ($PSBoundParameters["Credential"]) {$arguments["Credential"] = $Credential}
        
        $filter = @("(|")
        $output = @()
    }

    PROCESS {

        foreach ($Identity in $Identities) {

            if ($Identity.Contains("LDAP://") -and $Identity.Contains("DC=")) {

                 $filter += "(distinguishedName=$($Identity.Replace("LDAP://")))"
            } elseif ($Identity.Contains("DC=")) {

                $filter += "(distinguishedName=$Identity)"
            } elseif ($Identity.Split("-").Count -eq 8) {
                
                $filter += "(objectSid=$Identity)"
            } elseif ($Identity.Split(".") -ge 3) {

                $filter += "(dnshostname=$Identity)"
            } else {

                $filter += "(|(samAccountName=$Identity)(name=$Identity)(cn=$Identity))"
            }
        }

        $finalFilter = (-join $filter) + ")"

        $results = Invoke-DomainSearcher -Filter $finalFilter @arguments

        foreach ($result in $results) {

            $psObject = New-Object System.Management.Automation.PSObject -Property @{

               "path" = $result.Properties.adspath -as [String];
               "useraccountcontrol" = $result.Properties.useraccountcontrol -as [String];
               "name" = $result.Properties.name -as [String];
               "objectclass" = $result.Properties.objectclass -as [String];
               "samaccounttype" = $result.Properties.samaccounttype -as [String];
               "samaccountname" = $result.samaccountname -as [String];
               "cn" = $result.cn -as [String];
               "whencreated" = $result.whencreated -as [String];
               "whenchanged" = $result.whenchanged -as [String];
               "lastlogon" = $result.lastlogon -as [String];
               "lastlogoff" = $result.lastlogoff -as [String];
               "logoncount" = $result.logoncount -as [String];
               "sid" = (New-Object System.Security.Principal.SecurityIdentifier ($result.Properties.objectsid[0], 0)).Value;
            }

            $psObject.psObject.TypeNames.Insert(0, "PowerShellSample.Object")
            $output += $psObject
        }
    }

    END {

        return $output
    }
}

function Set-DomainObjectOwner {

<#

    .SYNOPISIS

        This function change the owner of an AD object.

    .DESCRIPTION

        This function mount ADSI path of the given object, searched with Get-DomainObject, and perform modification
        of the owner with the method SetOwner().

    .PARAMETER Identities

        Target identity/Identities to change the Owner.

    .PARAMETER OwnerIdentity

        The new owner identity to set.

    .PARAMETER Domain

        Specifies the domain name to query for, defaults to the current domain.

    .PARAMETER Credential

        Alternate PSCredential to use during research.

    .EXAMPLE

        Set-DomainObjectOwner -Identity Bobby -OwnerIdentity OurSelf

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
        $OwnerIdentity,

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

        $Objects = Get-DomainObject -Identities $Identity @arguments
        $OwberIdentity = Get-DomainObject -Identity $OwnerIdentity
    }

    PROCESS {

        foreach ($Object in $Objects) {
        
            $path = $Object.Path
            $domainName = ($path -split "," | Where-Object {$_ -like "DC=*"}) -join "." -replace ("DC=", "")

            if ($Credential) {

                $ADSIObject = New-Object System.DirectoryServices.DirectoryEntry($path, $Credential.GetNetworkCredential().UserName, $Credential.GetNetworkCredential().Password)

            } else {

                $ADSIObject = New-Object System.DirectoryServices.DirectoryEntry($path)
            }

            try {

                $IdentityReference = New-Object System.Security.Principal.NTAccount($domainName, $OwnerIdentity.SamAccountName)
                $ADSIObject.PSBase.ObjectSecurity.SetOwner($IdentityReference)
                $ADSIObject.CommitChanges()
                
                Write-Verbose "[Set-DomainObjectOwner] Object owner was successfully changed to $($OwnerIdentity.SamAccountName)"
                $returnValue = $true
            } catch {

                Write-Verbose "[Set-DomainObjectOwner] An error occured while changing ownership: $_"
                $returnValue = $false
            }
        }
    }

    END {

        return $returnValue
    }

}