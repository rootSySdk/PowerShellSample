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

function Add-DomainObjectAcl {

<#

    .SYNOPISIS

        This function add an ACE to the DACL of a target identity.

    .DESCRIPTION

        This function mount the ADSI path of the target object, craft a custom ACE, and add it with the method AddAccessRule().

    .PARAMETER TargetIdentities

        Specify the target to add an ACL on.

    .PARAMETER PrincipalIdentiy

        The reference identity to grant the access.

    .PARAMETER Access

        The type of AccessMask to place in the ACE.

    .PARAMETER Domain

        Specifies the domain name to query for, defaults to the current domain.

    .PARAMETER Credential

        Alternate PSCredential to use during research.

    .EXAMPLE

        Add-DomainObjectAcl -TargetIdentity Bobby -PrincipalIdentity Self -Access GenericAll
#>

    [OutputType([System.Boolean])]
    [CmdletBinding()]

    param (

        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("TargetIdentity")]
        [String[]]
        $TargetIdentities,

        [Parameter(Mandatory=$true, Position=1, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $PrincipalIdentity,

        [Parameter(Mandatory=$true, Position=2, ValueFromPipeline=$true)]
        [ValidateSet("GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "DCSync", "ForceChangePassword")]
        [String]
        $Access,

        [Parameter(Mandatory=$false, Position=3, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Parameter(Mandatory=$false, Position=4, ValueFromPipeline=$false)]
        [System.Management.Automation.CredentialAttribute()]
        [System.Management.Automation.PSCredential]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    BEGIN {

        $arguments = @{}

        if ($PSBoundParameters["Domain"]) {$arguments["Domain"] = $Domain}
        if ($PSBoundParameters["Credential"]) {$arguments["Credential"] = $Credential}

        $Principal = Get-DomainObject -Identities $PrincipalIdentity @arguments
        $Objects = Get-DomainObject -Identities $TargetIdentities @arguments
    }

    PROCESS {

        foreach ($Object in $Objects) {

            if ($PSBoundParameters["Credential"]) {

                $ADSIObject = New-Object System.DirectoryServices.DirectoryEntry($Object.Path, $Credential.GetNetworkCredential().UserName, $Credential.GetNetworkCredential().Password)
            } else {

                $ADSIObject = New-Object System.DirectoryServices.DirectoryEntry($Object.Path)
            }

            $ADSIObject.PSBase.Options.SecurityMasks = 'Dacl'

            if ($Access -eq "DCSync" -or $Access -eq "ForceChangePassword") {

                if ($Access -eq "DCSync") {
                    
                    # Get-Changes, Get-Changes-All, Get-Changes-All-In-Filtered-Set GUID for extendedRights 

                    $GUIDs = @("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2","1131f6ad-9c07-11d1-f79f-00c04fc2dcd2","89e95b76-444d-4c62-991a-0facbeda640c") 

                    foreach ($GUID in $GUIDs) {
                        
                        $FinalGUID = New-Object System.Guid($GUID)
                        $sid = [System.Security.Principal.SecurityIdentifier] $Principal.sid
                        $identity = [System.Security.Principal.IdentityReference] $SID
                        $adRights = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
                        $type = [System.Security.AccessControl.AccessControlType] "Allow"
                        $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"

                        $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($identity,$adRights,$type,$FinalGUID,$inheritanceType) 

                        $ADSIObject.PSBase.ObjectSecurity.AddAccessRule($ACE)
                    }
                } else {

                    $FinalGUID = New-Object System.Guid("00299570-246d-11d0-a768-00aa006e0529") # guid for ForceChangePassword
                    $sid = [System.Security.Principal.SecurityIdentifier] $Principal.sid
                    $identity = [System.Security.Principal.IdentityReference] $SID
                    $adRights = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
                    $type = [System.Security.AccessControl.AccessControlType] "Allow"
                    $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"

                    $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($identity,$adRights,$type,$FinalGUID,$inheritanceType) 

                    $ADSIObject.PSBase.ObjectSecurity.AddAccessRule($ACE)
                }
            } else {

                $sid = [System.Security.Principal.SecurityIdentifier] $Principal.sid
                $identity = [System.Security.Principal.IdentityReference] $SID
                $adRights = [System.DirectoryServices.ActiveDirectoryRights] $Access
                $type = [System.Security.AccessControl.AccessControlType] "Allow"
                $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"

                $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($identity,$adRights,$type,$inheritanceType)
                
                $ADSIObject.PSBase.ObjectSecurity.AddAccessRule($ACE)
            }

            try {
            
                
                $ADSIObject.PSBase.CommitChanges()

                $returnValue = $true
                Write-Verbose "[Add-DomainObjectAcl] ACE successfully added"
            } catch {

                $returnValue = $false
            }
        }
    }

    END {

        return $returnValue
    }
}