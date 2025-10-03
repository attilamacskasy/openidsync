# Canonical contracts for OpenIDSync
# PowerShell 5.1 compatible; avoid classes to keep PSv3+ compatibility if needed

function New-CanonicalUser {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Id,              # Stable source identifier (e.g., ObjectId, immutableId, or email)
        [Parameter(Mandatory)] [string] $UserPrincipalName,
        [Parameter()] [string] $DisplayName,
        [Parameter()] [string] $GivenName,
        [Parameter()] [string] $Surname,
        [Parameter()] [string] $Mail,
        [Parameter()] [string[]] $ProxyAddresses,
        [Parameter()] [hashtable] $Attributes,           # Extra attributes (extensible)
        [Parameter()] [string[]] $Groups                  # Canonical group ids this user belongs to
    )

    $obj = [ordered]@{
        Kind = 'User'
        Id = $Id
        UserPrincipalName = $UserPrincipalName
        DisplayName = $DisplayName
        GivenName = $GivenName
        Surname = $Surname
        Mail = $Mail
        ProxyAddresses = $ProxyAddresses
        Attributes = $Attributes
        Groups = $Groups
    }
    [pscustomobject]$obj
}

function New-CanonicalGroup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Id,            # Stable source identifier
        [Parameter(Mandatory)] [string] $DisplayName,
        [Parameter()] [string] $MailNickname,
        [Parameter()] [string] $Description,
        [Parameter()] [bool] $SecurityEnabled,
        [Parameter()] [bool] $MailEnabled,
        [Parameter()] [string] $GroupType               # e.g., 'Unified', 'Security', 'Distribution'
    )

    $obj = [ordered]@{
        Kind = 'Group'
        Id = $Id
        DisplayName = $DisplayName
        MailNickname = $MailNickname
        Description = $Description
        SecurityEnabled = $SecurityEnabled
        MailEnabled = $MailEnabled
        GroupType = $GroupType
    }
    [pscustomobject]$obj
}


