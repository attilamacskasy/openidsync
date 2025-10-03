# Lightweight orchestrator scaffolding for any-source -> canonical -> any-target

function ConvertTo-CanonicalUsers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)] [object[]] $InputRows,
        [Parameter()] [ValidateSet('Online','CSV','Keycloak','AWS','GCP','OCI')] [string] $Source
    )

    process {
        foreach ($r in $InputRows) {
            if ($Source -eq 'Online') {
                # Expect Graph user shape
                $id = [string]$r.Id
                $upn = [string]$r.UserPrincipalName
                $dn = [string]$r.DisplayName
                $given = [string]$r.GivenName
                $sn = [string]$r.Surname
                $mail = [string]$r.Mail
                $proxy = @()
                if ($r.ProxyAddresses) { $proxy = @([string[]]$r.ProxyAddresses) }
                New-CanonicalUser -Id $id -UserPrincipalName $upn -DisplayName $dn -GivenName $given -Surname $sn -Mail $mail -ProxyAddresses $proxy -Attributes @{} -Groups @()
            }
            elseif ($Source -eq 'CSV') {
                # Expect CSV columns from M365 export
                $upn = [string]$r.'User principal name'
                $mail = [string]$r.'Primary SMTP address'
                if (-not $mail) { $mail = $upn }
                $dn = [string]$r.'Display name'
                $given = [string]$r.'First name'
                $sn = [string]$r.'Last name'
                $proxy = @()
                if ($r.'Proxy addresses') { $proxy = @([string]$r.'Proxy addresses') }
                # Use UPN as Id when no stable id available
                New-CanonicalUser -Id $upn -UserPrincipalName $upn -DisplayName $dn -GivenName $given -Surname $sn -Mail $mail -ProxyAddresses $proxy -Attributes @{} -Groups @()
            }
            else {
                # Other providers to be implemented
                $id = [string]$r.Id
                $upn = [string]$r.UserPrincipalName
                if (-not $upn) { $upn = [string]$r.Mail }
                New-CanonicalUser -Id $id -UserPrincipalName $upn -DisplayName $r.DisplayName -GivenName $r.GivenName -Surname $r.Surname -Mail $r.Mail -ProxyAddresses @() -Attributes @{} -Groups @()
            }
        }
    }
}


