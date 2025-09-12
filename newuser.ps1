$param1=$args[0]

Write-OutPut "Loading users from file $param1"

#Enter a path to your import CSV file
$ADUsers = Import-csv $param1

foreach ($User in $ADUsers) 
{

       $Username      = $User.username
       $Password      = $User.password
       $Firstname     = $User.firstname
       $Lastname      = $User.lastname
       $Department    = $User.department
       $OU            = $User.ou
       $EmailAddress  = $User.EmailAddress

       #Check if the user account already exists in AD
       if (Get-ADUser -F {SamAccountName -eq $Username})
       {
               #If user does exist, output a warning message
               Write-Warning "A user account $Username has already exist in Active Directory."
       }
       else
       {
       #If a user does not exist then create a new user account
       #Account will be created in the OU listed in the $OU variable in the CSV file; don’t forget to change the domain name in the"-UserPrincipalName" variable
              New-ADUser `
            -SamAccountName $Username `
            -UserPrincipalName "$Username@modernworkplace.hu" `
            -Name "$Firstname $Lastname ($Department)" `
            -GivenName $Firstname `
            -Surname $Lastname `
            -EmailAddress $EmailAddress `
            -Enabled $True `
            -ChangePasswordAtLogon $False `
            -DisplayName "$Lastname, $Firstname ($Department)" `
            -Department $Department `
            -Path $OU `
            -AccountPassword (convertto-securestring $Password -AsPlainText -Force)
            Write-OutPut "A user account $Username has created in Active Directory."
       }
}