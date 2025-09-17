# All installed Microsoft.Graph modules (and submodules)
Get-Module -ListAvailable |
  Where-Object Name -like 'Microsoft.Graph*' |
  Sort-Object Name |
  Format-Table Name, Version, Path -Auto
