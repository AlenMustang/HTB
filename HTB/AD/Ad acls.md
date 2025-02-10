![[Pasted image 20241224101703.png]]

`Discretionary Access Control List` (`DACL`) - defines which security principals are granted or denied access to an object. DACLs are made up of ACEs that either allow or deny access.

`System Access Control Lists` (`SACL`) - allow administrators to log access attempts made to secured objects.



| `ForceChangePassword` | abused with Set-DomainUserPassword                           |
| --------------------- | ------------------------------------------------------------ |
| `Add Members`         | abused with Add-DomainGroupMember                            |
| `GenericAll`          | abused with Set-DomainUserPassword or Add-DomainGroupMember  |
| `WriteOwner`          | abused with Set-DomainObjectOwner                            |
| `WriteDACL`           | abused with Add-DomainObjectACL                              |
| `AllExtendedRights`   | abused with Set-DomainUserPassword or Add-DomainGroupMember` |
| `Addself`             | abused with Add-DomainGroupMember`                           |

## enumerating ACL

```powershell
foreach($line in [System.IO.File]::ReadLines("C:\Users\htb-student\Desktop\ad_users.txt")) {get-acl  "AD:\$(Get-ADUser $line)" | Select-Object Path -ExpandProperty Access | Where-Object {$_.IdentityReference -match 'INLANEFREIGHT\\wley'}}
```

```powershell
$sid= Convert-NameToSid <name>
Get-DomainObjectACL -Identity * | ? {$_.SecurityIdentifier -eq $sid}
```