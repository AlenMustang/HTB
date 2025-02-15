### 

**Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### 

[](https://book.hacktricks.xyz/windows-hardening/checklist-windows-privilege-escalation#system-info)

[System Info](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#system-info)

- [ ] Obtain [**System information**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#system-info)
    
- [ ] Search for **kernel** [**exploits using scripts**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#version-exploits)
    
- [ ] Use **Google to search** for kernel **exploits**
    
- [ ] Use **searchsploit to search** for kernel **exploits**
    
- [ ] Interesting info in [**env vars**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#environment)?
    
- [ ] Passwords in [**PowerShell history**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#powershell-history)?
    
- [ ] Interesting info in [**Internet settings**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#internet-settings)?
    
- [ ] [**Drives**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#drives)?
    
- [ ] [**WSUS exploit**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#wsus)?
    
- [ ] [**AlwaysInstallElevated**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#alwaysinstallelevated)?
    

### 

[](https://book.hacktricks.xyz/windows-hardening/checklist-windows-privilege-escalation#logging-av-enumeration)

[Logging/AV enumeration](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#enumeration)

- [ ] Check [**Audit**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#audit-settings) and [**WEF**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#wef) settings
    
- [ ] Check [**LAPS**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#laps)
    
- [ ] Check if [**WDigest**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#wdigest) is active
    
- [ ] [**LSA Protection**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#lsa-protection)?
    
- [ ] [**Credentials Guard**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#credentials-guard)[?](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#cached-credentials)
    
- [ ] [**Cached Credentials**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#cached-credentials)?
    
- [ ] Check if any [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
    
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
    
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
    
- [ ] [**User Privileges**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#users-and-groups)
    
- [ ] Check [**current** user **privileges**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#users-and-groups)
    
- [ ] Are you [**member of any privileged group**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#privileged-groups)?
    
- [ ] Check if you have [any of these tokens enabled](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
    
- [ ] [**Users Sessions**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#logged-users-sessions)?
    
- [ ] Check [**users homes**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#home-folders) (access?)
    
- [ ] Check [**Password Policy**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#password-policy)
    
- [ ] What is [**inside the Clipboard**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#get-the-content-of-the-clipboard)?
    

### 

[](https://book.hacktricks.xyz/windows-hardening/checklist-windows-privilege-escalation#network)

[Network](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#network)

- [ ] Check **current** [**network** **information**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#network)
    
- [ ] Check **hidden local services** restricted to the outside
    

### 

[](https://book.hacktricks.xyz/windows-hardening/checklist-windows-privilege-escalation#running-processes)

[Running Processes](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#running-processes)

- [ ] Processes binaries [**file and folders permissions**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#file-and-folder-permissions)
    
- [ ] [**Memory Password mining**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#memory-password-mining)
    
- [ ] [**Insecure GUI apps**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#insecure-gui-apps)
    
- [ ] Steal credentials with **interesting processes** via `ProcDump.exe` ? (firefox, chrome, etc ...)
    

### 

[](https://book.hacktricks.xyz/windows-hardening/checklist-windows-privilege-escalation#services)

[Services](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#services)

- [ ] [Can you **modify any service**?](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#permissions)
    
- [ ] [Can you **modify** the **binary** that is **executed** by any **service**?](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#modify-service-binary-path)
    
- [ ] [Can you **modify** the **registry** of any **service**?](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#services-registry-modify-permissions)
    
- [ ] [Can you take advantage of any **unquoted service** binary **path**?](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#unquoted-service-paths)
    

### 

[](https://book.hacktricks.xyz/windows-hardening/checklist-windows-privilege-escalation#applications)

[**Applications**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#applications)

- [ ] **Write** [**permissions on installed applications**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#write-permissions)
    
- [ ] [**Startup Applications**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#run-at-startup)
    
- [ ] **Vulnerable** [**Drivers**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#drivers)
    

### 

[](https://book.hacktricks.xyz/windows-hardening/checklist-windows-privilege-escalation#dll-hijacking)

[DLL Hijacking](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#path-dll-hijacking)

- [ ] Can you **write in any folder inside PATH**?
    
- [ ] Is there any known service binary that **tries to load any non-existant DLL**?
    
- [ ] Can you **write** in any **binaries folder**?
    

### 

[](https://book.hacktricks.xyz/windows-hardening/checklist-windows-privilege-escalation#network-1)

[Network](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#network)

- [ ] Enumerate the network (shares, interfaces, routes, neighbours, ...)
    
- [ ] Take a special look at network services listening on localhost (127.0.0.1)
    

### 

[](https://book.hacktricks.xyz/windows-hardening/checklist-windows-privilege-escalation#windows-credentials)

[Windows Credentials](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#windows-credentials)

- [ ] [**Winlogon**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#winlogon-credentials) credentials
    
- [ ] [**Windows Vault**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#credentials-manager-windows-vault) credentials that you could use?
    
- [ ] Interesting [**DPAPI credentials**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#dpapi)?
    
- [ ] Passwords of saved [**Wifi networks**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#wifi)?
    
- [ ] Interesting info in [**saved RDP Connections**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#saved-rdp-connections)?
    
- [ ] Passwords in [**recently run commands**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#recently-run-commands)?
    
- [ ] [**Remote Desktop Credentials Manager**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#remote-desktop-credential-manager) passwords?
    
- [ ] [**AppCmd.exe** exists](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#appcmd-exe)? Credentials?
    
- [ ] [**SCClient.exe**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#scclient-sccm)? DLL Side Loading?
    

### 

[](https://book.hacktricks.xyz/windows-hardening/checklist-windows-privilege-escalation#files-and-registry-credentials)

[Files and Registry (Credentials)](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#putty-creds) **and** [**SSH host keys**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#putty-ssh-host-keys)
    
- [ ] [**SSH keys in registry**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#ssh-keys-in-registry)?
    
- [ ] Passwords in [**unattended files**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#unattended-files)?
    
- [ ] Any [**SAM & SYSTEM**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#sam-and-system-backups) backup?
    
- [ ] [**Cloud credentials**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#cloud-credentials)?
    
- [ ] [**McAfee SiteList.xml**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#mcafee-sitelist.xml) file?
    
- [ ] [**Cached GPP Password**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#cached-gpp-pasword)?
    
- [ ] Password in [**IIS Web config file**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#iis-web-config)?
    
- [ ] Interesting info in [**web** **logs**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#logs)?
    
- [ ] Do you want to [**ask for credentials**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#ask-for-credentials) to the user?
    
- [ ] Interesting [**files inside the Recycle Bin**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#credentials-in-the-recyclebin)?
    
- [ ] Other [**registry containing credentials**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#inside-the-registry)?
    
- [ ] Inside [**Browser data**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#browsers-history) (dbs, history, bookmarks, ...)?
    
- [ ] [**Generic password search**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#generic-password-search-in-files-and-registry) in files and registry
    
- [ ] [**Tools**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#tools-that-search-for-passwords) to automatically search for passwords
    

### 

[](https://book.hacktricks.xyz/windows-hardening/checklist-windows-privilege-escalation#leaked-handlers)

[Leaked Handlers](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#leaked-handlers)

- [ ] Have you access to any handler of a process run by administrator?
    

### 

[](https://book.hacktricks.xyz/windows-hardening/checklist-windows-privilege-escalation#pipe-client-impersonation)

[Pipe Client Impersonation](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#named-pipe-client-impersonation)

- [ ] Check if you can abuse it