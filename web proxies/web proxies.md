# Automatic Modification


#### Burp Match and Replace


`Proxy>Options>Match and Replace`

|   |   |
|---|---|
|`Type`: `Request header`|Since the change we want to make will be in the request header and not in its body.|
|`Match`: `^User-Agent.*$`|The regex pattern that matches the entire line with `User-Agent` in it.|
|`Replace`: `User-Agent: HackTheBox Agent 1.0`|This is the value that will replace the line we matched above.|
|`Regex match`: True|We don't know the exact User-Agent string we want to replace, so we'll use regex to match any value that matches the pattern we specified above.|

#### ZAP Replacer

- `Description`: `HTB User-Agent`.
- `Match Type`: `Request Header (will add if not present)`.
- `Match String`: `User-Agent`. We can select the header we want from the drop-down menu, and ZAP will replace its value.
- `Replacement String`: `HackTheBox Agent 1.0`.
- `Enable`: True.

# Repeating Requests

- quickly repeat requests and edit
burp repeater


# Encoding/Decoding

select that text and right-click on it, then select (`Convert Selection>URL>URL encode key characters`) OR CTRL + u

## Decoding

- HTML
- Unicode
- Base64
- ASCII hex

# Proxying

To use `proxychains`, we first have to edit `/etc/proxychains.conf`, comment out the final line and add the following line at the end of it:
```shell-session
#socks4         127.0.0.1 9050
http 127.0.0.1 8080
```

this way all commands used in CLI rquessts will get also tracked in burp



### proxying with nmap

```shell-session
nmap --proxies http://127.0.0.1:8080 SERVER_IP -pPORT -Pn -sC
```

![[Pasted image 20250215200551.png]]

## Metasploit
```
set proxies protocol:127.0.0.1:8080
```



# Burp Intruder

- Target who we are fuzzing
- Positions where we place payload pointer
> select the payload posiution by enclosing it with the  `§` by pressing on `Add §` button

![[Pasted image 20250215201431.png]]

https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/positions#attack-type


  
## ADDONS FOR BURP

| .NET beautifier              | J2EEScan                  | Software Vulnerability Scanner |     |
| ---------------------------- | ------------------------- | ------------------------------ | --- |
| Software Version Reporter    | Active Scan++             | Additional Scanner Checks      |     |
| AWS Security Checks          | Backslash Powered Scanner | Wsdler                         |     |
| Java Deserialization Scanner | C02                       | Cloud Storage Tester           |     |
| CMS Scanner                  | Error Message Checks      | Detect Dynamic JS              |     |
| Headers Analyzer             | HTML5 Auditor             | PHP Object Injection Check     |     |
| JavaScript Security          | Retire.JS                 | CSP Auditor                    |     |
| Random IP Address Header     | Autorize                  | CSRF Scanner                   |     |
| JS Link Finder               |                           |                                | -   |
