
# Intro to Web Proxies

## Uses of Web Proxies

- Web application vulnerability scanning
- Web fuzzing
- Web crawling
- Web application mapping
- Web request analysis
- Web configuration testing
- Code reviews

## Burp Suite

Some of the `paid-only` features are:

- Active web app scanner
- Fast Burp Intruder
- The ability to load certain Burp Extensions
## OWASP Zed Attack Proxy (ZAP)

similar but free

## installing

Note: Both Burp and ZAP rely on Java Runtime Environment to run, but this package should be included in the installer by default. If not, we can follow the instructions found on this [page](https://docs.oracle.com/goldengate/1212/gg-winux/GDRAD/java.htm).

## Burp Suite

If Burp is not pre-installed in our VM, we can start by downloading it from [Burp's Download Page](https://portswigger.net/burp/releases/).
## ZAP

We can download ZAP from its [download page](https://www.zaproxy.org/download/),


### IMPORTANT VERY
Tip: If you prefer to use to a dark theme, you may do so in Burp by going to (`User Options>Display`) and selecting "dark" under (`theme`), and in ZAP by going to (`Tools>Options>Display`) and selecting "Flat Dark" in (`Look and Feel`).

## Installing CA Certificate
We can install Burp's certificate once we select Burp as our proxy in `Foxy Proxy`, by browsing to `http://burp`, and download

To get ZAP's certificate, we can go to (`Tools>Options>Dynamic SSL Certificate`), then click on `Save`:

## Manipulating Intercepted Requests

1. SQL injections
2. Command injections
3. Upload bypass
4. Authentication bypass
5. XSS
6. XXE
7. Error handling
8. Deserialization

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
