
| **`Files`**  | **`History`**        | **`Memory`**         | **`Key-Rings`**            |
| ------------ | -------------------- | -------------------- | -------------------------- |
| Configs      | Logs                 | Cache                | Browser stored credentials |
| Databases    | Command-line History | In-memory Processing |                            |
| Notes        |                      |                      |                            |
| Scripts      |                      |                      |                            |
| Source codes |                      |                      |                            |
| Cronjobs     |                      |                      |                            |
| SSH Keys     |                      |                      |                            |
|              |                      |                      |                            |
|              |                      |                      |                            |
```zshell
for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done
```
 

```shell-session
for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#";done
``` 


#### notes

```bash 
find /home/* -type f -name "*.txt" -o ! -name "*.*"
```
#### Cronjobs

```shell
cat /etc/crontab 
```
#### Logs
```shell-session
for i in $(ls /var/log/* 2>/dev/null);do GREP=$(grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null); if [[ $GREP ]];then echo -e "\n#### Log file: " $i; grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null;fi;done
```

#### Passwd Format

|`cry0l1t3`|`:`|`x`|`:`|`1000`|`:`|`1000`|`:`|`cry0l1t3,,,`|`:`|`/home/cry0l1t3`|`:`|`/bin/bash`|
|---|---|---|---|---|---|---|---|---|---|---|---|---|
|Login name||Password info||UID||GUID||Full name/comments||Home directory||Shell|
## Shadow File

Since reading the password hash values can put the entire system in danger, the file `/etc/shadow` was developed, which has a similar format to `/etc/passwd` but is only responsible for passwords and their management. It contains all the password information for the created users. For example, if there is no entry in the `/etc/shadow` file for a user in `/etc/passwd`, the user is considered invalid. The `/etc/shadow` file is also only readable by users who have administrator rights. The format of this file is divided into `nine fields`:

#### Shadow Format

|`cry0l1t3`|`:`|`$6$wBRzy$...SNIP...x9cDWUxW1`|`:`|`18937`|`:`|`0`|`:`|`99999`|`:`|`7`|`:`|`:`|`:`|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
|Username||Encrypted password||Last PW change||Min. PW age||Max. PW age||Warning period|Inactivity period|Expiration date|Unused|
#### Algorithm Types

- `$1$` – MD5
- `$2a$` – Blowfish
- `$2y$` – Eksblowfish
- `$5$` – SHA-256
- `$6$` – SHA-512

By default, the SHA-512 (`$6$`) encryption method is used on the latest Linux distributions.

## Cracking Linux Credentials

#### Unshadow


```shell
sudo cp /etc/passwd /tmp/passwd.bak 
sudo cp /etc/shadow /tmp/shadow.bak 
unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes
```

```shell
hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked
```

```shell
hashcat -m 500 -a 0 md5-hashes.list rockyou.txt
```

