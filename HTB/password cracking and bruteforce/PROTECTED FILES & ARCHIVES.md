https://fileinfo.com/filetypes/common

#### Hunting for Files

```shell
for ext in $(echo ".xls .xls* .xltx .csv .od* .doc .doc* .pdf .pot .pot* .pp*");do echo -e "\nFile extension: " $ext; find / -name *$ext 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done
```

#### Hunting for SSH Keys

```shell
grep -rnw "PRIVATE KEY" /* 2>/dev/null | grep ":1"
```

#### Encrypted SSH Keys


```shell
cat /home/cry0l1t3/.ssh/SSH.private

-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,2109D25CC91F8DBFCEB0F7589066B2CC

8Uboy0afrTahejVGmB7kgvxkqJLOczb1I0/hEzPU1leCqhCKBlxYldM2s65jhflD
4/OH4ENhU7qpJ62KlrnZhFX8UwYBmebNDvG12oE7i21hB/9UqZmmHktjD3+OYTsD
...SNIP...
```
> [!NOTE]
>  lightweight [AES-128-CBC](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) can be cracked.
##### cracking ssh

```shell
ssh2john.py SSH.private > ssh.hash
```

```shell
john --wordlist=rockyou.txt ssh.hash
```

## Cracking Documents

```shell
office2john.py Protected.docx > protected-docx.hash
```

```shell
john --wordlist=rockyou.txt protected-docx.hash
```

```shell
john protected-docx.hash --show
```

# Protected Archives

some common extension of arhives
  
|`tar`|`gz`|`rar`|`zip`|
|`vmdb/vmx`|`cpt`|`truecrypt`|`bitlocker`|
|`kdbx`|`luks`|`deb`|`7z`|
|`pkg`|`rpm`|`war`|`gzip`|


An extensive list of archive types can be found on [FileInfo.com](https://fileinfo.com/filetypes/compressed). However, instead of manually typing them out, we can also query them using a one-liner, filter them out, and save them to a file if needed. At the time of writing, there are `337`archive file types listed on fileinfo.com.

```shell
curl -s https://fileinfo.com/filetypes/compressed | html2text | awk '{print tolower($1)}' | grep "\." | tee -a compressed_ext.txt
```

## Cracking Archives

```shell
 zip2john ZIP.zip > zip.hash
```

## Cracking OpenSSL Encrypted Archives

#### Using a for-loop to Display Extracted Contents

```shell
for i in $(cat rockyou.txt);do openssl enc -aes-256-cbc -d -in GZIP.gzip -k $i 2>/dev/null| tar xz;done
```

## Cracking BitLocker Encrypted Drives


```shell
bitlocker2john -i Backup.vhd > backup.hashes

```
```shell
grep "bitlocker\$0" backup.hashes > backup.hash
```

crackinh with hashcat

```shell
hashcat -m 22100 backup.hash /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt -o backup.cracked
```

kira pass: L0vey0u1!