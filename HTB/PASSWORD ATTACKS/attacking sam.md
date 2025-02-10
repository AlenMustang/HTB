
#### sam registry hives

|Registry Hive|Description|
|---|---|
|`hklm\sam`|Contains the hashes associated with local account passwords. We will need the hashes so we can crack them and get the user account passwords in cleartext.|
|`hklm\system`|Contains the system bootkey, which is used to encrypt the SAM database. We will need the bootkey to decrypt the SAM database.|
|`hklm\security`|Contains cached credentials for domain accounts. We may benefit from having this on a domain-joined Windows target.|
##### questions
```
smbserver.py -smb2support Data .
```

#### Key Terms to Search

Whether we end up with access to the GUI or CLI, we know we will have some tools to use for searching but of equal importance is what exactly we are searching for. Here are some helpful key terms we can use that can help us discover some credentials:


| Passwords     | Passphrases  | Keys        |
| ------------- | ------------ | ----------- |
| Username      | User account | Creds       |
| Users         | Passkeys     | Passphrases |
| configuration | dbcredential | dbpassword  |
| pwd           | Login        | Credentials |
####  store 
 [Lazagne](https://github.com/AlessandroZ/LaZagne) to quickly discover credentials that web browsers or other installed applications may insecurely store.
https://github.com/AlessandroZ/LaZagne

```powershell
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
```

## Additional Considerations

> credenital hunting

- Passwords in Group Policy in the SYSVOL share
- Passwords in scripts in the SYSVOL share
- Password in scripts on IT shares
- Passwords in web.config files on dev machines and IT shares
- unattend.xml
- Passwords in the AD user or computer description fields
- KeePass databases --> pull hash, crack and get loads of access.
- Found on user systems and shares
- Files such as pass.txt, passwords.docx, passwords.xlsx found on user systems, shares, [Sharepoint](https://www.microsoft.com/en-us/microsoft-365/sharepoint/collaboration)