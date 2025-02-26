
SAM sotres MD4 users passwords
	> database is also secret 
	> encrypted by boot key
	

### BOOTKEY

PATH: Windows\System32\config\SYSTEM

### user secrets
##### Local user login 

> password se zakrpitira z md5 in primerja z hashem v SAM db
> obenem se kriptira z SHA1, ki je uporabljen za masterkey

##### domain user
> ntsd.dit (md4)
> 2 master keys 
> master key 1 protected by md4 of password
> master key 2 proteced by public key of domain


KDS ROOT KEY

