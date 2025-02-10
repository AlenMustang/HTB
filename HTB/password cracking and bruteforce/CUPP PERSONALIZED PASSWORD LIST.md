


``` bash
grep -E '^.{6,}$' list.txt | grep -E '[A-Z]' | grep -E '[a-z]' | grep -E '[0-9]' | grep -E '([!@#$%^&*].*){2,}' > list-filtered.txt
```