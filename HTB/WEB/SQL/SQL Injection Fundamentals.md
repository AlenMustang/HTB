![[Pasted image 20250216150411.png]]

## SQL Injection (SQLi)

 we have diff type of injections
- http injection
- code injection
- command injection
- sql injection

SQLi -> malicious users passes input that changes final SQL query sent to web app DB

In the most basic case, this is done by injecting a single quote (`'`) or a double quote (`"`)

https://www.sqlinjection.net/stacked-queries/

## Prevention


# Intro to Databases

## Database Management Systems

|**Feature**|**Description**|
|---|---|
|`Concurrency`|A real-world application might have multiple users interacting with it simultaneously. A DBMS makes sure that these concurrent interactions succeed without corrupting or losing any data.|
|`Consistency`|With so many concurrent interactions, the DBMS needs to ensure that the data remains consistent and valid throughout the database.|
|`Security`|DBMS provides fine-grained security controls through user authentication and permissions. This will prevent unauthorized viewing or editing of sensitive data.|
|`Reliability`|It is easy to backup databases and rolls them back to a previous state in case of data loss or a breach.|
|`Structured Query Language`|SQL simplifies user interaction with the database with an intuitive syntax supporting various operations.|
![[Pasted image 20250216151245.png]]

tier 1 - websites, guis
tier 2 - api calls ...

# Intro to MySQL


SQL syntax can differ from one RDBMS to another. However, they are all required to follow the [ISO standard](https://en.wikipedia.org/wiki/ISO/IEC_9075) for Structured Query Language

## INSERT Statement

insert statements add new records to a given table

```sql
INSERT INTO table_name VALUES (column1_value, column2_value, column3_value, ...);
```


## SELECT Statement

```sql
SELECT * FROM table_name;
```

## DROP Statement

```sql
DROP TABLE logins;
```


>[!note]
>The 'DROP' statement will permanently and completely delete the table with no confirmation, so it should be used with caution.

## ALTER Statement

```sql
ALTER TABLE logins ADD newColumn INT;
```
## UPDATE Statement

```sql
UPDATE table_name SET column1=newvalue1, column2=newvalue2, ... WHERE <condition>;
```

# Query Results
## Sorting Results


```sql
SELECT * FROM logins ORDER BY password;
```

## LIMIT results

```sql
SELECT * FROM logins LIMIT 2;
```

## WHERE Clause

```sql
SELECT * FROM table_name WHERE <condition>;
```

## LIKE Clause
```sql

SELECT * FROM table_name WHERE <condition> like <param>;
```


# SQL Operators

```sql
condition1 AND condition2
```

```sql
 SELECT 1 = 1 OR 'test' = 'abc';
```

## NOT Operator

The `NOT` operator simply toggles a `boolean` value 'i.e. `true` is converted to `false` and vice versa':
## Symbol Operators

The `AND`, `OR` and `NOT` operators can also be represented as `&&`, `||` and `!`

Here is a list of common operations and their precedence, as seen in the [MariaDB Documentation](https://mariadb.com/kb/en/operator-precedence/):

- Division (`/`), Multiplication (`*`), and Modulus (`%`)
- Addition (`+`) and subtraction (`-`)
- Comparison (`=`, `>`, `<`, `<=`, `>=`, `!=`, `LIKE`)
- NOT (`!`)
- AND (`&&`)
- OR (`||`)

# Intro to SQL Injections

# Subverting Query Logic

## SQLi Discovery

|ayload|URL Encoded|
|---|---|
|`'`|`%27`|
|`"`|`%22`|
|`#`|`%23`|
|`;`|`%3B`|
|`)`|`%29`|
Note: In some cases, we may have to use the URL encoded version of the payload. An example of this is when we put our payload directly in the URL 'i.e. HTTP GET request'.


Note: The payload we used above is one of many auth bypass payloads we can use to subvert the authentication logic. You can find a comprehensive list of SQLi auth bypass payloads in [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#authentication-bypass), each of which works on a certain type of SQL queries.


## Auth Bypass with OR operator

