# ZAP Scanning Report


## Summary of Alerts

| Risk Level | Number of Alerts |
| --- | --- |
| High | 0 |
| Medium | 5 |
| Low | 3 |
| Informational | 9 |




## Alerts

| Name | Risk Level | Number of Instances |
| --- | --- | --- |
| CORS Misconfiguration | Medium | 5 |
| Content Security Policy (CSP) Header Not Set | Medium | 1 |
| Cross-Domain Misconfiguration | Medium | 1 |
| Hidden File Found | Medium | 4 |
| Proxy Disclosure | Medium | 5 |
| Cross-Domain JavaScript Source File Inclusion | Low | 2 |
| Deprecated Feature Policy Header Set | Low | 1 |
| Strict-Transport-Security Header Not Set | Low | 5 |
| Modern Web Application | Informational | 1 |
| Non-Storable Content | Informational | 5 |
| Re-examine Cache-control Directives | Informational | 1 |
| Sec-Fetch-Dest Header is Missing | Informational | 3 |
| Sec-Fetch-Mode Header is Missing | Informational | 3 |
| Sec-Fetch-Site Header is Missing | Informational | 3 |
| Sec-Fetch-User Header is Missing | Informational | 3 |
| Storable but Non-Cacheable Content | Informational | 1 |
| User Agent Fuzzer | Informational | 60 |




## Alert Detail



### [ CORS Misconfiguration ](https://www.zaproxy.org/docs/alerts/40040/)



##### Medium (High)

### Description

This CORS misconfiguration could allow an attacker to perform AJAX queries to the vulnerable website from a malicious page loaded by the victim's user agent.
In order to perform authenticated AJAX queries, the server must specify the header "Access-Control-Allow-Credentials: true" and the "Access-Control-Allow-Origin" header must be set to null or the malicious page's domain. Even if this misconfiguration doesn't allow authenticated AJAX requests, unauthenticated sensitive content can still be accessed (e.g intranet websites).
A malicious page can belong to a malicious website but also a trusted website with flaws (e.g XSS, support of HTTP without TLS allowing code injection through MITM, etc).

* URL: https://as-devsecops.azurewebsites.net
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://rr4xGYJt.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://rr4xGYJt.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/favicon.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://rr4xGYJt.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/robots.txt
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://rr4xGYJt.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/sitemap.xml
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://rr4xGYJt.com`
  * Evidence: ``

Instances: 5

### Solution

If a web resource contains sensitive information, the origin should be properly specified in the Access-Control-Allow-Origin header. Only trusted websites needing this resource should be specified in this header, with the most secured protocol supported.

### Reference


* [ https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS ](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
* [ https://portswigger.net/web-security/cors ](https://portswigger.net/web-security/cors)


#### CWE Id: [ 942 ](https://cwe.mitre.org/data/definitions/942.html)


#### WASC Id: 14

#### Source ID: 1

### [ Content Security Policy (CSP) Header Not Set ](https://www.zaproxy.org/docs/alerts/10038/)



##### Medium (High)

### Description

Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

* URL: https://as-devsecops.azurewebsites.net/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``

Instances: 1

### Solution

Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

### Reference


* [ https://developer.mozilla.org/en-US/docs/Web/Security/CSP/Introducing_Content_Security_Policy ](https://developer.mozilla.org/en-US/docs/Web/Security/CSP/Introducing_Content_Security_Policy)
* [ https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html ](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
* [ http://www.w3.org/TR/CSP/ ](http://www.w3.org/TR/CSP/)
* [ http://w3c.github.io/webappsec/specs/content-security-policy/csp-specification.dev.html ](http://w3c.github.io/webappsec/specs/content-security-policy/csp-specification.dev.html)
* [ http://www.html5rocks.com/en/tutorials/security/content-security-policy/ ](http://www.html5rocks.com/en/tutorials/security/content-security-policy/)
* [ http://caniuse.com/#feat=contentsecuritypolicy ](http://caniuse.com/#feat=contentsecuritypolicy)
* [ http://content-security-policy.com/ ](http://content-security-policy.com/)


#### CWE Id: [ 693 ](https://cwe.mitre.org/data/definitions/693.html)


#### WASC Id: 15

#### Source ID: 3

### [ Cross-Domain Misconfiguration ](https://www.zaproxy.org/docs/alerts/10098/)



##### Medium (Medium)

### Description

Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server

* URL: https://as-devsecops.azurewebsites.net/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`

Instances: 1

### Solution

Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

### Reference


* [ https://vulncat.fortify.com/en/detail?id=desc.config.dotnet.html5_overly_permissive_cors_policy ](https://vulncat.fortify.com/en/detail?id=desc.config.dotnet.html5_overly_permissive_cors_policy)


#### CWE Id: [ 264 ](https://cwe.mitre.org/data/definitions/264.html)


#### WASC Id: 14

#### Source ID: 3

### [ Hidden File Found ](https://www.zaproxy.org/docs/alerts/40035/)



##### Medium (Low)

### Description

A sensitive file was identified as accessible or available. This may leak administrative, configuration, or credential information which can be leveraged by a malicious individual to further attack the system or conduct social engineering efforts.

* URL: https://as-devsecops.azurewebsites.net/._darcs
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `HTTP/1.1 200 OK`
* URL: https://as-devsecops.azurewebsites.net/.bzr
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `HTTP/1.1 200 OK`
* URL: https://as-devsecops.azurewebsites.net/.hg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `HTTP/1.1 200 OK`
* URL: https://as-devsecops.azurewebsites.net/BitKeeper
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `HTTP/1.1 200 OK`

Instances: 4

### Solution

Consider whether or not the component is actually required in production, if it isn't then disable it. If it is then ensure access to it requires appropriate authentication and authorization, or limit exposure to internal systems or specific source IPs, etc.

### Reference


* [ https://blog.hboeck.de/archives/892-Introducing-Snallygaster-a-Tool-to-Scan-for-Secrets-on-Web-Servers.html ](https://blog.hboeck.de/archives/892-Introducing-Snallygaster-a-Tool-to-Scan-for-Secrets-on-Web-Servers.html)


#### CWE Id: [ 538 ](https://cwe.mitre.org/data/definitions/538.html)


#### WASC Id: 13

#### Source ID: 1

### [ Proxy Disclosure ](https://www.zaproxy.org/docs/alerts/40025/)



##### Medium (Medium)

### Description

2 proxy server(s) were detected or fingerprinted. This information helps a potential attacker to determine 
 - A list of targets for an attack against the application.
 - Potential vulnerabilities on the proxy servers that service the application.
 - The presence or absence of any proxy-based components that might cause attacks against the application to be detected, prevented, or mitigated. 

* URL: https://as-devsecops.azurewebsites.net
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/favicon.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/robots.txt
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/sitemap.xml
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``

Instances: 5

### Solution

Disable the 'TRACE' method on the proxy servers, as well as the origin web/application server.
Disable the 'OPTIONS' method on the proxy servers, as well as the origin web/application server, if it is not required for other purposes, such as 'CORS' (Cross Origin Resource Sharing).
Configure the web and application servers with custom error pages, to prevent 'fingerprintable' product-specific error pages being leaked to the user in the event of HTTP errors, such as 'TRACK' requests for non-existent pages.
Configure all proxies, application servers, and web servers to prevent disclosure of the technology and version information in the 'Server' and 'X-Powered-By' HTTP response headers.


### Reference


* [ https://tools.ietf.org/html/rfc7231#section-5.1.2 ](https://tools.ietf.org/html/rfc7231#section-5.1.2)


#### CWE Id: [ 200 ](https://cwe.mitre.org/data/definitions/200.html)


#### WASC Id: 45

#### Source ID: 1

### [ Cross-Domain JavaScript Source File Inclusion ](https://www.zaproxy.org/docs/alerts/10017/)



##### Low (Medium)

### Description

The page includes one or more script files from a third-party domain.

* URL: https://as-devsecops.azurewebsites.net/
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
* URL: https://as-devsecops.azurewebsites.net/
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`

Instances: 2

### Solution

Ensure JavaScript source files are loaded from only trusted sources, and the sources can't be controlled by end users of the application.

### Reference



#### CWE Id: [ 829 ](https://cwe.mitre.org/data/definitions/829.html)


#### WASC Id: 15

#### Source ID: 3

### [ Deprecated Feature Policy Header Set ](https://www.zaproxy.org/docs/alerts/10063/)



##### Low (Medium)

### Description

The header has now been renamed to Permissions-Policy. 

* URL: https://as-devsecops.azurewebsites.net/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Feature-Policy`

Instances: 1

### Solution

Ensure that your web server, application server, load balancer, etc. is configured to set the Permissions-Policy header instead of the Feature-Policy header.

### Reference


* [ https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Feature-Policy ](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Feature-Policy)
* [ https://scotthelme.co.uk/goodbye-feature-policy-and-hello-permissions-policy/ ](https://scotthelme.co.uk/goodbye-feature-policy-and-hello-permissions-policy/)


#### CWE Id: [ 16 ](https://cwe.mitre.org/data/definitions/16.html)


#### WASC Id: 15

#### Source ID: 3

### [ Strict-Transport-Security Header Not Set ](https://www.zaproxy.org/docs/alerts/10035/)



##### Low (High)

### Description

HTTP Strict Transport Security (HSTS) is a web security policy mechanism whereby a web server declares that complying user agents (such as a web browser) are to interact with it using only secure HTTPS connections (i.e. HTTP layered over TLS/SSL). HSTS is an IETF standards track protocol and is specified in RFC 6797.

* URL: https://as-devsecops.azurewebsites.net
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/favicon.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/robots.txt
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/sitemap.xml
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``

Instances: 5

### Solution

Ensure that your web server, application server, load balancer, etc. is configured to enforce Strict-Transport-Security.

### Reference


* [ https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html ](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html)
* [ https://owasp.org/www-community/Security_Headers ](https://owasp.org/www-community/Security_Headers)
* [ http://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security ](http://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security)
* [ http://caniuse.com/stricttransportsecurity ](http://caniuse.com/stricttransportsecurity)
* [ http://tools.ietf.org/html/rfc6797 ](http://tools.ietf.org/html/rfc6797)


#### CWE Id: [ 319 ](https://cwe.mitre.org/data/definitions/319.html)


#### WASC Id: 15

#### Source ID: 3

### [ Modern Web Application ](https://www.zaproxy.org/docs/alerts/10109/)



##### Informational (Medium)

### Description

The application appears to be a modern web application. If you need to explore it automatically then the Ajax Spider may well be more effective than the standard one.

* URL: https://as-devsecops.azurewebsites.net/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`

Instances: 1

### Solution

This is an informational alert and so no changes are required.

### Reference




#### Source ID: 3

### [ Non-Storable Content ](https://www.zaproxy.org/docs/alerts/10049/)



##### Informational (Medium)

### Description

The response contents are not storable by caching components such as proxy servers. If the response does not contain sensitive, personal or user-specific information, it may benefit from being stored and cached, to improve performance.

* URL: https://as-devsecops.azurewebsites.net
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `502`
* URL: https://as-devsecops.azurewebsites.net/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `502`
* URL: https://as-devsecops.azurewebsites.net/favicon.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `502`
* URL: https://as-devsecops.azurewebsites.net/robots.txt
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `502`
* URL: https://as-devsecops.azurewebsites.net/sitemap.xml
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `502`

Instances: 5

### Solution

The content may be marked as storable by ensuring that the following conditions are satisfied:
The request method must be understood by the cache and defined as being cacheable ("GET", "HEAD", and "POST" are currently defined as cacheable)
The response status code must be understood by the cache (one of the 1XX, 2XX, 3XX, 4XX, or 5XX response classes are generally understood)
The "no-store" cache directive must not appear in the request or response header fields
For caching by "shared" caches such as "proxy" caches, the "private" response directive must not appear in the response
For caching by "shared" caches such as "proxy" caches, the "Authorization" header field must not appear in the request, unless the response explicitly allows it (using one of the "must-revalidate", "public", or "s-maxage" Cache-Control response directives)
In addition to the conditions above, at least one of the following conditions must also be satisfied by the response:
It must contain an "Expires" header field
It must contain a "max-age" response directive
For "shared" caches such as "proxy" caches, it must contain a "s-maxage" response directive
It must contain a "Cache Control Extension" that allows it to be cached
It must have a status code that is defined as cacheable by default (200, 203, 204, 206, 300, 301, 404, 405, 410, 414, 501).   

### Reference


* [ https://tools.ietf.org/html/rfc7234 ](https://tools.ietf.org/html/rfc7234)
* [ https://tools.ietf.org/html/rfc7231 ](https://tools.ietf.org/html/rfc7231)
* [ http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html (obsoleted by rfc7234) ](http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html (obsoleted by rfc7234))


#### CWE Id: [ 524 ](https://cwe.mitre.org/data/definitions/524.html)


#### WASC Id: 13

#### Source ID: 3

### [ Re-examine Cache-control Directives ](https://www.zaproxy.org/docs/alerts/10015/)



##### Informational (Low)

### Description

The cache-control header has not been set properly or is missing, allowing the browser and proxies to cache content. For static assets like css, js, or image files this might be intended, however, the resources should be reviewed to ensure that no sensitive content will be cached.

* URL: https://as-devsecops.azurewebsites.net/
  * Method: `GET`
  * Parameter: `cache-control`
  * Attack: ``
  * Evidence: `public, max-age=0`

Instances: 1

### Solution

For secure content, ensure the cache-control HTTP header is set with "no-cache, no-store, must-revalidate". If an asset should be cached consider setting the directives "public, max-age, immutable".

### Reference


* [ https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#web-content-caching ](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#web-content-caching)
* [ https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control ](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control)
* [ https://grayduck.mn/2021/09/13/cache-control-recommendations/ ](https://grayduck.mn/2021/09/13/cache-control-recommendations/)


#### CWE Id: [ 525 ](https://cwe.mitre.org/data/definitions/525.html)


#### WASC Id: 13

#### Source ID: 3

### [ Sec-Fetch-Dest Header is Missing ](https://www.zaproxy.org/docs/alerts/90005/)



##### Informational (High)

### Description

Specifies how and where the data would be used. For instance, if the value is audio, then the requested resource must be audio data and not any other type of resource.

* URL: https://as-devsecops.azurewebsites.net
  * Method: `GET`
  * Parameter: `Sec-Fetch-Dest`
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/
  * Method: `GET`
  * Parameter: `Sec-Fetch-Dest`
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/sitemap.xml
  * Method: `GET`
  * Parameter: `Sec-Fetch-Dest`
  * Attack: ``
  * Evidence: ``

Instances: 3

### Solution

Ensure that Sec-Fetch-Dest header is included in request headers.

### Reference


* [ https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-Fetch-Dest ](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-Fetch-Dest)


#### CWE Id: [ 352 ](https://cwe.mitre.org/data/definitions/352.html)


#### WASC Id: 9

#### Source ID: 3

### [ Sec-Fetch-Mode Header is Missing ](https://www.zaproxy.org/docs/alerts/90005/)



##### Informational (High)

### Description

Allows to differentiate between requests for navigating between HTML pages and requests for loading resources like images, audio etc.

* URL: https://as-devsecops.azurewebsites.net
  * Method: `GET`
  * Parameter: `Sec-Fetch-Mode`
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/
  * Method: `GET`
  * Parameter: `Sec-Fetch-Mode`
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/sitemap.xml
  * Method: `GET`
  * Parameter: `Sec-Fetch-Mode`
  * Attack: ``
  * Evidence: ``

Instances: 3

### Solution

Ensure that Sec-Fetch-Mode header is included in request headers.

### Reference


* [ https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-Fetch-Mode ](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-Fetch-Mode)


#### CWE Id: [ 352 ](https://cwe.mitre.org/data/definitions/352.html)


#### WASC Id: 9

#### Source ID: 3

### [ Sec-Fetch-Site Header is Missing ](https://www.zaproxy.org/docs/alerts/90005/)



##### Informational (High)

### Description

Specifies the relationship between request initiator's origin and target's origin.

* URL: https://as-devsecops.azurewebsites.net
  * Method: `GET`
  * Parameter: `Sec-Fetch-Site`
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/
  * Method: `GET`
  * Parameter: `Sec-Fetch-Site`
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/sitemap.xml
  * Method: `GET`
  * Parameter: `Sec-Fetch-Site`
  * Attack: ``
  * Evidence: ``

Instances: 3

### Solution

Ensure that Sec-Fetch-Site header is included in request headers.

### Reference


* [ https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-Fetch-Site ](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-Fetch-Site)


#### CWE Id: [ 352 ](https://cwe.mitre.org/data/definitions/352.html)


#### WASC Id: 9

#### Source ID: 3

### [ Sec-Fetch-User Header is Missing ](https://www.zaproxy.org/docs/alerts/90005/)



##### Informational (High)

### Description

Specifies if a navigation request was initiated by a user.

* URL: https://as-devsecops.azurewebsites.net
  * Method: `GET`
  * Parameter: `Sec-Fetch-User`
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/
  * Method: `GET`
  * Parameter: `Sec-Fetch-User`
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/sitemap.xml
  * Method: `GET`
  * Parameter: `Sec-Fetch-User`
  * Attack: ``
  * Evidence: ``

Instances: 3

### Solution

Ensure that Sec-Fetch-User header is included in user initiated requests.

### Reference


* [ https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-Fetch-User ](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-Fetch-User)


#### CWE Id: [ 352 ](https://cwe.mitre.org/data/definitions/352.html)


#### WASC Id: 9

#### Source ID: 3

### [ Storable but Non-Cacheable Content ](https://www.zaproxy.org/docs/alerts/10049/)



##### Informational (Medium)

### Description

The response contents are storable by caching components such as proxy servers, but will not be retrieved directly from the cache, without validating the request upstream, in response to similar requests from other users. 

* URL: https://as-devsecops.azurewebsites.net/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `max-age=0`

Instances: 1

### Solution



### Reference


* [ https://tools.ietf.org/html/rfc7234 ](https://tools.ietf.org/html/rfc7234)
* [ https://tools.ietf.org/html/rfc7231 ](https://tools.ietf.org/html/rfc7231)
* [ http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html (obsoleted by rfc7234) ](http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html (obsoleted by rfc7234))


#### CWE Id: [ 524 ](https://cwe.mitre.org/data/definitions/524.html)


#### WASC Id: 13

#### Source ID: 3

### [ User Agent Fuzzer ](https://www.zaproxy.org/docs/alerts/10104/)



##### Informational (Medium)

### Description

Check for differences in response based on fuzzed User Agent (eg. mobile sites, access as a Search Engine Crawler). Compares the response statuscode and the hashcode of the response body with the original response.

* URL: https://as-devsecops.azurewebsites.net
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/favicon.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/favicon.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/favicon.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/favicon.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/favicon.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/favicon.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/favicon.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/favicon.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/favicon.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/favicon.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/favicon.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/favicon.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/robots.txt
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/robots.txt
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/robots.txt
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/robots.txt
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/robots.txt
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/robots.txt
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/robots.txt
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/robots.txt
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/robots.txt
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/robots.txt
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/robots.txt
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/robots.txt
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/sitemap.xml
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/sitemap.xml
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/sitemap.xml
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/sitemap.xml
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/sitemap.xml
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/sitemap.xml
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/sitemap.xml
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/sitemap.xml
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/sitemap.xml
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/sitemap.xml
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/sitemap.xml
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/sitemap.xml
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``

Instances: 60

### Solution



### Reference


* [ https://owasp.org/wstg ](https://owasp.org/wstg)



#### Source ID: 1


