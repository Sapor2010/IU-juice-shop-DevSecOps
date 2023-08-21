# ZAP Scanning Report


## Summary of Alerts

| Risk Level | Number of Alerts |
| --- | --- |
| High | 0 |
| Medium | 8 |
| Low | 5 |
| Informational | 11 |




## Alerts

| Name | Risk Level | Number of Instances |
| --- | --- | --- |
| Backup File Disclosure | Medium | 15 |
| Bypassing 403 | Medium | 3 |
| CORS Misconfiguration | Medium | 22 |
| Content Security Policy (CSP) Header Not Set | Medium | 4 |
| Cross-Domain Misconfiguration | Medium | 11 |
| Hidden File Found | Medium | 4 |
| Proxy Disclosure | Medium | 22 |
| Web Cache Deception | Medium | 2 |
| Cross-Domain JavaScript Source File Inclusion | Low | 6 |
| Dangerous JS Functions | Low | 2 |
| Deprecated Feature Policy Header Set | Low | 8 |
| Strict-Transport-Security Header Not Set | Low | 11 |
| Timestamp Disclosure - Unix | Low | 1 |
| Base64 Disclosure | Informational | 3 |
| Information Disclosure - Suspicious Comments | Informational | 2 |
| Modern Web Application | Informational | 3 |
| Re-examine Cache-control Directives | Informational | 5 |
| Sec-Fetch-Dest Header is Missing | Informational | 3 |
| Sec-Fetch-Mode Header is Missing | Informational | 3 |
| Sec-Fetch-Site Header is Missing | Informational | 3 |
| Sec-Fetch-User Header is Missing | Informational | 3 |
| Storable and Cacheable Content | Informational | 2 |
| Storable but Non-Cacheable Content | Informational | 9 |
| User Agent Fuzzer | Informational | 168 |




## Alert Detail



### [ Backup File Disclosure ](https://www.zaproxy.org/docs/alerts/10095/)



##### Medium (Medium)

### Description

A backup of the file was disclosed by the web server

* URL: https://as-devsecops.azurewebsites.net/ftp/quarantine%2520-%2520Copy
  * Method: `GET`
  * Parameter: ``
  * Attack: `https://as-devsecops.azurewebsites.net/ftp/quarantine%20-%20Copy`
  * Evidence: `A backup of [https://as-devsecops.azurewebsites.net/ftp/quarantine] is available at [https://as-devsecops.azurewebsites.net/ftp/quarantine%20-%20Copy]`
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantine%2520-%2520Copy%2520(2&29
  * Method: `GET`
  * Parameter: ``
  * Attack: `https://as-devsecops.azurewebsites.net/ftp/quarantine%20-%20Copy%20(2)`
  * Evidence: `A backup of [https://as-devsecops.azurewebsites.net/ftp/quarantine] is available at [https://as-devsecops.azurewebsites.net/ftp/quarantine%20-%20Copy%20(2)]`
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantine%2520-%2520Copy%2520(3&29
  * Method: `GET`
  * Parameter: ``
  * Attack: `https://as-devsecops.azurewebsites.net/ftp/quarantine%20-%20Copy%20(3)`
  * Evidence: `A backup of [https://as-devsecops.azurewebsites.net/ftp/quarantine] is available at [https://as-devsecops.azurewebsites.net/ftp/quarantine%20-%20Copy%20(3)]`
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantine.bac
  * Method: `GET`
  * Parameter: ``
  * Attack: `https://as-devsecops.azurewebsites.net/ftp/quarantine.bac`
  * Evidence: `A backup of [https://as-devsecops.azurewebsites.net/ftp/quarantine] is available at [https://as-devsecops.azurewebsites.net/ftp/quarantine.bac]`
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantine.backup
  * Method: `GET`
  * Parameter: ``
  * Attack: `https://as-devsecops.azurewebsites.net/ftp/quarantine.backup`
  * Evidence: `A backup of [https://as-devsecops.azurewebsites.net/ftp/quarantine] is available at [https://as-devsecops.azurewebsites.net/ftp/quarantine.backup]`
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantine.bak
  * Method: `GET`
  * Parameter: ``
  * Attack: `https://as-devsecops.azurewebsites.net/ftp/quarantine.bak`
  * Evidence: `A backup of [https://as-devsecops.azurewebsites.net/ftp/quarantine] is available at [https://as-devsecops.azurewebsites.net/ftp/quarantine.bak]`
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantine.jar
  * Method: `GET`
  * Parameter: ``
  * Attack: `https://as-devsecops.azurewebsites.net/ftp/quarantine.jar`
  * Evidence: `A backup of [https://as-devsecops.azurewebsites.net/ftp/quarantine] is available at [https://as-devsecops.azurewebsites.net/ftp/quarantine.jar]`
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantine.log
  * Method: `GET`
  * Parameter: ``
  * Attack: `https://as-devsecops.azurewebsites.net/ftp/quarantine.log`
  * Evidence: `A backup of [https://as-devsecops.azurewebsites.net/ftp/quarantine] is available at [https://as-devsecops.azurewebsites.net/ftp/quarantine.log]`
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantine.old
  * Method: `GET`
  * Parameter: ``
  * Attack: `https://as-devsecops.azurewebsites.net/ftp/quarantine.old`
  * Evidence: `A backup of [https://as-devsecops.azurewebsites.net/ftp/quarantine] is available at [https://as-devsecops.azurewebsites.net/ftp/quarantine.old]`
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantine.swp
  * Method: `GET`
  * Parameter: ``
  * Attack: `https://as-devsecops.azurewebsites.net/ftp/quarantine.swp`
  * Evidence: `A backup of [https://as-devsecops.azurewebsites.net/ftp/quarantine] is available at [https://as-devsecops.azurewebsites.net/ftp/quarantine.swp]`
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantine.tar
  * Method: `GET`
  * Parameter: ``
  * Attack: `https://as-devsecops.azurewebsites.net/ftp/quarantine.tar`
  * Evidence: `A backup of [https://as-devsecops.azurewebsites.net/ftp/quarantine] is available at [https://as-devsecops.azurewebsites.net/ftp/quarantine.tar]`
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantine.zip
  * Method: `GET`
  * Parameter: ``
  * Attack: `https://as-devsecops.azurewebsites.net/ftp/quarantine.zip`
  * Evidence: `A backup of [https://as-devsecops.azurewebsites.net/ftp/quarantine] is available at [https://as-devsecops.azurewebsites.net/ftp/quarantine.zip]`
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantine.~bk
  * Method: `GET`
  * Parameter: ``
  * Attack: `https://as-devsecops.azurewebsites.net/ftp/quarantine.~bk`
  * Evidence: `A backup of [https://as-devsecops.azurewebsites.net/ftp/quarantine] is available at [https://as-devsecops.azurewebsites.net/ftp/quarantine.~bk]`
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantinebackup
  * Method: `GET`
  * Parameter: ``
  * Attack: `https://as-devsecops.azurewebsites.net/ftp/quarantinebackup`
  * Evidence: `A backup of [https://as-devsecops.azurewebsites.net/ftp/quarantine] is available at [https://as-devsecops.azurewebsites.net/ftp/quarantinebackup]`
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantine~
  * Method: `GET`
  * Parameter: ``
  * Attack: `https://as-devsecops.azurewebsites.net/ftp/quarantine~`
  * Evidence: `A backup of [https://as-devsecops.azurewebsites.net/ftp/quarantine] is available at [https://as-devsecops.azurewebsites.net/ftp/quarantine~]`

Instances: 15

### Solution

Do not edit files in-situ on the web server, and ensure that un-necessary files (including hidden files) are removed from the web server.

### Reference


* [ https://cwe.mitre.org/data/definitions/530.html ](https://cwe.mitre.org/data/definitions/530.html)
* [ https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information.html ](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information.html)


#### CWE Id: [ 530 ](https://cwe.mitre.org/data/definitions/530.html)


#### WASC Id: 34

#### Source ID: 1

### [ Bypassing 403 ](https://www.zaproxy.org/docs/alerts/40038/)



##### Medium (Medium)

### Description

Bypassing 403 endpoints may be possible, the scan rule sent a payload that caused the response to be accessible (status code 200).

* URL: https://as-devsecops.azurewebsites.net/%2520/ftp/eastere.gg%2520/
  * Method: `GET`
  * Parameter: ``
  * Attack: `/%20/ftp/eastere.gg%20/`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/%2520/ftp/encrypt.pyc%2520/
  * Method: `GET`
  * Parameter: ``
  * Attack: `/%20/ftp/encrypt.pyc%20/`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/%2520/ftp/suspicious_errors.yml%2520/
  * Method: `GET`
  * Parameter: ``
  * Attack: `/%20/ftp/suspicious_errors.yml%20/`
  * Evidence: ``

Instances: 3

### Solution



### Reference


* [ https://www.acunetix.com/blog/articles/a-fresh-look-on-reverse-proxy-related-attacks/ ](https://www.acunetix.com/blog/articles/a-fresh-look-on-reverse-proxy-related-attacks/)
* [ https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf ](https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf)
* [ https://www.contextis.com/en/blog/server-technologies-reverse-proxy-bypass ](https://www.contextis.com/en/blog/server-technologies-reverse-proxy-bypass)



#### Source ID: 1

### [ CORS Misconfiguration ](https://www.zaproxy.org/docs/alerts/40040/)



##### Medium (High)

### Description

This CORS misconfiguration could allow an attacker to perform AJAX queries to the vulnerable website from a malicious page loaded by the victim's user agent.
In order to perform authenticated AJAX queries, the server must specify the header "Access-Control-Allow-Credentials: true" and the "Access-Control-Allow-Origin" header must be set to null or the malicious page's domain. Even if this misconfiguration doesn't allow authenticated AJAX requests, unauthenticated sensitive content can still be accessed (e.g intranet websites).
A malicious page can belong to a malicious website but also a trusted website with flaws (e.g XSS, support of HTTP without TLS allowing code injection through MITM, etc).

* URL: https://as-devsecops.azurewebsites.net
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://tHWtLek0.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://tHWtLek0.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://tHWtLek0.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://tHWtLek0.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://tHWtLek0.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/favicon.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://tHWtLek0.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://tHWtLek0.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/acquisitions.md
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://tHWtLek0.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/announcement_encrypted.md
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://tHWtLek0.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/eastere.gg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://tHWtLek0.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/encrypt.pyc
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://tHWtLek0.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/incident-support.kdbx
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://tHWtLek0.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/legal.md
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://tHWtLek0.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantine
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://tHWtLek0.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/suspicious_errors.yml
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://tHWtLek0.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://tHWtLek0.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://tHWtLek0.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/robots.txt
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://tHWtLek0.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://tHWtLek0.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/sitemap.xml
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://tHWtLek0.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://tHWtLek0.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://tHWtLek0.com`
  * Evidence: ``

Instances: 22

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
* URL: https://as-devsecops.azurewebsites.net/ftp
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/sitemap.xml
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``

Instances: 4

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

* URL: https://as-devsecops.azurewebsites.net
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
* URL: https://as-devsecops.azurewebsites.net/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
* URL: https://as-devsecops.azurewebsites.net/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
* URL: https://as-devsecops.azurewebsites.net/ftp
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
* URL: https://as-devsecops.azurewebsites.net/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
* URL: https://as-devsecops.azurewebsites.net/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
* URL: https://as-devsecops.azurewebsites.net/robots.txt
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
* URL: https://as-devsecops.azurewebsites.net/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
* URL: https://as-devsecops.azurewebsites.net/sitemap.xml
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
* URL: https://as-devsecops.azurewebsites.net/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
* URL: https://as-devsecops.azurewebsites.net/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`

Instances: 11

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
* URL: https://as-devsecops.azurewebsites.net/assets
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/favicon.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/acquisitions.md
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/announcement_encrypted.md
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/eastere.gg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/encrypt.pyc
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/incident-support.kdbx
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/legal.md
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantine
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/suspicious_errors.yml
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/robots.txt
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/sitemap.xml
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``

Instances: 22

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

### [ Web Cache Deception ](https://www.zaproxy.org/docs/alerts/40039/)



##### Medium (Medium)

### Description

Web cache deception may be possible. It may be possible for unauthorised user to view sensitive data on this page.

* URL: https://as-devsecops.azurewebsites.net/assets
  * Method: `GET`
  * Parameter: ``
  * Attack: `/test.css,/test.jpg,/test.js,/test.html,/test.gif,/test.png,/test.svg,/test.php,/test.txt,/test.pdf,/test.asp,`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public
  * Method: `GET`
  * Parameter: ``
  * Attack: `/test.css,/test.jpg,/test.js,/test.html,/test.gif,/test.png,/test.svg,/test.php,/test.txt,/test.pdf,/test.asp,`
  * Evidence: ``

Instances: 2

### Solution

It is strongly advised to refrain from classifying file types, such as images or stylesheets solely by their URL and file extension. Instead you should make sure that files are cached based on their Content-Type header.

### Reference


* [ https://blogs.akamai.com/2017/03/on-web-cache-deception-attacks.html ](https://blogs.akamai.com/2017/03/on-web-cache-deception-attacks.html)
* [ https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/web-cache-deception/ ](https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/web-cache-deception/)



#### Source ID: 1

### [ Cross-Domain JavaScript Source File Inclusion ](https://www.zaproxy.org/docs/alerts/10017/)



##### Low (Medium)

### Description

The page includes one or more script files from a third-party domain.

* URL: https://as-devsecops.azurewebsites.net
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
* URL: https://as-devsecops.azurewebsites.net
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
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
* URL: https://as-devsecops.azurewebsites.net/sitemap.xml
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
* URL: https://as-devsecops.azurewebsites.net/sitemap.xml
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`

Instances: 6

### Solution

Ensure JavaScript source files are loaded from only trusted sources, and the sources can't be controlled by end users of the application.

### Reference



#### CWE Id: [ 829 ](https://cwe.mitre.org/data/definitions/829.html)


#### WASC Id: 15

#### Source ID: 3

### [ Dangerous JS Functions ](https://www.zaproxy.org/docs/alerts/10110/)



##### Low (Low)

### Description

A dangerous JS function seems to be in use that would leave the site vulnerable.

* URL: https://as-devsecops.azurewebsites.net/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `bypassSecurityTrustHtml`
* URL: https://as-devsecops.azurewebsites.net/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `bypassSecurityTrustHtml`

Instances: 2

### Solution

See the references for security advice on the use of these functions.

### Reference


* [ https://angular.io/guide/security ](https://angular.io/guide/security)


#### CWE Id: [ 749 ](https://cwe.mitre.org/data/definitions/749.html)


#### Source ID: 3

### [ Deprecated Feature Policy Header Set ](https://www.zaproxy.org/docs/alerts/10063/)



##### Low (Medium)

### Description

The header has now been renamed to Permissions-Policy. 

* URL: https://as-devsecops.azurewebsites.net
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Feature-Policy`
* URL: https://as-devsecops.azurewebsites.net/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Feature-Policy`
* URL: https://as-devsecops.azurewebsites.net/ftp
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Feature-Policy`
* URL: https://as-devsecops.azurewebsites.net/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Feature-Policy`
* URL: https://as-devsecops.azurewebsites.net/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Feature-Policy`
* URL: https://as-devsecops.azurewebsites.net/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Feature-Policy`
* URL: https://as-devsecops.azurewebsites.net/sitemap.xml
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Feature-Policy`
* URL: https://as-devsecops.azurewebsites.net/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Feature-Policy`

Instances: 8

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
* URL: https://as-devsecops.azurewebsites.net/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/robots.txt
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/sitemap.xml
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``

Instances: 11

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

### [ Timestamp Disclosure - Unix ](https://www.zaproxy.org/docs/alerts/10096/)



##### Low (Low)

### Description

A timestamp was disclosed by the application/web server - Unix

* URL: https://as-devsecops.azurewebsites.net/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1734944650`

Instances: 1

### Solution

Manually confirm that the timestamp data is not sensitive, and that the data cannot be aggregated to disclose exploitable patterns.

### Reference


* [ http://projects.webappsec.org/w/page/13246936/Information%20Leakage ](http://projects.webappsec.org/w/page/13246936/Information%20Leakage)


#### CWE Id: [ 200 ](https://cwe.mitre.org/data/definitions/200.html)


#### WASC Id: 13

#### Source ID: 3

### [ Base64 Disclosure ](https://www.zaproxy.org/docs/alerts/10094/)



##### Informational (Medium)

### Description

Base64 encoded data was disclosed by the application/web server. Note: in the interests of performance not all base64 strings in the response were analyzed individually, the entire response should be looked at by the analyst/security team/developer(s).

* URL: https://as-devsecops.azurewebsites.net/ftp
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAMAAAAoLQ9TAAAABGdBTUEAALGPC/xhBQAAAWtQTFRFAAAA/PPQ9Nhc2q402qQ12qs2/PTX2pg12p81+/LM89NE9dto2q82+/fp2rM22qY39d6U+/bo2qo2/frx/vz32q812qs12qE279SU8c4w9NZP+/LK//367s9y7s925cp0/vzw9t92//342po2/vz25s1579B6+OSO2bQ0/v799NyT8tE79dld8Msm+OrC/vzx79KA2IYs7s6I9d6R4cJe9+OF/PLI/fry79OF/v30//328tWB89RJ8c9p8c0u9eCf//7+9txs6sts5Mdr+++5+u2z/vrv+/fq6cFz8dBs8tA57cpq+OaU9uGs27Y8//799NdX/PbY9uB89unJ//z14sNf+emh+emk+vDc+uys9+OL8dJy89NH+eic8tN5+OaV+OWR9N2n9dtl9t529+KF9+GB9Nue9NdU8tR/9t5y89qW9dpj89iO89eG/vvu2pQ12Y4z/vzy2Ict/vvv48dr/vzz4sNg///+2Igty3PqwQAAAAF0Uk5TAEDm2GYAAACtSURBVBjTY2AgA2iYlJWVhfohBPg0yx38y92dS0pKVOVBAqIi6sb2vsWWpfrFeTI8QAEhYQEta28nCwM1OVleZqCAmKCEkUdwYWmhQnFeOStQgL9cySqkNNDHVJGbiY0FKCCuYuYSGRsV5KgjxcXIARRQNncNj09JTgqw0ZbkZAcK5LuFJaRmZqfHeNnpSucDBQoiEtOycnIz4qI9bfUKQA6pKKqAgqIKQyK8BgAZ5yfODmnHrQAAAABJRU5ErkJggg==`
* URL: https://as-devsecops.azurewebsites.net/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `com/forms/d/e/1FAIpQLSdaNEuz0dzFA2sexCa0AJ4QOb2OYdEL04eQOLFD2Y4T-BW6ag/viewform`
* URL: https://as-devsecops.azurewebsites.net/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ`

Instances: 3

### Solution

Manually confirm that the Base64 data does not leak sensitive information, and that the data cannot be aggregated/used to exploit other vulnerabilities.

### Reference


* [ http://projects.webappsec.org/w/page/13246936/Information%20Leakage ](http://projects.webappsec.org/w/page/13246936/Information%20Leakage)


#### CWE Id: [ 200 ](https://cwe.mitre.org/data/definitions/200.html)


#### WASC Id: 13

#### Source ID: 3

### [ Information Disclosure - Suspicious Comments ](https://www.zaproxy.org/docs/alerts/10027/)



##### Informational (Low)

### Description

The response appears to contain suspicious comments which may help an attacker. Note: Matches made within script blocks or files are against the entire content not only comments.

* URL: https://as-devsecops.azurewebsites.net/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `query`
* URL: https://as-devsecops.azurewebsites.net/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `query`

Instances: 2

### Solution

Remove all comments that return information that may help an attacker and fix any underlying problems they refer to.

### Reference



#### CWE Id: [ 200 ](https://cwe.mitre.org/data/definitions/200.html)


#### WASC Id: 13

#### Source ID: 3

### [ Modern Web Application ](https://www.zaproxy.org/docs/alerts/10109/)



##### Informational (Medium)

### Description

The application appears to be a modern web application. If you need to explore it automatically then the Ajax Spider may well be more effective than the standard one.

* URL: https://as-devsecops.azurewebsites.net
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
* URL: https://as-devsecops.azurewebsites.net/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
* URL: https://as-devsecops.azurewebsites.net/sitemap.xml
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`

Instances: 3

### Solution

This is an informational alert and so no changes are required.

### Reference




#### Source ID: 3

### [ Re-examine Cache-control Directives ](https://www.zaproxy.org/docs/alerts/10015/)



##### Informational (Low)

### Description

The cache-control header has not been set properly or is missing, allowing the browser and proxies to cache content. For static assets like css, js, or image files this might be intended, however, the resources should be reviewed to ensure that no sensitive content will be cached.

* URL: https://as-devsecops.azurewebsites.net
  * Method: `GET`
  * Parameter: `cache-control`
  * Attack: ``
  * Evidence: `public, max-age=0`
* URL: https://as-devsecops.azurewebsites.net/
  * Method: `GET`
  * Parameter: `cache-control`
  * Attack: ``
  * Evidence: `public, max-age=0`
* URL: https://as-devsecops.azurewebsites.net/ftp
  * Method: `GET`
  * Parameter: `cache-control`
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/robots.txt
  * Method: `GET`
  * Parameter: `cache-control`
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/sitemap.xml
  * Method: `GET`
  * Parameter: `cache-control`
  * Attack: ``
  * Evidence: `public, max-age=0`

Instances: 5

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

* URL: https://as-devsecops.azurewebsites.net/
  * Method: `GET`
  * Parameter: `Sec-Fetch-Dest`
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/favicon_js.ico
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

* URL: https://as-devsecops.azurewebsites.net/
  * Method: `GET`
  * Parameter: `Sec-Fetch-Mode`
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/favicon_js.ico
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

* URL: https://as-devsecops.azurewebsites.net/
  * Method: `GET`
  * Parameter: `Sec-Fetch-Site`
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/favicon_js.ico
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

* URL: https://as-devsecops.azurewebsites.net/
  * Method: `GET`
  * Parameter: `Sec-Fetch-User`
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/favicon_js.ico
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

### [ Storable and Cacheable Content ](https://www.zaproxy.org/docs/alerts/10049/)



##### Informational (Medium)

### Description

The response contents are storable by caching components such as proxy servers, and may be retrieved directly from the cache, rather than from the origin server by the caching servers, in response to similar requests from other users.  If the response data is sensitive, personal or user-specific, this may result in sensitive information being leaked. In some cases, this may even result in a user gaining complete control of the session of another user, depending on the configuration of the caching components in use in their environment. This is primarily an issue where "shared" caching servers such as "proxy" caches are configured on the local network. This configuration is typically found in corporate or educational environments, for instance.

* URL: https://as-devsecops.azurewebsites.net/ftp
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/robots.txt
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``

Instances: 2

### Solution

Validate that the response does not contain sensitive, personal or user-specific information.  If it does, consider the use of the following HTTP response headers, to limit, or prevent the content being stored and retrieved from the cache by another user:
Cache-Control: no-cache, no-store, must-revalidate, private
Pragma: no-cache
Expires: 0
This configuration directs both HTTP 1.0 and HTTP 1.1 compliant caching servers to not store the response, and to not retrieve the response (without validation) from the cache, in response to a similar request. 

### Reference


* [ https://tools.ietf.org/html/rfc7234 ](https://tools.ietf.org/html/rfc7234)
* [ https://tools.ietf.org/html/rfc7231 ](https://tools.ietf.org/html/rfc7231)
* [ http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html (obsoleted by rfc7234) ](http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html (obsoleted by rfc7234))


#### CWE Id: [ 524 ](https://cwe.mitre.org/data/definitions/524.html)


#### WASC Id: 13

#### Source ID: 3

### [ Storable but Non-Cacheable Content ](https://www.zaproxy.org/docs/alerts/10049/)



##### Informational (Medium)

### Description

The response contents are storable by caching components such as proxy servers, but will not be retrieved directly from the cache, without validating the request upstream, in response to similar requests from other users. 

* URL: https://as-devsecops.azurewebsites.net
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `max-age=0`
* URL: https://as-devsecops.azurewebsites.net/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `max-age=0`
* URL: https://as-devsecops.azurewebsites.net/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `max-age=0`
* URL: https://as-devsecops.azurewebsites.net/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `max-age=0`
* URL: https://as-devsecops.azurewebsites.net/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `max-age=0`
* URL: https://as-devsecops.azurewebsites.net/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `max-age=0`
* URL: https://as-devsecops.azurewebsites.net/sitemap.xml
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `max-age=0`
* URL: https://as-devsecops.azurewebsites.net/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `max-age=0`
* URL: https://as-devsecops.azurewebsites.net/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `max-age=0`

Instances: 9

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
* URL: https://as-devsecops.azurewebsites.net/assets
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public
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
* URL: https://as-devsecops.azurewebsites.net/ftp/acquisitions.md
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/acquisitions.md
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/acquisitions.md
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/acquisitions.md
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/acquisitions.md
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/acquisitions.md
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/acquisitions.md
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/acquisitions.md
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/acquisitions.md
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/acquisitions.md
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/acquisitions.md
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/acquisitions.md
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/announcement_encrypted.md
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/announcement_encrypted.md
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/announcement_encrypted.md
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/announcement_encrypted.md
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/announcement_encrypted.md
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/announcement_encrypted.md
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/announcement_encrypted.md
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/announcement_encrypted.md
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/announcement_encrypted.md
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/announcement_encrypted.md
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/announcement_encrypted.md
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/announcement_encrypted.md
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/eastere.gg
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/eastere.gg
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/eastere.gg
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/eastere.gg
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/eastere.gg
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/eastere.gg
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/eastere.gg
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/eastere.gg
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/eastere.gg
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/eastere.gg
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/eastere.gg
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/eastere.gg
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/encrypt.pyc
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/encrypt.pyc
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/encrypt.pyc
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/encrypt.pyc
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/encrypt.pyc
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/encrypt.pyc
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/encrypt.pyc
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/encrypt.pyc
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/encrypt.pyc
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/encrypt.pyc
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/encrypt.pyc
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/encrypt.pyc
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/incident-support.kdbx
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/incident-support.kdbx
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/incident-support.kdbx
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/incident-support.kdbx
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/incident-support.kdbx
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/incident-support.kdbx
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/incident-support.kdbx
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/incident-support.kdbx
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/incident-support.kdbx
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/incident-support.kdbx
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/incident-support.kdbx
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/incident-support.kdbx
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/legal.md
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/legal.md
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/legal.md
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/legal.md
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/legal.md
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/legal.md
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/legal.md
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/legal.md
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/legal.md
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/legal.md
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/legal.md
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/legal.md
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantine
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantine
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantine
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantine
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantine
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantine
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantine
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantine
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantine
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantine
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantine
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantine
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/suspicious_errors.yml
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/suspicious_errors.yml
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/suspicious_errors.yml
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/suspicious_errors.yml
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/suspicious_errors.yml
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/suspicious_errors.yml
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/suspicious_errors.yml
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/suspicious_errors.yml
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/suspicious_errors.yml
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/suspicious_errors.yml
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/suspicious_errors.yml
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/suspicious_errors.yml
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

Instances: 168

### Solution



### Reference


* [ https://owasp.org/wstg ](https://owasp.org/wstg)



#### Source ID: 1


