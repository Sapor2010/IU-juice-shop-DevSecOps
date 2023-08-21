# ZAP Scanning Report


## Summary of Alerts

| Risk Level | Number of Alerts |
| --- | --- |
| High | 1 |
| Medium | 10 |
| Low | 7 |
| Informational | 13 |




## Alerts

| Name | Risk Level | Number of Instances |
| --- | --- | --- |
| SQL Injection - SQLite | High | 1 |
| Backup File Disclosure | Medium | 31 |
| Bypassing 403 | Medium | 3 |
| CORS Misconfiguration | Medium | 196 |
| Content Security Policy (CSP) Header Not Set | Medium | 11 |
| Cross-Domain Misconfiguration | Medium | 11 |
| Missing Anti-clickjacking Header | Medium | 12 |
| Proxy Disclosure | Medium | 200 |
| Session ID in URL Rewrite | Medium | 12 |
| Vulnerable JS Library | Medium | 1 |
| Web Cache Deception | Medium | 7 |
| Cross-Domain JavaScript Source File Inclusion | Low | 10 |
| Dangerous JS Functions | Low | 3 |
| Deprecated Feature Policy Header Set | Low | 11 |
| Private IP Disclosure | Low | 1 |
| Strict-Transport-Security Header Not Set | Low | 11 |
| Timestamp Disclosure - Unix | Low | 3 |
| X-Content-Type-Options Header Missing | Low | 12 |
| Base64 Disclosure | Informational | 10 |
| Cookie Slack Detector | Informational | 100 |
| Information Disclosure - Suspicious Comments | Informational | 4 |
| Modern Web Application | Informational | 11 |
| Re-examine Cache-control Directives | Informational | 11 |
| Retrieved from Cache | Informational | 12 |
| Sec-Fetch-Dest Header is Missing | Informational | 3 |
| Sec-Fetch-Mode Header is Missing | Informational | 3 |
| Sec-Fetch-Site Header is Missing | Informational | 3 |
| Sec-Fetch-User Header is Missing | Informational | 3 |
| Storable and Cacheable Content | Informational | 1 |
| Storable but Non-Cacheable Content | Informational | 10 |
| User Agent Fuzzer | Informational | 868 |




## Alert Detail



### [ SQL Injection - SQLite ](https://www.zaproxy.org/docs/alerts/40018/)



##### High (Medium)

### Description

SQL injection may be possible.

* URL: https://as-devsecops.azurewebsites.net/rest/products/search%3Fq=%2527%2528
  * Method: `GET`
  * Parameter: `q`
  * Attack: `'(`
  * Evidence: `SQLITE_ERROR`

Instances: 1

### Solution

Do not trust client side input, even if there is client side validation in place.
In general, type check all data on the server side.
If the application uses JDBC, use PreparedStatement or CallableStatement, with parameters passed by '?'
If the application uses ASP, use ADO Command Objects with strong type checking and parameterized queries.
If database Stored Procedures can be used, use them.
Do *not* concatenate strings into queries in the stored procedure, or use 'exec', 'exec immediate', or equivalent functionality!
Do not create dynamic SQL queries using simple string concatenation.
Escape all data received from the client.
Apply an 'allow list' of allowed characters, or a 'deny list' of disallowed characters in user input.
Apply the principle of least privilege by using the least privileged database user possible.
In particular, avoid using the 'sa' or 'db-owner' database users. This does not eliminate SQL injection, but minimizes its impact.
Grant the minimum database access that is necessary for the application.

### Reference


* [ https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html ](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)


#### CWE Id: [ 89 ](https://cwe.mitre.org/data/definitions/89.html)


#### WASC Id: 19

#### Source ID: 1

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
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantine%2520-%2520Copy%2520(2&29/juicy_malware_linux_amd_64.url
  * Method: `GET`
  * Parameter: ``
  * Attack: `https://as-devsecops.azurewebsites.net/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_linux_amd_64.url`
  * Evidence: `A backup of [https://as-devsecops.azurewebsites.net/ftp/quarantine/juicy_malware_linux_amd_64.url] is available at [https://as-devsecops.azurewebsites.net/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_linux_amd_64.url]`
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantine%2520-%2520Copy%2520(2&29/juicy_malware_linux_arm_64.url
  * Method: `GET`
  * Parameter: ``
  * Attack: `https://as-devsecops.azurewebsites.net/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_linux_arm_64.url`
  * Evidence: `A backup of [https://as-devsecops.azurewebsites.net/ftp/quarantine/juicy_malware_linux_arm_64.url] is available at [https://as-devsecops.azurewebsites.net/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_linux_arm_64.url]`
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantine%2520-%2520Copy%2520(2&29/juicy_malware_macos_64.url
  * Method: `GET`
  * Parameter: ``
  * Attack: `https://as-devsecops.azurewebsites.net/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_macos_64.url`
  * Evidence: `A backup of [https://as-devsecops.azurewebsites.net/ftp/quarantine/juicy_malware_macos_64.url] is available at [https://as-devsecops.azurewebsites.net/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_macos_64.url]`
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantine%2520-%2520Copy%2520(2&29/juicy_malware_windows_64.exe.url
  * Method: `GET`
  * Parameter: ``
  * Attack: `https://as-devsecops.azurewebsites.net/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_windows_64.exe.url`
  * Evidence: `A backup of [https://as-devsecops.azurewebsites.net/ftp/quarantine/juicy_malware_windows_64.exe.url] is available at [https://as-devsecops.azurewebsites.net/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_windows_64.exe.url]`
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantine%2520-%2520Copy%2520(3&29
  * Method: `GET`
  * Parameter: ``
  * Attack: `https://as-devsecops.azurewebsites.net/ftp/quarantine%20-%20Copy%20(3)`
  * Evidence: `A backup of [https://as-devsecops.azurewebsites.net/ftp/quarantine] is available at [https://as-devsecops.azurewebsites.net/ftp/quarantine%20-%20Copy%20(3)]`
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantine%2520-%2520Copy%2520(3&29/juicy_malware_linux_amd_64.url
  * Method: `GET`
  * Parameter: ``
  * Attack: `https://as-devsecops.azurewebsites.net/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_linux_amd_64.url`
  * Evidence: `A backup of [https://as-devsecops.azurewebsites.net/ftp/quarantine/juicy_malware_linux_amd_64.url] is available at [https://as-devsecops.azurewebsites.net/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_linux_amd_64.url]`
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantine%2520-%2520Copy%2520(3&29/juicy_malware_linux_arm_64.url
  * Method: `GET`
  * Parameter: ``
  * Attack: `https://as-devsecops.azurewebsites.net/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_linux_arm_64.url`
  * Evidence: `A backup of [https://as-devsecops.azurewebsites.net/ftp/quarantine/juicy_malware_linux_arm_64.url] is available at [https://as-devsecops.azurewebsites.net/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_linux_arm_64.url]`
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantine%2520-%2520Copy%2520(3&29/juicy_malware_macos_64.url
  * Method: `GET`
  * Parameter: ``
  * Attack: `https://as-devsecops.azurewebsites.net/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_macos_64.url`
  * Evidence: `A backup of [https://as-devsecops.azurewebsites.net/ftp/quarantine/juicy_malware_macos_64.url] is available at [https://as-devsecops.azurewebsites.net/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_macos_64.url]`
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantine%2520-%2520Copy%2520(3&29/juicy_malware_windows_64.exe.url
  * Method: `GET`
  * Parameter: ``
  * Attack: `https://as-devsecops.azurewebsites.net/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_windows_64.exe.url`
  * Evidence: `A backup of [https://as-devsecops.azurewebsites.net/ftp/quarantine/juicy_malware_windows_64.exe.url] is available at [https://as-devsecops.azurewebsites.net/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_windows_64.exe.url]`
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantine%2520-%2520Copy/juicy_malware_linux_amd_64.url
  * Method: `GET`
  * Parameter: ``
  * Attack: `https://as-devsecops.azurewebsites.net/ftp/quarantine%20-%20Copy/juicy_malware_linux_amd_64.url`
  * Evidence: `A backup of [https://as-devsecops.azurewebsites.net/ftp/quarantine/juicy_malware_linux_amd_64.url] is available at [https://as-devsecops.azurewebsites.net/ftp/quarantine%20-%20Copy/juicy_malware_linux_amd_64.url]`
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantine%2520-%2520Copy/juicy_malware_linux_arm_64.url
  * Method: `GET`
  * Parameter: ``
  * Attack: `https://as-devsecops.azurewebsites.net/ftp/quarantine%20-%20Copy/juicy_malware_linux_arm_64.url`
  * Evidence: `A backup of [https://as-devsecops.azurewebsites.net/ftp/quarantine/juicy_malware_linux_arm_64.url] is available at [https://as-devsecops.azurewebsites.net/ftp/quarantine%20-%20Copy/juicy_malware_linux_arm_64.url]`
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantine%2520-%2520Copy/juicy_malware_macos_64.url
  * Method: `GET`
  * Parameter: ``
  * Attack: `https://as-devsecops.azurewebsites.net/ftp/quarantine%20-%20Copy/juicy_malware_macos_64.url`
  * Evidence: `A backup of [https://as-devsecops.azurewebsites.net/ftp/quarantine/juicy_malware_macos_64.url] is available at [https://as-devsecops.azurewebsites.net/ftp/quarantine%20-%20Copy/juicy_malware_macos_64.url]`
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantine%2520-%2520Copy/juicy_malware_windows_64.exe.url
  * Method: `GET`
  * Parameter: ``
  * Attack: `https://as-devsecops.azurewebsites.net/ftp/quarantine%20-%20Copy/juicy_malware_windows_64.exe.url`
  * Evidence: `A backup of [https://as-devsecops.azurewebsites.net/ftp/quarantine/juicy_malware_windows_64.exe.url] is available at [https://as-devsecops.azurewebsites.net/ftp/quarantine%20-%20Copy/juicy_malware_windows_64.exe.url]`
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
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantinebackup/juicy_malware_linux_amd_64.url
  * Method: `GET`
  * Parameter: ``
  * Attack: `https://as-devsecops.azurewebsites.net/ftp/quarantinebackup/juicy_malware_linux_amd_64.url`
  * Evidence: `A backup of [https://as-devsecops.azurewebsites.net/ftp/quarantine/juicy_malware_linux_amd_64.url] is available at [https://as-devsecops.azurewebsites.net/ftp/quarantinebackup/juicy_malware_linux_amd_64.url]`
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantinebackup/juicy_malware_linux_arm_64.url
  * Method: `GET`
  * Parameter: ``
  * Attack: `https://as-devsecops.azurewebsites.net/ftp/quarantinebackup/juicy_malware_linux_arm_64.url`
  * Evidence: `A backup of [https://as-devsecops.azurewebsites.net/ftp/quarantine/juicy_malware_linux_arm_64.url] is available at [https://as-devsecops.azurewebsites.net/ftp/quarantinebackup/juicy_malware_linux_arm_64.url]`
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantinebackup/juicy_malware_macos_64.url
  * Method: `GET`
  * Parameter: ``
  * Attack: `https://as-devsecops.azurewebsites.net/ftp/quarantinebackup/juicy_malware_macos_64.url`
  * Evidence: `A backup of [https://as-devsecops.azurewebsites.net/ftp/quarantine/juicy_malware_macos_64.url] is available at [https://as-devsecops.azurewebsites.net/ftp/quarantinebackup/juicy_malware_macos_64.url]`
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantinebackup/juicy_malware_windows_64.exe.url
  * Method: `GET`
  * Parameter: ``
  * Attack: `https://as-devsecops.azurewebsites.net/ftp/quarantinebackup/juicy_malware_windows_64.exe.url`
  * Evidence: `A backup of [https://as-devsecops.azurewebsites.net/ftp/quarantine/juicy_malware_windows_64.exe.url] is available at [https://as-devsecops.azurewebsites.net/ftp/quarantinebackup/juicy_malware_windows_64.exe.url]`
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantine~
  * Method: `GET`
  * Parameter: ``
  * Attack: `https://as-devsecops.azurewebsites.net/ftp/quarantine~`
  * Evidence: `A backup of [https://as-devsecops.azurewebsites.net/ftp/quarantine] is available at [https://as-devsecops.azurewebsites.net/ftp/quarantine~]`

Instances: 31

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
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ae.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/Challenges
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/Challenges/%3Fname=Score%2520Board
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/Feedbacks
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/Feedbacks/
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/Quantitys
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/Quantitys/
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/SecurityQuestions
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/SecurityQuestions/
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/i18n
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/i18n/en.json
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/carousel
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/carousel/1.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/carousel/2.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/carousel/3.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/carousel/4.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/carousel/5.png
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/carousel/6.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/carousel/7.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/hackingInstructor.png
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/JuiceShop_Logo.png
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/products
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/products/apple_juice.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/products/apple_pressings.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/products/artwork2.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/products/banana_juice.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/products/carrot_juice.jpeg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/products/eggfruit_juice.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/products/fan_facemask.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/products/fruit_press.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/products/green_smoothie.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/products/lemon_juice.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/products/melon_bike.jpeg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/products/no-results.png
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/products/permafrost.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/uploads
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/uploads/%25F0%259F%2598%25BC-
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/uploads/favorite-hiking-place.png
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/uploads/IMG_4253.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/uploads/magn(et&29ificent!-1571814229653.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/uploads/my-rare-collectors-item!-%255B%25CC%25B2%25CC%2585$%25CC%25B2%25CC%2585(%25CC%25B2%25CC%2585-%25CD%25A1%25C2%25B0-%25CD%259C%25CA%2596-%25CD%25A1%25C2%25B0%25CC%25B2%25CC%2585&29%25CC%25B2%25CC%2585$%25CC%25B2%25CC%2585%255D-1572603645543.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/az.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/bg.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/br.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ch.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/cn.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/cz.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/de.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/dk.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ee.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/es-ct.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/es.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/favicon.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/fi.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/font-mfizz.woff
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/fr.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/acquisitions.md
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/announcement_encrypted.md
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/eastere.gg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/encrypt.pyc
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/incident-support.kdbx
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/legal.md
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantine
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantine/juicy_malware_linux_amd_64.url
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantine/juicy_malware_linux_arm_64.url
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantine/juicy_malware_macos_64.url
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantine/juicy_malware_windows_64.exe.url
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/suspicious_errors.yml
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/gb.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ge.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/gr.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/hk.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/assets
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/assets/public
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/fileServer.js:39:13
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/fileServer.js:55:18
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/assets
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/assets/public
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:280:10
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:286:9
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:328:13
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:365:14
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:376:14
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:421:3
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/layer.js:95:5
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/assets
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/assets/public
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/index.js:145:39
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/hu.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/id.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ie.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/il.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/in.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/it.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/jp.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/kr.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/lv.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/MaterialIcons-Regular.woff2
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/mm.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/nl.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/no.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/pl.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/pt.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/admin
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/admin/application-configuration
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/admin/application-version
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/captcha
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/captcha/
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/languages
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/memories
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/memories/
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/products
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/products/search%3Fq=
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/user
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/user/whoami
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ro.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/robots.txt
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ru.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/se.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/si.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/sitemap.xml
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/th.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/tn.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/tr.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/tutorial.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/tw.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ua.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/us.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: https://VUyhTq0y.com`
  * Evidence: ``

Instances: 196

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
* URL: https://as-devsecops.azurewebsites.net/ftp/eastere.gg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/encrypt.pyc
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/suspicious_errors.yml
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/fileServer.js:39:13
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/fileServer.js:55:18
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:286:9
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:328:13
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/sitemap.xml
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``

Instances: 11

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
* URL: https://as-devsecops.azurewebsites.net/ftp/acquisitions.md
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

### [ Missing Anti-clickjacking Header ](https://www.zaproxy.org/docs/alerts/10020/)



##### Medium (Medium)

### Description

The response does not include either Content-Security-Policy with 'frame-ancestors' directive or X-Frame-Options to protect against 'ClickJacking' attacks.

* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=OdckamQ&sid=sHzyCZgWPwS3JxMSAAAa
  * Method: `POST`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=OdckcaR&sid=jI49TVsr8jeIx6AIAAAc
  * Method: `POST`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=OdckeDz&sid=2vIpDrkbZcZXPjmNAAAe
  * Method: `POST`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=OdckgCO&sid=UNHnA3ilNwCFizDmAAAg
  * Method: `POST`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=Odckger&sid=eHUecxOU_WFxlPt8AAAi
  * Method: `POST`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=Odckhgc&sid=LnDrZWCVYZqVYbxcAAAk
  * Method: `POST`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=Odckiia&sid=XUVx5b6c7RAkrEVMAAAm
  * Method: `POST`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=OdckjFw&sid=LSCnyExp2ws6Mig0AAAo
  * Method: `POST`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=Odckjvj&sid=fAWqOmlDImCLh2j8AAAq
  * Method: `POST`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=OdckkzX&sid=dEpDVKt7diZdpwJrAAAs
  * Method: `POST`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=OdckmAb&sid=uJx-gqobMn8fS5JRAAAu
  * Method: `POST`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=OdckZRY&sid=UzkL-OiyHQUfQ7XOAAAY
  * Method: `POST`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``

Instances: 12

### Solution

Modern Web browsers support the Content-Security-Policy and X-Frame-Options HTTP headers. Ensure one of them is set on all web pages returned by your site/app.
If you expect the page to be framed only by pages on your server (e.g. it's part of a FRAMESET) then you'll want to use SAMEORIGIN, otherwise if you never expect the page to be framed, you should use DENY. Alternatively consider implementing Content Security Policy's "frame-ancestors" directive.

### Reference


* [ https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options ](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options)


#### CWE Id: [ 1021 ](https://cwe.mitre.org/data/definitions/1021.html)


#### WASC Id: 15

#### Source ID: 3

### [ Proxy Disclosure ](https://www.zaproxy.org/docs/alerts/40025/)



##### Medium (Medium)

### Description

1 proxy server(s) were detected or fingerprinted. This information helps a potential attacker to determine 
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
* URL: https://as-devsecops.azurewebsites.net/ae.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/Challenges
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/Challenges/%3Fname=Score%2520Board
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/Feedbacks
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/Feedbacks/
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/Quantitys
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/Quantitys/
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/SecurityQuestions
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/SecurityQuestions/
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/i18n
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/i18n/en.json
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
* URL: https://as-devsecops.azurewebsites.net/assets/public/images
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/carousel
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/carousel/1.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/carousel/2.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/carousel/3.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/carousel/4.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/carousel/5.png
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/carousel/6.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/carousel/7.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/hackingInstructor.png
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/JuiceShop_Logo.png
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/products
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/products/apple_juice.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/products/apple_pressings.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/products/artwork2.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/products/banana_juice.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/products/carrot_juice.jpeg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/products/eggfruit_juice.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/products/fan_facemask.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/products/fruit_press.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/products/green_smoothie.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/products/lemon_juice.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/products/melon_bike.jpeg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/products/no-results.png
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/products/permafrost.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/uploads
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/uploads/%25F0%259F%2598%25BC-
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/uploads/favorite-hiking-place.png
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/uploads/IMG_4253.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/uploads/magn(et&29ificent!-1571814229653.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/uploads/my-rare-collectors-item!-%255B%25CC%25B2%25CC%2585$%25CC%25B2%25CC%2585(%25CC%25B2%25CC%2585-%25CD%25A1%25C2%25B0-%25CD%259C%25CA%2596-%25CD%25A1%25C2%25B0%25CC%25B2%25CC%2585&29%25CC%25B2%25CC%2585$%25CC%25B2%25CC%2585%255D-1572603645543.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/az.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/bg.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/br.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ch.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/cn.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/cz.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/de.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/dk.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ee.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/es-ct.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/es.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/favicon.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/fi.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/font-mfizz.woff
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/fr.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/
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
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantine/juicy_malware_linux_amd_64.url
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantine/juicy_malware_linux_arm_64.url
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantine/juicy_malware_macos_64.url
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantine/juicy_malware_windows_64.exe.url
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/suspicious_errors.yml
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/gb.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ge.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/gr.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/hk.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/assets
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/assets/public
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/fileServer.js:39:13
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/fileServer.js:55:18
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/assets
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/assets/public
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:280:10
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:286:9
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:328:13
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:365:14
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:376:14
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:421:3
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/layer.js:95:5
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/assets
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/assets/public
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/index.js:145:39
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/hu.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/id.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ie.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/il.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/in.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/it.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/jp.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/kr.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/lv.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/MaterialIcons-Regular.woff2
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/mm.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/nl.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/no.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/pl.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/pt.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/admin
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/admin/application-configuration
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/admin/application-version
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/captcha
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/captcha/
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/languages
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/memories
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/memories/
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/products
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/products/search%3Fq=
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/user
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/user/whoami
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ro.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/robots.txt
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ru.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/se.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/si.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/sitemap.xml
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=Odck-Mv
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=Odck-mz&sid=Sc5a5zaBuuqEbUooAABG
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=websocket&sid=UzkL-OiyHQUfQ7XOAAAY
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/th.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/tn.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/tr.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/tutorial.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/tw.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ua.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/us.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=Odck-fs&sid=gDtn5Cwuew9HY8g4AABI
  * Method: `POST`
  * Parameter: ``
  * Attack: `TRACE, OPTIONS methods with 'Max-Forwards' header. TRACK method.`
  * Evidence: ``

Instances: 200

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

### [ Session ID in URL Rewrite ](https://www.zaproxy.org/docs/alerts/3/)



##### Medium (High)

### Description

URL rewrite is used to track user session ID. The session ID may be disclosed via cross-site referer header. In addition, the session ID might be stored in browser history or server logs.

* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=OdckamT&sid=sHzyCZgWPwS3JxMSAAAa
  * Method: `GET`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `sHzyCZgWPwS3JxMSAAAa`
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=Odckar4&sid=sHzyCZgWPwS3JxMSAAAa
  * Method: `GET`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `sHzyCZgWPwS3JxMSAAAa`
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=Odckcah&sid=jI49TVsr8jeIx6AIAAAc
  * Method: `GET`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `jI49TVsr8jeIx6AIAAAc`
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=OdckciF&sid=jI49TVsr8jeIx6AIAAAc
  * Method: `GET`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `jI49TVsr8jeIx6AIAAAc`
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=OdckZRb&sid=UzkL-OiyHQUfQ7XOAAAY
  * Method: `GET`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `UzkL-OiyHQUfQ7XOAAAY`
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=websocket&sid=2vIpDrkbZcZXPjmNAAAe
  * Method: `GET`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `2vIpDrkbZcZXPjmNAAAe`
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=websocket&sid=jI49TVsr8jeIx6AIAAAc
  * Method: `GET`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `jI49TVsr8jeIx6AIAAAc`
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=websocket&sid=sHzyCZgWPwS3JxMSAAAa
  * Method: `GET`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `sHzyCZgWPwS3JxMSAAAa`
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=websocket&sid=UzkL-OiyHQUfQ7XOAAAY
  * Method: `GET`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `UzkL-OiyHQUfQ7XOAAAY`
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=OdckamQ&sid=sHzyCZgWPwS3JxMSAAAa
  * Method: `POST`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `sHzyCZgWPwS3JxMSAAAa`
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=OdckcaR&sid=jI49TVsr8jeIx6AIAAAc
  * Method: `POST`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `jI49TVsr8jeIx6AIAAAc`
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=OdckZRY&sid=UzkL-OiyHQUfQ7XOAAAY
  * Method: `POST`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `UzkL-OiyHQUfQ7XOAAAY`

Instances: 12

### Solution

For secure content, put session ID in a cookie. To be even more secure consider using a combination of cookie and URL rewrite.

### Reference


* [ http://seclists.org/lists/webappsec/2002/Oct-Dec/0111.html ](http://seclists.org/lists/webappsec/2002/Oct-Dec/0111.html)


#### CWE Id: [ 200 ](https://cwe.mitre.org/data/definitions/200.html)


#### WASC Id: 13

#### Source ID: 3

### [ Vulnerable JS Library ](https://www.zaproxy.org/docs/alerts/10003/)



##### Medium (Medium)

### Description

The identified library jquery, version 2.2.4 is vulnerable.

* URL: https://cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `/2.2.4/jquery.min.js`

Instances: 1

### Solution

Please upgrade to the latest version of jquery.

### Reference


* [ https://github.com/jquery/jquery/issues/2432 ](https://github.com/jquery/jquery/issues/2432)
* [ http://blog.jquery.com/2016/01/08/jquery-2-2-and-1-12-released/ ](http://blog.jquery.com/2016/01/08/jquery-2-2-and-1-12-released/)
* [ http://research.insecurelabs.org/jquery/test/ ](http://research.insecurelabs.org/jquery/test/)
* [ https://blog.jquery.com/2019/04/10/jquery-3-4-0-released/ ](https://blog.jquery.com/2019/04/10/jquery-3-4-0-released/)
* [ https://nvd.nist.gov/vuln/detail/CVE-2019-11358 ](https://nvd.nist.gov/vuln/detail/CVE-2019-11358)
* [ https://nvd.nist.gov/vuln/detail/CVE-2015-9251 ](https://nvd.nist.gov/vuln/detail/CVE-2015-9251)
* [ https://github.com/jquery/jquery/commit/753d591aea698e57d6db58c9f722cd0808619b1b ](https://github.com/jquery/jquery/commit/753d591aea698e57d6db58c9f722cd0808619b1b)
* [ https://bugs.jquery.com/ticket/11974 ](https://bugs.jquery.com/ticket/11974)
* [ https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/ ](https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/)
* [ https://github.com/jquery/jquery.com/issues/162 ](https://github.com/jquery/jquery.com/issues/162)


#### CWE Id: [ 829 ](https://cwe.mitre.org/data/definitions/829.html)


#### Source ID: 3

### [ Web Cache Deception ](https://www.zaproxy.org/docs/alerts/40039/)



##### Medium (Medium)

### Description

Web cache deception may be possible. It may be possible for unauthorised user to view sensitive data on this page.

* URL: https://as-devsecops.azurewebsites.net/assets
  * Method: `GET`
  * Parameter: ``
  * Attack: `/test.css,/test.jpg,/test.js,/test.html,/test.gif,/test.png,/test.svg,/test.php,/test.txt,/test.pdf,/test.asp,`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/i18n
  * Method: `GET`
  * Parameter: ``
  * Attack: `/test.css,/test.jpg,/test.js,/test.html,/test.gif,/test.png,/test.svg,/test.php,/test.txt,/test.pdf,/test.asp,`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public
  * Method: `GET`
  * Parameter: ``
  * Attack: `/test.css,/test.jpg,/test.js,/test.html,/test.gif,/test.png,/test.svg,/test.php,/test.txt,/test.pdf,/test.asp,`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images
  * Method: `GET`
  * Parameter: ``
  * Attack: `/test.css,/test.jpg,/test.js,/test.html,/test.gif,/test.png,/test.svg,/test.php,/test.txt,/test.pdf,/test.asp,`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/carousel
  * Method: `GET`
  * Parameter: ``
  * Attack: `/test.css,/test.jpg,/test.js,/test.html,/test.gif,/test.png,/test.svg,/test.php,/test.txt,/test.pdf,/test.asp,`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/products
  * Method: `GET`
  * Parameter: ``
  * Attack: `/test.css,/test.jpg,/test.js,/test.html,/test.gif,/test.png,/test.svg,/test.php,/test.txt,/test.pdf,/test.asp,`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/uploads
  * Method: `GET`
  * Parameter: ``
  * Attack: `/test.css,/test.jpg,/test.js,/test.html,/test.gif,/test.png,/test.svg,/test.php,/test.txt,/test.pdf,/test.asp,`
  * Evidence: ``

Instances: 7

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
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/fileServer.js:39:13
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/fileServer.js:39:13
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/fileServer.js:55:18
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/fileServer.js:55:18
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

Instances: 10

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
* URL: https://cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `eval`

Instances: 3

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
* URL: https://as-devsecops.azurewebsites.net/ftp/eastere.gg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Feature-Policy`
* URL: https://as-devsecops.azurewebsites.net/ftp/encrypt.pyc
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Feature-Policy`
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/fileServer.js:55:18
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

Instances: 11

### Solution

Ensure that your web server, application server, load balancer, etc. is configured to set the Permissions-Policy header instead of the Feature-Policy header.

### Reference


* [ https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Feature-Policy ](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Feature-Policy)
* [ https://scotthelme.co.uk/goodbye-feature-policy-and-hello-permissions-policy/ ](https://scotthelme.co.uk/goodbye-feature-policy-and-hello-permissions-policy/)


#### CWE Id: [ 16 ](https://cwe.mitre.org/data/definitions/16.html)


#### WASC Id: 15

#### Source ID: 3

### [ Private IP Disclosure ](https://www.zaproxy.org/docs/alerts/2/)



##### Low (Medium)

### Description

A private IP (such as 10.x.x.x, 172.x.x.x, 192.168.x.x) or an Amazon EC2 private hostname (for example, ip-10-0-56-78) has been found in the HTTP response body. This information might be helpful for further attacks targeting internal systems.

* URL: https://as-devsecops.azurewebsites.net/rest/admin/application-configuration
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `192.168.99.100:3000`

Instances: 1

### Solution

Remove the private IP address from the HTTP response body.  For comments, use JSP/ASP/PHP comment instead of HTML/JavaScript comment which can be seen by client browsers.

### Reference


* [ https://tools.ietf.org/html/rfc1918 ](https://tools.ietf.org/html/rfc1918)


#### CWE Id: [ 200 ](https://cwe.mitre.org/data/definitions/200.html)


#### WASC Id: 13

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
* URL: https://as-devsecops.azurewebsites.net/ftp/acquisitions.md
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
* URL: https://as-devsecops.azurewebsites.net/rest/admin/application-configuration
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1969196030`
* URL: https://as-devsecops.azurewebsites.net/rest/admin/application-configuration
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1970691216`

Instances: 3

### Solution

Manually confirm that the timestamp data is not sensitive, and that the data cannot be aggregated to disclose exploitable patterns.

### Reference


* [ http://projects.webappsec.org/w/page/13246936/Information%20Leakage ](http://projects.webappsec.org/w/page/13246936/Information%20Leakage)


#### CWE Id: [ 200 ](https://cwe.mitre.org/data/definitions/200.html)


#### WASC Id: 13

#### Source ID: 3

### [ X-Content-Type-Options Header Missing ](https://www.zaproxy.org/docs/alerts/10021/)



##### Low (Medium)

### Description

The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'. This allows older versions of Internet Explorer and Chrome to perform MIME-sniffing on the response body, potentially causing the response body to be interpreted and displayed as a content type other than the declared content type. Current (early 2014) and legacy versions of Firefox will use the declared content type (if one is set), rather than performing MIME-sniffing.

* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=OdckamT&sid=sHzyCZgWPwS3JxMSAAAa
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=Odckar4&sid=sHzyCZgWPwS3JxMSAAAa
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=OdckaYD
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=Odckcah&sid=jI49TVsr8jeIx6AIAAAc
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=OdckcH3
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=OdckciF&sid=jI49TVsr8jeIx6AIAAAc
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=Odckded
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=OdckZI_
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=OdckZRb&sid=UzkL-OiyHQUfQ7XOAAAY
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=OdckamQ&sid=sHzyCZgWPwS3JxMSAAAa
  * Method: `POST`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=OdckcaR&sid=jI49TVsr8jeIx6AIAAAc
  * Method: `POST`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=OdckZRY&sid=UzkL-OiyHQUfQ7XOAAAY
  * Method: `POST`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``

Instances: 12

### Solution

Ensure that the application/web server sets the Content-Type header appropriately, and that it sets the X-Content-Type-Options header to 'nosniff' for all web pages.
If possible, ensure that the end user uses a standards-compliant and modern web browser that does not perform MIME-sniffing at all, or that can be directed by the web application/web server to not perform MIME-sniffing.

### Reference


* [ http://msdn.microsoft.com/en-us/library/ie/gg622941%28v=vs.85%29.aspx ](http://msdn.microsoft.com/en-us/library/ie/gg622941%28v=vs.85%29.aspx)
* [ https://owasp.org/www-community/Security_Headers ](https://owasp.org/www-community/Security_Headers)


#### CWE Id: [ 693 ](https://cwe.mitre.org/data/definitions/693.html)


#### WASC Id: 15

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
* URL: https://as-devsecops.azurewebsites.net/ftp/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAMAAAAoLQ9TAAAABGdBTUEAALGPC/xhBQAAAWtQTFRFAAAA/PPQ9Nhc2q402qQ12qs2/PTX2pg12p81+/LM89NE9dto2q82+/fp2rM22qY39d6U+/bo2qo2/frx/vz32q812qs12qE279SU8c4w9NZP+/LK//367s9y7s925cp0/vzw9t92//342po2/vz25s1579B6+OSO2bQ0/v799NyT8tE79dld8Msm+OrC/vzx79KA2IYs7s6I9d6R4cJe9+OF/PLI/fry79OF/v30//328tWB89RJ8c9p8c0u9eCf//7+9txs6sts5Mdr+++5+u2z/vrv+/fq6cFz8dBs8tA57cpq+OaU9uGs27Y8//799NdX/PbY9uB89unJ//z14sNf+emh+emk+vDc+uys9+OL8dJy89NH+eic8tN5+OaV+OWR9N2n9dtl9t529+KF9+GB9Nue9NdU8tR/9t5y89qW9dpj89iO89eG/vvu2pQ12Y4z/vzy2Ict/vvv48dr/vzz4sNg///+2Igty3PqwQAAAAF0Uk5TAEDm2GYAAACtSURBVBjTY2AgA2iYlJWVhfohBPg0yx38y92dS0pKVOVBAqIi6sb2vsWWpfrFeTI8QAEhYQEta28nCwM1OVleZqCAmKCEkUdwYWmhQnFeOStQgL9cySqkNNDHVJGbiY0FKCCuYuYSGRsV5KgjxcXIARRQNncNj09JTgqw0ZbkZAcK5LuFJaRmZqfHeNnpSucDBQoiEtOycnIz4qI9bfUKQA6pKKqAgqIKQyK8BgAZ5yfODmnHrQAAAABJRU5ErkJggg==`
* URL: https://as-devsecops.azurewebsites.net/ftp/quarantine
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
* URL: https://cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2BZXcZxXY7ylCyrs5FWnpxJtYXLSDVaNgiLl`
* URL: https://cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `l00cgE8ELALBkCu2KEUxaFAoW52jbIdP2Fag7nLoqlxsBCziCEukaRLRGLaB8BfR`
* URL: https://cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2BBN689g7JybXzol3GIKyZ7eMfnnTwkf8WWKkYQXS4J4qlVhEtYllKVHvWrB8tSkw0rxM5zDoo8uk5w5PTN9N4bbZjYr0X79tGnxX4NofJSJaj`
* URL: https://cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2B6yrraUMzMukQQHhw7GIBWTxB5fWP9s2KU3SF6aG5Hwou1O2TRh9UoSPcvYw8rx6egVYLudDNrXkHSyPa3upqTUSvTORC1AWqm`
* URL: https://cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2Fj46RCPk2EzM27ecRXpJJIAQEgqVcCYOgOUai4kJe`

Instances: 10

### Solution

Manually confirm that the Base64 data does not leak sensitive information, and that the data cannot be aggregated/used to exploit other vulnerabilities.

### Reference


* [ http://projects.webappsec.org/w/page/13246936/Information%20Leakage ](http://projects.webappsec.org/w/page/13246936/Information%20Leakage)


#### CWE Id: [ 200 ](https://cwe.mitre.org/data/definitions/200.html)


#### WASC Id: 13

#### Source ID: 3

### [ Cookie Slack Detector ](https://www.zaproxy.org/docs/alerts/90027/)



##### Informational (Low)

### Description

Repeated GET requests: drop a different cookie each time, followed by normal request with all cookies to stabilize session, compare responses against original baseline GET. This can reveal areas where cookie based authentication/attributes are not actually enforced.

* URL: https://as-devsecops.azurewebsites.net/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ae.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/Challenges
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/Feedbacks
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/Feedbacks/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/Quantitys/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/SecurityQuestions
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/SecurityQuestions/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/i18n/en.json
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/carousel
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/carousel/1.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/carousel/2.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/carousel/3.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/carousel/4.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/carousel/5.png
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/carousel/6.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/carousel/7.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/hackingInstructor.png
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/JuiceShop_Logo.png
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/products
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/products/apple_juice.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/products/apple_pressings.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/products/artwork2.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/products/banana_juice.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/products/carrot_juice.jpeg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/products/eggfruit_juice.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/products/fan_facemask.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/products/fruit_press.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/products/green_smoothie.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/products/lemon_juice.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/products/melon_bike.jpeg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/products/no-results.png
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/products/permafrost.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/uploads
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/uploads/%25F0%259F%2598%25BC-
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/uploads/favorite-hiking-place.png
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/uploads/IMG_4253.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/uploads/magn(et&29ificent!-1571814229653.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/uploads/my-rare-collectors-item!-%255B%25CC%25B2%25CC%2585$%25CC%25B2%25CC%2585(%25CC%25B2%25CC%2585-%25CD%25A1%25C2%25B0-%25CD%259C%25CA%2596-%25CD%25A1%25C2%25B0%25CC%25B2%25CC%2585&29%25CC%25B2%25CC%2585$%25CC%25B2%25CC%2585%255D-1572603645543.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/az.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/bg.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/br.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ch.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/cn.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/cz.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/de.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/dk.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ee.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/es-ct.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/es.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/favicon.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/fi.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/font-mfizz.woff
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/fr.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/legal.md
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/gb.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ge.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/gr.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/hk.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/hu.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/id.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ie.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/il.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/in.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/it.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/jp.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/kr.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/lv.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/mm.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/nl.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/no.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/pl.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/pt.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/admin/application-configuration
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/admin/application-version
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/captcha
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/captcha/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/languages
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/memories
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/memories/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/products/search%3Fq=
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/user
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/user/whoami
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ro.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ru.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/se.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/si.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=Odck-Mv
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=Odck-mz&sid=Sc5a5zaBuuqEbUooAABG
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/th.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/tn.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/tr.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/tutorial.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/tw.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ua.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/us.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=Odck-fs&sid=gDtn5Cwuew9HY8g4AABI
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``

Instances: 100

### Solution



### Reference


* [ http://projects.webappsec.org/Fingerprinting ](http://projects.webappsec.org/Fingerprinting)


#### CWE Id: [ 200 ](https://cwe.mitre.org/data/definitions/200.html)


#### WASC Id: 45

#### Source ID: 1

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
* URL: https://cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `db`
* URL: https://cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `select`

Instances: 4

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
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/fileServer.js:39:13
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/fileServer.js:55:18
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:286:9
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:328:13
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:365:14
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:376:14
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:421:3
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/layer.js:95:5
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
* URL: https://as-devsecops.azurewebsites.net/sitemap.xml
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`

Instances: 11

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
* URL: https://as-devsecops.azurewebsites.net/ftp/acquisitions.md
  * Method: `GET`
  * Parameter: `cache-control`
  * Attack: ``
  * Evidence: `public, max-age=0`
* URL: https://as-devsecops.azurewebsites.net/ftp/announcement_encrypted.md
  * Method: `GET`
  * Parameter: `cache-control`
  * Attack: ``
  * Evidence: `public, max-age=0`
* URL: https://as-devsecops.azurewebsites.net/ftp/legal.md
  * Method: `GET`
  * Parameter: `cache-control`
  * Attack: ``
  * Evidence: `public, max-age=0`
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/fileServer.js:39:13
  * Method: `GET`
  * Parameter: `cache-control`
  * Attack: ``
  * Evidence: `public, max-age=0`
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/fileServer.js:55:18
  * Method: `GET`
  * Parameter: `cache-control`
  * Attack: ``
  * Evidence: `public, max-age=0`
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:328:13
  * Method: `GET`
  * Parameter: `cache-control`
  * Attack: ``
  * Evidence: `public, max-age=0`
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

Instances: 11

### Solution

For secure content, ensure the cache-control HTTP header is set with "no-cache, no-store, must-revalidate". If an asset should be cached consider setting the directives "public, max-age, immutable".

### Reference


* [ https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#web-content-caching ](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#web-content-caching)
* [ https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control ](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control)
* [ https://grayduck.mn/2021/09/13/cache-control-recommendations/ ](https://grayduck.mn/2021/09/13/cache-control-recommendations/)


#### CWE Id: [ 525 ](https://cwe.mitre.org/data/definitions/525.html)


#### WASC Id: 13

#### Source ID: 3

### [ Retrieved from Cache ](https://www.zaproxy.org/docs/alerts/10050/)



##### Informational (Medium)

### Description

The content was retrieved from a shared cache. If the response data is sensitive, personal or user-specific, this may result in sensitive information being leaked. In some cases, this may even result in a user gaining complete control of the session of another user, depending on the configuration of the caching components in use in their environment. This is primarily an issue where caching servers such as "proxy" caches are configured on the local network. This configuration is typically found in corporate or educational environments, for instance. 

* URL: https://cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Age: 10034183`
* URL: https://cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Age: 14812`
* URL: https://cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Age: 5440941`
* URL: https://cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Age: 5440952`
* URL: https://cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Age: 362847`
* URL: https://cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Age: 5458814`
* URL: https://cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Age: 5458825`
* URL: https://cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Age: 5458840`
* URL: https://cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Age: 6312751`
* URL: https://cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Age: 6312762`
* URL: https://cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Age: 746492`
* URL: https://cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Age: 8212661`

Instances: 12

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
* URL: https://as-devsecops.azurewebsites.net/assets/public/favicon_js.ico
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
* URL: https://as-devsecops.azurewebsites.net/assets/public/favicon_js.ico
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
* URL: https://as-devsecops.azurewebsites.net/assets/public/favicon_js.ico
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
* URL: https://as-devsecops.azurewebsites.net/assets/public/favicon_js.ico
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

* URL: https://as-devsecops.azurewebsites.net/robots.txt
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``

Instances: 1

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
* URL: https://as-devsecops.azurewebsites.net/ftp/acquisitions.md
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

Instances: 10

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
* URL: https://as-devsecops.azurewebsites.net/api/Challenges/%3Fname=Score%2520Board
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/Challenges/%3Fname=Score%2520Board
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/Challenges/%3Fname=Score%2520Board
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/Challenges/%3Fname=Score%2520Board
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/Challenges/%3Fname=Score%2520Board
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/Challenges/%3Fname=Score%2520Board
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/Challenges/%3Fname=Score%2520Board
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/Challenges/%3Fname=Score%2520Board
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/Challenges/%3Fname=Score%2520Board
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/Challenges/%3Fname=Score%2520Board
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/Challenges/%3Fname=Score%2520Board
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/Challenges/%3Fname=Score%2520Board
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/Feedbacks/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/Feedbacks/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/Feedbacks/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/Feedbacks/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/Feedbacks/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/Feedbacks/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/Feedbacks/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/Feedbacks/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/Feedbacks/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/Feedbacks/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/Feedbacks/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/Feedbacks/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/Quantitys/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/Quantitys/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/Quantitys/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/Quantitys/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/Quantitys/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/Quantitys/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/Quantitys/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/Quantitys/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/Quantitys/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/Quantitys/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/Quantitys/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/Quantitys/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/SecurityQuestions/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/SecurityQuestions/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/SecurityQuestions/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/SecurityQuestions/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/SecurityQuestions/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/SecurityQuestions/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/SecurityQuestions/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/SecurityQuestions/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/SecurityQuestions/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/SecurityQuestions/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/SecurityQuestions/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/api/SecurityQuestions/
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
* URL: https://as-devsecops.azurewebsites.net/assets/i18n
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/i18n
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/i18n
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/i18n
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/i18n
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/i18n
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/i18n
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/i18n
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/i18n
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/i18n
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/i18n
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/i18n
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
* URL: https://as-devsecops.azurewebsites.net/assets/public/images
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/carousel
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/carousel
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/carousel
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/carousel
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/carousel
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/carousel
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/carousel
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/carousel
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/carousel
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/carousel
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/carousel
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/carousel
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/products
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/products
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/products
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/products
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/products
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/products
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/products
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/products
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/products
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/products
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/products
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/products
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/uploads
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/uploads
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/uploads
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/uploads
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/uploads
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/uploads
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/uploads
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/uploads
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/uploads
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/uploads
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/uploads
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/uploads
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/uploads/%25F0%259F%2598%25BC-
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/uploads/%25F0%259F%2598%25BC-
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/uploads/%25F0%259F%2598%25BC-
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/uploads/%25F0%259F%2598%25BC-
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/uploads/%25F0%259F%2598%25BC-
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/uploads/%25F0%259F%2598%25BC-
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/uploads/%25F0%259F%2598%25BC-
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/uploads/%25F0%259F%2598%25BC-
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/uploads/%25F0%259F%2598%25BC-
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/uploads/%25F0%259F%2598%25BC-
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/uploads/%25F0%259F%2598%25BC-
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/assets/public/images/uploads/%25F0%259F%2598%25BC-
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
* URL: https://as-devsecops.azurewebsites.net/ftp
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/ftp/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/assets/public/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/fileServer.js:39:13
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/fileServer.js:39:13
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/fileServer.js:39:13
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/fileServer.js:39:13
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/fileServer.js:39:13
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/fileServer.js:39:13
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/fileServer.js:39:13
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/fileServer.js:39:13
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/fileServer.js:39:13
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/fileServer.js:39:13
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/fileServer.js:39:13
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/fileServer.js:39:13
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/fileServer.js:55:18
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/fileServer.js:55:18
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/fileServer.js:55:18
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/fileServer.js:55:18
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/fileServer.js:55:18
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/fileServer.js:55:18
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/fileServer.js:55:18
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/fileServer.js:55:18
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/fileServer.js:55:18
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/fileServer.js:55:18
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/fileServer.js:55:18
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/fileServer.js:55:18
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/build/routes/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/assets/public/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:280:10
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:280:10
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:280:10
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:280:10
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:280:10
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:280:10
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:280:10
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:280:10
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:280:10
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:280:10
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:280:10
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:280:10
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:286:9
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:286:9
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:286:9
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:286:9
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:286:9
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:286:9
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:286:9
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:286:9
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:286:9
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:286:9
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:286:9
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:286:9
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:328:13
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:328:13
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:328:13
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:328:13
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:328:13
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:328:13
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:328:13
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:328:13
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:328:13
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:328:13
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:328:13
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:328:13
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:365:14
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:365:14
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:365:14
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:365:14
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:365:14
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:365:14
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:365:14
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:365:14
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:365:14
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:365:14
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:365:14
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:365:14
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:376:14
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:376:14
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:376:14
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:376:14
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:376:14
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:376:14
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:376:14
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:376:14
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:376:14
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:376:14
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:376:14
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:376:14
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:421:3
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:421:3
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:421:3
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:421:3
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:421:3
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:421:3
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:421:3
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:421:3
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:421:3
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:421:3
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:421:3
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/index.js:421:3
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/layer.js:95:5
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/layer.js:95:5
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/layer.js:95:5
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/layer.js:95:5
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/layer.js:95:5
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/layer.js:95:5
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/layer.js:95:5
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/layer.js:95:5
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/layer.js:95:5
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/layer.js:95:5
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/layer.js:95:5
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/layer.js:95:5
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/express/lib/router/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/assets/public/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/index.js:145:39
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/index.js:145:39
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/index.js:145:39
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/index.js:145:39
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/index.js:145:39
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/index.js:145:39
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/index.js:145:39
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/index.js:145:39
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/index.js:145:39
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/index.js:145:39
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/index.js:145:39
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/index.js:145:39
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/main.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/polyfills.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/runtime.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/styles.css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/home/site/wwwroot/node_modules/serve-index/vendor.js
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/captcha
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/captcha
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/captcha
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/captcha
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/captcha
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/captcha
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/captcha
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/captcha
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/captcha
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/captcha
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/captcha
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/captcha
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/captcha/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/captcha/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/captcha/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/captcha/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/captcha/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/captcha/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/captcha/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/captcha/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/captcha/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/captcha/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/captcha/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/captcha/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/languages
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/languages
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/languages
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/languages
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/memories/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/memories/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/memories/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/memories/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/memories/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/memories/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/memories/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/memories/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/memories/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/memories/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/memories/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/memories/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/products/search%3Fq=
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/products/search%3Fq=
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/products/search%3Fq=
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/products/search%3Fq=
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/products/search%3Fq=
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/products/search%3Fq=
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/products/search%3Fq=
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/products/search%3Fq=
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/products/search%3Fq=
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/products/search%3Fq=
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/products/search%3Fq=
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/rest/products/search%3Fq=
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
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=Odck-Mv
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=Odck-Mv
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=Odck-Mv
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=Odck-Mv
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=Odck-Mv
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=Odck-Mv
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=Odck-Mv
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=Odck-Mv
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=Odck-Mv
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=Odck-Mv
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=Odck-Mv
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=Odck-Mv
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=Odck-mz&sid=Sc5a5zaBuuqEbUooAABG
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=Odck-mz&sid=Sc5a5zaBuuqEbUooAABG
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=Odck-mz&sid=Sc5a5zaBuuqEbUooAABG
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=Odck-mz&sid=Sc5a5zaBuuqEbUooAABG
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=Odck-mz&sid=Sc5a5zaBuuqEbUooAABG
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=Odck-mz&sid=Sc5a5zaBuuqEbUooAABG
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=Odck-mz&sid=Sc5a5zaBuuqEbUooAABG
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=Odck-mz&sid=Sc5a5zaBuuqEbUooAABG
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=Odck-mz&sid=Sc5a5zaBuuqEbUooAABG
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=Odck-mz&sid=Sc5a5zaBuuqEbUooAABG
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=Odck-mz&sid=Sc5a5zaBuuqEbUooAABG
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=Odck-mz&sid=Sc5a5zaBuuqEbUooAABG
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=websocket&sid=UzkL-OiyHQUfQ7XOAAAY
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=websocket&sid=UzkL-OiyHQUfQ7XOAAAY
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=websocket&sid=UzkL-OiyHQUfQ7XOAAAY
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=websocket&sid=UzkL-OiyHQUfQ7XOAAAY
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=websocket&sid=UzkL-OiyHQUfQ7XOAAAY
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=websocket&sid=UzkL-OiyHQUfQ7XOAAAY
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=websocket&sid=UzkL-OiyHQUfQ7XOAAAY
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=websocket&sid=UzkL-OiyHQUfQ7XOAAAY
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=websocket&sid=UzkL-OiyHQUfQ7XOAAAY
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=websocket&sid=UzkL-OiyHQUfQ7XOAAAY
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=websocket&sid=UzkL-OiyHQUfQ7XOAAAY
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=websocket&sid=UzkL-OiyHQUfQ7XOAAAY
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=Odck-fs&sid=gDtn5Cwuew9HY8g4AABI
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=Odck-fs&sid=gDtn5Cwuew9HY8g4AABI
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=Odck-fs&sid=gDtn5Cwuew9HY8g4AABI
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=Odck-fs&sid=gDtn5Cwuew9HY8g4AABI
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=Odck-fs&sid=gDtn5Cwuew9HY8g4AABI
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=Odck-fs&sid=gDtn5Cwuew9HY8g4AABI
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=Odck-fs&sid=gDtn5Cwuew9HY8g4AABI
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=Odck-fs&sid=gDtn5Cwuew9HY8g4AABI
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=Odck-fs&sid=gDtn5Cwuew9HY8g4AABI
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=Odck-fs&sid=gDtn5Cwuew9HY8g4AABI
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=Odck-fs&sid=gDtn5Cwuew9HY8g4AABI
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
* URL: https://as-devsecops.azurewebsites.net/socket.io/%3FEIO=4&transport=polling&t=Odck-fs&sid=gDtn5Cwuew9HY8g4AABI
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``

Instances: 868

### Solution



### Reference


* [ https://owasp.org/wstg ](https://owasp.org/wstg)



#### Source ID: 1


