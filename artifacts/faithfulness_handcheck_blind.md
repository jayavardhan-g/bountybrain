# Faithfulness hand check (blind)

Label each claim supported / partial / unsupported against the excerpts only.

## 13-10 — Unrestricted file upload

**Claim:** In a real-world scenario, Jadek Mark (@mase289) found an unrestricted file upload vulnerability that led to remote code execution on a bug bounty program [5].

```
[5] Exploiting Unrestricted File Upload to achieve Remote Code Execution on a bug bounty program
# Exploiting Unrestricted File Upload to achieve Remote Code Execution on a bug bounty program

**Program:** -
**Vulnerability:** Unrestricted file upload, RCE
**Published:** 2021-04-18
**Author:** Jadek Mark (@mase289)

Source: https://mase289.medium.com/exploiting-unrestricted-file-upload-to-achieve-remote-code-execution-on-a-bug-bounty-program-85661516712
```

## 11-05 — Insecure deserialization

**Claim:** **Identify Entry Points**: Look for places where the application accepts serialized objects from untrusted sources, such as HTTP headers, parameters, or cookies. [3]

```
[3] Testing for Insecure Deserialization
# Testing for Insecure Deserialization — Test Objectives (WSTG-INPV-23)

- Identify entry points where the application accepts serialized objects from untrusted
  sources (for example, HTTP headers, parameters, or cookies).
- Determine the serialization format used by the application.
- Assess whether serialized input is validated or restricted prior to deserialization.
- Evaluate whether manipulation of serialized data leads to unsafe behavior or security
  impact.
```

## 11-11 — Insecure deserialization

**Claim:** This allowed attackers to execute arbitrary code on the server simply by sending maliciously crafted serialized data. [6]

```
[6] WordPress BuddyForms Plugin — Unauthenticated Insecure Deserialization (CVE-2023–26326)
# WordPress BuddyForms Plugin — Unauthenticated Insecure Deserialization (CVE-2023–26326)

**Program:** -
**Vulnerability:** Insecure deserialization, Security code review, RCE
**Published:** 2023-03-07
**Author:** Joshua Martinelle (@J0_mart)

Source: https://medium.com/tenable-techblog/wordpress-buddyforms-plugin-unauthenticated-insecure-deserialization-cve-2023-26326-3becb5575ed8
```

## 14-15 — JWT

**Claim:** Citing [5], this misuse of the kid header can lead to unauthorized access.

```
[5] JWT - JSON Web Token
# JWT - JSON Web Token — JWT Secret

> To create a JWT, a secret key is used to sign the header and payload, which generates the signature. The secret key must be kept secret and secure to prevent unauthorized access to the JWT or tampering with its contents. If an attacker is able to access the secret key, they can create, modify or sign their own tokens, bypassing the intended security controls.

### Encode and Decode JWT with the secret

- Using [ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool):

```ps1
    jwt_tool.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UifQ.xuEv8qrfXu424LZk8bVgr9MQJUIrp1rHcPyZw_KSsds
    jwt_tool.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UifQ.xuEv8qrfXu424LZk8bVgr9MQJUIrp1rHcPyZw_KSsds -T
    
    Token header values:
    [+] alg = "HS256"
    [+] typ = "JWT"

    Token payload values:
    [+] name = "John Doe"
    ```

- Using [pyjwt](https://pyjwt.readthedocs.io/en/stable/): `pip install pyjwt`

```python
    import jwt
    encoded = jwt.encode({'some': 'payload'}, 'secret', algorithm='HS256')
    jwt.decode(encoded, 'secret', algorithms=['HS256']) 
    ```

### Break JWT secret

Useful list of 3502 public-ava
```

## 06-08 — CSRF

**Claim:** **Check for Lack of Anti-CSRF Tokens**: Ensure that forms and other state-changing requests include unique anti-CSRF tokens that are validated on the server side. [1]

```
[1] Testing for Cross Site Request Forgery
# Testing for Cross Site Request Forgery — Summary (WSTG-SESS-05)

Cross-Site Request Forgery ([CSRF](https://owasp.org/www-community/attacks/csrf)) is an attack that forces an end user to execute unintended actions on a web application in which they are currently authenticated. With a little social engineering help (like sending a link via email or chat), an attacker may force the users of a web application to execute actions of the attacker's choosing. A successful CSRF exploit can compromise end user data and operation when it targets a normal user. If the targeted end user is the administrator account, a CSRF attack can compromise the entire web application.

CSRF relies on:

1. Web browser behavior regarding the handling of session-related information such as cookies and HTTP authentication information.
2. An attacker's knowledge of valid web application URLs, requests, or functionality.
3. Application session management relying only on information known by the browser.
4. Existence of HTML tags whose presence cause immediate access to an HTTP[S] resource; for example the image tag `img`.

Points 1, 2, and 3 are essential for the vulnerability to be present, while point 4 faci
```

## 07-08 — Open redirect

**Claim:** Consider the scenario described in [5], where a researcher found an open redirect vulnerability in Instagram.com.

```
[5] Open redirect in Instagram.com
# Open redirect in Instagram.com

**Program:** Meta / Facebook
**Vulnerability:** Open redirect
**Bounty:** $500
**Published:** 2021-02-17
**Author:** Youssef Sammouda (@samm0uda)

Source: https://ysamm.com/?p=625
```

## 01-09 — IDOR

**Claim:** For instance, changing the URL to `https://example.com/profile?user_id=124` might reveal another user's profile details [2].

```
[2] Insecure Direct Object References
# Insecure Direct Object References — Methodology

IDOR stands for Insecure Direct Object Reference. It's a type of security vulnerability that arises when an application provides direct access to objects based on user-supplied input. As a result, attackers can bypass authorization and access resources in the system directly, potentially leading to unauthorized information disclosure, modification, or deletion.

**Example of IDOR**:

Imagine a web application that allows users to view their profile by clicking a link `https://example.com/profile?user_id=123`:

```php
<?php
    $user_id = $_GET['user_id'];
    $user_info = get_user_info($user_id);
    ...
```

Here, `user_id=123` is a direct reference to a specific user's profile. If the application doesn't properly check that the logged-in user has the right to view the profile associated with `user_id=123`, an attacker could simply change the `user_id` parameter to view other users' profiles:

```ps1
https://example.com/profile?user_id=124
```

![https://lh5.googleusercontent.com/VmLyyGH7dGxUOl60h97Lr57F7dcnDD8DmUMCZTD28BKivVI51BLPIqL0RmcxMPsmgXgvAqY8WcQ-Jyv5FhRiCBueX9Wj0HSCBhE-_SvrDdA6_wvDmtMSizlRsHNvTJHuy36LG47lstLpTqLK](https:/
```

## 23-07 — Information disclosure

**Claim:** **Subverting Environment Variable Values**: Check if environment variables are exposed in error responses or logs `[3]`.

```
[3] Staff Information Disclosure on Support Ticketing System ($x,xxx)
# Staff Information Disclosure on Support Ticketing System ($x,xxx)

**Program:** -
**Vulnerability:** Information disclosure
**Published:** 2021-01-22
**Author:** Ph.Hitachi

Source: https://ph-hitachi.medium.com/staff-information-disclosure-on-support-ticketing-system-p2-x-xxx-a08960aea7b1
```

## 04-10 — SSTI

**Claim:** For example, try injecting `{{7*7}}` to see if the template engine returns `49` instead of just displaying the text `{{7*7}}` [4].

```
[4] Server Side Template Injection - PHP
# Server Side Template Injection - PHP

# Server Side Template Injection - PHP

> Server-Side Template Injection (SSTI)  is a vulnerability that occurs when an attacker can inject malicious input into a server-side template, causing the template engine to execute arbitrary commands on the server. In PHP, SSTI can arise when user input is embedded within templates rendered by templating engines like Smarty, Twig, or even within plain PHP templates, without proper sanitization or validation.
```

## 24-09 — Account takeover

**Claim:** This led to a bounty of $4,100 [2].

```
[2] An Account Takeover Vulnerability Due to Response Manipulation.
# An Account Takeover Vulnerability Due to Response Manipulation.

**Program:** -
**Vulnerability:** Authentication bypass, Account takeover
**Bounty:** $4,100
**Published:** 2021-01-31
**Author:** Avanish Pathak (@avanish46)

Source: https://avanishpathak46.medium.com/an-account-takeover-vulnerability-due-to-response-manipulation-e23fe629bd1
```

## 29-05 — Authentication bypass

**Claim:** **URL Tampering**: Modify URL parameters to access restricted pages directly [1].

```
[1] Testing for Bypassing Authentication Schema
# Testing for Bypassing Authentication Schema — Summary (WSTG-ATHN-04)

In computer security, authentication is the process of attempting to verify the digital identity of the sender of a communication. A common example of such a process is the log on process. Testing the authentication schema means understanding how the authentication process works and using that information to circumvent the authentication mechanism.

While most applications require authentication to gain access to private information or to execute tasks, not every authentication method is able to provide adequate security. Negligence, ignorance, or simple understatement of security threats often result in authentication schemes that can be bypassed by simply skipping the log in page and directly calling an internal page that is supposed to be accessed only after authentication has been performed.

In addition, it is often possible to bypass authentication measures by tampering with requests and tricking the application into thinking that the user is already authenticated. This can be accomplished either by modifying the given URL parameter, by manipulating the form, or by counterfeiting sessions.

Problems relat
```

## 21-07 — Mass assignment

**Claim:** In one notable disclosure, an attacker exploited a mass assignment vulnerability to gain admin access to a company's server [3].

```
[3] Mass Assignment Leading to Pre Account Takeover
# Mass Assignment Leading to Pre Account Takeover

**Program:** -
**Vulnerability:** Mass assignment
**Bounty:** $1,300
**Published:** 2022-09-21
**Author:** Cyberali

Source: https://medium.com/@cyberali/mass-assignment-leading-to-pre-account-takeover-13041280a0d9
```

## 06-09 — CSRF

**Claim:** Consider the case of a CSRF vulnerability found in the Facebook Partners platform [5].

```
[5] CSRF in partners.facebook.com
# CSRF in partners.facebook.com

**Program:** Meta / Facebook
**Vulnerability:** CSRF
**Bounty:** $5,000
**Published:** 2016-09-20
**Author:** Prashanth Varma (@cymtrick)

Source: https://github.com/cymtrick/lol/blob/d17ed765129b26a1bf8060757e5aebd4e237c908/_posts/2016-09-20-Facebook-partners-CSRF.md
```

## 17-06 — Web cache poisoning

**Claim:** Testing for Host Header Injection can help reveal if the server improperly uses these headers to generate cache keys `[1]`.

```
[1] Testing for Host Header Injection
Potentially producing client-side output such as:

```html
[...]
<link src="https://www.attacker.com/link" />
[...]
```

Once again, this depends on how the web server processes the header value.

### Web Cache Poisoning

Using this technique, an attacker can manipulate a web-cache to serve poisoned content to anyone who requests it. This relies on the ability to poison the caching proxy run by the application itself, CDNs, or other downstream providers. As a result, the victim will have no control over receiving the malicious content when requesting the vulnerable application.

```http
GET / HTTP/1.1
Host: www.attacker.com
[...]
```

The following will be served from the web cache, when a victim visits the vulnerable application.

```html
[...]
<link src="https://www.attacker.com/link" />
[...]
```

### Password Reset Poisoning

It is common for password reset functionality to include the Host header value when creating password reset links that use a generated secret token. If the application processes an attacker-controlled domain to create a password reset link, the victim may click on the link in the email and allow the attacker to obtain the reset token, thus resetting the vi
```

## 03-08 — SQL injection

**Claim:** For example, if changing input causes a delay or changes the content returned, it might be a sign of SQL injection [5].

```
[5] SQL Injection
# SQL Injection — Second Order SQL Injection

Second Order SQL Injection is a subtype of SQL injection where the malicious SQL payload is primarily stored in the application's database and later executed by a different functionality of the same application.
Unlike first-order SQLi, the injection doesn't happen right away. It is **triggered in a separate step**, often in a different part of the application.

1. User submits input that is stored (e.g., during registration or profile update).

```text
   Username: attacker'--
   Email: attacker@example.com
   ```

2. That input is saved **without validation** but doesn't trigger a SQL injection.

```sql
   INSERT INTO users (username, email) VALUES ('attacker\'--', 'attacker@example.com');
   ```

3. Later, the application retrieves and uses the stored data in a SQL query.

```python
   query = "SELECT * FROM logs WHERE username = '" + user_from_db + "'"
   ```

4. If this query is built unsafely, the injection is triggered.
```

## 23-08 — Information disclosure

**Claim:** **Footprinting**: Gather publicly available information about the target, including server configurations and software versions `[3]`.

```
[3] Staff Information Disclosure on Support Ticketing System ($x,xxx)
# Staff Information Disclosure on Support Ticketing System ($x,xxx)

**Program:** -
**Vulnerability:** Information disclosure
**Published:** 2021-01-22
**Author:** Ph.Hitachi

Source: https://ph-hitachi.medium.com/staff-information-disclosure-on-support-ticketing-system-p2-x-xxx-a08960aea7b1
```

## 14-08 — JWT

**Claim:** Citing [2], ensure the application does not accept invalid signatures.

```
[2] Testing JSON Web Tokens
# Testing JSON Web Tokens — Summary (WSTG-SESS-10)

JSON Web Tokens (JWTs) are cryptographically signed JSON tokens, intended to share claims between systems. They are frequently used as authentication or session tokens, particularly on REST APIs.

JWTs are a common source of vulnerabilities, both in how they are in implemented in applications, and in the underlying libraries. As they are used for authentication, a vulnerability can easily result in a complete compromise of the application.
```

## 07-07 — Open redirect

**Claim:** Techniques for finding such vulnerabilities are detailed in [1].

```
[1] Open URL Redirect
# Open URL Redirect — Methodology

An open redirect vulnerability occurs when a web application or server uses unvalidated, user-supplied input to redirect users to other sites. This can allow an attacker to craft a link to the vulnerable site which redirects to a malicious site of their choosing.

Attackers can leverage this vulnerability in phishing campaigns, session theft, or forcing a user to perform an action without their consent.

**Example**: A web application has a feature that allows users to click on a link and be automatically redirected to a saved preferred homepage. This might be implemented like so:

```ps1
https://example.com/redirect?url=https://userpreferredsite.com
```

An attacker could exploit an open redirect here by replacing the `userpreferredsite.com` with a link to a malicious website. They could then distribute this link in a phishing email or on another website. When users click the link, they're taken to the malicious website.
```

## 02-11 — Cross-site scripting

**Claim:** When another user reads the comment, the script executes in their browser, potentially revealing sensitive information or performing other malicious actions. [1]

```
[1] Cross Site Scripting
# Cross Site Scripting

# Cross Site Scripting

> Cross-site scripting (XSS) is a type of computer security vulnerability typically found in web applications. XSS enables attackers to inject client-side scripts into web pages viewed by other users.
```

## 17-10 — Web cache poisoning

**Claim:** Subsequent visitors to the same URL will receive the poisoned content, executing the malicious script in their browser `[3]`.

```
[3] Web Cache Deception
Video of the attack by Omer Gil - Web Cache Deception Attack in PayPal Home Page
[![DEMO](https://i.vimeocdn.com/video/674856618-f9bac811a4c7bcf635c4eff51f68a50e3d5532ca5cade3db784c6d178b94d09a-d)](https://vimeo.com/249130093)

**Example 2** - Web Cache Deception on OpenAI

1. Attacker crafts a dedicated .css path of the `/api/auth/session` endpoint.
2. Attacker distributes the link
3. Victims visit the legitimate link.
4. Response is cached.
5. Attacker harvests JWT Credentials.

### Caching Custom JavaScript

1. Find an un-keyed input for a Cache Poisoning

```js
    Values: User-Agent
    Values: Cookie
    Header: X-Forwarded-Host
    Header: X-Host
    Header: X-Forwarded-Server
    Header: X-Forwarded-Scheme (header; also in combination with X-Forwarded-Host)
    Header: X-Original-URL (Symfony)
    Header: X-Rewrite-URL (Symfony)
    ```

2. Cache poisoning attack - Example for `X-Forwarded-Host` un-keyed input (remember to use a buster to only cache this webpage instead of the main page of the website)

```js
    GET /test?buster=123 HTTP/1.1
    Host: target.com
    X-Forwarded-Host: test"><script>alert(1)</script>

    HTTP/1.1 200 OK
    Cache-Control: public, no-cache
 
```

## 12-09 — Path traversal

**Claim:** For instance, if the application accepts a filename parameter like `?file=notes.txt`, an attacker could change it to `?file=../../../../etc/passwd` to attempt to read the password file on the server [1].

```
[1] Directory Traversal
# Directory Traversal

# Directory Traversal

> Path Traversal, also known as Directory Traversal, is a type of security vulnerability that occurs when an attacker manipulates variables that reference files with “dot-dot-slash (../)” sequences or similar constructs. This can allow the attacker to access arbitrary files and directories stored on the file system.
```

## 27-08 — CRLF injection

**Claim:** Consider the following scenario from [3]:

```
[3] Carriage Return Line Feed
**Requested page**:

```http
http://www.example.net/index.php?lang=en%0D%0AContent-Length%3A%200%0A%20%0AHTTP/1.1%20200%20OK%0AContent-Type%3A%20text/html%0ALast-Modified%3A%20Mon%2C%2027%20Oct%202060%2014%3A50%3A18%20GMT%0AContent-Length%3A%2034%0A%20%0A%3Chtml%3EYou%20have%20been%20Phished%3C/html%3E
```

**HTTP response**:

```http
Set-Cookie:en
Content-Length: 0

HTTP/1.1 200 OK
Content-Type: text/html
Last-Modified: Mon, 27 Oct 2060 14:50:18 GMT
Content-Length: 34

<html>You have been Phished</html>
```

In the case of an XSS, the CRLF injection allows to inject the `X-XSS-Protection` header with the value value "0", to disable it. And then we can add our HTML tag containing Javascript code .

**Requested page**:

```powershell
http://example.com/%0d%0aContent-Length:35%0d%0aX-XSS-Protection:0%0d%0a%0d%0a23%0d%0a<svg%20onload=alert(document.domain)>%0d%0a0%0d%0a/%2f%2e%2e
```

**HTTP Response**:

```http
HTTP/1.1 200 OK
Date: Tue, 20 Dec 2016 14:34:03 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 22907
Connection: close
X-Frame-Options: SAMEORIGIN
Last-Modified: Tue, 20 Dec 2016 11:50:50 GMT
ETag: "842fe-597b-54415a5c97a80"
Vary: Accept-Encoding
X-UA-Compatible: I
```

## 18-07 — OS command injection

**Claim:** **Exploiting Multiple Input Interpretation Layers**: Attackers can exploit multiple layers of input interpretation to bypass filters and execute commands `[3]`.

```
[3] CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
# CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

The product constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command when it is sent to a downstream component.
```

## 26-12 — Privilege escalation

**Claim:** This resulted in a bounty of $400. [2]

```
[2] Privilege escalation leads to deleting other user’s account and company Workspace [Access Control]
# Privilege escalation leads to deleting other user’s account and company Workspace [Access Control]

**Program:** -
**Vulnerability:** Privilege escalation, Broken Access Control
**Bounty:** $400
**Published:** 2022-12-14
**Author:** Pratik Gaikwad

Source: https://medium.com/@h4ck3rp4tik/privilege-escalation-leads-to-deleting-other-users-account-and-company-workspace-access-control-7b709eb88ef
```

## 02-07 — Cross-site scripting

**Claim:** **Stored XSS**: Check areas where user input is stored on the server and displayed to other users later, such as comments, forums, or profile sections. [5]

```
[5] CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
# CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

The product does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.

There are many variants of cross-site scripting, characterized by a variety of terms or involving different attack topologies. However, they all indicate the same fundamental weakness: improper neutralization of dangerous input between the adversary and a victim.

**Also known as:** XSS, HTML Injection, Reflected XSS / Non-Persistent XSS / Type 1 XSS, Stored XSS / Persistent XSS / Type 2 XSS, DOM-Based XSS / Type 0 XSS, CSS

**Likelihood of exploit:** High

**Applicable platforms:** Not Language-Specific, AI/ML, Web Based, Web Server
```

## 21-06 — Mass assignment

**Claim:** Check documentation and code for any mention of mass assignment or similar features, and ensure that only authorized fields are being updated [1].

```
[1] Mass Assignment
# Mass Assignment

# Mass Assignment

> A mass assignment attack is a security vulnerability that occurs when a web application automatically assigns user-supplied input values to properties or variables of a program object. This can become an issue if a user is able to modify attributes they should not have access to, like a user's permissions or an admin flag.
```

## 03-13 — SQL injection

**Claim:** The `--` comment operator would disable the rest of the query, effectively bypassing the password check and allowing the attacker to log in as the admin user [1].

```
[1] SQL Injection
# SQL Injection

# SQL Injection

> SQL Injection (SQLi)  is a type of security vulnerability that allows an attacker to interfere with the queries that an application makes to its database. SQL Injection is one of the most common and severe types of web application vulnerabilities, enabling attackers to execute arbitrary SQL code on the database. This can lead to unauthorized data access, data manipulation, and, in some cases, full compromise of the database server.
```

## 28-10 — NoSQL injection

**Claim:** This would return all products with a price greater than zero, instead of a specific product, potentially leaking sensitive data ([1]).

```
[1] NoSQL Injection
# NoSQL Injection — Methodology

NoSQL injection occurs when an attacker manipulates queries by injecting malicious input into a NoSQL database query. Unlike SQL injection, NoSQL injection often exploits JSON-based queries and operators like `$ne`, `$gt`, `$regex`, or `$where` in MongoDB.

### Operator Injection

| Operator | Description        |
| -------- | ------------------ |
| $ne      | not equal          |
| $regex   | regular expression |
| $gt      | greater than       |
| $lt      | lower than         |
| $nin     | not in             |

Example: A web application has a product search feature

```js
db.products.find({ "price": userInput })
```

An attacker can inject a NoSQL query: `{ "$gt": 0 }`.

```js
db.products.find({ "price": { "$gt": 0 } })
```

Instead of returning a specific product, the database returns all products with a price greater than zero, leaking data.

### Authentication Bypass

Basic authentication bypass using not equal (`$ne`) or greater (`$gt`)

* HTTP data

```ps1
  username[$ne]=toto&password[$ne]=toto
  login[$regex]=a.*&pass[$ne]=lol
  login[$gt]=admin&login[$lt]=test&pass[$ne]=1
  login[$nin][]=admin&login[$nin][]=test&pass[$ne]=toto
  ```

* 
```

## 14-10 — JWT

**Claim:** Citing [5], misusing the kid header can lead to key exposure.

```
[5] JWT - JSON Web Token
# JWT - JSON Web Token — JWT Secret

> To create a JWT, a secret key is used to sign the header and payload, which generates the signature. The secret key must be kept secret and secure to prevent unauthorized access to the JWT or tampering with its contents. If an attacker is able to access the secret key, they can create, modify or sign their own tokens, bypassing the intended security controls.

### Encode and Decode JWT with the secret

- Using [ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool):

```ps1
    jwt_tool.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UifQ.xuEv8qrfXu424LZk8bVgr9MQJUIrp1rHcPyZw_KSsds
    jwt_tool.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UifQ.xuEv8qrfXu424LZk8bVgr9MQJUIrp1rHcPyZw_KSsds -T
    
    Token header values:
    [+] alg = "HS256"
    [+] typ = "JWT"

    Token payload values:
    [+] name = "John Doe"
    ```

- Using [pyjwt](https://pyjwt.readthedocs.io/en/stable/): `pip install pyjwt`

```python
    import jwt
    encoded = jwt.encode({'some': 'payload'}, 'secret', algorithm='HS256')
    jwt.decode(encoded, 'secret', algorithms=['HS256']) 
    ```

### Break JWT secret

Useful list of 3502 public-ava
```

## 18-06 — OS command injection

**Claim:** For example, sending `; ls` as input should result in the listing of files if the application is vulnerable `[1]`.

```
[1] Testing for Command Injection
# Testing for Command Injection — Summary (WSTG-INPV-12)

This article describes how to test an application for OS command injection. The tester will try to inject an OS command through an HTTP request to the application.

OS command injection is a vulnerability that occurs when user input is directly passed to an operating system command without proper validation or sanitization. This allows the user to inject and execute arbitrary commands on the server which can lead to unauthorized data access, data corruption, and full server compromise. This vulnerability can be prevented by emphasizing security during the design and development of applications.
```

## 03-06 — SQL injection

**Claim:** This can indicate that user input is being directly used in SQL queries without proper handling [1].

```
[1] SQL Injection
# SQL Injection

# SQL Injection

> SQL Injection (SQLi)  is a type of security vulnerability that allows an attacker to interfere with the queries that an application makes to its database. SQL Injection is one of the most common and severe types of web application vulnerabilities, enabling attackers to execute arbitrary SQL code on the database. This can lead to unauthorized data access, data manipulation, and, in some cases, full compromise of the database server.
```

## 06-07 — CSRF

**Claim:** These actions should require additional verification beyond just the session cookie. [1]

```
[1] Testing for Cross Site Request Forgery
# Testing for Cross Site Request Forgery — Summary (WSTG-SESS-05)

Cross-Site Request Forgery ([CSRF](https://owasp.org/www-community/attacks/csrf)) is an attack that forces an end user to execute unintended actions on a web application in which they are currently authenticated. With a little social engineering help (like sending a link via email or chat), an attacker may force the users of a web application to execute actions of the attacker's choosing. A successful CSRF exploit can compromise end user data and operation when it targets a normal user. If the targeted end user is the administrator account, a CSRF attack can compromise the entire web application.

CSRF relies on:

1. Web browser behavior regarding the handling of session-related information such as cookies and HTTP authentication information.
2. An attacker's knowledge of valid web application URLs, requests, or functionality.
3. Application session management relying only on information known by the browser.
4. Existence of HTML tags whose presence cause immediate access to an HTTP[S] resource; for example the image tag `img`.

Points 1, 2, and 3 are essential for the vulnerability to be present, while point 4 faci
```

## 22-12 — Business logic

**Claim:** This scenario illustrates a business logic flaw where the application fails to enforce proper pricing rules. [4]

```
[4] Introduction to Business Logic
# Introduction to Business Logic — Challenges of Logic Testing

Automated tools find it hard to understand context, hence it's up to a person to perform these kinds of tests. The following two examples will illustrate how understanding the functionality of the application, the developer's intentions, and some creative "out-of-the-box" thinking can break the application's logic. The first example starts with a simplistic parameter manipulation, whereas the second is a real world example of a multi-step process leading to completely subverting the application.

**Example 1**:

Suppose an e-commerce site allows users to select items to purchase, view a summary page and then tender the sale. What if an attacker was able to go back to the summary page, maintaining their same valid session and inject a lower cost for an item and complete the transaction, and then check out?

**Example 2**:

Holding/locking resources and keeping others from purchasing these items online may result in attackers purchasing items at a lower price. The countermeasure to this problem is to implement timeouts and mechanisms to ensure that only the correct price can be charged.

**Example 3**:

What if a user wa
```

## 02-08 — Cross-site scripting

**Claim:** **DOM-Based XSS**: Identify parts of the application where JavaScript dynamically modifies the DOM based on user input. [3]

```
[3] Testing for Self DOM Based Cross-Site Scripting
# Testing for Self DOM Based Cross-Site Scripting — Summary

Self DOM-Based Cross-Site Scripting is a specific attack and needs prior knowledge of DOM-Based cross site scripting and successful social engineering. The term 'self' is a reference here to the fact, that the user needs to inject the payload into the input field, and thus execute the vulnerability themselves. The vulnerability is further specific, as the website's Content Security Policy (CSP) can block the execution of scripts.

This scenario will use the term "sink" in the following manner: In computing, a sink, event sink or data sink is a class or function designed to receive input or events from another object or function. Thus in order to find possible vulnerabilities we first need to identify the sinks of the application we want to test.
```

## 16-09 — Subdomain takeover

**Claim:** Tools like `can-i-take-over-xyz` can help automate this process. [2]

```
[2] Test for Subdomain Takeover
# Test for Subdomain Takeover — References (WSTG-CONF-10)

- [HackerOne - A Guide To Subdomain Takeovers](https://www.hackerone.com/blog/Guide-Subdomain-Takeovers)
- [Subdomain Takeover: Basics](https://0xpatrik.com/subdomain-takeover-basics/)
- [Subdomain Takeover: Going beyond CNAME](https://0xpatrik.com/subdomain-takeover-ns/)
- [can-i-take-over-xyz - A list of vulnerable services](https://github.com/EdOverflow/can-i-take-over-xyz/)
- [OWASP AppSec Europe 2017 - Frans Rosén: DNS hijacking using cloud providers – no verification needed](https://2017.appsec.eu/presos/Developer/DNS%20hijacking%20using%20cloud%20providers%20%E2%80%93%20no%20verification%20needed%20-%20Frans%20Rosen%20-%20OWASP_AppSec-Eu_2017.pdf)
```

## 24-06 — Account takeover

**Claim:** Another method involves testing if the system allows brute-forcing or guessing passwords easily [1].

```
[1] Account Takeover — Story of 2 same issues in a single program but different sub-domains.
# Account Takeover — Story of 2 same issues in a single program but different sub-domains.

**Program:** -
**Vulnerability:** Account takeover
**Published:** 2021-10-10
**Author:** Himanshu Pdy (@himanshu_pdy)

Source: https://hunter-55.medium.com/account-takeover-story-of-2-same-issues-in-a-single-program-but-different-sub-domains-in-10-minutes-840b2701db91
```

## 16-10 — Subdomain takeover

**Claim:** Consider the example of a subdomain takeover via Fastly CDN [1].

```
[1] Fastly Subdomain Takeover $2000
# Fastly Subdomain Takeover $2000

**Program:** -
**Vulnerability:** Subdomain takeover
**Bounty:** $2,000
**Published:** 2022-11-21
**Author:** ValluvarSploit (@ValluvarSploit)

Source: https://medium.com/@valluvarsploit/fastly-subdomain-takeover-2000-217bb180730f
```

## 29-08 — Authentication bypass

**Claim:** In the case of the Google Assistant vulnerability [3], an attacker was able to bypass authentication by exploiting an information disclosure issue.

```
[3] Auth Bypass in Google Assistant
# Auth Bypass in Google Assistant

**Program:** Google
**Vulnerability:** Information disclosure, Authentication bypass
**Bounty:** $2,674
**Published:** 2022-02-06
**Author:** David Schütz (@xdavidhu)

Source: https://feed.bugs.xdavidhu.me/bugs/0012
```

## 18-10 — OS command injection

**Claim:** This would not only ping the IP address but also display the contents of `/etc/passwd`, revealing sensitive information `[4]`.

```
[4] Command Injection
# Command Injection — Methodology

Command injection, also known as shell injection, is a type of attack in which the attacker can execute arbitrary commands on the host operating system via a vulnerable application. This vulnerability can exist when an application passes unsafe user-supplied data (forms, cookies, HTTP headers, etc.) to a system shell. In this context, the system shell is a command-line interface that processes commands to be executed, typically on a Unix or Linux system.

The danger of command injection is that it can allow an attacker to execute any command on the system, potentially leading to full system compromise.

**Example of Command Injection with PHP**:
Suppose you have a PHP script that takes a user input to ping a specified IP address or domain:

```php
<?php
    $ip = $_GET['ip'];
    system("ping -c 4 " . $ip);
?>
```

In the above code, the PHP script uses the `system()` function to execute the `ping` command with the IP address or domain provided by the user through the `ip` GET parameter.

If an attacker provides input like `8.8.8.8; cat /etc/passwd`, the actual command that gets executed would be: `ping -c 4 8.8.8.8; cat /etc/passwd`.

This means 
```

## 26-07 — Privilege escalation

**Claim:** This involves checking if the application correctly enforces access controls and prevents unauthorized actions. [1]

```
[1] Testing for Privilege Escalation
# Testing for Privilege Escalation — Summary (WSTG-ATHZ-03)

This section describes the issue of escalating privileges from one stage to another. During this phase, the tester should verify that it is not possible for a user to modify their privileges or roles inside the application in ways that could allow privilege escalation attacks.

Privilege escalation occurs when a user gets access to more resources or functionality than they are normally allowed, and such elevation or changes should have been prevented by the application. This is usually caused by a flaw in the application. The result is that the application performs actions with more privileges than those intended by the developer or system administrator.

The degree of escalation depends on what privileges the attacker is authorized to possess, and what privileges can be obtained in a successful exploit. For example, a programming error that allows a user to gain extra privilege after successful authentication limits the degree of escalation, because the user is already authorized to hold some privilege. Likewise, a remote attacker gaining superuser privilege without any authentication presents a greater degree of escalat
```
