# Faithfulness hand check (blind)

Label each claim supported / partial / unsupported against the excerpts only.

## 21-07 — Mass assignment

**Claim:** Try adding extra fields to the request and see if the app processes them [2].

```
[2] Mass Assignment
# Mass Assignment — Methodology

Mass assignment vulnerabilities are most common in web applications that use Object-Relational Mapping (ORM) techniques or functions to map user input to object properties, where properties can be updated all at once instead of individually. Many popular web development frameworks such as Ruby on Rails, Django, and Laravel (PHP) offer this functionality.

For instance, consider a web application that uses an ORM and has a user object with the attributes `username`, `email`, `password`, and `isAdmin`. In a normal scenario, a user might be able to update their own username, email, and password through a form, which the server then assigns to the user object.

However, an attacker may attempt to add an `isAdmin` parameter to the incoming data like so:

```json
{
    "username": "attacker",
    "email": "attacker@email.com",
    "password": "unsafe_password",
    "isAdmin": true
}
```

If the web application is not checking which parameters are allowed to be updated in this way, it might set the `isAdmin` attribute based on the user-supplied input, giving the attacker admin privileges
```

## 19-05 — Local file inclusion

**Claim:** Common parameters might be named `file`, `page`, or similar [3].

```
[3] File Inclusion
# File Inclusion — Local File Inclusion

**File Inclusion Vulnerability** should be differentiated from **Path Traversal**. The Path Traversal vulnerability allows an attacker to access a file, usually exploiting a "reading" mechanism implemented in the target application, when the File Inclusion will lead to the execution of arbitrary code.

Consider a PHP script that includes a file based on user input. If proper sanitization is not in place, an attacker could manipulate the `page` parameter to include local or remote files, leading to unauthorized access or code execution.

```php
<?php
$file = $_GET['page'];
include($file);
?>
```

In the following examples we include the `/etc/passwd` file, check the `Directory & Path Traversal` chapter for more interesting files.

```powershell
http://example.com/index.php?page=../../../etc/passwd
```

### Null Byte

:warning: In versions of PHP below 5.3.4 we can terminate with null byte (`%00`).

```powershell
http://example.com/index.php?page=../../../etc/passwd%00
```

**Example**: Joomla! Component Web TV 1.0 - CVE-2010-1470

```ps1
{{BaseURL}}/index.php?option=com_webtv&controller=../../../../../../../../../../etc/passwd%00
```

### Dou
```

## 25-12 — OAuth

**Claim:** OAuth misconfigurations can lead to serious security issues [1].

```
[1] OAuth Misconfiguration
# OAuth Misconfiguration

# OAuth Misconfiguration

> OAuth is a widely-used authorization framework that allows third-party applications to access user data without exposing user credentials. However, improper configuration and implementation of OAuth can lead to severe security vulnerabilities. This document explores common OAuth misconfigurations, potential attack vectors, and best practices for mitigating these risks.
```

## 04-09 — SSTI

**Claim:** User input embedded in templates without sanitization can lead to SSTI [1, 2, 3, 4, 5, 6].

```
[1] Server Side Template Injection - Java
# Server Side Template Injection - Java

# Server Side Template Injection - Java

> Server-Side Template Injection (SSTI)  is a security vulnerability that occurs when user input is embedded into server-side templates in an unsafe manner, allowing attackers to inject and execute arbitrary code. In Java, SSTI can be particularly dangerous due to the power and flexibility of Java-based templating engines such as JSP (JavaServer Pages), Thymeleaf, and FreeMarker.
```

```
[2] Server Side Template Injection - ASP.NET
# Server Side Template Injection - ASP.NET

# Server Side Template Injection - ASP.NET

> Server-Side Template Injection (SSTI)  is a class of vulnerabilities where an attacker can inject malicious input into a server-side template, causing the template engine to execute arbitrary code on the server. In the context of ASP.NET, SSTI can occur if user input is directly embedded into a template (such as Razor, ASPX, or other templating engines) without proper sanitization.
```

```
[3] Server Side Template Injection - Elixir
# Server Side Template Injection - Elixir

# Server Side Template Injection - Elixir

> Server-Side Template Injection (SSTI)  is a vulnerability that arises when an attacker can inject malicious code into a server-side template, causing the server to execute arbitrary commands. In Elixir, SSTI can occur when using templating engines like EEx (Embedded Elixir), especially when user input is incorporated into templates without proper sanitization or validation.
```

```
[4] Server Side Template Injection - PHP
# Server Side Template Injection - PHP

# Server Side Template Injection - PHP

> Server-Side Template Injection (SSTI)  is a vulnerability that occurs when an attacker can inject malicious input into a server-side template, causing the template engine to execute arbitrary commands on the server. In PHP, SSTI can arise when user input is embedded within templates rendered by templating engines like Smarty, Twig, or even within plain PHP templates, without proper sanitization or validation.
```

```
[5] Server Side Template Injection - Ruby
# Server Side Template Injection - Ruby

# Server Side Template Injection - Ruby

> Server-Side Template Injection (SSTI)  is a vulnerability that arises when an attacker can inject malicious code into a server-side template, causing the server to execute arbitrary commands. In Ruby, SSTI can occur when using templating engines like ERB (Embedded Ruby), Haml, liquid, or Slim, especially when user input is incorporated into templates without proper sanitization or validation.
```

```
[6] Server Side Template Injection - Python
# Server Side Template Injection - Python

# Server Side Template Injection - Python

> Server-Side Template Injection (SSTI)  is a vulnerability that arises when an attacker can inject malicious input into a server-side template, causing arbitrary code execution on the server. In Python, SSTI can occur when using templating engines such as Jinja2, Mako, or Django templates, where user input is included in templates without proper sanitization.
```

## 19-16 — Local file inclusion

**Claim:** To find LFI vulnerabilities, explore the application for URLs that accept file input parameters and test path traversal sequences [6].

```
[6] CAPEC-252: PHP Local File Inclusion
## Execution flow
**Step 1 (Explore):** [Survey application] Using a browser or an automated tool, an adversary follows all public links on a web site. They record all the links they find. The adversary is looking for URLs that show PHP file inclusion is used, which can look something like "http://vulnerable-website/file.php?file=index.php".
  - Use a spidering tool to follow and record all links. Make special note of any links that include parameters in the URL.
  - Use a proxy tool to record all links visited during a manual traversal of the web application. Make special note of any links that include parameters in the URL. Manual traversal of this type is frequently necessary to identify forms that are GET method forms rather than POST forms.
  - Use a browser to manually explore the website and analyze how it is constructed. Many browser's plugins are available to facilitate the analysis or automate the URL discovery.
**Step 2 (Experiment):** [Attempt variations on input parameters] Once the adversary finds a vulnerable URL that takes file input, they attempt a variety of path traversal techniques to attempt to get the application to display the contents of a local file, or exe
```

## 07-08 — Open redirect

**Claim:** The researcher reported this issue and received a bounty of $500 [5].

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

## 01-06 — IDOR

**Claim:** For instance, if a profile page uses a `user_id` parameter, try changing it to another user's ID to see if you can view their profile [2].

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

## 06-02 — CSRF

**Claim:** CSRF happens because web applications often rely solely on session cookies stored in the user’s browser to authenticate requests [1, 3].

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

```
[3] CWE-352: Cross-Site Request Forgery (CSRF)
# CWE-352: Cross-Site Request Forgery (CSRF)

The web application does not, or cannot, sufficiently verify whether a request was intentionally provided by the user who sent the request, which could have originated from an unauthorized actor.

**Also known as:** Session Riding, Cross Site Reference Forgery, XSRF, CSRF

**Likelihood of exploit:** Medium

**Applicable platforms:** Not Language-Specific, Web Based, Web Server

## Impact
- Confidentiality, Integrity, Availability, Non-Repudiation, Access Control: Gain Privileges or Assume Identity, Bypass Protection Mechanism, Read Application Data, Modify Application Data, DoS: Crash, Exit, or Restart — The consequences will vary depending on the nature of the functionality that is vulnerable to CSRF. An attacker could trick a client into making an unintentional request to the web server via a URL, image load, XMLHttpRequest, etc., which would then be treated as an authentic request from the client - effectively performing any operations as the victim, leading to an exposure of data, unintended code execution, etc. If the victim is an administrator or privileged user, the consequences may include obtaining complete control over the web
```

## 29-04 — Authentication bypass

**Claim:** Look for URLs that can be directly accessed without a login request [1].

```
[1] Testing for Bypassing Authentication Schema
# Testing for Bypassing Authentication Schema — Summary (WSTG-ATHN-04)

In computer security, authentication is the process of attempting to verify the digital identity of the sender of a communication. A common example of such a process is the log on process. Testing the authentication schema means understanding how the authentication process works and using that information to circumvent the authentication mechanism.

While most applications require authentication to gain access to private information or to execute tasks, not every authentication method is able to provide adequate security. Negligence, ignorance, or simple understatement of security threats often result in authentication schemes that can be bypassed by simply skipping the log in page and directly calling an internal page that is supposed to be accessed only after authentication has been performed.

In addition, it is often possible to bypass authentication measures by tampering with requests and tricking the application into thinking that the user is already authenticated. This can be accomplished either by modifying the given URL parameter, by manipulating the form, or by counterfeiting sessions.

Problems relat
```

## 24-12 — Account takeover

**Claim:** Always test in a safe environment with proper authorization [7].

```
[7] BountyBrain knowledge graph (MITRE CWE/CAPEC, disclosed-report metadata)
{
  "cwe": "CWE-640: Weak Password Recovery Mechanism for Forgotten Password",
  "likelihood_of_exploit": "High",
  "aliases": [
    "account takeover",
    "ato",
    "password reset",
    "password reset poisoning"
  ],
  "attack_patterns": [
    "CAPEC-50: Password Recovery Exploitation"
  ],
  "notable_disclosures": [
    {
      "title": "More secure Facebook Canvas : Tale of $126k worth of bugs that lead to Facebook Account Takeovers",
      "bounty": 126000.0
    },
    {
      "title": "Exploiting CSP in Webkit to Break Authentication & Authorization",
      "bounty": 100000.0
    },
    {
      "title": "Zero-day in Sign in with Apple",
      "bounty": 100000.0
    },
    {
      "title": "More secure Facebook Canvas Part 2: More Account Takeovers",
      "bounty": 98250.0
    },
    {
      "title": "Account Takeover in Canvas Apps served in Comet due to failure in Cross-Window-Message Origin validation",
      "bounty": 62500.0
    }
  ]
}
```

## 09-04 — Race condition

**Claim:** Also, search for scenarios where users can perform actions that depend on shared resources, like redeeming gift cards or registering accounts, without proper synchronization [1].

```
[1] Race Condition
# Race Condition

# Race Condition

> Race conditions may occur when a process is critically or unexpectedly dependent on the sequence or timings of other events. In a web application environment, where multiple requests can be processed at a given time, developers may leave concurrency to be handled by the framework, server, or programming language.
```

## 06-13 — CSRF

**Claim:** Look for actions that can be triggered by simple links or forms without additional validation [1].

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

## 26-12 — Privilege escalation

**Claim:** Look for areas where users can change their roles or permissions without proper checks [1].

```
[1] Testing for Privilege Escalation
# Testing for Privilege Escalation — Summary (WSTG-ATHZ-03)

This section describes the issue of escalating privileges from one stage to another. During this phase, the tester should verify that it is not possible for a user to modify their privileges or roles inside the application in ways that could allow privilege escalation attacks.

Privilege escalation occurs when a user gets access to more resources or functionality than they are normally allowed, and such elevation or changes should have been prevented by the application. This is usually caused by a flaw in the application. The result is that the application performs actions with more privileges than those intended by the developer or system administrator.

The degree of escalation depends on what privileges the attacker is authorized to possess, and what privileges can be obtained in a successful exploit. For example, a programming error that allows a user to gain extra privilege after successful authentication limits the degree of escalation, because the user is already authorized to hold some privilege. Likewise, a remote attacker gaining superuser privilege without any authentication presents a greater degree of escalat
```

## 24-07 — Account takeover

**Claim:** By manipulating these responses, the attacker was able to bypass authentication and take over accounts [2].

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

## 13-03 — Unrestricted file upload

**Claim:** Attackers can use this to upload files that can be executed as code, leading to unauthorized actions [1].

```
[1] CWE-434: Unrestricted Upload of File with Dangerous Type
# CWE-434: Unrestricted Upload of File with Dangerous Type

The product allows the upload or transfer of dangerous file types that are automatically processed within its environment.

**Also known as:** Unrestricted File Upload

**Likelihood of exploit:** Medium

**Applicable platforms:** ASP.NET, PHP, Not Language-Specific, Web Server, AI/ML

## Impact
- Integrity, Confidentiality, Availability: Execute Unauthorized Code or Commands — Arbitrary code execution is possible if an uploaded file is interpreted and executed as code by the recipient. This is especially true for web-server extensions such as .asp and .php because these file types are often treated as automatically executable, even when file system permissions do not specify execution. For example, in Unix environments, programs typically cannot run unless the execute bit is set, but PHP programs may be executed by the web server without directly invoking them on the operating system.
```

## 05-04 — XXE

**Claim:** If the application does not properly restrict or validate these external references, an attacker can manipulate the XML input to make the parser fetch data from unintended locations [1].

```
[1] Testing for XML Injection
### XML External Entity (XXE) Injection

The set of valid XML entities can be extended by defining new entities. If the definition of an entity is a URI, the entity is called an external entity. Unless configured to do otherwise, external entities force the XML parser to access the resource specified by the URI, e.g., a file on the local machine or on a remote system. This behavior exposes the application to XML External Entity (XXE) attacks, which can be used to perform denial of service, gain unauthorized access to files, scan internal networks, and perform Server-Side Request Forgery (SSRF).

To test for basic XXE vulnerabilities, one can inject a `DOCTYPE` declaration with an external entity into the XML payload:

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE user [ 
    <!ELEMENT user ANY >
    <!ENTITY xxe SYSTEM "file:///dev/random" >
]>
<user>
    <username>&xxe;</username>
    <password>Un6R34kb!e</password>
    <email>s4tan@hell.com</email>
</user>
```

> Note: The `DOCTYPE` name (`user`) matches the document's actual root element, and the `ELEMENT` declaration refers to that same root element — a mismatched or leftover `DOCTYPE`/`ELEMENT` name from a diffe
```

## 14-12 — JWT

**Claim:** JWTs are used for secure transmission of information, especially for authentication [1].

```
[1] JWT - JSON Web Token
# JWT - JSON Web Token

# JWT - JSON Web Token

> JSON Web Token (JWT) is an open standard (RFC 7519) that defines a compact and self-contained way for securely transmitting information between parties as a JSON object. This information can be verified and trusted because it is digitally signed.
```

## 05-09 — XXE

**Claim:** This allowed the attacker to read sensitive files on the server [3].

```
[3] 0day writeup: XXE in uber.com
# 0day writeup: XXE in uber.com

**Program:** Uber
**Vulnerability:** XXE
**Bounty:** $9,000
**Published:** 2017-01-24
**Author:** -

Source: https://httpsonly.blogspot.com/2017/01/0day-writeup-xxe-in-ubercom.html
```

## 10-02 — Prototype pollution

**Claim:** Almost all objects in JavaScript inherit from Object.prototype, making it a potential attack vector [1].

```
[1] Prototype Pollution
# Prototype Pollution

# Prototype Pollution

> Prototype pollution is a type of vulnerability that occurs in JavaScript when properties of Object.prototype are modified. This is particularly risky because JavaScript objects are dynamic and we can add properties to them at any time. Also, almost all objects in JavaScript inherit from Object.prototype, making it a potential attack vector.
```

## 05-06 — XXE

**Claim:** For example, you might use a payload that includes a `DOCTYPE` declaration pointing to a specific file or resource [1].

```
[1] Testing for XML Injection
### XML External Entity (XXE) Injection

The set of valid XML entities can be extended by defining new entities. If the definition of an entity is a URI, the entity is called an external entity. Unless configured to do otherwise, external entities force the XML parser to access the resource specified by the URI, e.g., a file on the local machine or on a remote system. This behavior exposes the application to XML External Entity (XXE) attacks, which can be used to perform denial of service, gain unauthorized access to files, scan internal networks, and perform Server-Side Request Forgery (SSRF).

To test for basic XXE vulnerabilities, one can inject a `DOCTYPE` declaration with an external entity into the XML payload:

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE user [ 
    <!ELEMENT user ANY >
    <!ENTITY xxe SYSTEM "file:///dev/random" >
]>
<user>
    <username>&xxe;</username>
    <password>Un6R34kb!e</password>
    <email>s4tan@hell.com</email>
</user>
```

> Note: The `DOCTYPE` name (`user`) matches the document's actual root element, and the `ELEMENT` declaration refers to that same root element — a mismatched or leftover `DOCTYPE`/`ELEMENT` name from a diffe
```

## 23-08 — Information disclosure

**Claim:** Check for sensitive details in public request responses [1, 2, 3].

```
[1] Information Disclosure leads to sensitive credential($$$)
# Information Disclosure leads to sensitive credential($$$)

**Program:** -
**Vulnerability:** Information disclosure
**Bounty:** $150
**Published:** 2021-12-25
**Author:** khan mamun (@mamunwhh)

Source: https://medium.com/@mamunwhh/information-disclosure-leads-to-sensitive-credential-35e779f6f4db
```

```
[2] Information Disclosure through Signup Endpoint
# Information Disclosure through Signup Endpoint

**Program:** -
**Vulnerability:** Information disclosure
**Published:** 2021-01-08
**Author:** Sunil Yedla (@sunilyedla2)

Source: https://orthonviper.medium.com/information-disclosure-through-signup-endpoint-86d2d66dfef1
```

```
[3] Staff Information Disclosure on Support Ticketing System ($x,xxx)
# Staff Information Disclosure on Support Ticketing System ($x,xxx)

**Program:** -
**Vulnerability:** Information disclosure
**Published:** 2021-01-22
**Author:** Ph.Hitachi

Source: https://ph-hitachi.medium.com/staff-information-disclosure-on-support-ticketing-system-p2-x-xxx-a08960aea7b1
```

## 04-01 — SSTI

**Claim:** This happens because user input is embedded into server-side templates without proper sanitization or validation [1, 2, 3, 4, 5, 6].

```
[1] Server Side Template Injection - Java
# Server Side Template Injection - Java

# Server Side Template Injection - Java

> Server-Side Template Injection (SSTI)  is a security vulnerability that occurs when user input is embedded into server-side templates in an unsafe manner, allowing attackers to inject and execute arbitrary code. In Java, SSTI can be particularly dangerous due to the power and flexibility of Java-based templating engines such as JSP (JavaServer Pages), Thymeleaf, and FreeMarker.
```

```
[2] Server Side Template Injection - ASP.NET
# Server Side Template Injection - ASP.NET

# Server Side Template Injection - ASP.NET

> Server-Side Template Injection (SSTI)  is a class of vulnerabilities where an attacker can inject malicious input into a server-side template, causing the template engine to execute arbitrary code on the server. In the context of ASP.NET, SSTI can occur if user input is directly embedded into a template (such as Razor, ASPX, or other templating engines) without proper sanitization.
```

```
[3] Server Side Template Injection - Elixir
# Server Side Template Injection - Elixir

# Server Side Template Injection - Elixir

> Server-Side Template Injection (SSTI)  is a vulnerability that arises when an attacker can inject malicious code into a server-side template, causing the server to execute arbitrary commands. In Elixir, SSTI can occur when using templating engines like EEx (Embedded Elixir), especially when user input is incorporated into templates without proper sanitization or validation.
```

```
[4] Server Side Template Injection - PHP
# Server Side Template Injection - PHP

# Server Side Template Injection - PHP

> Server-Side Template Injection (SSTI)  is a vulnerability that occurs when an attacker can inject malicious input into a server-side template, causing the template engine to execute arbitrary commands on the server. In PHP, SSTI can arise when user input is embedded within templates rendered by templating engines like Smarty, Twig, or even within plain PHP templates, without proper sanitization or validation.
```

```
[5] Server Side Template Injection - Ruby
# Server Side Template Injection - Ruby

# Server Side Template Injection - Ruby

> Server-Side Template Injection (SSTI)  is a vulnerability that arises when an attacker can inject malicious code into a server-side template, causing the server to execute arbitrary commands. In Ruby, SSTI can occur when using templating engines like ERB (Embedded Ruby), Haml, liquid, or Slim, especially when user input is incorporated into templates without proper sanitization or validation.
```

```
[6] Server Side Template Injection - Python
# Server Side Template Injection - Python

# Server Side Template Injection - Python

> Server-Side Template Injection (SSTI)  is a vulnerability that arises when an attacker can inject malicious input into a server-side template, causing arbitrary code execution on the server. In Python, SSTI can occur when using templating engines such as Jinja2, Mako, or Django templates, where user input is included in templates without proper sanitization.
```

## 05-13 — XXE

**Claim:** Attackers can use these vulnerabilities to read sensitive files or perform other malicious actions [1].

```
[1] Testing for XML Injection
### XML External Entity (XXE) Injection

The set of valid XML entities can be extended by defining new entities. If the definition of an entity is a URI, the entity is called an external entity. Unless configured to do otherwise, external entities force the XML parser to access the resource specified by the URI, e.g., a file on the local machine or on a remote system. This behavior exposes the application to XML External Entity (XXE) attacks, which can be used to perform denial of service, gain unauthorized access to files, scan internal networks, and perform Server-Side Request Forgery (SSRF).

To test for basic XXE vulnerabilities, one can inject a `DOCTYPE` declaration with an external entity into the XML payload:

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE user [ 
    <!ELEMENT user ANY >
    <!ENTITY xxe SYSTEM "file:///dev/random" >
]>
<user>
    <username>&xxe;</username>
    <password>Un6R34kb!e</password>
    <email>s4tan@hell.com</email>
</user>
```

> Note: The `DOCTYPE` name (`user`) matches the document's actual root element, and the `ELEMENT` declaration refers to that same root element — a mismatched or leftover `DOCTYPE`/`ELEMENT` name from a diffe
```

## 03-11 — SQL injection

**Claim:** Never perform tests on systems without permission [1].

```
[1] SQL Injection
# SQL Injection

# SQL Injection

> SQL Injection (SQLi)  is a type of security vulnerability that allows an attacker to interfere with the queries that an application makes to its database. SQL Injection is one of the most common and severe types of web application vulnerabilities, enabling attackers to execute arbitrary SQL code on the database. This can lead to unauthorized data access, data manipulation, and, in some cases, full compromise of the database server.
```

## 12-11 — Path traversal

**Claim:** Look for places where user input is used to construct file paths in applications [2].

```
[2] CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
# CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

The product uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the product does not properly neutralize special elements within the pathname that can cause the pathname to resolve to a location that is outside of the restricted directory.

Many file operations are intended to take place within a restricted directory. By using special elements such as ".." and "/" separators, attackers can escape outside of the restricted location to access files or directories that are elsewhere on the system. One of the most common special elements is the "../" sequence, which in most modern operating systems is interpreted as the parent directory of the current location. This is referred to as relative path traversal. Path traversal also covers the use of absolute pathnames such as "/usr/local/bin" to access unexpected files. This is referred to as absolute path traversal.

**Also known as:** Path traversal, Directory traversal, Path transversal

**Likelihood of exploit:** High

**Applicable platforms:** N
```

## 04-11 — SSTI

**Claim:** Testing for SSTI requires a safe environment to avoid unauthorized access or damage [7].

```
[7] BountyBrain knowledge graph (MITRE CWE/CAPEC, disclosed-report metadata)
{
  "cwe": "CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine",
  "likelihood_of_exploit": null,
  "aliases": [
    "Server-Side Template Injection / SSTI",
    "Client-Side Template Injection / CSTI",
    "csti",
    "server-side template injection",
    "ssti",
    "template injection"
  ],
  "attack_patterns": [],
  "notable_disclosures": [
    {
      "title": "Handlebars template injection and RCE in a Shopify app",
      "bounty": 10000.0
    },
    {
      "title": "How I earned $$$$ through Stored XSS",
      "bounty": 3205.0
    },
    {
      "title": "WPML Multilingual CMS Authenticated Contributor+ Remote Code Execution (RCE) via Twig Server-Side Template Injection (SSTI)",
      "bounty": 1639.0
    },
    {
      "title": "Injecting {{6*200}} to $1200",
      "bounty": 1200.0
    },
    {
      "title": "Remote Code execution at ws1.aholdusa.com \u2014 Compromising logins of Ahold Delhaize USA employees for >3.5 years (or even 18 years?)",
      "bounty": 300.0
    }
  ]
}
```

## 20-08 — Clickjacking

**Claim:** When the user clicks the button, the attacker redirects the iframe to a malicious site, exploiting the user's action [6].

```
[6] Clickjacking
# Clickjacking — Challenge

Inspect the following code:

```html
<div style="position: absolute; opacity: 0;">
  <iframe src="https://legitimate-site.com/login" width="500" height="500"></iframe>
</div>
<button onclick="document.getElementsByTagName('iframe')[0].contentWindow.location='malicious-site.com';">Click me</button>
```

Determine the Clickjacking vulnerability within this code snippet. Identify how the hidden iframe is being used to exploit the user's actions when they click the button, leading them to a malicious website.
```

## 03-12 — SQL injection

**Claim:** SQL Injection occurs when user inputs are directly included in SQL queries without proper sanitization [1].

```
[1] SQL Injection
# SQL Injection

# SQL Injection

> SQL Injection (SQLi)  is a type of security vulnerability that allows an attacker to interfere with the queries that an application makes to its database. SQL Injection is one of the most common and severe types of web application vulnerabilities, enabling attackers to execute arbitrary SQL code on the database. This can lead to unauthorized data access, data manipulation, and, in some cases, full compromise of the database server.
```

## 03-14 — SQL injection

**Claim:** Testing for SQL injection should always be conducted in a safe and authorized environment [1].

```
[1] SQL Injection
# SQL Injection

# SQL Injection

> SQL Injection (SQLi)  is a type of security vulnerability that allows an attacker to interfere with the queries that an application makes to its database. SQL Injection is one of the most common and severe types of web application vulnerabilities, enabling attackers to execute arbitrary SQL code on the database. This can lead to unauthorized data access, data manipulation, and, in some cases, full compromise of the database server.
```

## 02-14 — Cross-site scripting

**Claim:** XSS vulnerabilities occur when a server does not properly sanitize user input before displaying it on a webpage [1].

```
[1] Cross Site Scripting
# Cross Site Scripting

# Cross Site Scripting

> Cross-site scripting (XSS) is a type of computer security vulnerability typically found in web applications. XSS enables attackers to inject client-side scripts into web pages viewed by other users.
```

## 21-04 — Mass assignment

**Claim:** If the app doesn’t check which fields users are allowed to change, attackers can slip in changes to fields they shouldn’t be able to touch [2].

```
[2] Mass Assignment
# Mass Assignment — Methodology

Mass assignment vulnerabilities are most common in web applications that use Object-Relational Mapping (ORM) techniques or functions to map user input to object properties, where properties can be updated all at once instead of individually. Many popular web development frameworks such as Ruby on Rails, Django, and Laravel (PHP) offer this functionality.

For instance, consider a web application that uses an ORM and has a user object with the attributes `username`, `email`, `password`, and `isAdmin`. In a normal scenario, a user might be able to update their own username, email, and password through a form, which the server then assigns to the user object.

However, an attacker may attempt to add an `isAdmin` parameter to the incoming data like so:

```json
{
    "username": "attacker",
    "email": "attacker@email.com",
    "password": "unsafe_password",
    "isAdmin": true
}
```

If the web application is not checking which parameters are allowed to be updated in this way, it might set the `isAdmin` attribute based on the user-supplied input, giving the attacker admin privileges
```

## 01-01 — IDOR

**Claim:** This means that if a user tweaks a parameter in a URL or API request, they might be able to see or alter data they shouldn't have access to [1].

```
[1] Insecure Direct Object References
# Insecure Direct Object References

# Insecure Direct Object References

> Insecure Direct Object References (IDOR) is a security vulnerability that occurs when an application allows users to directly access or modify objects (such as files, database records, or URLs) based on user-supplied input, without sufficient access controls. This means that if a user changes a parameter value (like an ID) in a URL or API request, they might be able to access or manipulate data that they aren’t authorized to see or modify.
```

## 15-08 — CORS misconfiguration

**Claim:** This enabled the attacker to make requests from their site using the victim's credentials [1].

```
[1] CORS Misconfiguration
# CORS Misconfiguration

# CORS Misconfiguration

> A site-wide CORS misconfiguration was in place for an API domain. This allowed an attacker to make cross origin requests on behalf of the user as the application did not whitelist the Origin header and had Access-Control-Allow-Credentials: true meaning we could make requests from our attacker's site using the victim's credentials.
```

## 24-11 — Account takeover

**Claim:** Check for self-XSS vulnerabilities that can be used to bypass authentication [4].

```
[4] Account Takeover: An Epic Bug Bounty Story
# Account Takeover: An Epic Bug Bounty Story

**Program:** -
**Vulnerability:** Account takeover, Self-XSS, Pre-account takeover
**Published:** 2023-03-11
**Author:** Jaydev Ahire (@cybor_j)

Source: https://infosecwriteups.com/account-takeover-an-epic-bug-bounty-story-dd5468d5773d
```

## 03-06 — SQL injection

**Claim:** Test by injecting special characters and SQL keywords to see if they affect the query execution [1].

```
[1] SQL Injection
# SQL Injection

# SQL Injection

> SQL Injection (SQLi)  is a type of security vulnerability that allows an attacker to interfere with the queries that an application makes to its database. SQL Injection is one of the most common and severe types of web application vulnerabilities, enabling attackers to execute arbitrary SQL code on the database. This can lead to unauthorized data access, data manipulation, and, in some cases, full compromise of the database server.
```

## 04-04 — SSTI

**Claim:** Common indicators include URLs, form fields, or query parameters that appear in the output of a web page [1, 2, 3, 4, 5, 6].

```
[1] Server Side Template Injection - Java
# Server Side Template Injection - Java

# Server Side Template Injection - Java

> Server-Side Template Injection (SSTI)  is a security vulnerability that occurs when user input is embedded into server-side templates in an unsafe manner, allowing attackers to inject and execute arbitrary code. In Java, SSTI can be particularly dangerous due to the power and flexibility of Java-based templating engines such as JSP (JavaServer Pages), Thymeleaf, and FreeMarker.
```

```
[2] Server Side Template Injection - ASP.NET
# Server Side Template Injection - ASP.NET

# Server Side Template Injection - ASP.NET

> Server-Side Template Injection (SSTI)  is a class of vulnerabilities where an attacker can inject malicious input into a server-side template, causing the template engine to execute arbitrary code on the server. In the context of ASP.NET, SSTI can occur if user input is directly embedded into a template (such as Razor, ASPX, or other templating engines) without proper sanitization.
```

```
[3] Server Side Template Injection - Elixir
# Server Side Template Injection - Elixir

# Server Side Template Injection - Elixir

> Server-Side Template Injection (SSTI)  is a vulnerability that arises when an attacker can inject malicious code into a server-side template, causing the server to execute arbitrary commands. In Elixir, SSTI can occur when using templating engines like EEx (Embedded Elixir), especially when user input is incorporated into templates without proper sanitization or validation.
```

```
[4] Server Side Template Injection - PHP
# Server Side Template Injection - PHP

# Server Side Template Injection - PHP

> Server-Side Template Injection (SSTI)  is a vulnerability that occurs when an attacker can inject malicious input into a server-side template, causing the template engine to execute arbitrary commands on the server. In PHP, SSTI can arise when user input is embedded within templates rendered by templating engines like Smarty, Twig, or even within plain PHP templates, without proper sanitization or validation.
```

```
[5] Server Side Template Injection - Ruby
# Server Side Template Injection - Ruby

# Server Side Template Injection - Ruby

> Server-Side Template Injection (SSTI)  is a vulnerability that arises when an attacker can inject malicious code into a server-side template, causing the server to execute arbitrary commands. In Ruby, SSTI can occur when using templating engines like ERB (Embedded Ruby), Haml, liquid, or Slim, especially when user input is incorporated into templates without proper sanitization or validation.
```

```
[6] Server Side Template Injection - Python
# Server Side Template Injection - Python

# Server Side Template Injection - Python

> Server-Side Template Injection (SSTI)  is a vulnerability that arises when an attacker can inject malicious input into a server-side template, causing arbitrary code execution on the server. In Python, SSTI can occur when using templating engines such as Jinja2, Mako, or Django templates, where user input is included in templates without proper sanitization.
```

## 10-05 — Prototype pollution

**Claim:** This can be problematic if the product depends on the existence or non-existence of certain attributes, or uses predefined attributes of the object prototype [2].

```
[2] CWE-1321: Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')
# CWE-1321: Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')

The product receives input from an upstream component that specifies attributes that are to be initialized or updated in an object, but it does not properly control modifications of attributes of the object prototype.

**Applicable platforms:** JavaScript

## Impact
- Confidentiality, Integrity, Availability: Read Application Data, Modify Application Data — This weakness is usually exploited by using a special attribute of objects called proto, constructor, or prototype. Such attributes give access to the object prototype. An attacker can inject attributes that are used in other components by adding or modifying attributes of an object prototype. This creates attributes that exist on every object, or replace critical attributes with malicious ones. This can be problematic if the product depends on existence or non-existence of certain attributes, or uses pre-defined attributes of the object prototype (such as hasOwnProperty, toString, or valueOf).
- Availability: DoS: Crash, Exit, or Restart — An attacker can override existing attributes with ones that have incompatible type, whic
```

## 22-11 — Business logic

**Claim:** Business logic errors occur when software doesn't enforce its intended rules properly [1].

```
[1] Business Logic Errors
# Business Logic Errors

# Business Logic Errors

> Business logic errors, also known as business logic flaws, are a type of application vulnerability that stems from the application's business logic, which is the part of the program that deals with real-world business rules and processes. These rules could include things like pricing models, transaction limits, or the sequences of operations that need to be followed in a multi-step process.
```

## 01-11 — IDOR

**Claim:** IDOR vulnerabilities occur when applications allow direct access to objects based on user input without proper authorization checks [1].

```
[1] Insecure Direct Object References
# Insecure Direct Object References

# Insecure Direct Object References

> Insecure Direct Object References (IDOR) is a security vulnerability that occurs when an application allows users to directly access or modify objects (such as files, database records, or URLs) based on user-supplied input, without sufficient access controls. This means that if a user changes a parameter value (like an ID) in a URL or API request, they might be able to access or manipulate data that they aren’t authorized to see or modify.
```

## 25-05 — OAuth

**Claim:** Allows unauthorized access to tokens or credentials [2].

```
[2] Testing for OAuth Client Weaknesses
# Testing for OAuth Client Weaknesses — Summary

OAuth grants access rights on resources to clients. This allows them to act on behalf of the resource owner. The client receives the authorization code and refresh token in the token exchange and stores them.

Failure to protect the token exchange and credentials may result in unauthorized resource access and the elevation of privileges.
```
