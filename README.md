## Group Name: ADHD
## Group Members:
1. Muhammad Daniel Hakim Bin Mohd Suhaimi 2018451
2. Muhammad Hazim Bin Nor Aizi

## Assisgned Tasks for Group Members:
1. Server OS and Server-Side Scripting used(Windows or Linux, PHP or ASP.net or JavaScript, etc) : 
2. Hash Disclosure                                                                               : 
3. CSRF                                                                                          : 
4. Secured Cookies                                                                               : Daniel
5. CSP                                                                                           : Daniel
6. JS Library                                                                                    : 
7. HTTPS implementation(TL/SSL)                                                                  : 
8. Cookie Poisoning                                                                              : 
9. Potential XSS                                                                                 : 
10. Information Disclosure                                                                       : 
## Table of Contents
1. [Introduction](#introduction)
2. [Identify the vulnerabilities](#paragraph1)
    1. [Server OS and Server-Side Scripting used](#subparagraph1)
    2. [Hash Disclosure](#subparagraph2)
    3. [CSRF](#subparagraph3)
    4. [Secured Cookies](#subparagraph4)
    5. [CSP](#subparagraph5)
    6. [JS Library ](#subparagraph6)
    7. [HTTPS implementation](#subparagraph7)
    8. [Cookie Poisoning](#subparagraph8)
    9. [Potential XSS](#subparagraph9)
    10. [Information Disclosure](#subparagraph10)

3. [Evaluate the vulnerabilities](#paragraph2)
    1. [Server OS and Server-Side Scripting used](#subparagraph11)
    2. [Hash Disclosure](#subparagraph12)
    3. [CSRF](#subparagraph13)
    4. [Secured Cookies](#subparagraph14)
    5. [CSP](#subparagraph15)
    6. [JS Library ](#subparagraph16)
    7. [HTTPS implementation](#subparagraph17)
    8. [Cookie Poisoning](#subparagraph18)
    9. [Potential XSS](#subparagraph19)
    10. [Information Disclosure](#subparagraph20)

4. [Prevent the vulnerabilities](#paragraph3)
    1. [Server OS and Server-Side Scripting used](#subparagraph21)
    2. [Hash Disclosure](#subparagraph22)
    3. [CSRF](#subparagraph23)
    4. [Secured Cookies](#subparagraph24)
    5. [CSP](#subparagraph25)
    6. [JS Library ](#subparagraph26)
    7. [HTTPS implementation](#subparagraph27)
    8. [Cookie Poisoning](#subparagraph28)
    9. [Potential XSS](#subparagraph29)
    10. [Information Disclosure](#subparagraph30)

## Introduction<a name="introduction"></a>
The objective of this report is to conduct a case study upon the website https://www.mbot.org.my/ using OWASP ZAP. We first scan the website using traditional spider to get any alert or vulnerabilities that was assigned for us to check. After that we observe the additional information such as CWE ID and CVE ID.


## Identify the vulnerabilities <a name="paragraph1"></a>
We scan the website to identify if there are any vulnerabilites in the website.
Here is the scan result:
![Result](AssetGithub/Resultscanned.png)

### Server OS and Server-Side Scripting used <a name="subparagraph1"></a>

### Hash Disclosure <a name="subparagraph2"></a>

### CSRF <a name="subparagraph3"></a>

### Secured Cookies <a name="subparagraph4"></a>
After a thorough inspection, there are no alert for Secured cookies but another alert related to cookies was found which is Cookies Without Same Site Attribute.

![Cookie](AssetGithub/Cookiefound.png)

A report regarding this alert is made such as below

![Cookie](AssetGithub/Cookiereport.png)

This alert happened because of the cookie set in the website did not implement the SameSite Attribute resulting to cross-site request.

### CSP <a name="subparagraph5"></a>

### JS Library <a name="subparagraph6"></a>

### HTTPS implementation <a name="subparagraph7"></a>

### Cookie Poisoning <a name="subparagraph8"></a>

### Potential XSS <a name="subparagraph9"></a>

### Information Disclosure <a name="subparagraph10"></a>

## Evaluate the vulnerabilities <a name="paragraph2"></a>
After identifying vulnerabilities, we evaluate the vulnerabilities to decide the degree of risk of each vulnerabilities.

### Server OS and Server-Side Scripting used <a name="subparagraph11"></a>

### Hash Disclosure <a name="subparagraph12"></a>

### CSRF <a name="subparagraph13"></a>

### Secured Cookies <a name="subparagraph14"></a>
According to https://cwe.mitre.org/ Cookies Without Same Site Attribute is listed as Sensitive Cookie with Improper SameSite Attribute with CWE ID 1275
Just as stated above this is due to the SameSite attribute for sensitive cookies is not set, or an insecure value is used. The cookie transmission for cross-domain requests is managed by the SameSite property. 'Lax', 'Strict', or 'None' are the three possible values for this characteristic. A website may send a cross-domain POST HTTP request to another website if the 'None' option is provided, and the browser will add cookies to this request. If there are no extra safeguards in place (such as Anti-CSRF tokens), this could result in Cross-Site-Request-Forgery (CSRF) attacks. 

However this vulnerability is listed as a simple structure, it is not difficult to prevent as it only involve Web Based. Thus this vulnerability is categorized as a low to medium risk due to its low likelihood.

### CSP <a name="subparagraph15"></a>

### JS Library <a name="subparagraph16"></a>

### HTTPS implementation <a name="subparagraph17"></a>

### Cookie Poisoning <a name="subparagraph18"></a>

### Potential XSS <a name="subparagraph19"></a>

### Information Disclosure <a name="subparagraph20"></a>


## Prevent the vulnerabilities <a name="paragraph3"></a>
The last step is for us to suggest a way to prevent the vulnerabilities found from the scan.

### Server OS and Server-Side Scripting used <a name="subparagraph21"></a>

### Hash Disclosure <a name="subparagraph22"></a>

### CSRF <a name="subparagraph23"></a>

### Secured Cookies <a name="subparagraph24"></a>
Set the 'Lax' or 'Strict' options for the SameSite attribute of a sensitive cookie. This gives the browser specific instructions to use this cookie exclusively for requests from the same domain, which offers strong Defence in Depth against CSRF attacks. Cookies are also delivered for top-level cross-domain navigation via HTTP GET, HEAD, OPTIONS, and TRACE methods when the 'Lax' value is in use, but not for other HTTP methods that are more likely to result in state mutation side-effects.

Here is the example of the code:
```
// Set a cookie with SameSite attribute
document.cookie = "myCookie=value; SameSite=Strict";

// Alternatively, you can set multiple attributes in one cookie using semicolons
document.cookie = "myOtherCookie=anotherValue; SameSite=Lax; Secure; HttpOnly";

```
### CSP <a name="subparagraph25"></a>

### JS Library <a name="subparagraph26"></a>

### HTTPS implementation <a name="subparagraph27"></a>

### Cookie Poisoning <a name="subparagraph28"></a>

### Potential XSS <a name="subparagraph29"></a>

### Information Disclosure <a name="subparagraph30"></a>
