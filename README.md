E-Commerce Security Assessment: Securing Websites and Online Payment Systems

First Quadrant Labs Internship, Project 2.

Overview

A black-box penetration test of an e-commerce platform (OWASP Juice Shop, run locally in Docker), followed by a remediation plan, monitoring, phishing protection, incident response planning and data privacy documentation.

Scope and Authorization
Item	Details
Target	OWASP Juice Shop, an intentionally vulnerable training application, running in an isolated local Docker environment
In scope	Web interface, REST API, authentication, product search and reviews, basket and checkout flow, static file storage
Out of scope	Live systems, real customer data, social engineering, denial of service
Authorization	I hosted the target myself. No live systems, real customer data or third parties were accessed
Methodology	OWASP Web Security Testing Guide and OWASP Top 10 (2021): reconnaissance, automated scan (OWASP ZAP), manual verification, proof-of-concept exploitation, rating and reporting
Highlights
Exploited 8 vulnerabilities (2 Critical, 3 High, 3 Medium), each mapped to OWASP Top 10 and CWE with CVSS scores.
SQL injection authentication bypass giving administrator access (CVSS 9.8), then database extraction through error-based injection (CVSS 9.1).
Also found and validated stored XSS, IDOR, public directory exposure, missing rate limiting, weak security headers and insecure JWT storage, using OWASP ZAP and manual testing.
Remediation plan: parameterized queries, output encoding, Content Security Policy, ModSecurity WAF with OWASP CRS, HttpOnly cookies, MFA and RBAC.
Retested against a hardened demo application: SQL injection, XSS and brute-force payloads were blocked.
SPF, DKIM and DMARC phishing protection, plus a NIST SP 800-61 incident response plan with a GDPR 72-hour notification procedure.
A monitoring script that detected a simulated brute-force attack and blocked the attacking IP automatically.
Findings Summary
ID	Finding	Severity	CVSS v3.1	OWASP Top 10 (2021)	CWE	Retest status
F-01	SQL injection: authentication bypass	Critical	9.8	A03 Injection	CWE-89	Blocked by WAF in demo (HTTP 403)
F-02	SQL injection: error disclosure and data extraction	Critical	9.1	A03 Injection	CWE-89	Blocked by WAF in demo (HTTP 403)
F-03	Stored and DOM XSS in product content	High	8.1	A03 Injection	CWE-79	Neutralized in demo (output encoding, CSP)
F-04	IDOR: access to other users' baskets	High	6.5	A01 Broken Access Control	CWE-639	Fix documented (server-side ownership checks)
F-05	Public directory listing (/ftp)	High	7.5	A02 / A05	CWE-548	Fix documented (listing disabled, WAF rule)
F-06	No rate limiting or account lockout on login	Medium	5.3	A07 Identification and Authentication Failures	CWE-307	Detected and IP auto-blocked in demo
F-07	Missing or permissive security headers	Medium	6.1	A05 Security Misconfiguration	CWE-693	Headers present in hardened demo
F-08	JWT session token stored in localStorage	Medium	6.5	A07 / A02	CWE-347	Fix documented (HttpOnly cookies)

Attack chain demonstrated: an attacker with no credentials reaches administrator access (F-01), exfiltrates the customer credentials table (F-02) and can impersonate customers (F-03, F-08), all from a browser in a single session.

Deliverables
#	Document	Covers
D1	SECURITY ASSESSMENT REPORT.docx	Findings F-01 to F-08, proof of concept, STRIDE threat model, remediation roadmap
D2	IMPLEMENTATION PLAN FOR SECURITY MEASURES.docx	Parameterized queries, output encoding, CSP and headers, ModSecurity WAF, TLS 1.3, payment tokenization
D3	PHISHING PROTECTION STRATEGY.docx	SPF, DKIM, DMARC phased rollout, user awareness program
D4	MONITORING AND INCIDENT RESPONSE PLAN.docx	Wazuh SIEM design, detection rules R1 to R7, NIST SP 800-61 incident response, tabletop exercise
D5	SECURITY AUDIT AND PENETRATION TESTING REPORT.docx	Penetration test with CVSS scores, retest results, 15-control audit, testing cadence
D6	DATA PRIVACY AND COMPLIANCE DOCUMENTATION.docx	GDPR and CCPA/CPRA checklists, data inventory, MFA (TOTP) and RBAC

Screenshot evidence is in evidence/. The reports refer to these as figures (for example, Fig. 6.1 to 6.11 in D1).

Repository Structure
.
├── README.md
├── SECURITY ASSESSMENT REPORT.docx
├── IMPLEMENTATION PLAN FOR SECURITY MEASURES.docx
├── PHISHING PROTECTION STRATEGY.docx
├── MONITORING AND INCIDENT RESPONSE PLAN.docx
├── SECURITY AUDIT AND PENETRATION TESTING REPORT.docx
├── DATA PRIVACY AND COMPLIANCE DOCUMENTATION.docx
└── evidence/
    ├── screenshots of exploits, retests, monitoring and MFA/RBAC demos
    └── secure-demo.js
Running the Demo

secure-demo.js shows the vulnerable, output-encoded and WAF-protected versions of an endpoint side by side. It uses only built-in Node.js modules, so there is nothing to install.

bash
node evidence/secure-demo.js
Retest and Limitations
The retest was run against a hardened demonstration application and local control demos, not against a patched copy of Juice Shop. The Juice Shop source code was not modified.
Fixes that need production code changes (parameterized queries, server-side ownership checks, cookie-based sessions) are documented in D2 and D6 but not applied. These are marked "Fix documented" above.
This was a black-box test without source code access. It is not a guarantee of security, which is why D5 sets out a quarterly audit and annual penetration test.
Tools

Kali Linux, OWASP ZAP, ModSecurity, Node.js, Docker.

Disclaimer

All testing was performed against OWASP Juice Shop, an intentionally vulnerable training application, which I ran in an isolated local environment as part of an internship project. No live systems, real customer data or third parties were accessed. The techniques are documented for education only. Do not use them against any system you do not own or do not have written permission to test.
