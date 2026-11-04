# E-Commerce Security Assessment: Securing Websites and Online Payment Systems

First Quadrant Labs Internship, Project 2.

## Overview
A black-box penetration test of an e-commerce platform, followed by a remediation plan, monitoring, phishing protection and incident response planning.

## Highlights
- Exploited 8 vulnerabilities (2 Critical, 3 High, 3 Medium), each mapped to OWASP Top 10 and CWE with CVSS scores.
- SQL injection authentication bypass giving administrator access (CVSS 9.8), then database extraction through error-based injection (CVSS 9.1).
- Also found and validated stored XSS, IDOR, public directory exposure, missing rate limiting, weak security headers and insecure JWT storage, using OWASP ZAP and manual testing.
- Remediation plan: parameterized queries, output encoding, Content Security Policy, ModSecurity WAF with OWASP CRS, HttpOnly cookies, MFA and RBAC.
- Retested and confirmed that SQL injection, XSS and brute-force attacks were blocked.
- SPF, DKIM and DMARC phishing protection, plus a NIST SP 800-61 incident response plan with a GDPR 72-hour notification procedure.
- A monitoring script that detected a simulated brute-force attack and blocked the attacking IP automatically.

## Deliverables
- Security Audit and Penetration Testing Report
- Security Assessment Report
- Implementation Plan for Security Measures
- Phishing Protection Strategy
- Monitoring and Incident Response Plan
- Data Privacy and Compliance Documentation
- Screenshot evidence, plus `secure-demo.js`, a small demo showing the vulnerable, encoded and WAF-protected versions of an endpoint

## Tools
Kali Linux, OWASP ZAP, ModSecurity, Node.js.

## Disclaimer
Testing was performed on a lab environment as part of an internship project.
