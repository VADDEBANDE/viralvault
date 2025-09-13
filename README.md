# ViralVault - Advanced Web Application Security Lab

![ViralVault Logo](https://img.shields.io/badge/ViralVault-Security%20Lab-red?style=for-the-badge\&logo=security\&logoColor=white)

> *⚠️ WARNING*: This is an intentionally vulnerable application designed for advanced security training. *DO NOT* deploy in production environments.

## Overview

ViralVault is a sophisticated Flask-based social media virality betting platform containing **9 carefully crafted vulnerabilities** designed for Intermediate-to-advanced bug bounty hunters and security researchers. Each vulnerability represents real-world attack scenarios found in production applications, including my own finds.
Please note, there are both documented and undocumented vulnerabilities with this software. This is intentional. You are encouraged to try and discover as many issues as possible.

## Quick Start

```bash
# Clone the repository
git clone https://github.com/VADDEBANDE/viralvault
cd viralvault

# Install dependencies
pip install -r requirements.txt

install wkhtmltopdf from https://wkhtmltopdf.org/downloads.html  # Required for PDF generation

# Run the application
python app.py

# Access the application
open http://localhost:5000
```

## Default Credentials

| Username | Password | Role |
|----------|----------|------|
| alice | alice123 | Standard User |
| bob | bob456 | Standard User |
|/admin endpoint  | ultra_secure_admin_password_2025_!@#$% | Administrator |

### ⚠️ *I would encourage that you start with the lab without reading further since the next part provides an overview of the vulnerabilities present, and real applications do not tell what they are vulnerable to.*

## Writeup

* 📖 [Complete Writeup](writeup.md)

## Vulnerabilities Overview

| ID | Vulnerability Type | Severity | Impact |
|:---|:---|:---|:---|
| V1 | Referral Program Abuse | Medium | Financial |
| V2 | Verification Code Leak | Low | Data Exposure |
| V3 | Stale Cache Race Condition | High | Financial |
| V4 | Double Claim Race Condition | High | Financial |
| V5 | IDOR in API endpoint | Medium | Privacy |
| V6 | External SSRF | Medium | Data Exfiltration |
| V7 | Cross-Site Scripting (XSS) | Critical | Account Takeover |
| V8 | CSRF (CSPT2CSRF)| Medium | Financial
| V9 | Internal SSRF (Local File Access) | Critical | Internal Access |



## Learning Objectives

After completing this lab, you will understand:

* Advanced race condition exploitation techniques
* Complex business logic vulnerability identification
* Server-Side Request Forgery (SSRF) bypass methods
* Multi-vector attack chain development
* Advanced CSRF attacks

## Coming Updates:
* Add Business Logic Vulnerbilitites in regards to the economics of betting.
* Add GraphQL based Vulnerabilities

