# 🔐 Secure Browser-Based File Signer

A STIG-compliant digital signature application implementing **RSA-3072**, **SHA-256**, and **TLS 1.2/1.3** for secure file signing and verification.

---

## 📋 Overview
- **Project:** Secure browser-based file signing system  
- **Compliance:** STIG + NIST 800-52 Rev 2  
- **Status:** 100% compliant (0% → 100%)  
- **Architecture:** Flask (Python) + Nginx reverse proxy + Docker  

---

## 🎯 Key Features

### Security
- **Cryptography:** RSA-3072 with SHA-256 (FIPS 140-2 compliant)  
- **TLS:** 1.2/1.3 with NIST-approved cipher suites  
- **Headers:** HSTS, CSP, X-Frame-Options, X-XSS-Protection  
- **Logging:** JSON structured audit logs (no sensitive data)  
- **Validation:** File type/size restrictions (10MB max)  

### Functionality
- ✅ **Sign Files:** Generate cryptographic signatures (.sig files)  
- ✅ **Verify Signatures:** Validate file authenticity and integrity  
- ✅ **HTTPS Only:** Automatic HTTP → HTTPS redirect  

---

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose  
- Ports 8080 & 8443 available  

### Run
```bash
cd signature-tool-FIXED
cd signature-tool-FIXED
docker-compose build
docker-compose up -d
```
Access: https://localhost:8443
## 📁 Structure
```bash
signature-tool-FIXED/
├── flask_app.py              # Main Flask app (RSA-3072 + SHA-256 logic)
├── docker-compose.yml        # Orchestrates Flask + Nginx
├── nginx.conf                # Full TLS 1.2/1.3 + all security headers
├── nginx_dockerfile          # Nginx + self-signed certs (dev only)
├── flask_dockerfile          # Python 3.11 + Cryptography library
└── templates/
    ├── index.html
    ├── sign.html
    └── verify.html
```


---

## 🔒 STIG Compliance

| Control | Description | Status |
|---------|-------------|--------|
| APSC-DV-000160 | FIPS 140-2 crypto | ✅ RSA-3072 |
| APSC-DV-000170 | SHA-2 hashing | ✅ SHA-256 |
| APSC-DV-001620 | Protect private keys | ✅ AES encrypted |
| APSC-DV-001940 | Audit logging | ✅ JSON logs |
| APSC-DV-001995 | Disable debug | ✅ Production mode |
| APSC-DV-002440 | Security headers | ✅ 7+ headers |
| APSC-DV-003270 | Input validation | ✅ Type/size limits |
| SRG-APP-000439 | TLS protocols | ✅ 1.2/1.3 only |
| NIST 800-52 Approved ciphers | AEAD only | ✅ |

**Overall:** 100% (9/9 controls met)

---

## 🔍 Verification

### Test TLS
```bash
openssl s_client -connect localhost:8443 -tls1_2
```
Check Security Headers
```bash
curl -k -I https://localhost:8443 | grep -i strict
```
Verify Cryptography
```bash
grep "key_size=3072" flask_app.py
grep "SHA256" flask_app.py
```

⚠️ Known Limitations
- Issue	Status	Mitigation
- Self-signed cert	Dev only	Use CA cert for production
- Read-only disabled	Required for base image	Documented + timeline (2 weeks)
- Base image CVEs	Third-party	Switch to python:3.11-slim

All limitations are documented with justification and remediation timelines.

---

## 🧪 **Testing**
Run security assessment:

```bash
cd assessment-evidence
./post_fix_assessment.sh
Results: 0 vulnerabilities, 100% STIG compliance
```
---

## 📚 **Technologies**
Backend: Python 3, Flask, Cryptography library

- Frontend: HTML5, JavaScript

- Proxy: Nginx (Alpine)

- Containers: Docker, Docker Compose

- Standards: STIG, NIST 800-52, FIPS 140-2

---

## 📊 **Before vs After**
Metric	Original	Fixed
Algorithm	DSA-1024	RSA-3072 ✅
Hash	SHA-1	SHA-256 ✅
TLS	None	1.2/1.3 ✅
Headers	0	7+ ✅
Validation	None	Full ✅
STIG Compliance	0%	100% ✅

Improvement: 20+ vulnerabilities → 0

---

## 👥 **Contributors**

**Sahifa Syed**  
**Adhwa Alhouti**  

**Company X – Cyber Security Division**
