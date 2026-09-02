# Nexora

### Professional Cybersecurity Reconnaissance & Security Assessment Framework

Nexora is a modular Python-based cybersecurity reconnaissance framework designed to automate information gathering, service discovery, security analysis, and report generation for authorized security assessments.

It combines multiple reconnaissance modules with a rule-based security intelligence engine that analyzes discovered information, identifies security weaknesses, assigns severity levels, calculates an overall security score, and generates professional JSON and HTML reports.

---

## Features

### Reconnaissance

* **TCP Port Scanning**

  * Concurrent TCP scanning
  * Scans ports `1–1000`
  * Identifies open ports
  * Measures scan duration

* **DNS Enumeration**

  * Resolves target DNS information
  * Collects relevant DNS records

* **WHOIS Lookup**

  * Retrieves domain registration information
  * Extracts available registration details

### Web Security Analysis

* **HTTP Security Headers**

  * HSTS
  * Content Security Policy
  * X-Frame-Options
  * X-Content-Type-Options
  * Referrer-Policy
  * Permissions-Policy

* **SSL/TLS Analysis**

  * TLS version
  * Cipher information
  * Cipher strength
  * Certificate issuer
  * Certificate validity
  * Certificate expiration
  * Subject Alternative Names

* **Technology Detection**

  * Web server identification
  * Framework detection
  * CMS detection
  * JavaScript library detection
  * Technology fingerprinting from HTTP headers and page content

### Security Intelligence

Nexora includes a rule-based intelligence engine that analyzes reconnaissance results and converts raw technical information into security findings.

It can identify issues such as:

* Risky exposed services
* Missing HTTP security headers
* Outdated TLS versions
* Expired SSL/TLS certificates
* Certificates approaching expiration
* Technology exposure

Each finding can contain:

* Severity
* Category
* Description
* Security recommendation

### Security Scoring

Nexora calculates an overall security score from **0–100** based on identified findings.

|  Score | Rating    |
| -----: | --------- |
| 90–100 | Excellent |
|  75–89 | Good      |
|  60–74 | Moderate  |
|  40–59 | Poor      |
|   0–39 | Critical  |

The score is accompanied by a severity summary showing the number of:

* 🔴 High findings
* 🟠 Medium findings
* 🟡 Low findings
* 🔵 Informational findings

### Automated Reporting

Nexora generates:

* **JSON reports** for structured data and further processing
* **HTML reports** containing a professional security assessment dashboard

The HTML report includes:

* Target information
* Security score
* Security rating
* Executive summary
* Priority actions
* Security findings
* Open ports
* Detected technologies
* HTTP security headers
* SSL/TLS information
* DNS information
* WHOIS information
* Reconnaissance module results

---

# Architecture

Nexora follows a modular architecture where reconnaissance modules collect data, the results layer centralizes the information, and the intelligence/reporting layers process the collected data.

```text
                         ┌─────────────────────┐
                         │       Nexora CLI    │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │     Dispatcher      │
                         └──────────┬──────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    │               │               │
                    ▼               ▼               ▼
              ┌──────────┐   ┌──────────┐    ┌──────────┐
              │ Portscan │   │   DNS    │    │  WHOIS   │
              └──────────┘   └──────────┘    └──────────┘
                    │               │               │
                    └───────────────┼───────────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    │               │               │
                    ▼               ▼               ▼
              ┌──────────┐   ┌──────────┐    ┌────────────┐
              │ Headers  │   │ SSL/TLS  │    │Technology  │
              └──────────┘   └──────────┘    └────────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │   Results Manager   │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │ Intelligence Engine │
                         └──────────┬──────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    │               │               │
                    ▼               ▼               ▼
             ┌────────────┐  ┌────────────┐  ┌────────────┐
             │   Score    │  │ Findings   │  │ Priority   │
             │  Analysis  │  │ Detection  │  │  Actions   │
             └────────────┘  └────────────┘  └────────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │  Report Generation  │
                         └──────────┬──────────┘
                                    │
                          ┌─────────┴─────────┐
                          ▼                   ▼
                    ┌──────────┐        ┌──────────┐
                    │   JSON   │        │   HTML   │
                    │  Report  │        │  Report  │
                    └──────────┘        └──────────┘
```

---

# Project Structure

```text
Nexora/
│
├── core/
│   ├── banner.py
│   ├── cli.py
│   ├── config.py
│   ├── dispatcher.py
│   └── __init__.py
│
├── modules/
│   ├── dns.py
│   ├── headers.py
│   ├── portscan.py
│   ├── sslscan.py
│   ├── technology.py
│   └── whois.py
│
├── services/
│   ├── findings.py
│   ├── html_report.py
│   ├── intelligence.py
│   ├── logger.py
│   ├── output.py
│   ├── report.py
│   ├── results.py
│   └── scoring.py
│
├── output/
│
├── wordlists/
│
├── main.py
├── requirements.txt
├── README.md
└── .gitignore
```

---

# Installation

## 1. Clone the repository

```bash
git clone https://github.com/YOUR-USERNAME/Nexora.git
cd Nexora
```

Replace `YOUR-USERNAME` with your GitHub username.

## 2. Create a virtual environment

```bash
python3 -m venv .venv
```

Activate it:

### Linux / Kali Linux

```bash
source .venv/bin/activate
```

### Windows

```powershell
.venv\Scripts\activate
```

## 3. Install dependencies

```bash
pip install -r requirements.txt
```

---

# Usage

Nexora provides a command-line interface for running individual reconnaissance modules as well as the complete assessment pipeline.

### Full Security Assessment

```bash
python3 main.py full example.com
```

The full scan performs the available reconnaissance and security analysis modules, followed by intelligence processing and report generation.

### Port Scan

```bash
python3 main.py scan example.com
```

### DNS Enumeration

```bash
python3 main.py dns example.com
```

### WHOIS Lookup

```bash
python3 main.py whois example.com
```

---

# Full Scan Workflow

A complete Nexora assessment follows this general workflow:

```text
Target
  │
  ▼
Target Resolution
  │
  ├── TCP Port Scan
  ├── DNS Enumeration
  ├── WHOIS Lookup
  ├── HTTP Header Analysis
  ├── SSL/TLS Analysis
  └── Technology Detection
          │
          ▼
    Centralized Results
          │
          ▼
    Intelligence Engine
          │
          ├── Security Findings
          ├── Severity Classification
          ├── Security Score
          └── Priority Actions
          │
          ▼
      Report Generation
          │
          ├── JSON
          └── HTML
```

---

# Intelligence Engine

The intelligence engine evaluates reconnaissance data using security rules.

For example, exposed services associated with commonly risky ports can generate higher-severity findings.

The engine also evaluates:

* Missing security headers
* TLS configuration
* Certificate status
* Technology exposure

The resulting findings are used to calculate the security score and generate remediation-oriented priority actions.

> **Note:** Nexora's intelligence engine is currently rule-based. It does not claim to use machine learning or generative AI.

---

# Example Assessment

A typical full assessment can produce information such as:

```text
NEXORA INTELLIGENCE

Executive Summary:
Nexora identified several areas for security improvement.

Priority Actions:
1. Implement a restrictive Content-Security Policy.
2. Enable HSTS after confirming full HTTPS compatibility.

Security Score:
72 / 100

Assessment:
Moderate
```

The exact results depend on the target being assessed.

---

# Reports

Nexora automatically generates timestamped reports inside the `output/` directory.

### JSON

JSON reports provide structured reconnaissance and assessment data suitable for:

* Further processing
* Automation
* Data analysis
* Integration with other tools

### HTML

HTML reports provide a human-readable security assessment dashboard containing the major findings and reconnaissance results.

---

# Technology Stack

* **Python 3**
* `socket`
* `ssl`
* `requests`
* DNS/WHOIS libraries
* `argparse`
* `concurrent.futures`
* HTML/CSS
* JSON

---

# Security Considerations

Nexora is intended for **authorized security testing and reconnaissance**.

Only scan:

* Systems you own
* Systems you have explicit permission to test
* Purpose-built security labs
* Authorized CTF environments

Do not use Nexora to scan or assess systems without authorization.

---

# Future Improvements

Potential future development includes:

* Expanded port ranges and service detection
* Subdomain enumeration
* More DNS record types
* Advanced web technology fingerprinting
* CVE/CPE-based vulnerability correlation
* Improved security scoring
* Configurable scanning profiles
* PDF report generation

---

# Project Goals

Nexora was developed to demonstrate practical understanding of:

* Cybersecurity reconnaissance
* Network security
* Web security assessment
* Python development
* Security analysis
* 
---

# Author

**Yogendra Panchal**

Cybersecurity & Computer Engineering Student at Parul University Vadodara

Interested in:

* Cybersecurity
* Ethical Hacking
* Network Security
* Security Automation
* AI/ML
* Red & Blue Team Operations

---

# Disclaimer

Nexora is developed for educational purposes, authorized security assessments, cybersecurity research, and controlled lab environments.

The author is not responsible for misuse of this software or unauthorized activity performed with it.

**Always obtain appropriate authorization before scanning or assessing a target.**
