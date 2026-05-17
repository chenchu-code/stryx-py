<div align="center">

<br/>

```
███████╗████████╗██████╗ ██╗   ██╗██╗  ██╗
██╔════╝╚══██╔══╝██╔══██╗╚██╗ ██╔╝╚██╗██╔╝
███████╗   ██║   ██████╔╝ ╚████╔╝  ╚███╔╝ 
╚════██║   ██║   ██╔══██╗  ╚██╔╝   ██╔██╗ 
███████║   ██║   ██║  ██║   ██║   ██╔╝ ██╗
╚══════╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝
```

**Email & URL Threat Analyzer — SOC Intelligence Tool**

[![Python](https://img.shields.io/badge/Python-3.9%2B-3dff8f?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.32%2B-ff4b4b?style=flat-square&logo=streamlit&logoColor=white)](https://streamlit.io)
[![License](https://img.shields.io/badge/License-MIT-00d4ff?style=flat-square)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Live-3dff8f?style=flat-square)]()
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20Mapped-f5c842?style=flat-square)](https://attack.mitre.org)

[**Live Demo →**](https://stryx-py.streamlit.app) · [**Report Bug**](https://github.com/chenchu-code/stryx-py/issues) · [**Request Feature**](https://github.com/chenchu-code/stryx-py/issues)

<br/>

</div>

---

## ⟩ Overview

**STRYX** is an open-source threat intelligence tool built for SOC analysts, cybersecurity students, and security-aware individuals. It analyzes URLs and emails in real time using a custom-built heuristic rule engine — detecting phishing, spoofing, social engineering, and brand impersonation with zero API dependencies.

> Built by **Chenchu (Silent Storm)** as a portfolio project demonstrating practical SOC analyst skills including threat detection, MITRE ATT&CK mapping, and incident response workflows.

---

## ⟩ Key Features

| Feature | Description |
|---|---|
| 🔍 **URL Analysis** | 12 detection rules covering lookalike domains, IP hosts, suspicious TLDs, obfuscation, homoglyphs, and more |
| 📧 **Email Analysis** | 8 detection rules covering spoofed senders, urgency language, credential requests, phishing links, payment scams |
| 🎯 **MITRE ATT&CK** | Threat findings mapped to real technique IDs (T1566, T1598, T1657, T1071) |
| 📊 **Dashboard** | Visual analytics — risk score trend, verdict distribution, top threat type breakdown |
| 🟢 **Simple Mode** | Plain-English verdict for non-technical users |
| 🔴 **Advanced Mode** | Full technical breakdown with per-indicator severity ratings |
| 📄 **Report Export** | Download professional `.txt` incident report from any scan |
| ⚡ **Instant Results** | Pure rule-based engine — no API calls, no waiting, no internet required |
| 🔒 **100% Private** | Zero data sent anywhere. All analysis runs locally in your session |

---

## ⟩ Detection Engine

### URL Rules (12 active)

```
┌─────────────────────────┬──────────┬──────────────────────────────────────────────┐
│ Rule                    │ Severity │ Description                                  │
├─────────────────────────┼──────────┼──────────────────────────────────────────────┤
│ PROTOCOL                │ MEDIUM   │ HTTP instead of HTTPS                        │
│ IP AS HOST              │ CRITICAL │ Raw IP address used as domain                │
│ SUSPICIOUS TLD          │ HIGH     │ .xyz .tk .top .ml .ga and 15+ more           │
│ URL SHORTENER           │ MEDIUM   │ bit.ly tinyurl rb.gy and 8+ more             │
│ LOOKALIKE DOMAIN        │ CRITICAL │ paypa1 g00gle amaz0n and similar             │
│ SUSPICIOUS PATH         │ HIGH     │ /login /verify /account /credential          │
│ EXCESS SUBDOMAINS       │ MEDIUM   │ More than 4 subdomains                       │
│ OBFUSCATION             │ HIGH     │ 3+ URL-encoded characters                    │
│ LONG URL                │ LOW      │ Over 120 characters                          │
│ MANY PARAMETERS         │ LOW      │ More than 5 query parameters                 │
│ AT-SIGN IN URL          │ HIGH     │ @ symbol used to redirect                    │
│ BRAND IMPERSONATION     │ CRITICAL │ Brand name + action keyword pattern          │
└─────────────────────────┴──────────┴──────────────────────────────────────────────┘
```

### Email Rules (8 active)

```
┌─────────────────────────┬──────────┬──────────────────────────────────────────────┐
│ Rule                    │ Severity │ Description                                  │
├─────────────────────────┼──────────┼──────────────────────────────────────────────┤
│ URGENCY LANGUAGE        │ HIGH     │ Urgent, act now, suspended, expires          │
│ CREDENTIAL REQUEST      │ CRITICAL │ Password, CVV, SSN, bank account             │
│ SUSPICIOUS LINK         │ CRITICAL │ High-risk URLs embedded in body              │
│ BRAND MENTION           │ MEDIUM   │ Known brands — cross-checks sender domain    │
│ GENERIC GREETING        │ LOW      │ Dear Customer / Dear User                    │
│ SPOOFED SENDER          │ CRITICAL │ Display name vs domain mismatch              │
│ PAYMENT REQUEST         │ HIGH     │ Wire, gift card, Zelle, Western Union        │
│ THREAT LANGUAGE         │ HIGH     │ Legal action, arrest, account closure        │
└─────────────────────────┴──────────┴──────────────────────────────────────────────┘
```

### Scoring System

```
Score 0–14   →  SAFE      🔵  No action needed
Score 15–34  →  LOW       🟢  Verify before proceeding  
Score 35–54  →  MEDIUM    🟡  Suspicious — do not click
Score 55–74  →  HIGH      🟠  Likely malicious — block
Score 75–100 →  CRITICAL  🔴  Confirmed threat — escalate
```

---

## ⟩ MITRE ATT&CK Mapping

| Indicator Type | MITRE Technique |
|---|---|
| Lookalike Domain | T1566.002 — Spearphishing via Service |
| Spoofed Sender | T1566.001 — Spearphishing Attachment |
| Credential Request | T1598 — Phishing for Information |
| Suspicious Link | T1566.002 — Spearphishing Link |
| Brand Impersonation | T1566 — Phishing |
| IP as Host | T1071 — Application Layer Protocol Abuse |
| Payment Request | T1657 — Financial Theft |

---

## ⟩ Tech Stack

```
Language    →  Python 3.9+
Framework   →  Streamlit 1.32+
Detection   →  Custom rule engine (regex + heuristics)
Charts      →  Streamlit native charts
Storage     →  Session state (no database)
Deploy      →  Streamlit Community Cloud (free)
```

---

## ⟩ Project Structure

```
stryx-py/
├── app.py              ← Main Streamlit application
├── requirements.txt    ← Python dependencies
└── README.md           ← This file
```

---

## ⟩ Run Locally

**Requirements:** Python 3.9+

```bash
# Clone the repo
git clone https://github.com/chenchu-code/stryx-py.git
cd stryx-py

# Install dependencies
pip install -r requirements.txt

# Run the app
streamlit run app.py
```

Open `http://localhost:8501` in your browser.

---

## ⟩ Deploy on Streamlit Cloud (Free)

1. Fork this repo to your GitHub
2. Go to [streamlit.io/cloud](https://streamlit.io/cloud)
3. Sign in with GitHub
4. Click **New app** → Select this repo
5. Main file path: `app.py`
6. Click **Deploy**

Live in under 2 minutes. Free forever.

---

## ⟩ Sample Test Cases

**Phishing URL:**
```
http://paypa1-secure-login.xyz/verify?user=account&token=8fx2k
```

**Phishing Email:**
```
From: security@paypa1-alerts.com
Subject: URGENT: Your account will be suspended in 24 hours!

Dear Valued Customer,
We detected suspicious activity. Verify immediately:
http://paypa1-secure.xyz/verify

PayPal Security Team
```

**Safe URL:**
```
https://www.google.com
```

---

## ⟩ Roadmap

- [x] URL threat analysis engine
- [x] Email threat analysis engine
- [x] MITRE ATT&CK mapping
- [x] Simple & Advanced output modes
- [x] Dashboard with visual analytics
- [x] Report download (.txt)
- [ ] Bulk URL scanner (multiple URLs at once)
- [ ] VirusTotal API integration (optional)
- [ ] Export report as PDF
- [ ] Custom rule builder
- [ ] Browser extension version

---

## ⟩ Use Cases

- **SOC Analysts** — Quick triage of suspicious URLs and emails
- **Security Students** — Learn phishing detection patterns and MITRE mapping
- **IT Teams** — Verify suspicious emails reported by employees
- **Individuals** — Check URLs before clicking

---

## ⟩ Disclaimer

STRYX is built for **security research and educational purposes only**. Do not use this tool for malicious or unauthorized activity. The tool uses heuristic rules — always verify findings with additional investigation before taking action.

---

## ⟩ Built By

**Chenchu** · Silent Storm

- 🐙 GitHub: [@chenchu-code](https://github.com/chenchu-code)

---

## ⟩ License

MIT License — free to use, modify, and distribute with attribution.

---

<div align="center">

**⟩ STRYX v1.0 — Email & URL Threat Analyzer — Silent Storm**

*If this project helped you, consider giving it a ⭐ on GitHub*

</div>
