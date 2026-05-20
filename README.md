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
[![Flask](https://img.shields.io/badge/Flask-3.0%2B-00d4ff?style=flat-square&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![License](https://img.shields.io/badge/License-MIT-f5c842?style=flat-square)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Live-3dff8f?style=flat-square)]()
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20Mapped-ff6b00?style=flat-square)](https://attack.mitre.org)

[**Live Demo →**](https://stryx-py.onrender.com) · [**Report Bug**](https://github.com/chenchu-code/stryx-py/issues) · [**Request Feature**](https://github.com/chenchu-code/stryx-py/issues)

<br/>

</div>

---

## ⟩ Overview

**STRYX** is an open-source threat intelligence tool built for SOC analysts, cybersecurity students, and security-aware individuals. It analyzes URLs and emails in real time using a custom-built heuristic rule engine — detecting phishing, spoofing, social engineering, and brand impersonation with zero API dependencies.

Built with **Python + Flask** on the backend and a fully custom **HTML/CSS/JS** frontend — no UI frameworks, no templates, pure product design.

> Built by **Chenchu (Silent Storm)** as a portfolio project demonstrating practical SOC analyst skills including threat detection, MITRE ATT&CK mapping, and incident response workflows.

---

## ⟩ Key Features

| Feature | Description |
|---|---|
| 🔍 **URL Analysis** | 12 detection rules covering lookalike domains, IP hosts, suspicious TLDs, obfuscation, homoglyphs, and more |
| 📧 **Email Analysis** | 8 detection rules covering spoofed senders, urgency language, credential requests, phishing links, payment scams |
| 🎯 **MITRE ATT&CK** | Threat findings mapped to real technique IDs (T1566, T1598, T1657, T1071) |
| 📊 **Dashboard** | Visual analytics — total scans, verdict breakdown, risk scores, recent scan history |
| 🟢 **Simple Mode** | Plain-English verdict for non-technical users |
| 🔴 **Advanced Mode** | Full technical breakdown with per-indicator severity ratings |
| 📄 **Report Export** | Download professional `.txt` incident report from any scan |
| ⚡ **Instant Results** | Pure rule-based engine — no API calls, no waiting, no internet required |
| 🔒 **100% Private** | Zero data sent anywhere. All analysis runs on the server. |
| 🌐 **Full Stack** | Python Flask backend + custom HTML/CSS/JS frontend |

---

## ⟩ Tech Stack

```
Backend     →  Python 3.9+ · Flask 3.0+
Frontend    →  HTML5 · CSS3 · Vanilla JavaScript
Detection   →  Custom rule engine (regex + heuristics)
Storage     →  localStorage (client-side scan history)
Deploy      →  Render.com (free tier)
Server      →  Gunicorn (production WSGI)
```

---

## ⟩ Detection Engine

### URL Rules (12 active)

```
┌─────────────────────────┬──────────┬──────────────────────────────────────────┐
│ Rule                    │ Severity │ Description                              │
├─────────────────────────┼──────────┼──────────────────────────────────────────┤
│ PROTOCOL                │ MEDIUM   │ HTTP instead of HTTPS                    │
│ IP AS HOST              │ CRITICAL │ Raw IP address used as domain            │
│ SUSPICIOUS TLD          │ HIGH     │ .xyz .tk .top .ml .ga and 15+ more       │
│ URL SHORTENER           │ MEDIUM   │ bit.ly tinyurl rb.gy and 8+ more         │
│ LOOKALIKE DOMAIN        │ CRITICAL │ paypa1 g00gle amaz0n and similar         │
│ SUSPICIOUS PATH         │ HIGH     │ /login /verify /account /credential      │
│ EXCESS SUBDOMAINS       │ MEDIUM   │ More than 4 subdomains                   │
│ OBFUSCATION             │ HIGH     │ 3+ URL-encoded characters                │
│ LONG URL                │ LOW      │ Over 120 characters                      │
│ MANY PARAMETERS         │ LOW      │ More than 5 query parameters             │
│ AT-SIGN IN URL          │ HIGH     │ @ symbol used to redirect                │
│ BRAND IMPERSONATION     │ CRITICAL │ Brand name + action keyword pattern      │
└─────────────────────────┴──────────┴──────────────────────────────────────────┘
```

### Email Rules (8 active)

```
┌─────────────────────────┬──────────┬──────────────────────────────────────────┐
│ Rule                    │ Severity │ Description                              │
├─────────────────────────┼──────────┼──────────────────────────────────────────┤
│ URGENCY LANGUAGE        │ HIGH     │ Urgent, act now, suspended, expires      │
│ CREDENTIAL REQUEST      │ CRITICAL │ Password, CVV, SSN, bank account         │
│ SUSPICIOUS LINK         │ CRITICAL │ High-risk URLs embedded in body          │
│ BRAND MENTION           │ MEDIUM   │ Known brands — cross-checks sender       │
│ GENERIC GREETING        │ LOW      │ Dear Customer / Dear User                │
│ SPOOFED SENDER          │ CRITICAL │ Display name vs domain mismatch          │
│ PAYMENT REQUEST         │ HIGH     │ Wire, gift card, Zelle, Western Union    │
│ THREAT LANGUAGE         │ HIGH     │ Legal action, arrest, account closure    │
└─────────────────────────┴──────────┴──────────────────────────────────────────┘
```

### Risk Scoring

```
Score 0–14   →  SAFE      🔵  No action needed
Score 15–34  →  LOW       🟢  Verify before proceeding
Score 35–54  →  MEDIUM    🟡  Suspicious — do not click
Score 55–74  →  HIGH      🟠  Likely malicious — block
Score 75–100 →  CRITICAL  🔴  Confirmed threat — escalate
```

---

## ⟩ MITRE ATT&CK Mapping

| Indicator | Technique |
|---|---|
| Lookalike Domain | T1566.002 — Spearphishing via Service |
| Spoofed Sender | T1566.001 — Spearphishing Attachment |
| Credential Request | T1598 — Phishing for Information |
| Suspicious Link | T1566.002 — Spearphishing Link |
| Brand Impersonation | T1566 — Phishing |
| IP as Host | T1071 — Application Layer Protocol Abuse |
| Payment Request | T1657 — Financial Theft |

---

## ⟩ Project Structure

```
stryx-py/
├── app.py              ← Flask backend + detection engine
├── requirements.txt    ← Python dependencies
├── templates/
│   └── index.html      ← Full custom frontend (HTML/CSS/JS)
└── README.md
```

---

## ⟩ Run Locally

```bash
git clone https://github.com/chenchu-code/stryx-py.git
cd stryx-py
pip install -r requirements.txt
python app.py
```

Open `http://localhost:5000`

---

## ⟩ Deploy on Render.com (Free)

1. Push this repo to GitHub
2. Go to [render.com](https://render.com) → Sign in with GitHub
3. Click **New → Web Service** → Select this repo
4. Build command: `pip install -r requirements.txt`
5. Start command: `gunicorn app:app`
6. Click **Deploy**

Live in under 3 minutes. Free forever.

---

## ⟩ Roadmap

- [x] URL threat analysis engine
- [x] Email threat analysis engine
- [x] MITRE ATT&CK mapping
- [x] Simple & Advanced output modes
- [x] Dashboard with analytics
- [x] Report download (.txt)
- [x] Full custom frontend (Flask)
- [ ] Bulk URL scanner
- [ ] PDF report export
- [ ] Custom rule builder
- [ ] Browser extension

---

## ⟩ Disclaimer

STRYX is built for **security research and educational purposes only**. The tool uses heuristic rules — always verify findings with additional investigation before taking action.

---

## ⟩ Built By

**Chenchu** · Silent Storm

- 🐙 GitHub: [@chenchu-code](https://github.com/chenchu-code)


---

<div align="center">

**⟩ STRYX v1.0 — Email & URL Threat Analyzer — Silent Storm**

*If this project helped you, consider giving it a ⭐ on GitHub*

</div>
