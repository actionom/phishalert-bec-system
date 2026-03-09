# 🛡️ PhishAlert — Multi-Agent AI Phishing Detection System

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)
![Streamlit](https://img.shields.io/badge/Streamlit-Cloud-FF4B4B?style=flat-square&logo=streamlit)
![scikit-learn](https://img.shields.io/badge/scikit--learn-ML-F7931E?style=flat-square&logo=scikit-learn)
![Gmail API](https://img.shields.io/badge/Gmail-API-D44638?style=flat-square&logo=gmail)
![License](https://img.shields.io/badge/License-Academic-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Live-brightgreen?style=flat-square)

> **Real-time phishing detection powered by three collaborative AI agents with live Gmail API integration.**

🌐 **Live Demo:** [https://phishalert.streamlit.app](https://phishalert.streamlit.app)

---

## 📌 Overview

PhishAlert is a multi-agent AI system that autonomously detects phishing emails in real time — including social engineering attacks, executive impersonation, credential harvesting, and financial fraud. Built for the **Agentic AI Hackathon 2025** as part of the MSc Cybersecurity Technology programme at Northumbria University.

The system classifies every email as either **PHISHING** or **LEGITIMATE**, enriches the result with threat intelligence, and delivers a clear verdict with automated actions — including mandatory human expert escalation for any email containing an attachment.

---

## 🏗️ Three-Agent Architecture

```
┌─────────────────────┐     ┌─────────────────────┐     ┌─────────────────────┐
│      AGENT 1        │────▶│      AGENT 2        │────▶│      AGENT 3        │
│  Data-Driven AI     │     │   Reactive AI       │     │  Autonomous         │
│  Classification     │     │   Intelligence      │     │  Response           │
└─────────────────────┘     └─────────────────────┘     └─────────────────────┘
   TF-IDF + Random              Sender reputation           Attachment Rule +
   Forest Classifier            URL analysis                Final Verdict
   PHISHING / LEGITIMATE        Domain intelligence         Human Review Gate
```

| Agent | Type | Responsibility |
|---|---|---|
| **Agent 1** | Data-Driven AI | Classifies email text using TF-IDF + Random Forest |
| **Agent 2** | Reactive AI | Enriches classification with sender, URL, and domain intelligence |
| **Agent 3** | Autonomous Response | Applies attachment rule and delivers final verdict + actions |

---

## 🔑 Key Design Decisions

### Binary Classification
All threat types — phishing, social engineering, executive impersonation, financial fraud — are unified under a single **PHISHING** label. The model makes one clear, decisive call: PHISHING or LEGITIMATE.

### Human-in-the-Loop (HITL) Attachment Rule
```
Email has attachment?
    YES  →  HUMAN EXPERT REVIEW  (regardless of AI verdict)
    NO   →  AI delivers final verdict autonomously
```
This is a non-negotiable gate. The AI still analyses the text body and provides context for the human reviewer — but no attachment is ever processed autonomously.

### Four Decision Scenarios

| Classification | Attachment | Outcome |
|---|---|---|
| 🔴 PHISHING | YES | Phishing detected + Human Expert Review |
| 🔴 PHISHING | NO | Phishing detected + Auto Quarantine |
| 🟡 LEGITIMATE | YES | Text clear + Human Expert Review (precaution) |
| ✅ LEGITIMATE | NO | All clear — No action required |

---

## 🤖 Agent 1 — Threat Classification

**Technology:** scikit-learn (TF-IDF + Random Forest), NumPy, SciPy

**How it works:**
- Combines subject line, sender email, and body text into a single analysable string
- TF-IDF vectoriser extracts 3,000 text features (1–2 word n-grams)
- 15 handcrafted features capture urgency language, threat words, social engineering patterns, suspicious URLs, and high-risk sender domains
- Random Forest (200 trees, balanced class weights) classifies the combined feature vector
- Outputs: classification, confidence score (0–1), threat level (NONE / LOW / MEDIUM / HIGH / CRITICAL), and detected indicators

**Training data:** 20 labelled samples (10 PHISHING, 10 LEGITIMATE) covering credential phishing, executive fraud, invoice scams, gift card requests, payroll diversion, and crypto scams.

---

## 🌐 Agent 2 — Threat Intelligence

**Technology:** Rule-based analysis, regex pattern matching

**How it works:**
- Analyses sender domain against a high-risk TLD list (`.tk`, `.xyz`, `.online`, `.click` etc.)
- Detects brand spoofing — trusted brand name in local part but unrecognised domain
- Analyses all URLs for HTTP-only links, IP-based addresses, and malicious TLDs
- Computes an enriched threat score combining classification confidence + sender risk + URL risk
- Outputs recommended actions for Agent 3

---

## ⚡ Agent 3 — Autonomous Response

**Technology:** Python logic engine, Streamlit session state

**How it works:**
- Checks for attachments first — if present, immediately routes to HUMAN_REVIEW
- For non-attachment emails: maps enriched threat score to action (QUARANTINE / ALERT_USER / FLAG_FOR_REVIEW / NO_ACTION)
- Builds human-readable verdict message explaining the AI's reasoning
- Generates user-specific recommendations based on threat type and action

---

## 📬 Live Gmail Integration

- Connects via **OAuth 2.0** — no credentials stored
- Fetches real inbox emails and runs each through the full three-agent pipeline
- **Web version:** reconnect per session via authorisation code
- **Local version:** token saved permanently — auto-connects on launch

---

## 🛠️ Tech Stack

| Technology | Purpose |
|---|---|
| Python 3.10+ | Core language |
| scikit-learn | TF-IDF vectorisation + Random Forest classifier |
| NumPy / SciPy | Feature extraction and sparse matrix operations |
| Gmail API | Live inbox access and email fetching |
| google-auth-oauthlib | OAuth 2.0 authentication flow |
| Streamlit | Web interface |
| Streamlit Cloud | Cloud deployment |
| GitHub | Version control |

---

## 🚀 Running the App

### Web Version (No Installation)
Visit **[https://phishalert.streamlit.app](https://phishalert.streamlit.app)** — no setup required.

### Local Version
```bash
# 1. Clone the repository
git clone https://github.com/actionom/phishalert-bec-system.git
cd phishalert-bec-system

# 2. Install dependencies
pip install streamlit scikit-learn scipy numpy google-auth google-auth-oauthlib google-api-python-client

# 3. Run the app
streamlit run streamlit_app.py
```

Or simply double-click **`START_PHISHALERT.bat`** on Windows — it installs dependencies and launches automatically.

---

## 📁 Repository Structure

```
phishalert-bec-system/
├── streamlit_app.py          # Complete system — all agents + web interface (single file)
├── START_PHISHALERT.bat      # One-click Windows launcher for local version
├── requirements.txt          # Python dependencies
└── README.md                 # This file
```

---

## 📊 Performance

| Metric | Score |
|---|---|
| Training Accuracy | 100% |
| Phishing Detection F1 | 1.0 |
| Legitimate Detection F1 | 1.0 |
| Average Analysis Time | < 2 seconds |

> Note: Metrics based on synthetic training dataset. Real-world performance varies with email diversity.

---

## 🎓 Academic Context

| Detail | Info |
|---|---|
| Programme | MSc Cybersecurity Technology |
| Institution | Northumbria University |
| Module | Agentic AI Hackathon 2025 |
| Team Size | 5 members |

---

## ⚠️ Disclaimer

This system is an academic prototype developed for educational purposes. It is not a production-grade security tool. Do not rely on it as the sole line of defence for real-world email security.

---

## 📄 Licence

This project is developed for academic purposes — MSc Cybersecurity Technology, Northumbria University. All rights reserved by the project team.

---

<div align="center">
  <strong>🛡️ PhishAlert — Protecting inboxes, one email at a time</strong><br/>
  <a href="https://phishalert.streamlit.app">Live Demo</a> •
  <a href="https://github.com/actionom/phishalert-bec-system">GitHub</a> •
  MSc Cybersecurity Technology | Northumbria University
</div>
