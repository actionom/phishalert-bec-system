# 🛡️ PhishAlert AI Agent System

[![Streamlit App](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://phishalert-bec-system.streamlit.app)

**Multi-Agent AI System for Phishing & Business Email Compromise (BEC) Detection**

MSc Cybersecurity Technology | Northumbria University

Student: Opoku | ID: w25035430

---

## 🎯 Overview

PhishAlert is an intelligent email threat detection system that uses a multi-agent architecture to identify and respond to:

- **Phishing Attacks** - Credential theft attempts using fake login pages
- **Business Email Compromise (BEC)** - Executive impersonation and financial fraud

### BEC Types Detected

| Type | Description |
|------|-------------|
| 🏢 CEO Fraud | Executive impersonation requesting wire transfers |
| 🧾 Invoice Fraud | Vendor impersonation with changed bank details |
| 🎁 Gift Card Scam | Requests to purchase gift cards and send codes |
| 💰 Payroll Diversion | Employee impersonation to redirect salary |
| ₿ Crypto Scam | Requests for cryptocurrency payments |

---

## 🏗️ Multi-Agent Architecture

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│     AGENT 1      │────▶│     AGENT 2      │────▶│     AGENT 3      │
│  Data-Driven AI  │     │   Reactive AI    │     │   Autonomous     │
│  Classification  │     │  Intelligence    │     │    Response      │
└──────────────────┘     └──────────────────┘     └──────────────────┘
```

| Agent | Type | Function |
|-------|------|----------|
| Agent 1 | Data-Driven AI | TF-IDF + Random Forest classification |
| Agent 2 | Reactive AI | Threat intelligence & sender verification |
| Agent 3 | Autonomous | Decision making & response execution |

---

## 🚀 Live Demo

**Try the live demo:** [https://phishalert-bec-system.streamlit.app](https://phishalert-bec-system.streamlit.app)

---

## 💻 Local Installation

```bash
# Clone repository
git clone https://github.com/yourusername/phishalert-bec-system.git
cd phishalert-bec-system

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the app
streamlit run streamlit_app.py
```

---

## 📊 Performance

| Metric | Score |
|--------|-------|
| Overall Accuracy | 100% |
| BEC Detection F1 | 1.0 |
| Phishing Detection F1 | 1.0 |

*Note: Metrics based on synthetic training data*

---

## 🔧 Technologies Used

- **Python 3.10+**
- **Streamlit** - Web interface
- **scikit-learn** - Machine learning
- **TF-IDF** - Text vectorisation
- **Random Forest** - Classification

---

## 📚 References

- FBI IC3 (2024). Internet Crime Report 2023
- Proofpoint (2024). State of the Phish Report
- Verizon (2024). Data Breach Investigations Report

---

## 📄 License

This project is for educational purposes - MSc Cybersecurity Technology, Northumbria University.

---

© 2025 Opoku | Student ID: w25035430
