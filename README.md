# 🛡️ PhishAlert AI Agent System

Multi-Agent Phishing Detection System  
MSc Cybersecurity Technology | Northumbria University  
Group Leader & System Architect: Opoku Mensah (w25035430)

## Classification Model
- **PHISHING** — Any malicious or deceptive email threat
- **LEGITIMATE** — Safe, clean email

## Attachment Rule
Any email with attachments → Human Expert Review (regardless of AI verdict)

## Agent Pipeline
- **Agent 1** — ThreatClassificationAgent: Binary ML classifier (Random Forest + TF-IDF)
- **Agent 2** — ThreatIntelligenceAgent: Sender & URL threat enrichment
- **Agent 3** — ThreatResponseAgent: Applies attachment rule & delivers final verdict

## Live Demo
[![Open in Streamlit](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://phishalert.streamlit.app)
