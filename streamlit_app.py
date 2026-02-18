"""
PhishAlert AI Agent System v2.2 — Streamlit Cloud Deployment
=============================================================
Multi-Agent Phishing Detection System

Classification Model (Final):
    PHISHING   — Any malicious or deceptive email threat
    LEGITIMATE — Safe, clean email

Attachment Rule:
    Any email with attachments → Human Expert Review
    (regardless of AI verdict)

Module  : MSc Cybersecurity Technology
Uni     : Northumbria University
"""

import re
import numpy as np
import streamlit as st
from typing import Dict, List
from datetime import datetime
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from scipy.sparse import hstack

# =============================================================
#  AGENT 1 — THREAT CLASSIFICATION AGENT
#  Data-Driven AI | Binary: PHISHING or LEGITIMATE
# =============================================================

class ThreatClassificationAgent:

    AGENT_NAME  = "ThreatClassificationAgent"
    AGENT_ID    = "AGENT_01"
    VERSION     = "2.2.0"

    URGENCY_WORDS = [
        'urgent', 'immediately', 'expire', 'suspended', 'verify',
        'confirm', 'update', 'validate', 'authenticate', 'alert',
        'warning', 'limited time', 'deadline', 'act now', 'asap',
        'within 24 hours', 'locked', 'quick action required'
    ]
    THREAT_WORDS = [
        'suspended', 'blocked', 'locked', 'disabled', 'terminated',
        'closed', 'unauthorized', 'unusual activity', 'suspicious',
        'compromise', 'breach', 'hack', 'fraud', 'security alert',
        'violation', 'restricted', 'unauthorized access'
    ]
    ACTION_WORDS = [
        'click here', 'click below', 'click the link', 'login now',
        'sign in', 'verify now', 'confirm now', 'update now',
        'secure your account', 'access here', 'open the link'
    ]
    SOCIAL_ENGINEERING_WORDS = [
        'ceo', 'cfo', 'cto', 'coo', 'president', 'director',
        'chairman', 'executive', 'managing director', 'chief',
        'wire transfer', 'bank transfer', 'eft', 'swift',
        'routing number', 'account number', 'invoice', 'remittance',
        'gift card', 'itunes', 'google play', 'amazon card',
        'voucher code', 'card number',
        'confidential', 'strictly confidential', 'do not discuss',
        'keep this between us', 'do not forward', 'sensitive matter',
        'direct deposit', 'payroll', 'salary diversion',
        'bitcoin', 'btc', 'ethereum', 'cryptocurrency', 'crypto wallet'
    ]
    CREDENTIAL_WORDS = [
        'password', 'username', 'login', 'credentials', 'ssn',
        'social security', 'credit card', 'card number', 'cvv',
        'pin number', 'account details', 'billing information'
    ]
    HIGH_RISK_TLDS = [
        '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top',
        '.click', '.link', '.work', '.online', '.site', '.win'
    ]

    def __init__(self):
        self.vectorizer = TfidfVectorizer(max_features=3000, ngram_range=(1, 2),
                                          stop_words='english', min_df=1)
        self.classifier = RandomForestClassifier(n_estimators=200, max_depth=15,
                                                  random_state=42, class_weight='balanced')
        self.is_trained = False

    def _prepare_text(self, email: Dict) -> str:
        return f"{email.get('subject','')} {email.get('sender_email','')} {email.get('body_text','')}".lower()

    def _count_matches(self, text: str, word_list: List[str]) -> int:
        return sum(1 for w in word_list if w in text)

    def _extract_features(self, email: Dict) -> np.ndarray:
        text   = self._prepare_text(email)
        body   = email.get('body_text', '').lower()
        sender = email.get('sender_email', '').lower()
        urls   = email.get('urls', [])
        return np.array([
            self._count_matches(text, self.URGENCY_WORDS),
            self._count_matches(text, self.THREAT_WORDS),
            self._count_matches(text, self.ACTION_WORDS),
            self._count_matches(text, self.SOCIAL_ENGINEERING_WORDS),
            self._count_matches(text, self.CREDENTIAL_WORDS),
            len(urls),
            sum(1 for u in urls if 'http://' in u.lower()),
            sum(1 for u in urls if any(t in u.lower() for t in self.HIGH_RISK_TLDS)),
            sum(1 for u in urls if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', u)),
            int(any(t in sender for t in self.HIGH_RISK_TLDS)),
            int(bool(re.search(r'\d{4,}', sender.split('@')[0] if '@' in sender else sender))),
            int('@' not in sender),
            int('dear customer' in body or 'dear user' in body),
            int(body.count('!') > 3),
            int(bool(re.search(r'\$\d+|£\d+|€\d+|\d+\s*(usd|gbp|eur)', body))),
            len(body.split()) // 20,
        ], dtype=float)

    def _detect_indicators(self, email: Dict) -> List[str]:
        text = self._prepare_text(email)
        indicators = []
        if self._count_matches(text, self.URGENCY_WORDS):
            indicators.append("Urgency or pressure language detected")
        if self._count_matches(text, self.THREAT_WORDS):
            indicators.append("Account-suspension or threat language detected")
        if self._count_matches(text, self.ACTION_WORDS):
            indicators.append("Suspicious call-to-action detected")
        if self._count_matches(text, self.SOCIAL_ENGINEERING_WORDS):
            indicators.append("Social engineering / impersonation language detected")
        if self._count_matches(text, self.CREDENTIAL_WORDS):
            indicators.append("Credential harvesting language detected")
        urls = email.get('urls', [])
        if urls:
            risky = [u for u in urls if any(t in u.lower() for t in self.HIGH_RISK_TLDS) or 'http://' in u.lower()]
            if risky:
                indicators.append(f"Suspicious URL(s) detected: {', '.join(risky[:2])}")
        sender = email.get('sender_email', '').lower()
        if any(t in sender for t in self.HIGH_RISK_TLDS):
            indicators.append("High-risk sender domain detected")
        return indicators

    def train(self, training_data: List[Dict]):
        normalised = []
        for d in training_data:
            s = dict(d)
            if s.get('label') in ('BEC', 'SPAM', 'MALWARE'):
                s['label'] = 'PHISHING'
            normalised.append(s)
        texts  = [self._prepare_text(d) for d in normalised]
        labels = [d['label'] for d in normalised]
        tfidf     = self.vectorizer.fit_transform(texts)
        handcraft = np.array([self._extract_features(d) for d in normalised])
        combined  = hstack([tfidf, handcraft])
        self.classifier.fit(combined, labels)
        self.is_trained = True

    def classify(self, email: Dict) -> Dict:
        text      = self._prepare_text(email)
        tfidf     = self.vectorizer.transform([text])
        handcraft = np.array([self._extract_features(email)])
        combined  = hstack([tfidf, handcraft])
        prediction    = self.classifier.predict(combined)[0]
        proba_array   = self.classifier.predict_proba(combined)[0]
        probabilities = dict(zip(self.classifier.classes_, proba_array))
        confidence    = float(max(proba_array))
        is_threat     = (prediction == 'PHISHING')
        if not is_threat:
            threat_level = 'NONE'
        elif confidence >= 0.90:
            threat_level = 'CRITICAL'
        elif confidence >= 0.75:
            threat_level = 'HIGH'
        elif confidence >= 0.55:
            threat_level = 'MEDIUM'
        else:
            threat_level = 'LOW'
        return {
            'classification': prediction,
            'confidence'    : round(confidence, 4),
            'threat_level'  : threat_level,
            'is_threat'     : is_threat,
            'indicators'    : self._detect_indicators(email) if is_threat else [],
            'probabilities' : {k: round(v, 4) for k, v in probabilities.items()},
        }

# =============================================================
#  AGENT 2 — THREAT INTELLIGENCE AGENT
#  Reactive AI | Enriches with sender & URL intelligence
# =============================================================

class ThreatIntelligenceAgent:

    AGENT_NAME = "ThreatIntelligenceAgent"
    AGENT_ID   = "AGENT_02"
    VERSION    = "2.2.0"

    HIGH_RISK_TLDS  = ['.tk','.ml','.ga','.cf','.gq','.xyz','.top','.click','.link','.work','.online','.site','.win']
    TRUSTED_DOMAINS = ['gmail.com','outlook.com','hotmail.com','yahoo.com','microsoft.com','apple.com',
                       'amazon.com','paypal.com','gov.uk','ac.uk','northumbria.ac.uk','hmrc.gov.uk']
    TRUSTED_BRANDS  = ['paypal','microsoft','apple','amazon','google','facebook','netflix',
                       'barclays','lloyds','hsbc','hmrc','gov','natwest','halifax']

    def _analyse_sender(self, sender_email: str) -> Dict:
        sender = sender_email.lower()
        domain = sender.split('@')[-1] if '@' in sender else sender
        local  = sender.split('@')[0]  if '@' in sender else sender
        is_trusted   = any(t in domain for t in self.TRUSTED_DOMAINS)
        is_high_risk = any(t in domain for t in self.HIGH_RISK_TLDS)
        has_numbers  = bool(re.search(r'\d{4,}', local))
        looks_spoofed = any(b in local for b in self.TRUSTED_BRANDS) and not is_trusted
        score = 0.0
        if is_high_risk:   score += 0.40
        if has_numbers:    score += 0.15
        if looks_spoofed:  score += 0.35
        if not is_trusted: score += 0.10
        return {'sender_email': sender_email, 'domain': domain, 'is_trusted': is_trusted,
                'is_high_risk': is_high_risk, 'looks_spoofed': looks_spoofed,
                'risk_score': round(min(score, 1.0), 4)}

    def _analyse_urls(self, urls: List[str]) -> Dict:
        if not urls:
            return {'url_count': 0, 'suspicious_count': 0, 'url_risk_score': 0.0, 'details': []}
        details = []
        for url in urls:
            u = url.lower()
            is_http = u.startswith('http://')
            has_ip  = bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', u))
            bad_tld = any(t in u for t in self.HIGH_RISK_TLDS)
            details.append({'url': url[:80], 'is_http': is_http, 'has_ip': has_ip,
                            'risky_tld': bad_tld, 'suspicious': is_http or has_ip or bad_tld})
        suspicious_count = sum(1 for d in details if d['suspicious'])
        return {'url_count': len(urls), 'suspicious_count': suspicious_count,
                'url_risk_score': round(min(suspicious_count / max(len(urls),1), 1.0), 4),
                'details': details}

    def enrich(self, email: Dict, classification: Dict) -> Dict:
        sender_intel = self._analyse_sender(email.get('sender_email', ''))
        url_intel    = self._analyse_urls(email.get('urls', []))
        base         = classification.get('confidence', 0.5)
        is_threat    = classification.get('is_threat', False)

        if not is_threat:
            score = round(min(sender_intel['risk_score'] * 0.4 + url_intel['url_risk_score'] * 0.3, 0.49), 4)
        else:
            score = round(min(base * 0.50 + sender_intel['risk_score'] * 0.30 + url_intel['url_risk_score'] * 0.20, 1.0), 4)

        actions = []
        if is_threat and score >= 0.75:
            actions = ['QUARANTINE', 'BLOCK_SENDER', 'ALERT_ADMIN']
        elif is_threat and score >= 0.45:
            actions = ['QUARANTINE', 'ALERT_USER']
        elif is_threat:
            actions = ['FLAG_FOR_REVIEW', 'ALERT_USER']
        else:
            actions = ['NO_ACTION']
        if sender_intel.get('looks_spoofed') and 'BLOCK_SENDER' not in actions:
            actions.append('BLOCK_SENDER')

        parts = []
        if is_threat:
            parts.append(f"Phishing threat confirmed with {classification['confidence']:.0%} model confidence.")
        if sender_intel['looks_spoofed']:
            parts.append("Sender domain appears to be spoofing a trusted brand.")
        if sender_intel['is_high_risk']:
            parts.append("Sender uses a high-risk top-level domain.")
        if url_intel['suspicious_count'] > 0:
            parts.append(f"{url_intel['suspicious_count']} suspicious URL(s) found in email body.")
        if not parts:
            parts.append("No significant threat intelligence signals detected.")

        return {
            'enriched_threat_score': score,
            'sender_intelligence'  : sender_intel,
            'url_intelligence'     : url_intel,
            'recommended_actions'  : actions,
            'intelligence_summary' : ' '.join(parts),
        }

# =============================================================
#  AGENT 3 — THREAT RESPONSE AGENT
#  Autonomous | Attachment Rule + Final Verdict
# =============================================================

class ThreatResponseAgent:

    AGENT_NAME = "ThreatResponseAgent"
    AGENT_ID   = "AGENT_03"
    VERSION    = "2.2.0"

    def __init__(self):
        self.stats = {
            'total_processed'       : 0,
            'phishing_detected'     : 0,
            'legitimate_cleared'    : 0,
            'human_review_escalated': 0,
        }
        self.action_history = []

    def _build_verdict(self, classification: Dict, has_attachments: bool, att_names: List[str]) -> str:
        is_threat  = classification.get('is_threat', False)
        confidence = classification.get('confidence', 0.0)
        level      = classification.get('threat_level', '')
        att_list   = ', '.join(att_names) if att_names else 'attachment present'

        if is_threat and has_attachments:
            return (f"⚠️ PHISHING DETECTED — Threat Level: {level} (Confidence: {confidence:.0%})\n\n"
                    f"Analysis of the email body has identified indicators consistent with a phishing attack. "
                    f"Additionally, this email contains an attachment ({att_list}) which cannot be safely "
                    f"analysed by the automated system.\n\n"
                    f"🔴 This email has been flagged for HUMAN EXPERT REVIEW. "
                    f"Do not open the attachment until it has been cleared by a security analyst.")
        elif is_threat and not has_attachments:
            return (f"⚠️ PHISHING DETECTED — Threat Level: {level} (Confidence: {confidence:.0%})\n\n"
                    f"Analysis of the email body has identified indicators consistent with a phishing attack. "
                    f"This email has been quarantined automatically. "
                    f"Do not click any links or reply to this email.")
        elif not is_threat and has_attachments:
            return (f"✅ EMAIL APPEARS LEGITIMATE (Confidence: {confidence:.0%})\n\n"
                    f"Analysis of the email body has not identified any phishing indicators. "
                    f"However, this email contains an attachment ({att_list}) which cannot be safely "
                    f"assessed by the automated system.\n\n"
                    f"🟡 This email has been flagged for HUMAN EXPERT REVIEW as a precaution. "
                    f"Even legitimate-looking emails can carry malicious attachments.")
        else:
            return (f"✅ EMAIL IS LEGITIMATE (Confidence: {confidence:.0%})\n\n"
                    f"No phishing indicators detected in the email body or metadata. "
                    f"This email is safe to read. No action required.")

    def _decide_action(self, classification: Dict, intelligence: Dict, has_attachments: bool) -> str:
        if has_attachments:
            return "HUMAN_REVIEW"
        if not classification.get('is_threat', False):
            return "NO_ACTION"
        score = intelligence.get('enriched_threat_score', 0.0)
        if score >= 0.75:
            return "QUARANTINE"
        elif score >= 0.45:
            return "ALERT_USER"
        else:
            return "FLAG_FOR_REVIEW"

    def _build_recommendations(self, classification: Dict, intelligence: Dict,
                                has_attachments: bool, action: str) -> List[str]:
        recs      = []
        is_threat = classification.get('is_threat', False)
        if action == "HUMAN_REVIEW":
            recs.append("Do not open any attachments until cleared by a security analyst.")
            recs.append("Forward this email to your IT security team for review.")
            if is_threat:
                recs.append("Do not click any links or reply to the sender.")
                recs.append("Report the email to your organisation's security helpdesk.")
        elif is_threat:
            recs.append("Do not click any links in this email.")
            recs.append("Do not reply to or forward this email.")
            recs.append("Do not enter any credentials on linked pages.")
            recs.append("Report this email to your IT security team.")
            if intelligence.get('sender_intelligence', {}).get('looks_spoofed'):
                recs.append("This sender appears to be impersonating a trusted organisation.")
        else:
            recs.append("This email has been cleared as legitimate.")
            recs.append("Always remain cautious — verify unexpected requests independently.")
        return recs

    def respond(self, email: Dict, classification: Dict, intelligence: Dict) -> Dict:
        attachments     = email.get('attachments', [])
        has_attachments = len(attachments) > 0
        att_names       = [a if isinstance(a, str) else a.get('filename', 'file') for a in attachments]
        action          = self._decide_action(classification, intelligence, has_attachments)
        verdict_message = self._build_verdict(classification, has_attachments, att_names)
        recommendations = self._build_recommendations(classification, intelligence, has_attachments, action)

        self.stats['total_processed'] += 1
        if action == "HUMAN_REVIEW":
            self.stats['human_review_escalated'] += 1
        elif classification.get('is_threat'):
            self.stats['phishing_detected'] += 1
        else:
            self.stats['legitimate_cleared'] += 1

        self.action_history.append({
            'subject'       : email.get('subject', '')[:60],
            'action'        : action,
            'is_threat'     : classification.get('is_threat'),
            'has_attachment': has_attachments,
            'timestamp'     : datetime.now().strftime('%H:%M:%S'),
        })

        return {
            'verdict_message': verdict_message,
            'action'         : action,
            'has_attachments': has_attachments,
            'attachment_names': att_names,
            'recommendations': recommendations,
            'classification' : classification,
            'intelligence'   : intelligence,
        }

# =============================================================
#  TRAINING DATA
# =============================================================

TRAINING_DATA = [
    {'label':'PHISHING','subject':'Your account has been suspended — verify now','sender_email':'alert@secure-bank-update.tk','body_text':'Dear customer, your account is suspended. Click here to verify immediately. Failure to act will result in permanent account closure.','urls':['http://bank-verify.tk/login'],'attachments':[]},
    {'label':'PHISHING','subject':'Urgent: Wire transfer required — CEO','sender_email':'ceo@company-director99.xyz','body_text':'I need you to process a wire transfer of £30,000 immediately. This is confidential. Do not discuss with anyone.','urls':[],'attachments':[]},
    {'label':'PHISHING','subject':'HMRC Tax Refund Available — Claim Now','sender_email':'refund@hmrc-taxalert.click','body_text':'You are eligible for a tax refund of £542. Click the link to claim. Offer expires today. Validate your details now.','urls':['http://hmrc-refund.click/claim'],'attachments':[]},
    {'label':'PHISHING','subject':'Your PayPal account requires verification','sender_email':'security@paypa1-secure.tk','body_text':'Unusual activity detected on your account. Confirm your password and credit card details to restore access. Act within 24 hours.','urls':['http://paypal-secure.tk/verify'],'attachments':[]},
    {'label':'PHISHING','subject':'Gift card purchase request — urgent','sender_email':'managing.director@corp-email99.xyz','body_text':'I need you to purchase 5 x £100 Amazon gift cards and send me the redemption codes urgently. Keep this confidential.','urls':[],'attachments':[]},
    {'label':'PHISHING','subject':'Invoice payment overdue — bank details changed','sender_email':'accounts@vendor-invoicing.online','body_text':'Please process the attached invoice for £12,500. Our bank account details have changed. New routing number: 998877. Transfer immediately.','urls':[],'attachments':[]},
    {'label':'PHISHING','subject':'Microsoft: Your password expires today','sender_email':'noreply@microsoft-helpdesk.online','body_text':'Your Microsoft account password will expire today. Update your credentials now or your account will be locked. Click here immediately.','urls':['http://microsoft-reset.online/update'],'attachments':[]},
    {'label':'PHISHING','subject':'Salary payroll update required','sender_email':'hr.payroll@company-update99.xyz','body_text':'Please update your direct deposit information. Your salary will not be processed unless you validate your bank account details today.','urls':['http://payroll-update.xyz/login'],'attachments':[]},
    {'label':'PHISHING','subject':'Bitcoin investment — exclusive offer','sender_email':'invest@crypto-earnings.top','body_text':'Earn £5,000 daily with our Bitcoin cryptocurrency system. Send your wallet address and invest now. Limited time offer. Act fast.','urls':['http://crypto-invest.top/join'],'attachments':[]},
    {'label':'PHISHING','subject':'Security alert: suspicious login detected','sender_email':'security@apple-id-alert.tk','body_text':'Your Apple ID was used to sign in from an unknown device. Verify your account credentials and update your password immediately.','urls':['http://appleid-verify.tk/secure'],'attachments':[]},
    {'label':'LEGITIMATE','subject':'Team meeting rescheduled to Friday','sender_email':'manager@northumbria.ac.uk','body_text':'Hi team, just a heads up that our weekly catch-up has been moved to Friday at 3pm. Same room. See you then.','urls':[],'attachments':[]},
    {'label':'LEGITIMATE','subject':'Lecture notes for Week 6 now uploaded','sender_email':'lecturer@northumbria.ac.uk','body_text':'Hi everyone, the Week 6 lecture slides have been uploaded to the portal. Let me know if you have any questions.','urls':['https://elp.northumbria.ac.uk/week6'],'attachments':[]},
    {'label':'LEGITIMATE','subject':'Catch up this week?','sender_email':'friend@gmail.com','body_text':'Hey, are you free for coffee on Thursday? It has been ages. Let me know what time suits you.','urls':[],'attachments':[]},
    {'label':'LEGITIMATE','subject':'Your order has been dispatched','sender_email':'orders@amazon.com','body_text':'Your order has been dispatched and is on its way. Estimated delivery is Thursday. Track your parcel via your account.','urls':['https://www.amazon.com/orders'],'attachments':[]},
    {'label':'LEGITIMATE','subject':'Quarterly newsletter — February 2026','sender_email':'newsletter@northumbria.ac.uk','body_text':'Welcome to the February edition of the Northumbria University newsletter. Student achievements and upcoming events.','urls':['https://www.northumbria.ac.uk/newsletter'],'attachments':[]},
    {'label':'LEGITIMATE','subject':'Project files updated on shared drive','sender_email':'colleague@outlook.com','body_text':'Hi, I have updated the project files on the shared drive. Please review the latest version and add your comments.','urls':[],'attachments':[]},
    {'label':'LEGITIMATE','subject':'Library book due for return','sender_email':'library@northumbria.ac.uk','body_text':'This is a reminder that the following book is due for return in 3 days. You can renew online via your library account.','urls':['https://library.northumbria.ac.uk/renew'],'attachments':[]},
    {'label':'LEGITIMATE','subject':'Birthday dinner invitation','sender_email':'friend@hotmail.com','body_text':'Hey! We are having a birthday dinner for Kofi on Saturday evening at 7pm. Hope you can make it. Let me know by Thursday.','urls':[],'attachments':[]},
    {'label':'LEGITIMATE','subject':'Dissertation supervisor meeting — notes','sender_email':'supervisor@northumbria.ac.uk','body_text':'Thanks for the meeting today. Key points: finalise methodology by end of next week, submit draft chapter 2 by 1st March.','urls':[],'attachments':[]},
    {'label':'LEGITIMATE','subject':'Tech conference registration confirmed','sender_email':'events@microsoft.com','body_text':'Your registration for the Microsoft Security Summit 2026 has been confirmed. Ticket and session details are in your account.','urls':['https://www.microsoft.com/events'],'attachments':[]},
]

# =============================================================
#  TEST SCENARIOS
# =============================================================

TEST_EMAILS = [
    {
        'id'         : 'A',
        'scenario'   : '🔴 Scenario A — Phishing + Attachment',
        'subject'    : 'URGENT: Your PayPal account has been suspended',
        'sender_email': 'security@paypa1-alerts.tk',
        'body_text'  : 'Dear Customer, we have detected unusual activity on your PayPal account. Your account has been temporarily suspended. You must verify your details immediately to restore access. Failure to act within 24 hours will result in permanent closure. Please review the attached document and complete the verification form. Click here to verify: http://paypal-verify.tk/login',
        'urls'       : ['http://paypal-verify.tk/login'],
        'attachments': [{'filename': 'Account_Verification_Form.pdf'}],
        'expected'   : 'PHISHING + Attachment → Human Expert Review',
    },
    {
        'id'         : 'B',
        'scenario'   : '🔴 Scenario B — Phishing, No Attachment',
        'subject'    : 'Immediate Wire Transfer Required — CEO Request',
        'sender_email': 'ceo.johnson99@gmail-executive.xyz',
        'body_text'  : 'Hi, I need you to process a confidential wire transfer of £45,000 immediately. This is strictly confidential — do not discuss with anyone else. Our auditors require this to be completed within the hour. Account: 12345678 Sort Code: 20-45-67. Do not forward this email. Robert Johnson, Chief Executive Officer.',
        'urls'       : [],
        'attachments': [],
        'expected'   : 'PHISHING + No Attachment → Quarantine/Alert',
    },
    {
        'id'         : 'C',
        'scenario'   : '🟡 Scenario C — Legitimate + Attachment',
        'subject'    : 'Q1 Project Update — Team Meeting Notes',
        'sender_email': 'sarah.thompson@northumbria.ac.uk',
        'body_text'  : 'Hi team, please find attached the notes from today\'s project meeting. Key action points are highlighted in yellow. Our next check-in is scheduled for Friday at 2pm. Let me know if you have any questions. Best regards, Sarah Thompson, Project Lead.',
        'urls'       : [],
        'attachments': [{'filename': 'Meeting_Notes_Q1_2026.docx'}],
        'expected'   : 'LEGITIMATE + Attachment → Human Expert Review (precaution)',
    },
    {
        'id'         : 'D',
        'scenario'   : '✅ Scenario D — Legitimate, No Attachment',
        'subject'    : 'Lunch catch-up this week?',
        'sender_email': 'james.okoro@gmail.com',
        'body_text'  : 'Hey, are you free for lunch on Thursday or Friday? Was thinking we could try that new place near the university. Let me know what works for you. Cheers, James.',
        'urls'       : [],
        'attachments': [],
        'expected'   : 'LEGITIMATE + No Attachment → All Clear',
    },
    {
        'id'         : 'E',
        'scenario'   : '🔴 Scenario E — Credential Phishing, No Attachment',
        'subject'    : 'Your Microsoft account password will expire today',
        'sender_email': 'noreply@microsoft-accounts.online',
        'body_text'  : 'Dear User, your Microsoft account password is due to expire today. Please update your credentials immediately to avoid losing access to your email, OneDrive, and Office applications. Update your password now: http://microsoft-reset.online/update. If you do not update within 24 hours, your account will be locked.',
        'urls'       : ['http://microsoft-reset.online/update'],
        'attachments': [],
        'expected'   : 'PHISHING + No Attachment → Quarantine',
    },
]

# =============================================================
#  SYSTEM INITIALISATION (cached)
# =============================================================

@st.cache_resource
def load_system():
    agent1 = ThreatClassificationAgent()
    agent1.train(TRAINING_DATA)
    agent2 = ThreatIntelligenceAgent()
    agent3 = ThreatResponseAgent()
    return agent1, agent2, agent3

def analyse_email(email: Dict) -> Dict:
    agent1, agent2, agent3 = load_system()
    classification = agent1.classify(email)
    intelligence   = agent2.enrich(email, classification)
    response       = agent3.respond(email, classification, intelligence)
    return response

# =============================================================
#  STREAMLIT UI
# =============================================================

st.set_page_config(
    page_title="PhishAlert AI Agent System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    .main-title   { font-size:2.4rem; font-weight:800; color:#1a2e4a; text-align:center; padding:1rem 0 0.2rem 0; }
    .subtitle     { font-size:1rem; color:#555; text-align:center; margin-bottom:1.5rem; }
    .phishing-box { background:#fff0f0; border-left:6px solid #c0392b; padding:1.2rem 1.5rem; border-radius:8px; margin:1rem 0; }
    .legit-box    { background:#f0fff4; border-left:6px solid #27ae60; padding:1.2rem 1.5rem; border-radius:8px; margin:1rem 0; }
    .human-box    { background:#fffbe6; border-left:6px solid #f39c12; padding:1.2rem 1.5rem; border-radius:8px; margin:1rem 0; }
</style>
""", unsafe_allow_html=True)

st.markdown('<div class="main-title">🛡️ PhishAlert AI Agent System</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="subtitle">Multi-Agent Phishing Detection &nbsp;|&nbsp; '
    'MSc Cybersecurity Technology &nbsp;|&nbsp; Northumbria University</div>',
    unsafe_allow_html=True
)

# ── Sidebar ───────────────────────────────────────────────────

with st.sidebar:
    st.markdown("### ⚙️ System v2.2.0")
    st.info("**Classes:** PHISHING | LEGITIMATE\n\n**Attachment Rule:** Any email with an attachment is always escalated to Human Expert Review.")    st.markdown("### 🤖 Agent Pipeline")
    st.markdown("**Agent 1** → Classifies email text\n\n**Agent 2** → Enriches with intelligence\n\n**Agent 3** → Applies attachment rule & delivers verdict")
    st.markdown("### 📋 Decision Logic")
    st.markdown("""
| Scenario | Outcome |
|---|---|
| 🔴 Phishing + Attachment | Human Review |
| 🔴 Phishing Only | Quarantine |
| 🟡 Legit + Attachment | Human Review |
| ✅ Legit Only | All Clear |
    """)

# ── Tabs ──────────────────────────────────────────────────────

tab1, tab2, tab3 = st.tabs(["🔍 Analyse Email", "📧 Test Scenarios", "📊 Statistics"])

# TAB 1 — Analyse Email
with tab1:
    st.markdown("### Enter Email Details")
    col1, col2 = st.columns(2)
    with col1:
        subject      = st.text_input("📌 Subject Line", placeholder="Enter email subject...")
        sender_email = st.text_input("📤 Sender Email", placeholder="sender@domain.com")
        urls_input   = st.text_area("🔗 URLs in email (one per line)", height=80)
    with col2:
        body_text      = st.text_area("📝 Email Body", height=200, placeholder="Paste the full email body here...")
        has_attachment = st.checkbox("📎 This email has an attachment")
        att_name       = ""
        if has_attachment:
            att_name = st.text_input("Attachment filename", placeholder="e.g. Invoice.pdf")

    if st.button("🔍 Analyse Email", type="primary", use_container_width=True):
        if not subject and not body_text:
            st.warning("Please enter at least a subject or email body.")
        else:
            email_input = {
                'subject'     : subject,
                'sender_email': sender_email,
                'body_text'   : body_text,
                'urls'        : [u.strip() for u in urls_input.split('\n') if u.strip()],
                'attachments' : [{'filename': att_name or 'attachment'}] if has_attachment else [],
            }
            with st.spinner("Running three-agent analysis pipeline..."):
                response = analyse_email(email_input)

            clf       = response['classification']
            intel     = response['intelligence']
            action    = response['action']
            is_threat = clf['is_threat']

            # Verdict banner
            if action == 'HUMAN_REVIEW' and is_threat:
                st.error("🔴 PHISHING DETECTED + ATTACHMENT — Human Expert Review Required")
            elif action == 'HUMAN_REVIEW':
                st.warning("🟡 LEGITIMATE TEXT + ATTACHMENT — Human Expert Review Required (Precaution)")
            elif is_threat:
                st.error(f"🔴 PHISHING DETECTED — Action: {action}")
            else:
                st.success("✅ LEGITIMATE — No Threat Detected")

            st.markdown(f"**Verdict Message:**\n\n{response['verdict_message']}")
            st.divider()

            col_a, col_b, col_c = st.columns(3)
            col_a.metric("Classification", clf['classification'])
            col_b.metric("Confidence",     f"{clf['confidence']:.0%}")
            col_c.metric("Threat Level",   clf['threat_level'])

            col_d, col_e = st.columns(2)
            with col_d:
                st.markdown("#### ⚠️ Phishing Indicators")
                if clf['indicators']:
                    for i in clf['indicators']:
                        st.write(f"• {i}")
                else:
                    st.success("No phishing indicators detected.")
            with col_e:
                st.markdown("#### 🌐 Threat Intelligence")
                s = intel.get('sender_intelligence', {})
                u = intel.get('url_intelligence', {})
                st.write(f"**Sender Risk:** {s.get('risk_score',0):.0%}")
                st.write(f"**Spoofed Sender:** {'Yes ⚠️' if s.get('looks_spoofed') else 'No'}")
                st.write(f"**Suspicious URLs:** {u.get('suspicious_count',0)}")
                st.write(f"**Enriched Score:** {intel.get('enriched_threat_score',0):.0%}")

            st.markdown("#### 💡 Recommendations")
            for r in response['recommendations']:
                st.write(f"• {r}")

# TAB 2 — Test Scenarios
with tab2:
    st.markdown("### Pre-built Test Scenarios")
    st.caption("These cover all four decision paths of the system.")

    selected = st.selectbox("Choose a scenario:", options=range(len(TEST_EMAILS)),
                             format_func=lambda i: TEST_EMAILS[i]['scenario'])
    email = TEST_EMAILS[selected]

    with st.expander("📧 View Email Details", expanded=True):
        st.write(f"**Subject:** {email['subject']}")
        st.write(f"**Sender:** {email['sender_email']}")
        st.write(f"**Attachments:** {', '.join(a['filename'] for a in email['attachments']) if email['attachments'] else 'None'}")
        st.write(f"**URLs:** {', '.join(email['urls']) if email['urls'] else 'None'}")
        st.text_area("Email Body", value=email['body_text'], height=120, disabled=True)
        st.caption(f"*Expected: {email['expected']}*")

    if st.button("▶️ Run Analysis", type="primary", use_container_width=True):
        with st.spinner("Analysing..."):
            response  = analyse_email(email)
        clf       = response['classification']
        action    = response['action']
        is_threat = clf['is_threat']
        has_att   = response['has_attachments']

        if action == 'HUMAN_REVIEW' and is_threat:
            st.error("🔴 PHISHING + ATTACHMENT → Human Expert Review")
        elif action == 'HUMAN_REVIEW':
            st.warning("🟡 LEGITIMATE + ATTACHMENT → Human Expert Review (Precaution)")
        elif is_threat:
            st.error(f"🔴 PHISHING → {action}")
        else:
            st.success(f"✅ LEGITIMATE → {action}")

        st.markdown(f"**Verdict:**\n\n{response['verdict_message']}")

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Verdict",     clf['classification'])
        c2.metric("Confidence",  f"{clf['confidence']:.0%}")
        c3.metric("Threat Level",clf['threat_level'])
        c4.metric("Action",      action)

        if clf['indicators']:
            st.markdown("**Indicators:**")
            for i in clf['indicators']:
                st.write(f"  ⚠️ {i}")

        st.markdown("**Recommendations:**")
        for r in response['recommendations']:
            st.write(f"  • {r}")

# TAB 3 — Statistics
with tab3:
    st.markdown("### System Statistics")
    _, _, agent3 = load_system()
    stats = agent3.stats

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Processed",        stats['total_processed'])
    c2.metric("Phishing Detected",      stats['phishing_detected'])
    c3.metric("Legitimate Cleared",     stats['legitimate_cleared'])
    c4.metric("Human Review Escalated", stats['human_review_escalated'])

    history = agent3.action_history
    if history:
        st.markdown("### Recent Action History")
        for h in reversed(history[-15:]):
            icon = "🔴" if h['is_threat'] else "✅"
            att  = " 📎" if h['has_attachment'] else ""
            st.write(f"{icon}{att} `{h['action']}` — {h['subject']} *(at {h['timestamp']})*")
    else:
        st.info("No emails analysed yet. Run some scenarios in Tab 2.")
