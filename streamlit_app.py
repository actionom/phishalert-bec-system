"""
PhishAlert AI Agent System - Streamlit Cloud Deployment
Multi-Agent Phishing & BEC Detection System (All-in-One Version)

Student: Opoku | ID: w25035430 | MSc Cybersecurity Technology | Northumbria University
"""

import streamlit as st
import re
import numpy as np
from typing import Dict, List, Tuple
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from scipy.sparse import hstack
from enum import Enum
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

# ==================== PAGE CONFIG ====================
st.set_page_config(
    page_title="PhishAlert - BEC & Phishing Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ==================== CUSTOM CSS ====================
st.markdown("""
<style>
    .main-header { font-size: 2.5rem; font-weight: bold; color: #1E3A5F; text-align: center; padding: 1rem; }
    .sub-header { font-size: 1.2rem; color: #666; text-align: center; margin-bottom: 2rem; }
    .bec-alert { background-color: #FFE0E0; border-left: 5px solid #DC3545; padding: 1.5rem; border-radius: 10px; margin: 1rem 0; }
    .phishing-alert { background-color: #FFE6E6; border-left: 5px solid #E74C3C; padding: 1.5rem; border-radius: 10px; margin: 1rem 0; }
    .spam-alert { background-color: #FFF8E6; border-left: 5px solid #F39C12; padding: 1.5rem; border-radius: 10px; margin: 1rem 0; }
    .safe-alert { background-color: #E6FFE6; border-left: 5px solid #28A745; padding: 1.5rem; border-radius: 10px; margin: 1rem 0; }
    .agent-card { background: linear-gradient(135deg, #2C3E50 0%, #3498DB 100%); color: white; padding: 1.5rem; border-radius: 15px; margin: 0.5rem 0; }
</style>
""", unsafe_allow_html=True)


# ==================== ENUMS ====================
class OperationMode(Enum):
    AUTONOMOUS = "autonomous"
    INTERACTIVE = "interactive"
    SUPERVISED = "supervised"


class ResponseAction(Enum):
    QUARANTINE = "quarantine"
    ALERT_USER = "alert_user"
    ALERT_ADMIN = "alert_admin"
    ALERT_FINANCE = "alert_finance"
    BLOCK_SENDER = "block_sender"
    FLAG_SUSPICIOUS = "flag_suspicious"
    MOVE_TO_SPAM = "move_to_spam"
    DELETE = "delete"
    ALLOW = "allow"


# ==================== AGENT 1: THREAT CLASSIFICATION ====================
class ThreatClassificationAgent:
    """Data-Driven AI Agent for email threat classification."""
    
    def __init__(self):
        self.vectorizer = TfidfVectorizer(
            max_features=3000, ngram_range=(1, 3), min_df=2, max_df=0.95, stop_words='english'
        )
        self.classifier = RandomForestClassifier(
            n_estimators=200, max_depth=30, min_samples_split=3,
            class_weight='balanced', random_state=42, n_jobs=-1
        )
        self.is_trained = False
        self.classes = ['LEGITIMATE', 'SPAM', 'PHISHING', 'BEC']
        self.bec_patterns = {
            'executive_terms': ['ceo', 'cfo', 'president', 'director', 'chairman', 'chief', 'executive'],
            'payment_terms': ['wire transfer', 'bank transfer', 'payment', 'invoice', 'account number', 'routing number'],
            'giftcard_terms': ['gift card', 'amazon card', 'itunes', 'google play', 'card codes'],
            'urgency_terms': ['urgent', 'asap', 'immediately', 'right now', 'today', 'time sensitive'],
            'secrecy_terms': ['confidential', 'keep quiet', 'do not share', 'between us', 'private matter'],
            'unavailability_terms': ['in a meeting', 'cannot call', 'traveling', 'unreachable', 'on a flight']
        }
    
    def _prepare_text(self, email: Dict) -> str:
        subject = email.get('subject', '')
        body = email.get('body_text', email.get('body', ''))
        sender = email.get('sender', email.get('sender_email', ''))
        combined = f"{subject} {body} {sender}".lower()
        combined = re.sub(r'[^\w\s]', ' ', combined)
        return re.sub(r'\s+', ' ', combined).strip()
    
    def _extract_bec_features(self, email: Dict) -> np.ndarray:
        text = self._prepare_text(email).lower()
        sender = email.get('sender_email', email.get('sender', '')).lower()
        features = [
            len(text), len(text.split()),
            sum(1 for t in self.bec_patterns['executive_terms'] if t in text),
            sum(1 for t in self.bec_patterns['payment_terms'] if t in text),
            sum(1 for t in self.bec_patterns['giftcard_terms'] if t in text),
            sum(1 for t in self.bec_patterns['urgency_terms'] if t in text),
            sum(1 for t in self.bec_patterns['secrecy_terms'] if t in text),
            sum(1 for t in self.bec_patterns['unavailability_terms'] if t in text),
            1 if any(d in sender for d in ['gmail.com', 'yahoo.com', 'hotmail.com']) else 0,
            1 if re.search(r'\$[\d,]+|\d+\s*(?:dollars|usd)', text) else 0,
            1 if re.search(r'account\s*(?:number|#|:)?\s*\d{6,}', text) else 0,
            len(email.get('urls', []))
        ]
        features.append(features[2] + features[3] + features[5] + features[6] + features[7])  # CEO fraud score
        features.append(features[4] + features[5] + features[6])  # Gift card score
        features.append(features[3] + features[10] + features[9])  # Invoice score
        return np.array(features)
    
    def _detect_bec_subtype(self, email: Dict) -> Tuple[bool, str]:
        text = self._prepare_text(email).lower()
        scores = {'CEO_FRAUD': 0, 'INVOICE_FRAUD': 0, 'GIFT_CARD_SCAM': 0, 'PAYROLL_DIVERSION': 0, 'CRYPTO_PAYMENT_SCAM': 0}
        
        if any(t in text for t in self.bec_patterns['executive_terms']): scores['CEO_FRAUD'] += 3
        if any(t in text for t in ['wire transfer', 'wire', 'transfer funds']): scores['CEO_FRAUD'] += 2
        if any(t in text for t in self.bec_patterns['secrecy_terms']): scores['CEO_FRAUD'] += 2
        if any(t in text for t in self.bec_patterns['unavailability_terms']): scores['CEO_FRAUD'] += 2
        if any(t in text for t in self.bec_patterns['giftcard_terms']): scores['GIFT_CARD_SCAM'] += 5
        if 'code' in text and 'send' in text: scores['GIFT_CARD_SCAM'] += 2
        if 'bank details' in text or 'bank account' in text: scores['INVOICE_FRAUD'] += 3
        if 'changed' in text or 'updated' in text or 'new account' in text: scores['INVOICE_FRAUD'] += 3
        if 'direct deposit' in text or 'payroll' in text or 'salary' in text: scores['PAYROLL_DIVERSION'] += 4
        if any(t in text for t in ['bitcoin', 'btc', 'ethereum', 'cryptocurrency', 'crypto']): scores['CRYPTO_PAYMENT_SCAM'] += 5
        
        max_score = max(scores.values())
        if max_score >= 4:
            return True, max(scores, key=scores.get)
        return False, ''
    
    def train(self, training_data: List[Dict]):
        texts = [self._prepare_text(d) for d in training_data]
        labels = [d['label'] for d in training_data]
        tfidf_features = self.vectorizer.fit_transform(texts)
        bec_features = np.array([self._extract_bec_features(d) for d in training_data])
        combined_features = hstack([tfidf_features, bec_features])
        self.classifier.fit(combined_features, labels)
        self.is_trained = True
    
    def classify(self, email: Dict) -> Dict:
        if not self.is_trained:
            return {'verdict': 'UNKNOWN', 'confidence': 0.0, 'error': 'Model not trained'}
        
        text = self._prepare_text(email)
        tfidf_features = self.vectorizer.transform([text])
        bec_features = self._extract_bec_features(email).reshape(1, -1)
        combined_features = hstack([tfidf_features, bec_features])
        
        prediction = self.classifier.predict(combined_features)[0]
        probabilities = self.classifier.predict_proba(combined_features)[0]
        class_idx = list(self.classifier.classes_).index(prediction)
        confidence = probabilities[class_idx]
        
        is_bec, bec_subtype = self._detect_bec_subtype(email)
        if is_bec and prediction != 'BEC':
            bec_prob = probabilities[list(self.classifier.classes_).index('BEC')] if 'BEC' in self.classifier.classes_ else 0
            if bec_prob > 0.2:
                prediction = 'BEC'
                confidence = bec_prob
        
        return {
            'verdict': prediction,
            'confidence': float(confidence),
            'is_bec': prediction == 'BEC' or is_bec,
            'bec_subtype': bec_subtype if (prediction == 'BEC' or is_bec) else '',
            'class_probabilities': {cls: float(probabilities[i]) for i, cls in enumerate(self.classifier.classes_)},
            'risk_indicators': self._get_risk_indicators(email)
        }
    
    def _get_risk_indicators(self, email: Dict) -> List[str]:
        indicators = []
        text = self._prepare_text(email).lower()
        if any(t in text for t in self.bec_patterns['urgency_terms']): indicators.append("High urgency language")
        if any(t in text for t in self.bec_patterns['secrecy_terms']): indicators.append("Secrecy requests")
        if any(t in text for t in self.bec_patterns['executive_terms']): indicators.append("Executive impersonation")
        if any(t in text for t in self.bec_patterns['payment_terms']): indicators.append("Payment requests")
        if any(t in text for t in self.bec_patterns['giftcard_terms']): indicators.append("Gift card request")
        return indicators


# ==================== AGENT 2: THREAT INTELLIGENCE ====================
class ThreatIntelligenceAgent:
    """Reactive AI Agent for threat intelligence enrichment."""
    
    def __init__(self):
        self.freemail_providers = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com']
        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
    
    def analyse(self, email: Dict, classification: Dict) -> Dict:
        sender_email = email.get('sender_email', email.get('sender', '')).lower()
        sender_name = email.get('sender', '').lower()
        
        is_freemail = any(p in sender_email for p in self.freemail_providers)
        has_exec_title = any(t in sender_name for t in ['ceo', 'cfo', 'president', 'director', 'chief'])
        
        threat_score = 0
        if classification.get('verdict') == 'BEC': threat_score += 40
        elif classification.get('verdict') == 'PHISHING': threat_score += 35
        if is_freemail and has_exec_title: threat_score += 25
        
        return {
            'sender_analysis': {'is_freemail': is_freemail, 'has_executive_title': has_exec_title},
            'threat_score': min(100, threat_score),
            'intelligence_summary': "Executive using freemail detected" if (is_freemail and has_exec_title) else "Analysis complete"
        }


# ==================== AGENT 3: THREAT RESPONSE ====================
class ThreatResponseAgent:
    """Autonomous Agent for threat response decisions."""
    
    def __init__(self, operation_mode: OperationMode = OperationMode.SUPERVISED):
        self.operation_mode = operation_mode
        self.bec_policies = {
            'CEO_FRAUD': {'actions': ['quarantine', 'alert_admin', 'alert_finance'], 'severity': 'CRITICAL'},
            'INVOICE_FRAUD': {'actions': ['quarantine', 'alert_admin', 'alert_finance'], 'severity': 'CRITICAL'},
            'GIFT_CARD_SCAM': {'actions': ['quarantine', 'alert_user', 'alert_admin'], 'severity': 'HIGH'},
            'CRYPTO_PAYMENT_SCAM': {'actions': ['quarantine', 'alert_admin'], 'severity': 'HIGH'},
            'PAYROLL_DIVERSION': {'actions': ['quarantine', 'alert_admin', 'alert_finance'], 'severity': 'CRITICAL'}
        }
    
    def decide_response(self, email: Dict, classification: Dict, intelligence: Dict) -> Dict:
        verdict = classification.get('verdict', 'LEGITIMATE')
        is_bec = classification.get('is_bec', False)
        bec_subtype = classification.get('bec_subtype', '')
        
        response = {'actions': [], 'primary_action': 'allow', 'severity': 'LOW', 'user_warnings': []}
        
        if is_bec and bec_subtype in self.bec_policies:
            policy = self.bec_policies[bec_subtype]
            response['actions'] = policy['actions']
            response['primary_action'] = policy['actions'][0]
            response['severity'] = policy['severity']
            response['user_warnings'] = self._get_bec_warnings(bec_subtype)
        elif verdict == 'PHISHING':
            response['actions'] = ['quarantine', 'alert_user']
            response['primary_action'] = 'quarantine'
            response['severity'] = 'HIGH'
            response['user_warnings'] = ["⚠️ Phishing attempt detected", "Do NOT click any links"]
        elif verdict == 'SPAM':
            response['actions'] = ['move_to_spam']
            response['primary_action'] = 'move_to_spam'
            response['severity'] = 'LOW'
        
        return response
    
    def _get_bec_warnings(self, bec_subtype: str) -> List[str]:
        warnings = {
            'CEO_FRAUD': ["🚨 CEO/Executive Impersonation Fraud", "Do NOT process any wire transfers"],
            'INVOICE_FRAUD': ["🚨 Invoice/Vendor Fraud", "Do NOT update bank account details"],
            'GIFT_CARD_SCAM': ["⚠️ Gift Card Scam", "Do NOT purchase gift cards"],
            'CRYPTO_PAYMENT_SCAM': ["🚨 Cryptocurrency Scam", "Do NOT send any cryptocurrency"],
            'PAYROLL_DIVERSION': ["🚨 Payroll Diversion Attempt", "Do NOT change payroll information"]
        }
        return warnings.get(bec_subtype, ["⚠️ BEC detected"])


# ==================== MAIN SYSTEM ====================
class PhishAlertSystem:
    """Main coordinator for the PhishAlert multi-agent system."""
    
    def __init__(self):
        self.agent1 = ThreatClassificationAgent()
        self.agent2 = ThreatIntelligenceAgent()
        self.agent3 = ThreatResponseAgent()
        self._train_system()
    
    def _train_system(self):
        training_data = self._generate_training_data()
        self.agent1.train(training_data)
    
    def _generate_training_data(self) -> List[Dict]:
        data = []
        
        # BEC samples
        bec_templates = [
            ("Urgent Wire Transfer", "I need you to process an urgent wire transfer of $50,000. Keep this confidential.", "CEO_FRAUD"),
            ("Gift Cards Needed", "Please purchase 5 Amazon gift cards for $100 each. Send me the codes.", "GIFT_CARD_SCAM"),
            ("Bank Details Changed", "Our bank details have changed. New account: 12345678. Update immediately.", "INVOICE_FRAUD"),
            ("Direct Deposit Update", "Please update my direct deposit to new account 11223344.", "PAYROLL_DIVERSION"),
            ("Bitcoin Payment", "Please send $25,000 in Bitcoin to this wallet address.", "CRYPTO_PAYMENT_SCAM"),
        ]
        for subject, body, subtype in bec_templates:
            for i in range(30):
                data.append({'subject': subject, 'body': body, 'sender': f'ceo{i}@gmail.com', 'urls': [], 'label': 'BEC', 'bec_subtype': subtype})
        
        # Phishing samples
        phishing_templates = [
            "Your account has been compromised. Click here to verify.",
            "URGENT: Your password expires today. Click to renew.",
            "Security alert: Unusual activity detected. Verify now.",
        ]
        for template in phishing_templates:
            for i in range(20):
                data.append({'subject': 'URGENT', 'body': template, 'sender': f'security@fake{i}.tk', 'urls': ['http://malicious.tk'], 'label': 'PHISHING'})
        
        # Spam samples
        for i in range(30):
            data.append({'subject': 'Special Offer', 'body': 'Get rich quick! Earn $10,000 per week!', 'sender': f'offers{i}@marketing.com', 'urls': [], 'label': 'SPAM'})
        
        # Legitimate samples
        for i in range(40):
            data.append({'subject': 'Meeting Notes', 'body': 'Please find attached the meeting notes from today.', 'sender': f'colleague{i}@company.com', 'urls': [], 'label': 'LEGITIMATE'})
        
        return data
    
    def analyse_email(self, email: Dict) -> Dict:
        classification = self.agent1.classify(email)
        intelligence = self.agent2.analyse(email, classification)
        response = self.agent3.decide_response(email, classification, intelligence)
        
        return {
            'classification': classification,
            'intelligence': intelligence,
            'response': response,
            'summary': {
                'verdict': classification['verdict'],
                'is_bec': classification.get('is_bec', False),
                'bec_subtype': classification.get('bec_subtype', ''),
                'confidence': classification['confidence'],
                'threat_level': response['severity'],
                'action_taken': response['primary_action']
            }
        }


# ==================== STREAMLIT UI ====================
@st.cache_resource
def init_system():
    return PhishAlertSystem()


def display_results(result: dict):
    summary = result['summary']
    classification = result['classification']
    response = result['response']
    
    verdict = summary['verdict']
    is_bec = summary.get('is_bec', False)
    bec_subtype = summary.get('bec_subtype', '')
    
    st.markdown("---")
    st.markdown("### 📊 Analysis Results")
    
    if is_bec:
        st.markdown(f"""
        <div class="bec-alert">
            <h2>🚨 BEC DETECTED: {bec_subtype.replace('_', ' ')}</h2>
            <p><strong>Threat Level:</strong> {summary['threat_level']}</p>
            <p><strong>Confidence:</strong> {summary['confidence']:.1%}</p>
            <p><strong>Action:</strong> {summary['action_taken']}</p>
        </div>
        """, unsafe_allow_html=True)
    elif verdict == "PHISHING":
        st.markdown(f"""
        <div class="phishing-alert">
            <h2>⚠️ PHISHING DETECTED</h2>
            <p><strong>Threat Level:</strong> {summary['threat_level']}</p>
            <p><strong>Confidence:</strong> {summary['confidence']:.1%}</p>
            <p><strong>Action:</strong> {summary['action_taken']}</p>
        </div>
        """, unsafe_allow_html=True)
    elif verdict == "SPAM":
        st.markdown(f"""
        <div class="spam-alert">
            <h2>📢 SPAM DETECTED</h2>
            <p><strong>Confidence:</strong> {summary['confidence']:.1%}</p>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown(f"""
        <div class="safe-alert">
            <h2>✅ LEGITIMATE EMAIL</h2>
            <p><strong>Confidence:</strong> {summary['confidence']:.1%}</p>
        </div>
        """, unsafe_allow_html=True)
    
    # Confidence breakdown
    col1, col2, col3, col4 = st.columns(4)
    probs = classification.get('class_probabilities', {})
    col1.metric("Legitimate", f"{probs.get('LEGITIMATE', 0):.1%}")
    col2.metric("Spam", f"{probs.get('SPAM', 0):.1%}")
    col3.metric("Phishing", f"{probs.get('PHISHING', 0):.1%}")
    col4.metric("BEC", f"{probs.get('BEC', 0):.1%}")
    
    # Warnings
    warnings = response.get('user_warnings', [])
    if warnings:
        st.markdown("### ⚠️ Security Warnings")
        for warning in warnings:
            st.warning(warning)


def main():
    # Header
    st.markdown('<p class="main-header">🛡️ PhishAlert AI Agent System</p>', unsafe_allow_html=True)
    st.markdown('<p class="sub-header">Business Email Compromise (BEC) & Phishing Detection<br>MSc Cybersecurity Technology | Northumbria University</p>', unsafe_allow_html=True)
    
    # Sidebar
    with st.sidebar:
        st.title("📋 System Control")
        st.success("☁️ CLOUD DEMO MODE")
        st.caption("Running on Streamlit Cloud")
        
        with st.spinner("Initialising AI Agents..."):
            system = init_system()
        
        st.success("✅ System Ready")
        st.success("✅ BEC Detection Enabled")
        
        st.markdown("---")
        st.markdown("### 🎯 BEC Types Detected")
        st.caption("🏢 CEO Fraud")
        st.caption("🧾 Invoice Fraud")
        st.caption("🎁 Gift Card Scam")
        st.caption("💰 Payroll Diversion")
        st.caption("₿ Crypto Scam")
        
        st.markdown("---")
        st.markdown("### 👤 Project Info")
        st.caption("**Student:** Opoku")
        st.caption("**ID:** w25035430")
        st.caption("**Course:** MSc Cybersecurity")
    
    # Main tabs
    tab1, tab2, tab3 = st.tabs(["🔍 Analyse Email", "📧 Demo Samples", "📐 Architecture"])
    
    # Tab 1: Manual Analysis
    with tab1:
        st.markdown("### ✍️ Analyse Any Email for Threats")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            sender = st.text_input("📧 Sender Email", placeholder="ceo@company.com")
            subject = st.text_input("📝 Subject Line", placeholder="Enter email subject...")
            body = st.text_area("📄 Email Body", height=200, placeholder="Paste email content here...")
        
        with col2:
            st.markdown("### 🧪 Quick Test")
            if st.button("🏢 CEO Fraud", use_container_width=True):
                sender, subject, body = "ceo@gmail.com", "Urgent Wire Transfer", "I need you to process an urgent wire transfer of $50,000. Keep this confidential. I am in meetings."
            if st.button("🎁 Gift Card Scam", use_container_width=True):
                sender, subject, body = "director@yahoo.com", "Quick Favor", "Please purchase 5 Amazon gift cards for $100 each. Send me the codes. This is urgent."
            if st.button("🧾 Invoice Fraud", use_container_width=True):
                sender, subject, body = "accounts@supplier.tk", "Bank Details Changed", "Our bank details have changed. New account: 12345678. Please update immediately."
            if st.button("🚨 Phishing", use_container_width=True):
                sender, subject, body = "security@micros0ft.tk", "URGENT: Password Expires", "Your password expires today! Click here to verify immediately."
            if st.button("✅ Legitimate", use_container_width=True):
                sender, subject, body = "john@company.com", "Meeting Notes", "Hi team, please find the meeting notes from today. Best regards, John"
        
        if st.button("🔍 Analyse for Threats", type="primary", use_container_width=True):
            if not subject or not body:
                st.error("⚠️ Please enter subject and body text")
            else:
                email = {'id': 'manual', 'subject': subject, 'body_text': body, 'sender_email': sender, 'sender': sender, 'urls': [], 'attachments': []}
                with st.spinner("🔄 Running AI analysis..."):
                    result = system.analyse_email(email)
                display_results(result)
    
    # Tab 2: Demo Samples
    with tab2:
        st.markdown("### 📧 Pre-loaded Demo Samples")
        
        demos = [
            ("🏢 CEO Fraud", "ceo@gmail.com", "Urgent Wire Transfer", "Process urgent wire transfer of $50,000. Confidential. I am in meetings."),
            ("🎁 Gift Card", "director@yahoo.com", "Gift Cards Needed", "Purchase 5 Amazon gift cards $100 each. Send codes urgently."),
            ("🧾 Invoice Fraud", "accounts@supplier.tk", "Bank Details Changed", "Our bank details changed. New account: 12345678."),
            ("🚨 Phishing", "security@micros0ft.tk", "Password Expires", "Your password expires! Click to verify immediately."),
            ("✅ Legitimate", "john@company.com", "Meeting Notes", "Please find the meeting notes attached. Best regards."),
        ]
        
        for label, sender, subject, body in demos:
            if st.button(f"Analyse: {label}", use_container_width=True):
                email = {'id': 'demo', 'subject': subject, 'body_text': body, 'sender_email': sender, 'sender': sender, 'urls': [] if 'Phishing' not in label else ['http://malicious.tk'], 'attachments': []}
                with st.spinner("Analysing..."):
                    result = system.analyse_email(email)
                display_results(result)
    
    # Tab 3: Architecture
    with tab3:
        st.markdown("### 🏗️ Multi-Agent Architecture")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("""
            <div class="agent-card">
                <h3>🧠 Agent 1</h3>
                <h4>Data-Driven AI</h4>
                <hr>
                <p>• TF-IDF Vectorisation</p>
                <p>• Random Forest Classifier</p>
                <p>• BEC Feature Extraction</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown("""
            <div class="agent-card">
                <h3>🔍 Agent 2</h3>
                <h4>Reactive AI</h4>
                <hr>
                <p>• Sender Verification</p>
                <p>• Domain Analysis</p>
                <p>• Threat Intelligence</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col3:
            st.markdown("""
            <div class="agent-card">
                <h3>⚡ Agent 3</h3>
                <h4>Autonomous Response</h4>
                <hr>
                <p>• Decision Engine</p>
                <p>• BEC Policies</p>
                <p>• Action Execution</p>
            </div>
            """, unsafe_allow_html=True)


if __name__ == "__main__":
    main()
