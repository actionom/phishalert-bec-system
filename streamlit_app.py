"""
PhishAlert AI Agent System - Streamlit Cloud Deployment
Multi-Agent Phishing & BEC Detection System

Deployed on Streamlit Community Cloud
Student: Opoku | ID: w25035430 | MSc Cybersecurity Technology | Northumbria University
"""

import streamlit as st
import sys
import os
import json
import pickle
from pathlib import Path

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from phishalert_system import PhishAlertSystem
from agents.threat_response_agent import OperationMode

# Page configuration
st.set_page_config(
    page_title="PhishAlert - BEC & Phishing Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header { font-size: 2.5rem; font-weight: bold; color: #1E3A5F; text-align: center; padding: 1rem; }
    .sub-header { font-size: 1.2rem; color: #666; text-align: center; margin-bottom: 2rem; }
    .bec-alert { background-color: #FFE0E0; border-left: 5px solid #DC3545; padding: 1.5rem; border-radius: 10px; margin: 1rem 0; }
    .phishing-alert { background-color: #FFE6E6; border-left: 5px solid #E74C3C; padding: 1.5rem; border-radius: 10px; margin: 1rem 0; }
    .spam-alert { background-color: #FFF8E6; border-left: 5px solid #F39C12; padding: 1.5rem; border-radius: 10px; margin: 1rem 0; }
    .safe-alert { background-color: #E6FFE6; border-left: 5px solid #28A745; padding: 1.5rem; border-radius: 10px; margin: 1rem 0; }
    .agent-card { background: linear-gradient(135deg, #2C3E50 0%, #3498DB 100%); color: white; padding: 1.5rem; border-radius: 15px; margin: 0.5rem 0; }
    .demo-badge { background-color: #17A2B8; color: white; padding: 0.3rem 0.8rem; border-radius: 15px; font-size: 0.8rem; }
</style>
""", unsafe_allow_html=True)


@st.cache_resource
def init_system():
    """Initialise the PhishAlert system in demo mode for cloud deployment."""
    return PhishAlertSystem(
        use_mock_gmail=True,  # Always use mock for cloud deployment
        operation_mode=OperationMode.SUPERVISED,
        auto_train=True
    )


def main():
    # Header
    st.markdown('<p class="main-header">🛡️ PhishAlert AI Agent System</p>', unsafe_allow_html=True)
    st.markdown('<p class="sub-header">Business Email Compromise (BEC) & Phishing Detection<br>MSc Cybersecurity Technology | Northumbria University</p>', unsafe_allow_html=True)
    
    # Sidebar
    with st.sidebar:
        st.title("📋 System Control")
        
        st.markdown('<span class="demo-badge">☁️ CLOUD DEMO</span>', unsafe_allow_html=True)
        st.caption("Running on Streamlit Cloud")
        
        st.markdown("---")
        
        # Initialise system
        with st.spinner("Initialising AI Agents..."):
            system = init_system()
        
        status = system.get_system_status()
        if status['is_trained']:
            st.success("✅ BEC Detection Ready")
        else:
            st.error("❌ System Not Trained")
        
        st.markdown("---")
        st.markdown("### 🎯 BEC Types Detected")
        
        bec_types = [
            ("🏢 CEO Fraud", "Executive impersonation"),
            ("🧾 Invoice Fraud", "Bank details change"),
            ("🎁 Gift Card Scam", "Purchase requests"),
            ("💰 Payroll Diversion", "Salary redirect"),
            ("₿ Crypto Scam", "Bitcoin payment")
        ]
        
        for bec_type, desc in bec_types:
            st.markdown(f"**{bec_type}**")
            st.caption(desc)
        
        st.markdown("---")
        st.markdown("### 🤖 Agent Status")
        st.caption(f"Agent 1: {'Trained ✅' if status['agent1_status']['is_trained'] else 'Not Ready ❌'}")
        st.caption(f"Agent 2: Active ✅")
        st.caption(f"Agent 3: {status['agent3_status']['operation_mode']}")
        
        st.markdown("---")
        st.markdown("### 👤 Project Info")
        st.caption("**Student:** Opoku")
        st.caption("**ID:** w25035430")
        st.caption("**Course:** MSc Cybersecurity")
        st.caption("**University:** Northumbria")
    
    # Main tabs
    tab1, tab2, tab3, tab4 = st.tabs([
        "🔍 Analyse Email",
        "📧 Demo Samples", 
        "📐 Architecture",
        "📚 BEC Education"
    ])
    
    # === Tab 1: Manual Analysis ===
    with tab1:
        st.markdown("### ✍️ Analyse Any Email for Threats")
        st.info("📝 Paste email content below to check for Phishing or BEC threats")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            sender = st.text_input("📧 Sender Email", placeholder="ceo@company.com", key="manual_sender")
            sender_display = st.text_input("👤 Sender Display Name", placeholder="CEO John Smith", key="manual_display")
            subject = st.text_input("📝 Subject Line", placeholder="Enter email subject...", key="manual_subject")
            body = st.text_area("📄 Email Body", height=200, placeholder="Paste email content here...", key="manual_body")
            urls = st.text_input("🔗 URLs (comma-separated)", placeholder="http://example.com", key="manual_urls")
        
        with col2:
            st.markdown("### 🧪 Quick Test")
            st.caption("Click to load example:")
            
            if st.button("🏢 CEO Fraud", use_container_width=True):
                st.session_state.test_example = "ceo_fraud"
                st.rerun()
            
            if st.button("🎁 Gift Card Scam", use_container_width=True):
                st.session_state.test_example = "giftcard"
                st.rerun()
            
            if st.button("🧾 Invoice Fraud", use_container_width=True):
                st.session_state.test_example = "invoice"
                st.rerun()
            
            if st.button("💰 Payroll Diversion", use_container_width=True):
                st.session_state.test_example = "payroll"
                st.rerun()
            
            st.markdown("---")
            
            if st.button("🚨 Phishing Attack", use_container_width=True):
                st.session_state.test_example = "phishing"
                st.rerun()
            
            if st.button("✅ Legitimate Email", use_container_width=True):
                st.session_state.test_example = "legitimate"
                st.rerun()
        
        # Handle test examples
        examples = {
            "ceo_fraud": {
                "sender": "ceo.office@gmail.com",
                "sender_display": "CEO John Anderson",
                "subject": "Urgent Wire Transfer Needed",
                "body": "Hi,\n\nI need you to process an urgent wire transfer of $47,500 today. This is for a confidential acquisition deal.\n\nPlease keep this between us - do not discuss with anyone else. I am in meetings all day and cannot take calls.\n\nWire the funds to:\nAccount: 12345678\nRouting: 987654321\n\nLet me know once done.\n\nThanks,\nJohn Anderson\nCEO",
                "urls": ""
            },
            "giftcard": {
                "sender": "director.james@yahoo.com",
                "sender_display": "Director James",
                "subject": "Quick Favor Needed",
                "body": "Hi,\n\nI need a quick favor. Can you purchase 5 Amazon gift cards ($100 each) for client appreciation gifts?\n\nThis is urgent - I need them today. Keep this confidential as it's a surprise. I'm in a conference and can't call.\n\nSend me the card codes once you have them.\n\nThanks,\nJames",
                "urls": ""
            },
            "invoice": {
                "sender": "accounts@supplier-intl.tk",
                "sender_display": "ABC Suppliers - Accounts",
                "subject": "Updated Bank Details - ACTION REQUIRED",
                "body": "Dear Accounts Payable Team,\n\nPlease note that our bank details have changed effective immediately.\n\nAll future payments should be sent to our new account:\n\nBank: International Bank\nAccount Number: 9876543210\nRouting Number: 123456789\n\nPlease update your records and confirm receipt. The next invoice payment of $125,000 should use these new details.\n\nBest regards,\nABC Suppliers",
                "urls": ""
            },
            "payroll": {
                "sender": "sarah.johnson.hr@gmail.com",
                "sender_display": "Sarah Johnson - Marketing",
                "subject": "Direct Deposit Update Request",
                "body": "Hi Payroll Team,\n\nI need to update my direct deposit information before the next pay period.\n\nPlease change my bank details to:\n\nBank: First National Bank\nAccount: 5544332211\nRouting: 111222333\n\nPlease process this urgently as my old account will be closed.\n\nThanks,\nSarah Johnson\nMarketing Department",
                "urls": ""
            },
            "phishing": {
                "sender": "security@micros0ft-alerts.tk",
                "sender_display": "Microsoft Security Team",
                "subject": "URGENT: Your Microsoft 365 password expires today!",
                "body": "Your Microsoft 365 password will expire in 24 hours!\n\nClick here immediately to verify your account and prevent suspension.\n\nIf you do not verify within 24 hours, your account will be permanently locked.\n\nMicrosoft Security Team",
                "urls": "http://microsoft-365-verify.tk/login?user=12345"
            },
            "legitimate": {
                "sender": "john.smith@company.com",
                "sender_display": "John Smith",
                "subject": "Re: Q4 Budget Meeting - Agenda",
                "body": "Hi Team,\n\nThanks for confirming attendance for tomorrow's Q4 budget meeting. Here's the agenda:\n\n1. Q3 Results Review\n2. Q4 Projections\n3. Department Requests\n\nPlease bring your department summaries. Meeting is at 2pm in Conference Room B.\n\nBest,\nJohn",
                "urls": ""
            }
        }
        
        if 'test_example' in st.session_state:
            ex = st.session_state.test_example
            if ex in examples:
                data = examples[ex]
                sender = data["sender"]
                sender_display = data["sender_display"]
                subject = data["subject"]
                body = data["body"]
                urls = data["urls"]
            del st.session_state.test_example
        
        st.markdown("---")
        
        if st.button("🔍 Analyse for Threats", type="primary", use_container_width=True):
            if not subject or not body:
                st.error("⚠️ Please enter subject and body text")
            else:
                url_list = [u.strip() for u in urls.split(',') if u.strip()] if urls else []
                
                email = {
                    'id': 'manual_001',
                    'subject': subject,
                    'body_text': body,
                    'sender_email': sender,
                    'sender': sender_display or sender,
                    'urls': url_list,
                    'attachments': [],
                    'reply_to': ''
                }
                
                with st.spinner("🔄 Running AI analysis..."):
                    result = system.analyse_email(email)
                
                display_results(result)
    
    # === Tab 2: Demo Samples ===
    with tab2:
        st.markdown("### 📧 Pre-loaded Demo Samples")
        st.info("Click any sample to see how the AI detects threats")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### 🚨 Threat Samples")
            
            if st.button("🏢 Analyse CEO Fraud Email", use_container_width=True, key="demo_ceo"):
                email = {
                    'id': 'demo_ceo',
                    'subject': "Urgent Wire Transfer Needed",
                    'body_text': "I need you to process an urgent wire transfer of $47,500 today. This is confidential - do not discuss with anyone. I am in meetings and cannot take calls. Wire to Account: 12345678.",
                    'sender_email': 'ceo.office@gmail.com',
                    'sender': 'CEO John Anderson',
                    'urls': [],
                    'attachments': [],
                    'reply_to': ''
                }
                with st.spinner("Analysing..."):
                    result = system.analyse_email(email)
                display_results(result)
            
            if st.button("🎁 Analyse Gift Card Scam", use_container_width=True, key="demo_gift"):
                email = {
                    'id': 'demo_gift',
                    'subject': "Quick Favor - Gift Cards Needed",
                    'body_text': "Can you purchase 5 Amazon gift cards ($100 each) for client gifts? This is urgent and confidential. I'm in a conference and can't call. Send me the codes once you have them.",
                    'sender_email': 'director@yahoo.com',
                    'sender': 'Director James',
                    'urls': [],
                    'attachments': [],
                    'reply_to': ''
                }
                with st.spinner("Analysing..."):
                    result = system.analyse_email(email)
                display_results(result)
            
            if st.button("🧾 Analyse Invoice Fraud", use_container_width=True, key="demo_invoice"):
                email = {
                    'id': 'demo_invoice',
                    'subject': "Updated Bank Details - ACTION REQUIRED",
                    'body_text': "Our bank details have changed. All future payments should be sent to new account: Account Number: 9876543210, Routing: 123456789. Please update immediately for next payment of $125,000.",
                    'sender_email': 'accounts@supplier-intl.tk',
                    'sender': 'ABC Suppliers',
                    'urls': [],
                    'attachments': [],
                    'reply_to': ''
                }
                with st.spinner("Analysing..."):
                    result = system.analyse_email(email)
                display_results(result)
            
            if st.button("🚨 Analyse Phishing Email", use_container_width=True, key="demo_phish"):
                email = {
                    'id': 'demo_phish',
                    'subject': "URGENT: Your Microsoft 365 password expires today!",
                    'body_text': "Your Microsoft 365 password will expire in 24 hours! Click here immediately to verify your account. If you do not verify, your account will be permanently locked.",
                    'sender_email': 'security@micros0ft-alerts.tk',
                    'sender': 'Microsoft Security',
                    'urls': ['http://microsoft-365-verify.tk/login'],
                    'attachments': [],
                    'reply_to': ''
                }
                with st.spinner("Analysing..."):
                    result = system.analyse_email(email)
                display_results(result)
        
        with col2:
            st.markdown("#### ✅ Safe Sample")
            
            if st.button("✅ Analyse Legitimate Email", use_container_width=True, key="demo_legit"):
                email = {
                    'id': 'demo_legit',
                    'subject': "Q4 Budget Meeting - Agenda",
                    'body_text': "Hi Team, Thanks for confirming attendance for tomorrow's Q4 budget meeting. Agenda: Q3 Review, Q4 Projections, Department Requests. Meeting at 2pm. Best, John",
                    'sender_email': 'john.smith@company.com',
                    'sender': 'John Smith',
                    'urls': [],
                    'attachments': [],
                    'reply_to': ''
                }
                with st.spinner("Analysing..."):
                    result = system.analyse_email(email)
                display_results(result)
            
            st.markdown("---")
            st.markdown("#### 📊 Detection Capabilities")
            st.markdown("""
            **Phishing Detection:**
            - Fake login pages
            - Malicious URLs
            - Urgency/threat language
            - Brand impersonation
            
            **BEC Detection:**
            - CEO/Executive fraud
            - Invoice manipulation
            - Gift card scams
            - Payroll diversion
            - Crypto payment scams
            """)
    
    # === Tab 3: Architecture ===
    with tab3:
        st.markdown("### 🏗️ Multi-Agent Architecture")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("""
            <div class="agent-card">
                <h3>🧠 Agent 1</h3>
                <h4>Data-Driven AI</h4>
                <hr style="border-color: rgba(255,255,255,0.3);">
                <p>• TF-IDF Vectorisation</p>
                <p>• Random Forest Classifier</p>
                <p>• 41 BEC-Specific Features</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown("""
            <div class="agent-card">
                <h3>🔍 Agent 2</h3>
                <h4>Reactive AI</h4>
                <hr style="border-color: rgba(255,255,255,0.3);">
                <p>• Sender Verification</p>
                <p>• Domain Spoofing Check</p>
                <p>• Threat Intelligence</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col3:
            st.markdown("""
            <div class="agent-card">
                <h3>⚡ Agent 3</h3>
                <h4>Autonomous Response</h4>
                <hr style="border-color: rgba(255,255,255,0.3);">
                <p>• Decision Engine</p>
                <p>• BEC Response Policies</p>
                <p>• Action Execution</p>
            </div>
            """, unsafe_allow_html=True)
        
        st.markdown("---")
        st.markdown("### 📊 System Workflow")
        st.code("""
┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Gmail API  │────▶│   Agent 1    │────▶│   Agent 2    │────▶│   Agent 3    │
│  (Email In)  │     │ Classify     │     │ Enrich       │     │ Respond      │
└──────────────┘     └──────────────┘     └──────────────┘     └──────────────┘
                            │                    │                    │
                            ▼                    ▼                    ▼
                     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
                     │  LEGITIMATE  │     │ Intelligence │     │  QUARANTINE  │
                     │  SPAM        │     │ Report       │     │  ALERT       │
                     │  PHISHING    │     │              │     │  FLAG        │
                     │  BEC         │     │              │     │              │
                     └──────────────┘     └──────────────┘     └──────────────┘
        """, language="text")
    
    # === Tab 4: BEC Education ===
    with tab4:
        st.markdown("### 📚 Understanding BEC Attacks")
        
        col1, col2, col3 = st.columns(3)
        col1.metric("FBI Losses (2023)", "$2.9 Billion")
        col2.metric("Avg Loss Per Attack", "$125,000")
        col3.metric("Annual Growth", "+17%")
        
        st.markdown("---")
        st.markdown("### 🎭 BEC Attack Types")
        
        with st.expander("🏢 CEO/Executive Fraud"):
            st.write("Attacker impersonates CEO to request urgent wire transfers")
            st.code("Example: 'I need you to wire $50,000 urgently. Keep this confidential.'")
        
        with st.expander("🧾 Invoice/Vendor Fraud"):
            st.write("Fake vendor requests payment to changed bank account")
            st.code("Example: 'Our bank details have changed. Please update for next payment.'")
        
        with st.expander("🎁 Gift Card Scam"):
            st.write("Request to purchase gift cards and send codes")
            st.code("Example: 'Buy 5 Amazon gift cards for client gifts. Send me the codes.'")
        
        with st.expander("💰 Payroll Diversion"):
            st.write("Employee impersonation to redirect salary")
            st.code("Example: 'Please update my direct deposit to this new account.'")
        
        st.markdown("---")
        st.markdown("### 🛡️ Red Flags")
        flags = [
            "Urgency and pressure to act quickly",
            "Requests to keep transaction confidential", 
            "Executive claims to be unavailable for calls",
            "Changes to bank account details",
            "Gift card or cryptocurrency requests",
            "Email from free provider (Gmail, Yahoo) claiming to be executive"
        ]
        for flag in flags:
            st.markdown(f"🚩 {flag}")


def display_results(result: dict):
    """Display analysis results."""
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
            <p><strong>Action:</strong> {summary['action_taken']}</p>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown(f"""
        <div class="safe-alert">
            <h2>✅ LEGITIMATE EMAIL</h2>
            <p><strong>Confidence:</strong> {summary['confidence']:.1%}</p>
            <p><strong>Action:</strong> {summary['action_taken']}</p>
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
        for warning in warnings[:3]:
            st.warning(warning)


if __name__ == "__main__":
    main()
