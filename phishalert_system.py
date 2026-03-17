"""
PhishAlert System - Main Coordinator
Multi-Agent AI System for Phishing & BEC Detection

Student: Opoku | ID: w25035430 | MSc Cybersecurity Technology | Northumbria University
"""

import os
import sys
from typing import Dict, List, Optional
from datetime import datetime

from agents.threat_classification_agent import ThreatClassificationAgent
from agents.threat_intelligence_agent import ThreatIntelligenceAgent
from agents.threat_response_agent import ThreatResponseAgent, OperationMode


class PhishAlertSystem:
    """Main coordinator for the PhishAlert multi-agent system."""
    
    def __init__(
        self,
        use_mock_gmail: bool = True,
        operation_mode: OperationMode = OperationMode.SUPERVISED,
        auto_train: bool = True
    ):
        self.use_mock_gmail = use_mock_gmail
        self.operation_mode = operation_mode
        
        print("[System] Initialising PhishAlert BEC-Enhanced System...")
        
        # Initialise agents
        self.agent1 = ThreatClassificationAgent()
        self.agent2 = ThreatIntelligenceAgent()
        self.agent3 = ThreatResponseAgent(operation_mode=operation_mode)
        
        # Auto-train if requested
        if auto_train and not self.agent1.is_trained:
            self._train_system()
        
        print("[System] Initialisation complete!")
        print(f"[System] BEC Detection: ENABLED")
        print(f"[System] Operation mode: {operation_mode.value}")
    
    def _train_system(self):
        """Train the classification model with BEC-focused data."""
        print("[System] Training BEC-Enhanced models...")
        
        training_data = self._generate_bec_training_data()
        
        print(f"[System] Training samples: {len(training_data)}")
        print(f"[System] - LEGITIMATE: {sum(1 for d in training_data if d['label'] == 'LEGITIMATE')}")
        print(f"[System] - SPAM: {sum(1 for d in training_data if d['label'] == 'SPAM')}")
        print(f"[System] - PHISHING: {sum(1 for d in training_data if d['label'] == 'PHISHING')}")
        print(f"[System] - BEC: {sum(1 for d in training_data if d['label'] == 'BEC')}")
        
        self.agent1.train(training_data)
    
    def _generate_bec_training_data(self) -> List[Dict]:
        """Generate BEC-focused training dataset."""
        data = []
        
        # BEC - CEO Fraud samples
        ceo_fraud_templates = [
            "I need you to process an urgent wire transfer of $50,000 today. This is confidential.",
            "Please wire $75,000 to this account immediately. I am in meetings and cannot discuss.",
            "Urgent - transfer $100,000 to our new vendor. Keep this between us.",
            "I need you to handle a confidential wire transfer of $45,000. Do not tell anyone.",
            "Process this urgent payment of $60,000. I am traveling and unreachable by phone.",
        ]
        
        for i, template in enumerate(ceo_fraud_templates):
            for j in range(20):
                data.append({
                    'subject': f'Urgent Wire Transfer Request',
                    'body': template,
                    'sender': f'ceo{i}@gmail.com',
                    'sender_name': 'CEO John Smith',
                    'urls': [],
                    'label': 'BEC',
                    'bec_subtype': 'CEO_FRAUD'
                })
        
        # BEC - Gift Card Scam samples
        giftcard_templates = [
            "I need you to purchase 5 Amazon gift cards for $100 each. Send me the codes.",
            "Can you buy iTunes gift cards worth $500? It's for client gifts. Keep it confidential.",
            "Please get me 10 Google Play cards at $50 each. Send the redemption codes ASAP.",
            "I need Amazon gift cards urgently for a surprise. Buy $1000 worth and send codes.",
            "Purchase gift cards for employee rewards. 5 cards at $200 each. This is confidential.",
        ]
        
        for i, template in enumerate(giftcard_templates):
            for j in range(20):
                data.append({
                    'subject': f'Quick Favor Needed',
                    'body': template,
                    'sender': f'director{i}@yahoo.com',
                    'sender_name': 'Director',
                    'urls': [],
                    'label': 'BEC',
                    'bec_subtype': 'GIFT_CARD_SCAM'
                })
        
        # BEC - Invoice Fraud samples
        invoice_templates = [
            "Our bank details have changed. New account: 12345678. Please update immediately.",
            "Please note our banking information has been updated. Route payments to new account.",
            "Action required: Update vendor payment details. New routing number: 987654321.",
            "Our company has changed banks. Please update your records for future payments.",
            "Important: Bank account change. All payments should now go to account 55667788.",
        ]
        
        for i, template in enumerate(invoice_templates):
            for j in range(20):
                data.append({
                    'subject': f'Updated Bank Details - ACTION REQUIRED',
                    'body': template,
                    'sender': f'accounts@supplier{i}.tk',
                    'sender_name': 'Accounts Payable',
                    'urls': [],
                    'label': 'BEC',
                    'bec_subtype': 'INVOICE_FRAUD'
                })
        
        # BEC - Payroll Diversion samples
        payroll_templates = [
            "Please update my direct deposit to new account 11223344. Process before next payday.",
            "I need to change my bank details for salary. New account: 99887766.",
            "Update my payroll information. My new bank account is 44556677.",
            "Change my direct deposit immediately. New routing: 111222333, account: 444555666.",
            "Please redirect my salary to my new bank. Account details attached.",
        ]
        
        for i, template in enumerate(payroll_templates):
            for j in range(15):
                data.append({
                    'subject': f'Direct Deposit Update Request',
                    'body': template,
                    'sender': f'employee{i}@gmail.com',
                    'sender_name': 'Employee',
                    'urls': [],
                    'label': 'BEC',
                    'bec_subtype': 'PAYROLL_DIVERSION'
                })
        
        # BEC - Crypto Payment Scam
        crypto_templates = [
            "Please send $25,000 in Bitcoin to this wallet address immediately.",
            "I need you to purchase cryptocurrency for a confidential deal. $50,000 in BTC.",
            "Transfer funds via Bitcoin. It's faster and more secure. Wallet: 1A2b3C4d5E.",
            "Purchase Ethereum worth $30,000. This is for a time-sensitive acquisition.",
            "Send the payment in cryptocurrency. Bitcoin address: bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
        ]
        
        for i, template in enumerate(crypto_templates):
            for j in range(15):
                data.append({
                    'subject': f'Urgent Payment Request',
                    'body': template,
                    'sender': f'finance{i}@gmail.com',
                    'sender_name': 'CFO',
                    'urls': [],
                    'label': 'BEC',
                    'bec_subtype': 'CRYPTO_PAYMENT_SCAM'
                })
        
        # Phishing samples
        phishing_templates = [
            "Your account has been compromised. Click here to verify immediately.",
            "URGENT: Your password expires today. Click to renew now.",
            "Suspicious login detected. Verify your identity immediately.",
            "Your account will be suspended. Click here to prevent this.",
            "Security alert: Unusual activity detected. Verify now.",
            "Your package could not be delivered. Click to reschedule.",
            "You have won a prize! Click here to claim your reward.",
            "Your invoice is attached. Click to view and pay.",
            "Account verification required. Login here to confirm.",
            "Your subscription is expiring. Click to renew.",
        ]
        
        for i, template in enumerate(phishing_templates):
            for j in range(10):
                data.append({
                    'subject': f'URGENT: Action Required',
                    'body': template,
                    'sender': f'security@fake-bank{i}.tk',
                    'sender_name': 'Security Team',
                    'urls': [f'http://malicious-site{i}.tk/login'],
                    'label': 'PHISHING'
                })
        
        # Spam samples
        spam_templates = [
            "Get rich quick! Earn $10,000 per week from home!",
            "Congratulations! You've been selected for a special offer!",
            "Limited time offer! 90% off all products!",
            "Make money fast! No experience needed!",
            "Free vacation! Click here to claim your prize!",
            "Best prices on medications! Order now!",
        ]
        
        for i, template in enumerate(spam_templates):
            for j in range(10):
                data.append({
                    'subject': f'Special Offer Just For You!',
                    'body': template,
                    'sender': f'offers@marketing{i}.com',
                    'sender_name': 'Marketing',
                    'urls': [f'http://spam-site{i}.com'],
                    'label': 'SPAM'
                })
        
        # Legitimate samples
        legitimate_templates = [
            "Hi team, please find attached the meeting notes from today's discussion.",
            "The project deadline has been extended to next Friday. Let me know if you have questions.",
            "Thanks for your email. I'll review the proposal and get back to you tomorrow.",
            "Please join us for the quarterly review meeting on Thursday at 2pm.",
            "Here's the report you requested. Let me know if you need any changes.",
            "Following up on our conversation. The budget has been approved.",
            "Great work on the presentation! The client was very impressed.",
            "Reminder: Team lunch tomorrow at noon. Please RSVP.",
            "The conference call has been rescheduled to 3pm.",
            "Please review the attached document and provide your feedback.",
            "Happy to help with your request. I've forwarded it to the appropriate team.",
            "Thanks for the update. We'll proceed as discussed.",
        ]
        
        for i, template in enumerate(legitimate_templates):
            for j in range(10):
                data.append({
                    'subject': f'Re: Project Update',
                    'body': template,
                    'sender': f'colleague{i}@company.com',
                    'sender_name': f'Colleague {i}',
                    'urls': [],
                    'label': 'LEGITIMATE'
                })
        
        return data
    
    def analyse_email(self, email: Dict) -> Dict:
        """Analyse email using all three agents."""
        # Agent 1: Classification
        classification = self.agent1.classify(email)
        
        # Agent 2: Intelligence enrichment
        intelligence = self.agent2.analyse(email, classification)
        
        # Agent 3: Response decision
        response = self.agent3.decide_response(email, classification, intelligence)
        
        # Compile results
        result = {
            'email_id': email.get('id', 'unknown'),
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
        
        return result
    
    def get_system_status(self) -> Dict:
        """Get current system status."""
        return {
            'is_trained': self.agent1.is_trained,
            'operation_mode': self.operation_mode.value,
            'agent1_status': {
                'name': 'Threat Classification Agent',
                'is_trained': self.agent1.is_trained
            },
            'agent2_status': {
                'name': 'Threat Intelligence Agent',
                'is_active': True
            },
            'agent3_status': {
                'name': 'Threat Response Agent',
                'operation_mode': self.operation_mode.value
            }
        }
    
    def get_statistics(self) -> Dict:
        """Get system statistics."""
        return {
            'response_statistics': self.agent3.get_statistics()
        }
