"""
Agent 3: Threat Response Agent (Autonomous Agent)
BEC-Enhanced Automated Response and Decision Making

Student: Opoku | ID: w25035430 | MSc Cybersecurity Technology | Northumbria University
"""

from enum import Enum
from typing import Dict, List
from datetime import datetime


class OperationMode(Enum):
    """Agent operation modes."""
    AUTONOMOUS = "autonomous"
    INTERACTIVE = "interactive"
    SUPERVISED = "supervised"


class ResponseAction(Enum):
    """Available response actions."""
    QUARANTINE = "quarantine"
    ALERT_USER = "alert_user"
    ALERT_ADMIN = "alert_admin"
    ALERT_FINANCE = "alert_finance"
    BLOCK_SENDER = "block_sender"
    FLAG_SUSPICIOUS = "flag_suspicious"
    MOVE_TO_SPAM = "move_to_spam"
    DELETE = "delete"
    ALLOW = "allow"


class ThreatResponseAgent:
    """Autonomous Agent for threat response decisions."""
    
    def __init__(self, operation_mode: OperationMode = OperationMode.SUPERVISED):
        self.operation_mode = operation_mode
        self.action_log = []
        
        # BEC-specific response policies
        self.bec_policies = {
            'CEO_FRAUD': {
                'actions': [ResponseAction.QUARANTINE, ResponseAction.ALERT_ADMIN, ResponseAction.ALERT_FINANCE, ResponseAction.ALERT_USER],
                'severity': 'CRITICAL',
                'requires_verification': True
            },
            'INVOICE_FRAUD': {
                'actions': [ResponseAction.QUARANTINE, ResponseAction.ALERT_ADMIN, ResponseAction.ALERT_FINANCE],
                'severity': 'CRITICAL',
                'requires_verification': True
            },
            'GIFT_CARD_SCAM': {
                'actions': [ResponseAction.QUARANTINE, ResponseAction.ALERT_USER, ResponseAction.ALERT_ADMIN],
                'severity': 'HIGH',
                'requires_verification': False
            },
            'CRYPTO_PAYMENT_SCAM': {
                'actions': [ResponseAction.QUARANTINE, ResponseAction.ALERT_ADMIN, ResponseAction.ALERT_USER],
                'severity': 'HIGH',
                'requires_verification': False
            },
            'PAYROLL_DIVERSION': {
                'actions': [ResponseAction.QUARANTINE, ResponseAction.ALERT_ADMIN, ResponseAction.ALERT_FINANCE],
                'severity': 'CRITICAL',
                'requires_verification': True
            }
        }
    
    def decide_response(
        self,
        email: Dict,
        classification: Dict,
        intelligence: Dict
    ) -> Dict:
        """Decide appropriate response based on classification and intelligence."""
        verdict = classification.get('verdict', 'LEGITIMATE')
        confidence = classification.get('confidence', 0)
        is_bec = classification.get('is_bec', False)
        bec_subtype = classification.get('bec_subtype', '')
        threat_score = intelligence.get('threat_score', 0)
        
        response = {
            'actions': [],
            'primary_action': 'allow',
            'severity': 'LOW',
            'requires_verification': False,
            'user_warnings': [],
            'user_recommendations': [],
            'admin_notes': []
        }
        
        # BEC Response
        if is_bec and bec_subtype in self.bec_policies:
            policy = self.bec_policies[bec_subtype]
            response['actions'] = [a.value for a in policy['actions']]
            response['primary_action'] = policy['actions'][0].value
            response['severity'] = policy['severity']
            response['requires_verification'] = policy['requires_verification']
            response['user_warnings'] = self._generate_bec_warnings(bec_subtype)
            response['user_recommendations'] = self._generate_bec_recommendations(bec_subtype)
            response['admin_notes'] = [f"BEC Attack Detected: {bec_subtype}"]
        
        # Phishing Response
        elif verdict == 'PHISHING':
            if confidence >= 0.7:
                response['actions'] = ['quarantine', 'alert_user', 'alert_admin']
                response['primary_action'] = 'quarantine'
                response['severity'] = 'HIGH'
            else:
                response['actions'] = ['flag_suspicious', 'alert_user']
                response['primary_action'] = 'flag_suspicious'
                response['severity'] = 'MEDIUM'
            
            response['user_warnings'] = [
                "⚠️ This email may be a phishing attempt",
                "Do NOT click any links in this email",
                "Do NOT enter any credentials or personal information"
            ]
            response['user_recommendations'] = [
                "Delete this email immediately",
                "Report to IT security if you clicked any links",
                "Change your password if you entered credentials"
            ]
        
        # Spam Response
        elif verdict == 'SPAM':
            response['actions'] = ['move_to_spam']
            response['primary_action'] = 'move_to_spam'
            response['severity'] = 'LOW'
            response['user_warnings'] = ["This email appears to be spam"]
        
        # Legitimate - but check threat score
        else:
            if threat_score > 50:
                response['actions'] = ['flag_suspicious']
                response['primary_action'] = 'flag_suspicious'
                response['severity'] = 'MEDIUM'
                response['user_warnings'] = ["Some suspicious indicators detected - proceed with caution"]
            else:
                response['actions'] = ['allow']
                response['primary_action'] = 'allow'
                response['severity'] = 'LOW'
        
        # Log the action
        self._log_action(email, response)
        
        return response
    
    def _generate_bec_warnings(self, bec_subtype: str) -> List[str]:
        """Generate warnings for BEC attacks."""
        warnings = {
            'CEO_FRAUD': [
                "🚨 CRITICAL: This appears to be CEO/Executive Impersonation Fraud",
                "Do NOT process any wire transfers or payments",
                "Verify ALL requests through official channels (phone call to known number)"
            ],
            'INVOICE_FRAUD': [
                "🚨 CRITICAL: This appears to be Invoice/Vendor Fraud",
                "Do NOT update any bank account details",
                "Contact the vendor directly using known contact information"
            ],
            'GIFT_CARD_SCAM': [
                "⚠️ WARNING: This is a Gift Card Scam",
                "Do NOT purchase any gift cards",
                "Legitimate executives never request gift cards via email"
            ],
            'CRYPTO_PAYMENT_SCAM': [
                "🚨 CRITICAL: Cryptocurrency Payment Scam Detected",
                "Do NOT send any cryptocurrency",
                "Cryptocurrency transactions are irreversible"
            ],
            'PAYROLL_DIVERSION': [
                "🚨 CRITICAL: Payroll Diversion Attempt Detected",
                "Do NOT change any payroll information",
                "Verify employee identity through HR processes"
            ]
        }
        return warnings.get(bec_subtype, ["⚠️ Business Email Compromise detected"])
    
    def _generate_bec_recommendations(self, bec_subtype: str) -> List[str]:
        """Generate recommendations for BEC attacks."""
        recommendations = {
            'CEO_FRAUD': [
                "Call the executive directly on their known phone number",
                "Do not use contact information from the suspicious email",
                "Report this incident to IT Security immediately",
                "Document all details of this attempted fraud"
            ],
            'INVOICE_FRAUD': [
                "Contact the vendor using previously verified contact details",
                "Never use phone numbers or emails from the suspicious message",
                "Implement dual-approval for payment detail changes",
                "Report to your finance security team"
            ],
            'GIFT_CARD_SCAM': [
                "Do not respond to this email",
                "Report to IT Security",
                "If cards were purchased, contact card issuer immediately",
                "Preserve the email as evidence"
            ],
            'CRYPTO_PAYMENT_SCAM': [
                "Do not send any cryptocurrency",
                "Report to law enforcement (crypto fraud is increasing)",
                "Report to IT Security immediately",
                "If payment was made, contact law enforcement"
            ],
            'PAYROLL_DIVERSION': [
                "Contact HR to verify employee identity",
                "Use official HR processes for payroll changes",
                "Require in-person or video verification",
                "Report to IT Security and HR immediately"
            ]
        }
        return recommendations.get(bec_subtype, ["Report this email to IT Security"])
    
    def _log_action(self, email: Dict, response: Dict):
        """Log action for audit trail."""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'email_id': email.get('id', 'unknown'),
            'subject': email.get('subject', '')[:50],
            'action': response['primary_action'],
            'severity': response['severity'],
            'operation_mode': self.operation_mode.value
        }
        self.action_log.append(log_entry)
    
    def get_statistics(self) -> Dict:
        """Get response statistics."""
        stats = {
            'total_actions': len(self.action_log),
            'actions_by_type': {},
            'actions_by_severity': {}
        }
        
        for log in self.action_log:
            action = log['action']
            severity = log['severity']
            
            stats['actions_by_type'][action] = stats['actions_by_type'].get(action, 0) + 1
            stats['actions_by_severity'][severity] = stats['actions_by_severity'].get(severity, 0) + 1
        
        return stats
