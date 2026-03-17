"""
Agent 2: Threat Intelligence Agent (Reactive AI Agent)
BEC-Enhanced Threat Intelligence and Sender Verification

Student: Opoku | ID: w25035430 | MSc Cybersecurity Technology | Northumbria University
"""

import re
from typing import Dict, List
from urllib.parse import urlparse


class ThreatIntelligenceAgent:
    """Reactive AI Agent for threat intelligence enrichment."""
    
    def __init__(self):
        self.freemail_providers = [
            'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
            'aol.com', 'mail.com', 'protonmail.com', 'icloud.com'
        ]
        
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club',
            '.work', '.date', '.racing', '.download', '.stream'
        ]
        
        self.spoofed_brands = {
            'microsoft': ['micros0ft', 'microsft', 'mircosoft', 'microsoft-security', 'ms-online'],
            'google': ['g00gle', 'googl3', 'google-security', 'google-verify'],
            'paypal': ['paypa1', 'paypal-security', 'paypa-l', 'pay-pal'],
            'amazon': ['amaz0n', 'amazon-security', 'amazonn', 'arnazon'],
            'apple': ['app1e', 'apple-id', 'apple-security', 'icloud-verify']
        }
        
        self.executive_titles = [
            'ceo', 'cfo', 'coo', 'cto', 'president', 'director',
            'chairman', 'chief', 'executive', 'vp', 'vice president'
        ]
    
    def analyse(self, email: Dict, classification: Dict) -> Dict:
        """Analyse email for threat intelligence."""
        
        sender_analysis = self._analyse_sender(email)
        url_analysis = self._analyse_urls(email)
        bec_analysis = self._analyse_bec_indicators(email, classification)
        
        # Calculate overall threat score
        threat_score = self._calculate_threat_score(
            classification, sender_analysis, url_analysis, bec_analysis
        )
        
        result = {
            'sender_analysis': sender_analysis,
            'url_analysis': url_analysis,
            'bec_analysis': bec_analysis,
            'threat_score': threat_score,
            'intelligence_summary': self._generate_summary(
                sender_analysis, url_analysis, bec_analysis, threat_score
            )
        }
        
        return result
    
    def _analyse_sender(self, email: Dict) -> Dict:
        """Analyse sender for suspicious indicators."""
        sender_email = email.get('sender_email', email.get('sender', '')).lower()
        sender_name = email.get('sender', email.get('sender_name', '')).lower()
        reply_to = email.get('reply_to', '').lower()
        
        analysis = {
            'email': sender_email,
            'display_name': sender_name,
            'is_freemail': False,
            'has_executive_title': False,
            'name_email_mismatch': False,
            'reply_to_mismatch': False,
            'domain_spoofing': False,
            'spoofed_brand': None,
            'risk_level': 'LOW'
        }
        
        # Check freemail
        for provider in self.freemail_providers:
            if provider in sender_email:
                analysis['is_freemail'] = True
                break
        
        # Check executive title in display name
        for title in self.executive_titles:
            if title in sender_name:
                analysis['has_executive_title'] = True
                break
        
        # Check name vs email mismatch
        if sender_name and sender_email:
            name_parts = sender_name.replace('.', ' ').split()
            email_local = sender_email.split('@')[0] if '@' in sender_email else ''
            if name_parts and email_local:
                match_found = any(part in email_local for part in name_parts if len(part) > 2)
                if not match_found and len(name_parts) > 0:
                    analysis['name_email_mismatch'] = True
        
        # Check reply-to mismatch
        if reply_to and sender_email and reply_to != sender_email:
            analysis['reply_to_mismatch'] = True
        
        # Check domain spoofing
        for brand, variants in self.spoofed_brands.items():
            for variant in variants:
                if variant in sender_email:
                    analysis['domain_spoofing'] = True
                    analysis['spoofed_brand'] = brand
                    break
        
        # Calculate risk level
        risk_score = 0
        if analysis['is_freemail'] and analysis['has_executive_title']:
            risk_score += 3
        if analysis['name_email_mismatch']:
            risk_score += 1
        if analysis['reply_to_mismatch']:
            risk_score += 2
        if analysis['domain_spoofing']:
            risk_score += 3
        
        if risk_score >= 4:
            analysis['risk_level'] = 'HIGH'
        elif risk_score >= 2:
            analysis['risk_level'] = 'MEDIUM'
        
        return analysis
    
    def _analyse_urls(self, email: Dict) -> Dict:
        """Analyse URLs for suspicious indicators."""
        urls = email.get('urls', [])
        
        analysis = {
            'total_urls': len(urls),
            'suspicious_urls': [],
            'http_urls': 0,
            'suspicious_tlds': 0,
            'spoofed_domains': 0,
            'risk_level': 'LOW'
        }
        
        for url in urls:
            url_info = {
                'url': url,
                'issues': []
            }
            
            # Check HTTP (not HTTPS)
            if url.startswith('http://'):
                analysis['http_urls'] += 1
                url_info['issues'].append('Non-HTTPS')
            
            # Check suspicious TLD
            for tld in self.suspicious_tlds:
                if tld in url.lower():
                    analysis['suspicious_tlds'] += 1
                    url_info['issues'].append(f'Suspicious TLD: {tld}')
                    break
            
            # Check spoofed domain
            for brand, variants in self.spoofed_brands.items():
                for variant in variants:
                    if variant in url.lower():
                        analysis['spoofed_domains'] += 1
                        url_info['issues'].append(f'Spoofed: {brand}')
                        break
            
            if url_info['issues']:
                analysis['suspicious_urls'].append(url_info)
        
        # Calculate risk level
        if analysis['spoofed_domains'] > 0 or analysis['suspicious_tlds'] > 1:
            analysis['risk_level'] = 'HIGH'
        elif analysis['http_urls'] > 0 or analysis['suspicious_tlds'] > 0:
            analysis['risk_level'] = 'MEDIUM'
        
        return analysis
    
    def _analyse_bec_indicators(self, email: Dict, classification: Dict) -> Dict:
        """Analyse BEC-specific indicators."""
        body = email.get('body_text', email.get('body', '')).lower()
        subject = email.get('subject', '').lower()
        
        analysis = {
            'is_bec': classification.get('is_bec', False),
            'bec_subtype': classification.get('bec_subtype', ''),
            'payment_request_detected': False,
            'impersonation_detected': False,
            'urgency_detected': False,
            'secrecy_detected': False,
            'bec_indicators': []
        }
        
        # Payment request detection
        payment_terms = ['wire transfer', 'bank transfer', 'payment', 'invoice', 'account number', 'gift card']
        if any(term in body for term in payment_terms):
            analysis['payment_request_detected'] = True
            analysis['bec_indicators'].append("Payment/transfer request detected")
        
        # Impersonation detection
        exec_terms = ['ceo', 'cfo', 'president', 'director', 'chief']
        sender_name = email.get('sender', '').lower()
        if any(term in sender_name or term in subject for term in exec_terms):
            analysis['impersonation_detected'] = True
            analysis['bec_indicators'].append("Executive impersonation suspected")
        
        # Urgency detection
        urgency_terms = ['urgent', 'asap', 'immediately', 'right now', 'today']
        if any(term in body or term in subject for term in urgency_terms):
            analysis['urgency_detected'] = True
            analysis['bec_indicators'].append("High urgency language")
        
        # Secrecy detection
        secrecy_terms = ['confidential', 'keep quiet', 'do not share', 'between us', 'secret']
        if any(term in body for term in secrecy_terms):
            analysis['secrecy_detected'] = True
            analysis['bec_indicators'].append("Secrecy/confidentiality request")
        
        return analysis
    
    def _calculate_threat_score(
        self, 
        classification: Dict, 
        sender_analysis: Dict, 
        url_analysis: Dict,
        bec_analysis: Dict
    ) -> float:
        """Calculate overall threat score (0-100)."""
        score = 0
        
        # Classification confidence
        verdict = classification.get('verdict', 'LEGITIMATE')
        confidence = classification.get('confidence', 0)
        
        if verdict == 'BEC':
            score += 40 * confidence
        elif verdict == 'PHISHING':
            score += 35 * confidence
        elif verdict == 'SPAM':
            score += 10 * confidence
        
        # Sender risk
        if sender_analysis['risk_level'] == 'HIGH':
            score += 25
        elif sender_analysis['risk_level'] == 'MEDIUM':
            score += 15
        
        # URL risk
        if url_analysis['risk_level'] == 'HIGH':
            score += 20
        elif url_analysis['risk_level'] == 'MEDIUM':
            score += 10
        
        # BEC indicators
        if bec_analysis['payment_request_detected']:
            score += 10
        if bec_analysis['impersonation_detected']:
            score += 5
        if bec_analysis['urgency_detected']:
            score += 5
        if bec_analysis['secrecy_detected']:
            score += 5
        
        return min(100, score)
    
    def _generate_summary(
        self,
        sender_analysis: Dict,
        url_analysis: Dict,
        bec_analysis: Dict,
        threat_score: float
    ) -> str:
        """Generate human-readable intelligence summary."""
        findings = []
        
        if sender_analysis['is_freemail'] and sender_analysis['has_executive_title']:
            findings.append("CRITICAL: Executive title used with freemail provider")
        
        if sender_analysis['domain_spoofing']:
            findings.append(f"WARNING: Domain spoofing detected ({sender_analysis['spoofed_brand']})")
        
        if sender_analysis['reply_to_mismatch']:
            findings.append("SUSPICIOUS: Reply-to address differs from sender")
        
        if url_analysis['spoofed_domains'] > 0:
            findings.append("CRITICAL: Spoofed domain URLs detected")
        
        if url_analysis['suspicious_tlds'] > 0:
            findings.append("WARNING: Suspicious TLD in URLs")
        
        if bec_analysis['payment_request_detected']:
            findings.append("ALERT: Payment/transfer request detected")
        
        if bec_analysis['secrecy_detected']:
            findings.append("WARNING: Secrecy tactics detected")
        
        if not findings:
            return "No significant threat indicators detected."
        
        return " | ".join(findings)
