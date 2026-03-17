"""
Agent 1: Threat Classification Agent (Data-Driven AI Agent)
BEC-Enhanced Email Classification using Machine Learning

Student: Opoku | ID: w25035430 | MSc Cybersecurity Technology | Northumbria University
"""

import re
import numpy as np
from typing import Dict, List, Tuple
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import warnings
warnings.filterwarnings('ignore')


class ThreatClassificationAgent:
    """Data-Driven AI Agent for email threat classification."""
    
    def __init__(self):
        self.vectorizer = TfidfVectorizer(
            max_features=3000,
            ngram_range=(1, 3),
            min_df=2,
            max_df=0.95,
            stop_words='english'
        )
        
        self.classifier = RandomForestClassifier(
            n_estimators=200,
            max_depth=30,
            min_samples_split=3,
            class_weight='balanced',
            random_state=42,
            n_jobs=-1
        )
        
        self.is_trained = False
        self.classes = ['LEGITIMATE', 'SPAM', 'PHISHING', 'BEC']
        
        # BEC detection patterns
        self.bec_patterns = {
            'executive_terms': ['ceo', 'cfo', 'president', 'director', 'chairman', 'chief', 'executive', 'managing director'],
            'payment_terms': ['wire transfer', 'bank transfer', 'payment', 'invoice', 'account number', 'routing number', 'bank details'],
            'giftcard_terms': ['gift card', 'amazon card', 'itunes', 'google play', 'card codes', 'redemption code'],
            'urgency_terms': ['urgent', 'asap', 'immediately', 'right now', 'today', 'time sensitive', 'quickly'],
            'secrecy_terms': ['confidential', 'keep quiet', 'do not share', 'between us', 'private matter', 'do not tell'],
            'unavailability_terms': ['in a meeting', 'cannot call', 'traveling', 'unreachable', 'on a flight']
        }
    
    def _prepare_text(self, email: Dict) -> str:
        """Prepare email text for analysis."""
        subject = email.get('subject', '')
        body = email.get('body_text', email.get('body', ''))
        sender = email.get('sender', email.get('sender_email', ''))
        
        combined = f"{subject} {body} {sender}"
        combined = combined.lower()
        combined = re.sub(r'[^\w\s]', ' ', combined)
        combined = re.sub(r'\s+', ' ', combined).strip()
        
        return combined
    
    def _extract_bec_features(self, email: Dict) -> np.ndarray:
        """Extract BEC-specific features."""
        text = self._prepare_text(email).lower()
        subject = email.get('subject', '').lower()
        sender = email.get('sender_email', email.get('sender', '')).lower()
        
        features = []
        
        # Text statistics
        features.append(len(text))
        features.append(len(text.split()))
        
        # Executive terms
        exec_count = sum(1 for term in self.bec_patterns['executive_terms'] if term in text)
        features.append(exec_count)
        
        # Payment terms
        payment_count = sum(1 for term in self.bec_patterns['payment_terms'] if term in text)
        features.append(payment_count)
        
        # Gift card terms
        giftcard_count = sum(1 for term in self.bec_patterns['giftcard_terms'] if term in text)
        features.append(giftcard_count)
        
        # Urgency terms
        urgency_count = sum(1 for term in self.bec_patterns['urgency_terms'] if term in text)
        features.append(urgency_count)
        
        # Secrecy terms
        secrecy_count = sum(1 for term in self.bec_patterns['secrecy_terms'] if term in text)
        features.append(secrecy_count)
        
        # Unavailability terms
        unavail_count = sum(1 for term in self.bec_patterns['unavailability_terms'] if term in text)
        features.append(unavail_count)
        
        # Freemail check
        freemail_domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com']
        is_freemail = 1 if any(domain in sender for domain in freemail_domains) else 0
        features.append(is_freemail)
        
        # Money pattern
        has_money = 1 if re.search(r'\$[\d,]+|\d+\s*(?:dollars|usd)', text) else 0
        features.append(has_money)
        
        # Account number pattern
        has_account = 1 if re.search(r'account\s*(?:number|#|:)?\s*\d{6,}', text) else 0
        features.append(has_account)
        
        # URL count
        urls = email.get('urls', [])
        features.append(len(urls))
        
        # BEC composite scores
        ceo_fraud_score = exec_count + payment_count + urgency_count + secrecy_count + unavail_count
        features.append(ceo_fraud_score)
        
        giftcard_score = giftcard_count + urgency_count + secrecy_count
        features.append(giftcard_score)
        
        invoice_score = payment_count + has_account + has_money
        features.append(invoice_score)
        
        return np.array(features)
    
    def _detect_bec_subtype(self, email: Dict) -> Tuple[bool, str]:
        """Detect specific BEC attack subtype."""
        text = self._prepare_text(email).lower()
        
        scores = {
            'CEO_FRAUD': 0,
            'INVOICE_FRAUD': 0,
            'GIFT_CARD_SCAM': 0,
            'PAYROLL_DIVERSION': 0,
            'CRYPTO_PAYMENT_SCAM': 0
        }
        
        # CEO Fraud indicators
        if any(term in text for term in self.bec_patterns['executive_terms']):
            scores['CEO_FRAUD'] += 3
        if any(term in text for term in ['wire transfer', 'wire', 'transfer funds']):
            scores['CEO_FRAUD'] += 2
        if any(term in text for term in self.bec_patterns['secrecy_terms']):
            scores['CEO_FRAUD'] += 2
        if any(term in text for term in self.bec_patterns['unavailability_terms']):
            scores['CEO_FRAUD'] += 2
        
        # Gift Card Scam indicators
        if any(term in text for term in self.bec_patterns['giftcard_terms']):
            scores['GIFT_CARD_SCAM'] += 5
        if 'code' in text and 'send' in text:
            scores['GIFT_CARD_SCAM'] += 2
        
        # Invoice Fraud indicators
        if 'bank details' in text or 'bank account' in text:
            scores['INVOICE_FRAUD'] += 3
        if 'changed' in text or 'updated' in text or 'new account' in text:
            scores['INVOICE_FRAUD'] += 3
        if re.search(r'account\s*(?:number|#|:)?\s*\d{6,}', text):
            scores['INVOICE_FRAUD'] += 2
        
        # Payroll Diversion indicators
        if 'direct deposit' in text or 'payroll' in text or 'salary' in text:
            scores['PAYROLL_DIVERSION'] += 4
        if 'update' in text and ('bank' in text or 'account' in text):
            scores['PAYROLL_DIVERSION'] += 2
        
        # Crypto Payment Scam indicators
        crypto_terms = ['bitcoin', 'btc', 'ethereum', 'cryptocurrency', 'crypto', 'wallet address']
        if any(term in text for term in crypto_terms):
            scores['CRYPTO_PAYMENT_SCAM'] += 5
        
        max_score = max(scores.values())
        if max_score >= 4:
            subtype = max(scores, key=scores.get)
            return True, subtype
        
        return False, ''
    
    def train(self, training_data: List[Dict]):
        """Train the classification model."""
        print("[ThreatClassificationAgent] Initiating BEC-Enhanced training sequence...")
        
        texts = [self._prepare_text(d) for d in training_data]
        labels = [d['label'] for d in training_data]
        
        print(f"[ThreatClassificationAgent] Dataset size: {len(texts)} samples")
        
        # TF-IDF features
        print("[ThreatClassificationAgent] Creating TF-IDF vectors...")
        tfidf_features = self.vectorizer.fit_transform(texts)
        print(f"[ThreatClassificationAgent] Feature dimensions: {tfidf_features.shape}")
        
        # BEC features
        print(f"[ThreatClassificationAgent] BEC-specific features: {15} handcrafted features")
        bec_features = np.array([self._extract_bec_features(d) for d in training_data])
        
        # Combine features
        from scipy.sparse import hstack
        combined_features = hstack([tfidf_features, bec_features])
        
        # Train
        print("[ThreatClassificationAgent] Training BEC-Enhanced Random Forest classifier...")
        self.classifier.fit(combined_features, labels)
        
        self.is_trained = True
        print("[ThreatClassificationAgent] Training complete!")
        
        # Evaluate
        y_pred = self.classifier.predict(combined_features)
        accuracy = accuracy_score(labels, y_pred)
        print(f"[ThreatClassificationAgent] Overall Accuracy: {accuracy:.4f}")
        
        # Per-class metrics
        from sklearn.metrics import f1_score
        for cls in self.classes:
            cls_labels = [1 if l == cls else 0 for l in labels]
            cls_preds = [1 if p == cls else 0 for p in y_pred]
            f1 = f1_score(cls_labels, cls_preds) if sum(cls_labels) > 0 else 0
            print(f"[ThreatClassificationAgent] {cls} Detection F1: {f1:.4f}")
    
    def classify(self, email: Dict) -> Dict:
        """Classify an email."""
        if not self.is_trained:
            return {
                'verdict': 'UNKNOWN',
                'confidence': 0.0,
                'error': 'Model not trained'
            }
        
        # Prepare features
        text = self._prepare_text(email)
        tfidf_features = self.vectorizer.transform([text])
        bec_features = self._extract_bec_features(email).reshape(1, -1)
        
        from scipy.sparse import hstack
        combined_features = hstack([tfidf_features, bec_features])
        
        # Predict
        prediction = self.classifier.predict(combined_features)[0]
        probabilities = self.classifier.predict_proba(combined_features)[0]
        
        # Get confidence
        class_idx = list(self.classifier.classes_).index(prediction)
        confidence = probabilities[class_idx]
        
        # Check for BEC subtype
        is_bec, bec_subtype = self._detect_bec_subtype(email)
        
        # If high BEC indicators but classified differently, check
        if is_bec and prediction != 'BEC':
            bec_prob = probabilities[list(self.classifier.classes_).index('BEC')] if 'BEC' in self.classifier.classes_ else 0
            if bec_prob > 0.2:
                prediction = 'BEC'
                confidence = bec_prob
        
        # Build result
        result = {
            'verdict': prediction,
            'confidence': float(confidence),
            'is_bec': prediction == 'BEC' or is_bec,
            'bec_subtype': bec_subtype if (prediction == 'BEC' or is_bec) else '',
            'class_probabilities': {
                cls: float(probabilities[i]) 
                for i, cls in enumerate(self.classifier.classes_)
            },
            'risk_indicators': self._get_risk_indicators(email, prediction)
        }
        
        return result
    
    def _get_risk_indicators(self, email: Dict, verdict: str) -> List[str]:
        """Get human-readable risk indicators."""
        indicators = []
        text = self._prepare_text(email).lower()
        
        if any(term in text for term in self.bec_patterns['urgency_terms']):
            indicators.append("High urgency language detected")
        
        if any(term in text for term in self.bec_patterns['secrecy_terms']):
            indicators.append("Secrecy/confidentiality requests")
        
        if any(term in text for term in self.bec_patterns['executive_terms']):
            indicators.append("Executive impersonation indicators")
        
        if any(term in text for term in self.bec_patterns['payment_terms']):
            indicators.append("Payment/wire transfer requests")
        
        if any(term in text for term in self.bec_patterns['giftcard_terms']):
            indicators.append("Gift card purchase request")
        
        sender = email.get('sender_email', '').lower()
        if any(d in sender for d in ['gmail.com', 'yahoo.com', 'hotmail.com']):
            indicators.append("Freemail provider used")
        
        urls = email.get('urls', [])
        if urls:
            indicators.append(f"Contains {len(urls)} URL(s)")
            for url in urls:
                if not url.startswith('https://'):
                    indicators.append("Non-HTTPS URL detected")
                    break
        
        return indicators
