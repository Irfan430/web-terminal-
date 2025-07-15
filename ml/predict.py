"""
AI Risk Prediction Module
Uses machine learning to predict cybersecurity risks based on scan data
"""

import pickle
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import json
import time
import socket
import requests
from typing import Dict, List, Optional, Tuple
from pathlib import Path
from shared.logger import get_logger
from shared.utils import save_scan_results

logger = get_logger(__name__)

class RiskPredictor:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.feature_names = [
            'open_ports_count', 'critical_services', 'outdated_services',
            'weak_credentials', 'missing_patches', 'network_exposure',
            'ssl_issues', 'domain_age', 'reputation_score', 'geo_risk'
        ]
        self.reports_dir = Path("reports")
        self.models_dir = Path("ml")
        self.models_dir.mkdir(exist_ok=True)
        
        # Load or create model
        self.load_or_create_model()
        
    def load_or_create_model(self):
        """Load existing model or create a new one"""
        model_path = self.models_dir / "trained_model.pkl"
        scaler_path = self.models_dir / "scaler.pkl"
        
        try:
            if model_path.exists() and scaler_path.exists():
                with open(model_path, 'rb') as f:
                    self.model = pickle.load(f)
                with open(scaler_path, 'rb') as f:
                    self.scaler = pickle.load(f)
                logger.info("Loaded existing ML model")
            else:
                self.create_and_train_model()
                logger.info("Created and trained new ML model")
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            self.create_and_train_model()
            
    def generate_training_data(self, n_samples: int = 1000) -> Tuple[np.ndarray, np.ndarray]:
        """Generate synthetic training data for the model"""
        logger.info(f"Generating {n_samples} training samples")
        
        np.random.seed(42)  # For reproducible results
        
        X = []
        y = []
        
        for _ in range(n_samples):
            # Generate realistic feature values
            features = {
                'open_ports_count': np.random.poisson(8),  # Average 8 open ports
                'critical_services': np.random.binomial(5, 0.3),  # 0-5 critical services
                'outdated_services': np.random.binomial(10, 0.2),  # 0-10 outdated services
                'weak_credentials': np.random.binomial(3, 0.15),  # 0-3 weak credentials
                'missing_patches': np.random.poisson(3),  # Average 3 missing patches
                'network_exposure': np.random.uniform(0, 10),  # 0-10 exposure score
                'ssl_issues': np.random.binomial(3, 0.25),  # 0-3 SSL issues
                'domain_age': np.random.exponential(5),  # Domain age in years
                'reputation_score': np.random.uniform(0, 10),  # 0-10 reputation
                'geo_risk': np.random.uniform(0, 10)  # 0-10 geographical risk
            }
            
            # Calculate risk score based on features (ground truth)
            risk_score = (
                features['open_ports_count'] * 0.3 +
                features['critical_services'] * 0.8 +
                features['outdated_services'] * 0.5 +
                features['weak_credentials'] * 1.2 +
                features['missing_patches'] * 0.6 +
                features['network_exposure'] * 0.4 +
                features['ssl_issues'] * 0.7 +
                max(0, 5 - features['domain_age']) * 0.3 +
                (10 - features['reputation_score']) * 0.3 +
                features['geo_risk'] * 0.2
            )
            
            # Normalize to 0-10 scale and add some noise
            risk_score = min(10, max(0, risk_score + np.random.normal(0, 0.5)))
            
            X.append(list(features.values()))
            y.append(risk_score)
            
        return np.array(X), np.array(y)
        
    def create_and_train_model(self):
        """Create and train a new ML model"""
        logger.info("Creating and training new ML model")
        
        # Generate training data
        X, y = self.generate_training_data(1000)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42
        )
        
        # Scale features
        self.scaler = StandardScaler()
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train model
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            n_jobs=-1
        )
        
        # Convert regression to classification for RandomForest
        y_train_class = np.digitize(y_train, bins=np.linspace(0, 10, 11)) - 1
        y_test_class = np.digitize(y_test, bins=np.linspace(0, 10, 11)) - 1
        
        self.model.fit(X_train_scaled, y_train_class)
        
        # Evaluate model
        train_score = self.model.score(X_train_scaled, y_train_class)
        test_score = self.model.score(X_test_scaled, y_test_class)
        
        logger.info(f"Model training completed - Train accuracy: {train_score:.3f}, Test accuracy: {test_score:.3f}")
        
        # Save model and scaler
        self.save_model()
        
    def save_model(self):
        """Save the trained model and scaler"""
        try:
            model_path = self.models_dir / "trained_model.pkl"
            scaler_path = self.models_dir / "scaler.pkl"
            
            with open(model_path, 'wb') as f:
                pickle.dump(self.model, f)
            with open(scaler_path, 'wb') as f:
                pickle.dump(self.scaler, f)
                
            logger.info("Model and scaler saved successfully")
        except Exception as e:
            logger.error(f"Error saving model: {e}")
            
    def extract_features_from_target(self, target: str) -> Dict[str, float]:
        """Extract features from target for prediction"""
        logger.info(f"Extracting features for {target}")
        
        features = {}
        
        try:
            # Domain/IP analysis
            features['domain_age'] = self.estimate_domain_age(target)
            features['reputation_score'] = self.check_reputation(target)
            features['geo_risk'] = self.assess_geographical_risk(target)
            
            # Network analysis
            features['open_ports_count'] = self.simulate_port_scan(target)
            features['critical_services'] = self.identify_critical_services(target)
            features['network_exposure'] = self.assess_network_exposure(target)
            
            # Security analysis
            features['ssl_issues'] = self.check_ssl_configuration(target)
            features['outdated_services'] = self.detect_outdated_services(target)
            features['weak_credentials'] = self.assess_credential_strength(target)
            features['missing_patches'] = self.estimate_missing_patches(target)
            
        except Exception as e:
            logger.error(f"Error extracting features: {e}")
            # Use default values if extraction fails
            features = {name: 0.0 for name in self.feature_names}
            
        return features
        
    def estimate_domain_age(self, target: str) -> float:
        """Estimate domain age (simulation)"""
        # Simulate domain age estimation
        # In real implementation, would use WHOIS data
        import hashlib
        hash_value = int(hashlib.md5(target.encode()).hexdigest(), 16)
        return (hash_value % 10) + np.random.uniform(0, 5)
        
    def check_reputation(self, target: str) -> float:
        """Check domain/IP reputation (simulation)"""
        # Simulate reputation check
        # In real implementation, would use threat intelligence feeds
        import hashlib
        hash_value = int(hashlib.md5(f"rep_{target}".encode()).hexdigest(), 16)
        base_score = (hash_value % 8) + 2  # 2-10 range
        return min(10, base_score + np.random.uniform(-1, 1))
        
    def assess_geographical_risk(self, target: str) -> float:
        """Assess geographical risk based on IP location (simulation)"""
        # Simulate geo-risk assessment
        try:
            # Try to resolve IP
            ip = socket.gethostbyname(target)
            # Simulate risk based on IP range
            ip_parts = ip.split('.')
            risk_factor = (int(ip_parts[0]) + int(ip_parts[1])) % 10
            return risk_factor + np.random.uniform(0, 2)
        except:
            return np.random.uniform(3, 7)  # Default moderate risk
            
    def simulate_port_scan(self, target: str) -> float:
        """Simulate port scan results"""
        # Simulate realistic port counts
        common_ports = [22, 25, 53, 80, 110, 143, 443, 993, 995]
        open_count = 0
        
        for port in common_ports:
            if np.random.random() < 0.4:  # 40% chance port is open
                open_count += 1
                
        # Add some random additional ports
        open_count += np.random.poisson(2)
        
        return float(open_count)
        
    def identify_critical_services(self, target: str) -> float:
        """Identify critical services (simulation)"""
        critical_services = ['ssh', 'telnet', 'ftp', 'database', 'admin_panel']
        count = 0
        
        for service in critical_services:
            if np.random.random() < 0.2:  # 20% chance service exists
                count += 1
                
        return float(count)
        
    def assess_network_exposure(self, target: str) -> float:
        """Assess network exposure level"""
        # Simulate network exposure assessment
        exposure_factors = [
            np.random.uniform(0, 3),  # DMZ exposure
            np.random.uniform(0, 2),  # Public cloud exposure  
            np.random.uniform(0, 2),  # CDN exposure
            np.random.uniform(0, 2),  # DNS exposure
            np.random.uniform(0, 1)   # Other factors
        ]
        
        return sum(exposure_factors)
        
    def check_ssl_configuration(self, target: str) -> float:
        """Check SSL/TLS configuration issues (simulation)"""
        ssl_issues = 0
        
        # Simulate various SSL issues
        if np.random.random() < 0.3:  # Weak cipher suites
            ssl_issues += 1
        if np.random.random() < 0.2:  # Expired certificate
            ssl_issues += 1
        if np.random.random() < 0.15:  # Self-signed certificate
            ssl_issues += 1
        if np.random.random() < 0.1:  # Protocol vulnerabilities
            ssl_issues += 1
            
        return float(ssl_issues)
        
    def detect_outdated_services(self, target: str) -> float:
        """Detect outdated software versions (simulation)"""
        services = ['apache', 'nginx', 'mysql', 'ssh', 'php', 'wordpress']
        outdated_count = 0
        
        for service in services:
            if np.random.random() < 0.25:  # 25% chance service is outdated
                outdated_count += 1
                
        return float(outdated_count)
        
    def assess_credential_strength(self, target: str) -> float:
        """Assess credential strength (simulation)"""
        # Simulate findings from brute force results
        weak_creds = 0
        
        if np.random.random() < 0.1:  # Default passwords
            weak_creds += 1
        if np.random.random() < 0.05:  # Empty passwords
            weak_creds += 1
        if np.random.random() < 0.08:  # Common passwords
            weak_creds += 1
            
        return float(weak_creds)
        
    def estimate_missing_patches(self, target: str) -> float:
        """Estimate missing security patches (simulation)"""
        # Simulate patch assessment
        patch_categories = ['os', 'web_server', 'database', 'applications']
        missing_patches = 0
        
        for category in patch_categories:
            missing_patches += np.random.poisson(1)  # Average 1 missing patch per category
            
        return float(missing_patches)
        
    def predict_risk(self, target: str) -> float:
        """
        Predict cybersecurity risk for a target
        
        Args:
            target: Domain or IP address to analyze
            
        Returns:
            Risk score from 0-10 (10 being highest risk)
        """
        logger.info(f"Predicting risk for {target}")
        
        try:
            # Extract features
            features = self.extract_features_from_target(target)
            
            # Prepare features for prediction
            feature_vector = np.array([[features[name] for name in self.feature_names]])
            
            # Scale features
            if self.scaler:
                feature_vector_scaled = self.scaler.transform(feature_vector)
            else:
                feature_vector_scaled = feature_vector
                
            # Make prediction
            if self.model:
                prediction_class = self.model.predict(feature_vector_scaled)[0]
                # Convert class back to risk score
                risk_score = float(prediction_class)
                
                # Add some probability-based adjustment
                probabilities = self.model.predict_proba(feature_vector_scaled)[0]
                confidence = max(probabilities)
                
                # Adjust score based on confidence
                if confidence < 0.6:  # Low confidence
                    risk_score += np.random.uniform(-1, 1)
                    
            else:
                # Fallback: calculate risk based on features
                risk_score = self.calculate_risk_heuristic(features)
                
            # Ensure score is in valid range
            risk_score = max(0, min(10, risk_score))
            
            # Create detailed results
            results = {
                "target": target,
                "risk_score": round(risk_score, 2),
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "scan_type": "ai_risk_prediction",
                "features": features,
                "risk_factors": self.analyze_risk_factors(features),
                "recommendations": self.generate_recommendations(features, risk_score),
                "confidence": confidence if 'confidence' in locals() else 0.8
            }
            
            # Save results
            save_scan_results(results, "ai_prediction")
            
            logger.info(f"Risk prediction completed for {target}: {risk_score:.2f}/10")
            return risk_score
            
        except Exception as e:
            logger.error(f"Risk prediction failed: {e}")
            return 5.0  # Default medium risk
            
    def calculate_risk_heuristic(self, features: Dict[str, float]) -> float:
        """Calculate risk using simple heuristic (fallback method)"""
        weights = {
            'open_ports_count': 0.3,
            'critical_services': 0.8,
            'outdated_services': 0.5,
            'weak_credentials': 1.2,
            'missing_patches': 0.6,
            'network_exposure': 0.4,
            'ssl_issues': 0.7,
            'domain_age': -0.3,  # Negative weight (older domains are less risky)
            'reputation_score': -0.3,  # Negative weight (higher reputation = lower risk)
            'geo_risk': 0.2
        }
        
        risk_score = 0
        for feature, value in features.items():
            if feature in weights:
                if feature == 'domain_age':
                    risk_score += weights[feature] * max(0, 5 - value)
                elif feature == 'reputation_score':
                    risk_score += weights[feature] * (10 - value)
                else:
                    risk_score += weights[feature] * value
                    
        return max(0, min(10, risk_score))
        
    def analyze_risk_factors(self, features: Dict[str, float]) -> Dict[str, str]:
        """Analyze individual risk factors"""
        risk_factors = {}
        
        if features['open_ports_count'] > 15:
            risk_factors['network'] = "HIGH - Many open ports detected"
        elif features['open_ports_count'] > 8:
            risk_factors['network'] = "MEDIUM - Moderate number of open ports"
        else:
            risk_factors['network'] = "LOW - Few open ports"
            
        if features['weak_credentials'] > 0:
            risk_factors['authentication'] = "HIGH - Weak credentials detected"
        else:
            risk_factors['authentication'] = "LOW - No weak credentials found"
            
        if features['outdated_services'] > 5:
            risk_factors['patch_management'] = "HIGH - Many outdated services"
        elif features['outdated_services'] > 2:
            risk_factors['patch_management'] = "MEDIUM - Some outdated services"
        else:
            risk_factors['patch_management'] = "LOW - Services appear up to date"
            
        if features['ssl_issues'] > 2:
            risk_factors['encryption'] = "HIGH - Multiple SSL/TLS issues"
        elif features['ssl_issues'] > 0:
            risk_factors['encryption'] = "MEDIUM - Some SSL/TLS issues"
        else:
            risk_factors['encryption'] = "LOW - SSL/TLS appears secure"
            
        return risk_factors
        
    def generate_recommendations(self, features: Dict[str, float], risk_score: float) -> List[str]:
        """Generate security recommendations based on risk analysis"""
        recommendations = []
        
        if risk_score >= 8:
            recommendations.append("🚨 CRITICAL: Immediate security review required")
        elif risk_score >= 6:
            recommendations.append("⚠️  HIGH RISK: Schedule security assessment soon")
        elif risk_score >= 4:
            recommendations.append("💡 MEDIUM RISK: Consider security improvements")
        else:
            recommendations.append("✅ LOW RISK: Maintain current security posture")
            
        # Specific recommendations based on features
        if features['open_ports_count'] > 10:
            recommendations.append("🔒 Close unnecessary open ports")
            
        if features['weak_credentials'] > 0:
            recommendations.append("🔐 Implement strong password policies and MFA")
            
        if features['outdated_services'] > 3:
            recommendations.append("🔄 Update outdated software and services")
            
        if features['ssl_issues'] > 0:
            recommendations.append("🛡️  Fix SSL/TLS configuration issues")
            
        if features['missing_patches'] > 5:
            recommendations.append("🩹 Apply security patches promptly")
            
        if features['network_exposure'] > 7:
            recommendations.append("🌐 Review network exposure and segmentation")
            
        # General recommendations
        recommendations.extend([
            "📊 Regular security monitoring and logging",
            "🎯 Conduct periodic penetration testing",
            "📚 Security awareness training for staff",
            "📋 Maintain incident response procedures"
        ])
        
        return recommendations
        
    def batch_predict(self, targets: List[str]) -> Dict[str, float]:
        """Predict risk for multiple targets"""
        logger.info(f"Batch predicting risk for {len(targets)} targets")
        
        results = {}
        for target in targets:
            try:
                risk_score = self.predict_risk(target)
                results[target] = risk_score
                time.sleep(0.1)  # Small delay between predictions
            except Exception as e:
                logger.error(f"Failed to predict risk for {target}: {e}")
                results[target] = 5.0  # Default medium risk
                
        return results
        
    def get_model_info(self) -> Dict:
        """Get information about the ML model"""
        info = {
            "model_type": "Random Forest Classifier",
            "features": self.feature_names,
            "model_loaded": self.model is not None,
            "scaler_loaded": self.scaler is not None,
            "last_updated": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        
        if self.model:
            info["n_estimators"] = getattr(self.model, 'n_estimators', 'Unknown')
            info["max_depth"] = getattr(self.model, 'max_depth', 'Unknown')
            
        return info