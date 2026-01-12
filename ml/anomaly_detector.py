#!/usr/bin/env python3
"""
ML-based Anomaly Detector for Web Server Access Logs
"""

import numpy as np
import pickle
import os
import re
from typing import Dict, List, Any
from datetime import datetime
import json
import logging

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.neighbors import LocalOutlierFactor
    from sklearn.svm import OneClassSVM
    from sklearn.covariance import EllipticEnvelope
    from sklearn.preprocessing import RobustScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

from ml.feature_extractor import LogFeatureExtractor

class MLAnomalyDetector:
    """Machine Learning based anomaly detector for web access logs."""
    
    def __init__(self, model_dir: str = "ml/models"):
        self.model_dir = model_dir
        self.feature_extractor = LogFeatureExtractor()
        self.scaler = None
        self.models = {}
        self.feature_names = []
        self.is_trained = False
        self.training_stats = {}
        self.anomaly_threshold = 0.1
        self.pattern_memory = {}  # Store patterns for learning
        
        # Ensure model directory exists
        os.makedirs(model_dir, exist_ok=True)
        
        if not SKLEARN_AVAILABLE:
            raise ImportError("scikit-learn is required for ML-based anomaly detection")
        
        self._initialize_models()
        self.load_models()
    
    def _initialize_models(self):
        """Initialize multiple anomaly detection models."""
        self.models = {
            'isolation_forest': IsolationForest(
                contamination=self.anomaly_threshold,
                random_state=42,
                n_estimators=100
            ),
            'local_outlier_factor': LocalOutlierFactor(
                contamination=self.anomaly_threshold,
                novelty=True
            ),
            'one_class_svm': OneClassSVM(
                nu=self.anomaly_threshold,
                kernel='rbf',
                gamma='scale'
            ),
            'elliptic_envelope': EllipticEnvelope(
                contamination=self.anomaly_threshold,
                random_state=42
            )
        }
        
        self.scaler = RobustScaler()
    
    def train(self, log_entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Train the anomaly detection models on normal traffic."""
        if not log_entries:
            raise ValueError("No log entries provided for training")
        
        # Extract features
        features = self.feature_extractor.extract_batch_features(log_entries)
        
        if features.size == 0:
            raise ValueError("No features extracted from log entries")
        
        # Scale features
        features_scaled = self.scaler.fit_transform(features)
        
        # Store feature names
        self.feature_names = self.feature_extractor.get_feature_names()
        
        # Train each model
        training_results = {}
        
        for model_name, model in self.models.items():
            try:
                model.fit(features_scaled)
                training_results[model_name] = {'status': 'success'}
            except Exception as e:
                training_results[model_name] = {'status': 'failed', 'error': str(e)}
        
        # Calculate training statistics
        self.training_stats = {
            'training_samples': len(log_entries),
            'feature_count': features.shape[1],
            'training_date': datetime.now().isoformat(),
            'feature_names': self.feature_names,
            'model_results': training_results
        }
        
        self.is_trained = True
        self.save_models()
        
        return self.training_stats
    
    def predict_anomalies(self, log_entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Predict anomalies in log entries using ensemble of models."""
        if not self.is_trained:
            raise ValueError("Models must be trained before prediction")
        
        if not log_entries:
            return []
        
        # Extract features
        features = self.feature_extractor.extract_batch_features(log_entries)
        
        if features.size == 0:
            return []
        
        # Scale features
        features_scaled = self.scaler.transform(features)
        
        # Get predictions from each model
        predictions = {}
        anomaly_scores = {}
        
        for model_name, model in self.models.items():
            try:
                if model_name == 'local_outlier_factor':
                    scores = model.decision_function(features_scaled)
                    preds = model.predict(features_scaled)
                    anomaly_scores[model_name] = -scores
                    predictions[model_name] = (preds == -1).astype(int)
                else:
                    scores = model.decision_function(features_scaled)
                    preds = model.predict(features_scaled)
                    anomaly_scores[model_name] = -scores
                    predictions[model_name] = (preds == -1).astype(int)
                    
            except Exception as e:
                predictions[model_name] = np.zeros(len(log_entries))
                anomaly_scores[model_name] = np.zeros(len(log_entries))
        
        # Ensemble predictions
        results = []
        for i, log_entry in enumerate(log_entries):
            ensemble_score = np.mean([scores[i] for scores in anomaly_scores.values()])
            ensemble_prediction = np.mean([preds[i] for preds in predictions.values()])
            is_anomaly = ensemble_prediction > 0.5
            
            model_scores = {name: float(scores[i]) for name, scores in anomaly_scores.items()}
            
            result = {
                'log_entry': log_entry,
                'is_anomaly': bool(is_anomaly),
                'anomaly_score': float(ensemble_score),
                'confidence': float(abs(ensemble_prediction - 0.5) * 2),
                'model_scores': model_scores
            }
            
            results.append(result)
        
        return results
    
    def save_models(self):
        """Save trained models to disk."""
        if not self.is_trained:
            return
        
        model_data = {
            'models': self.models,
            'scaler': self.scaler,
            'feature_names': self.feature_names,
            'training_stats': self.training_stats,
            'is_trained': self.is_trained,
            'anomaly_threshold': self.anomaly_threshold
        }
        
        model_path = os.path.join(self.model_dir, 'anomaly_models.pkl')
        
        try:
            with open(model_path, 'wb') as f:
                pickle.dump(model_data, f)
        except Exception as e:
            logging.error(f"Failed to save models: {e}")
    
    def load_models(self) -> bool:
        """Load trained models from disk."""
        model_path = os.path.join(self.model_dir, 'anomaly_models.pkl')
        
        if not os.path.exists(model_path):
            return False
        
        try:
            with open(model_path, 'rb') as f:
                model_data = pickle.load(f)
            
            self.models = model_data['models']
            self.scaler = model_data['scaler']
            self.feature_names = model_data['feature_names']
            self.training_stats = model_data['training_stats']
            self.is_trained = model_data['is_trained']
            self.anomaly_threshold = model_data.get('anomaly_threshold', 0.1)
            
            return True
            
        except Exception as e:
            return False
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about trained models."""
        return {
            'is_trained': self.is_trained,
            'training_stats': self.training_stats,
            'feature_count': len(self.feature_names),
            'feature_names': self.feature_names,
            'model_names': list(self.models.keys()),
            'anomaly_threshold': self.anomaly_threshold
        }
    
    def learn_from_feedback(self, log_entry: Dict[str, Any], is_attack: bool, attack_type: str = None):
        """Learn from user feedback to improve detection."""
        # Extract features for this entry
        features = self.feature_extractor.extract_features(log_entry)
        
        # Create pattern signature
        pattern_key = self._create_pattern_signature(log_entry)
        
        # Store in pattern memory
        if pattern_key not in self.pattern_memory:
            self.pattern_memory[pattern_key] = {
                'count': 0,
                'attack_count': 0,
                'features': features,
                'examples': []
            }
        
        self.pattern_memory[pattern_key]['count'] += 1
        if is_attack:
            self.pattern_memory[pattern_key]['attack_count'] += 1
        
        # Store example (limit to 5 examples per pattern)
        if len(self.pattern_memory[pattern_key]['examples']) < 5:
            self.pattern_memory[pattern_key]['examples'].append({
                'log_entry': log_entry,
                'is_attack': is_attack,
                'attack_type': attack_type,
                'timestamp': datetime.now().isoformat()
            })
    
    def detect_similar_patterns(self, log_entry: Dict[str, Any], threshold: float = 0.8) -> List[Dict[str, Any]]:
        """Detect if current log entry matches previously learned suspicious patterns."""
        if not self.pattern_memory:
            return []
        
        current_pattern = self._create_pattern_signature(log_entry)
        current_features = self.feature_extractor.extract_features(log_entry)
        
        similar_patterns = []
        
        for pattern_key, pattern_data in self.pattern_memory.items():
            # Calculate similarity
            similarity = self._calculate_pattern_similarity(current_features, pattern_data['features'])
            
            if similarity >= threshold:
                # Check if this pattern has been marked as suspicious
                attack_ratio = pattern_data['attack_count'] / pattern_data['count']
                
                if attack_ratio > 0.5:  # More than 50% of similar patterns were attacks
                    similar_patterns.append({
                        'pattern_key': pattern_key,
                        'similarity': similarity,
                        'attack_ratio': attack_ratio,
                        'total_count': pattern_data['count'],
                        'attack_count': pattern_data['attack_count'],
                        'examples': pattern_data['examples']
                    })
        
        return sorted(similar_patterns, key=lambda x: x['similarity'], reverse=True)
    
    def _create_pattern_signature(self, log_entry: Dict[str, Any]) -> str:
        """Create a signature for pattern matching."""
        # Use URL structure, method, and key characteristics
        url = log_entry.get('url', '')
        method = log_entry.get('method', '')
        user_agent = log_entry.get('user_agent', '')
        
        # Normalize URL for pattern matching
        normalized_url = self._normalize_url_for_pattern(url)
        
        # Create signature
        signature_parts = [
            method,
            normalized_url,
            self._categorize_user_agent(user_agent)
        ]
        
        signature = '|'.join(signature_parts)
        return signature
    
    def _normalize_url_for_pattern(self, url: str) -> str:
        """Normalize URL for pattern matching."""
        # Replace numbers with placeholder
        normalized = re.sub(r'\d+', 'NUM', url)
        
        # Replace common variable patterns
        normalized = re.sub(r'[a-f0-9]{32}', 'HASH32', normalized)  # MD5 hashes
        normalized = re.sub(r'[a-f0-9]{40}', 'HASH40', normalized)  # SHA1 hashes
        normalized = re.sub(r'[A-Za-z0-9+/]{20,}={0,2}', 'BASE64', normalized)  # Base64
        
        return normalized
    
    def _categorize_user_agent(self, user_agent: str) -> str:
        """Categorize user agent for pattern matching."""
        ua_lower = user_agent.lower()
        
        if any(browser in ua_lower for browser in ['mozilla', 'chrome', 'safari', 'firefox']):
            return 'BROWSER'
        elif any(bot in ua_lower for bot in ['bot', 'crawler', 'spider']):
            return 'BOT'
        elif any(tool in ua_lower for tool in ['curl', 'wget', 'python', 'java']):
            return 'TOOL'
        elif any(scanner in ua_lower for scanner in ['nmap', 'sqlmap', 'nikto', 'burp']):
            return 'SCANNER'
        else:
            return 'OTHER'
    
    def _calculate_pattern_similarity(self, features1: Dict[str, float], features2: Dict[str, float]) -> float:
        """Calculate similarity between two feature sets."""
        # Get common features
        common_features = set(features1.keys()) & set(features2.keys())
        
        if not common_features:
            return 0.0
        
        # Calculate cosine similarity
        vec1 = np.array([features1[f] for f in common_features])
        vec2 = np.array([features2[f] for f in common_features])
        
        # Normalize vectors
        norm1 = np.linalg.norm(vec1)
        norm2 = np.linalg.norm(vec2)
        
        if norm1 == 0 or norm2 == 0:
            return 0.0
        
        similarity = np.dot(vec1, vec2) / (norm1 * norm2)
        return max(0.0, similarity)  # Ensure non-negative