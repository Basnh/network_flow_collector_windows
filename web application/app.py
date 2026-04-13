#!/usr/bin/env python3
"""
Network Security Management System
Collects data from agents and detects trojans/malware
"""

from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from datetime import datetime, timedelta
from pytz import timezone
import json
import sqlite3
import threading
import time
import os
import hashlib
import socket
import subprocess
import uuid
from collections import defaultdict
import logging
import pickle
import pandas as pd
import numpy as np

# Timezone settings
UTC_PLUS_7 = timezone('Asia/Bangkok')  # UTC+7

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:123456@localhost/network_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['WTF_CSRF_TIME_LIMIT'] = None  # No limit on CSRF token age

db = SQLAlchemy(app)
csrf = CSRFProtect(app)

# Configure logging
logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Disable Werkzeug logger to remove HTTP request logs
logging.getLogger('werkzeug').setLevel(logging.ERROR)

# In-memory request/response store for process collection between server and agent
PROCESS_REQUESTS = {}
PROCESS_RESULTS = {}
PROCESS_LOCK = threading.Lock()
FILE_REQUESTS = {}
FILE_RESULTS = {}
FILE_LOCK = threading.Lock()


# Utility function to get current time in UTC+7
def get_utc7_now():
    """Get current datetime in UTC+7 timezone"""
    from datetime import datetime
    return datetime.now(UTC_PLUS_7).replace(tzinfo=None)

# Convert UTC datetime to UTC+7
def utc_to_utc7(dt):
    """Convert UTC datetime to UTC+7"""
    if dt is None:
        return None
    if dt.tzinfo is None:
        # Assume it's UTC if no timezone info
        from pytz import UTC
        dt = UTC.localize(dt)
    return dt.astimezone(UTC_PLUS_7).replace(tzinfo=None)

# Template context processor to make utility functions available in templates
@app.context_processor
def inject_datetime():
    return {
        'datetime': datetime,
        'get_utc7_now': get_utc7_now,
        'utc_to_utc7': utc_to_utc7,
        'min': min,
        'max': max,
        'len': len,
        'abs': abs,
        'round': round,
        'int': int,
        'str': str
    }

# Jinja2 filter for formatting datetime in UTC+7
@app.template_filter('utc7_format')
def utc7_format(dt, fmt='%H:%M:%S'):
    """Format UTC datetime as UTC+7"""
    if dt is None:
        return ''
    converted_dt = utc_to_utc7(dt)
    return converted_dt.strftime(fmt)

def is_icmp_echo_traffic(protocol, payload_content='', src_port=0, dst_port=0):
    """Return True for ICMP Echo Request/Reply traffic that should be ignored by auto-alert."""
    protocol_str = str(protocol or '').strip().upper()
    if protocol_str not in {'ICMP', 'ICMPV4', 'ICMPV6', '1'}:
        return False

    # Most collectors store ICMP flow with src/dst port = 0.
    # Treat this as echo-like ICMP for alert suppression.
    try:
        if int(src_port or 0) == 0 and int(dst_port or 0) == 0:
            return True
    except Exception:
        pass

    payload_str = str(payload_content or '').upper()
    echo_markers = [
        'ECHO REQUEST',
        'ECHO REPLY',
        'ICMP TYPE 8',
        'ICMP TYPE 0',
        'ICMPV6 TYPE 128',
        'ICMPV6 TYPE 129',
    ]
    return any(marker in payload_str for marker in echo_markers)

# ==================== DATABASE MODELS ====================

class Agent(db.Model):
    """Agent devices running network collectors"""
    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.String(100), unique=True, nullable=False)
    hostname = db.Column(db.String(200), nullable=False)
    ip_address = db.Column(db.String(50), nullable=False)
    os_info = db.Column(db.Text)
    status = db.Column(db.String(20), default='active')  # active, disconnected, isolated
    last_seen = db.Column(db.DateTime, default=get_utc7_now)
    threat_level = db.Column(db.String(20), default='low')  # low, medium, high, critical
    created_at = db.Column(db.DateTime, default=get_utc7_now)
    isolated_until = db.Column(db.DateTime, nullable=True) # For timed isolation
    pending_command = db.Column(db.Text, nullable=True)  # JSON string of pending network isolation command
    network_adapter_name = db.Column(db.String(100), nullable=True)  # Name of network adapter to isolate
    
    @property
    def is_online(self):
        """Check if agent is online (last seen within 2 minutes)"""
        if self.last_seen:
            # last_seen is stored as naive UTC+7, so we need naive UTC+7 now
            return (get_utc7_now() - self.last_seen).total_seconds() < 120
        return False

    # Relationships
    flows = db.relationship('NetworkFlow', backref='agent', lazy=True, cascade='all, delete-orphan')
    alerts = db.relationship('SecurityAlert', backref='agent', lazy=True, cascade='all, delete-orphan')

class NetworkFlow(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.String(100), db.ForeignKey('agent.agent_id'), nullable=False)
    flow_id = db.Column(db.String(200), nullable=False)
    src_ip = db.Column(db.String(50), nullable=False)
    dst_ip = db.Column(db.String(50), nullable=False)
    src_port = db.Column(db.Integer)
    dst_port = db.Column(db.Integer)
    protocol = db.Column(db.String(10))
    payload_content = db.Column(db.Text) 
    threat_score = db.Column(db.Float, default=0.0)
    is_malicious = db.Column(db.Boolean, default=False)
    classification = db.Column(db.String(20), default='Benign') 
    timestamp = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=get_utc7_now)

class SecurityAlert(db.Model):
    """Security alerts for detected threats"""
    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.String(100), db.ForeignKey('agent.agent_id'), nullable=False)
    alert_type = db.Column(db.String(50), nullable=False)  # trojan, malware, suspicious_traffic
    severity = db.Column(db.String(20), nullable=False)  # low, medium, high, critical
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    flow_id = db.Column(db.String(200))
    payload_signature = db.Column(db.Text)
    is_resolved = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=get_utc7_now)

class IsolationAction(db.Model):
    """Network isolation actions"""
    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.String(100), nullable=False)
    action_type = db.Column(db.String(50), nullable=False)  # isolate, restore
    reason = db.Column(db.Text)
    executed_at = db.Column(db.DateTime, default=get_utc7_now)
    success = db.Column(db.Boolean, default=False)

# ==================== THREAT DETECTION ENGINE ====================

class ThreatDetector:
    """AI-powered threat detection system using best_model.pkl"""
    
    # List of 79 features collected; only first 68 used by the model
    # Features 69-79: Act/Idle statistics (for extended analysis)
    FEATURE_NAMES = [
        'Source Port', 'Destination Port', 'Protocol',
        'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
        'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
        'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
        'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std',
        'Flow Bytes/s', 'Flow Packets/s',
        'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
        'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
        'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
        'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags',
        'Fwd Header Length', 'Bwd Header Length',
        'Fwd Packets/s', 'Bwd Packets/s',
        'Min Packet Length', 'Max Packet Length', 'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance',
        'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count',
        'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count',
        'Down/Up Ratio', 'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
        'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate',
        'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate',
        'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes',
        'Init_Win_bytes_forward', 'Init_Win_bytes_backward',
        'act_data_pkt_fwd', 'min_seg_size_forward',
        'Active Mean', 'Active Std', 'Active Max', 'Active Min',
        'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
    ]
    
    def __init__(self, default_model='best_model.pkl'):
        self.model_filename = default_model
        self.model = None
        self.scaler = None
        self.label_encoder = None
        self.is_trained = False
        self.model_path = None
        self.scaler_path = None
        self.label_encoder_path = None
        self.processed_data_path = None
        self.last_error = ''
        self.prediction_count = 0
        self.scaler_used_count = 0
        self.encoder_used_count = 0
        self.last_prediction_label = None
        self.last_decoded_label = None
        self.last_threat_score = 0.0
        self.load_model()

    def _build_candidate_paths(self, file_name, env_var_name=None):
        app_dir = os.path.dirname(os.path.abspath(__file__))
        project_dir = os.path.dirname(app_dir)
        model_dir = os.path.join(project_dir, 'model') # Point to the new 'model' folder
        env_path = os.environ.get(env_var_name, '').strip() if env_var_name else ''
        candidates = [
            env_path,
            os.path.join(model_dir, file_name), # Prioritize 'model' folder
            os.path.join(app_dir, file_name),
            os.path.join(project_dir, file_name),
            os.path.join(os.getcwd(), file_name)
        ]
        return [p for p in candidates if p]

    def _find_existing_path(self, file_name, env_var_name=None):
        candidates = self._build_candidate_paths(file_name, env_var_name)
        found = next((p for p in candidates if os.path.exists(p)), None)
        return found, candidates
        
    def change_model(self, new_model_filename):
        """Switch to a new model dynamically"""
        self.model_filename = new_model_filename
        return self.load_model()

    def load_model(self):
        """Load model and optional preprocessing artifacts from PKL files."""
        try:
            model_path, candidate_paths = self._find_existing_path(self.model_filename, 'THREAT_MODEL_PATH')
            if not model_path:
                logger.error(f"Model file {self.model_filename} not found. Checked paths: %s", candidate_paths)
                self.model_path = None
                self.is_trained = False
                self.model = None
                self.last_error = f"{self.model_filename} not found"
                return False

            with open(model_path, 'rb') as f:
                try:
                    self.model = pickle.load(f)
                except Exception as e:
                    import joblib
                    self.model = joblib.load(model_path)

            self.model_path = model_path
            self.is_trained = True
            logger.warning(f" Đã tải thành công model từ {model_path}")

            # Optional scaler for feature preprocessing
            scaler_path, scaler_candidates = self._find_existing_path('scaler.pkl', 'THREAT_SCALER_PATH')
            if scaler_path:
                try:
                    import joblib
                    self.scaler = joblib.load(scaler_path)
                    self.scaler_path = scaler_path
                    logger.warning(f" Đã tải thành công scaler từ {scaler_path}")
                except Exception as scaler_error:
                    self.scaler = None
                    self.scaler_path = None
                    logger.error(f" Không thể tải scaler.pkl: {scaler_error}")
            else:
                self.scaler = None
                self.scaler_path = None
                logger.warning("scaler.pkl not found. Checked paths: %s", scaler_candidates)

            # Optional label encoder for class decoding
            encoder_path, encoder_candidates = self._find_existing_path('mahoa_nhan.pkl', 'THREAT_LABEL_ENCODER_PATH')
            if encoder_path:
                try:
                    import joblib
                    self.label_encoder = joblib.load(encoder_path)
                    self.label_encoder_path = encoder_path
                    logger.warning(f" Đã tải thành công label encoder từ {encoder_path}")
                except Exception as encoder_error:
                    self.label_encoder = None
                    self.label_encoder_path = None
                    logger.error(f" Không thể tải mahoa_nhan.pkl: {encoder_error}")
            else:
                self.label_encoder = None
                self.label_encoder_path = None
                logger.warning("mahoa_nhan.pkl not found. Checked paths: %s", encoder_candidates)

            # Optional processed_data.pkl path for traceability/consistency checks
            processed_path, _ = self._find_existing_path('processed_data.pkl', 'THREAT_PROCESSED_DATA_PATH')
            self.processed_data_path = processed_path

            self.last_error = ''
            return True
            
        except Exception as e:
            logger.error(f" Không thể tải   model: {e}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            self.model_path = None
            self.scaler_path = None
            self.label_encoder_path = None
            self.processed_data_path = None
            self.model = None
            self.scaler = None
            self.label_encoder = None
            self.last_error = str(e)
            self.is_trained = False
            return False

    def get_pipeline_status(self):
        """Return current PKL pipeline status for diagnostics."""
        return {
            'model_loaded': bool(self.model is not None and self.is_trained),
            'model_path': self.model_path,
            'scaler_loaded': bool(self.scaler is not None),
            'scaler_path': self.scaler_path,
            'label_encoder_loaded': bool(self.label_encoder is not None),
            'label_encoder_path': self.label_encoder_path,
            'processed_data_found': bool(self.processed_data_path),
            'processed_data_path': self.processed_data_path,
            'prediction_count': self.prediction_count,
            'scaler_used_count': self.scaler_used_count,
            'encoder_used_count': self.encoder_used_count,
            'last_prediction_label': self.last_prediction_label,
            'last_decoded_label': self.last_decoded_label,
            'last_threat_score': self.last_threat_score,
            'last_error': self.last_error,
        }

    def _is_malicious_label(self, label):
        """Normalize model output label to malicious/non-malicious."""
        try:
            if isinstance(label, (bool, np.bool_)):
                return bool(label)

            if isinstance(label, (int, float, np.integer, np.floating)):
                return float(label) >= 1.0

            label_str = str(label).strip().lower()
            if not label_str:
                return False

            benign_tokens = {'0', 'benign', 'normal', 'safe', 'false', 'clean'}
            if label_str in benign_tokens:
                return False

            malicious_tokens = {
                '1', 'malicious', 'trojan', 'attack', 'anomaly', 'suspicious',
                'malware', 'bot', 'botnet', 'backdoor', 'worm', 'ransomware',
                'true', 'threat'
            }
            return label_str in malicious_tokens
        except Exception:
            return False
    
    def extract_flow_features(self, flow, raw_ml_features=None):
        """
        Extract 79 features from network flow.
        - Features 1-68: Match CIC-IDS dataset format for model prediction
        - Features 69-79: Activity statistics for extended analysis
        """
        # Náº¿u Agent/Client Ä‘Ă£ trĂ­ch xuáº¥t sáºµn Ä‘áº§y Ä‘á»§ features (80+ parameters) -> Náº¡p luĂ´n!
        if raw_ml_features and isinstance(raw_ml_features, list) and len(raw_ml_features) > 80:
            try:
                # 0: flow_id, 1: src_ip, 2: src_port, 3: dst_ip, 4: dst_port, 5: protocol, 6: timestamp
                
                # Protocol mapper
                protocol_val = raw_ml_features[5]
                if isinstance(protocol_val, str):
                    protocol_num = {'TCP': 1, 'UDP': 2, 'ICMP': 3}.get(protocol_val.upper(), 0)
                else:
                    protocol_num = float(protocol_val)

                # Chuyá»ƒn Ä‘á»•i feature tá»« array cá»§a WindowsNetworkFlowCollector thĂ nh máº£ng float
                advanced_features = [
                    float(raw_ml_features[2] or 0),   # Source Port
                    float(raw_ml_features[4] or 0),   # Destination Port
                    float(protocol_num)               # Protocol
                ]
                
                # Tá»« index 7 trá»Ÿ Ä‘i (tá»©c Flow Duration)
                for val in raw_ml_features[7:83]: # Äáº£m báº£o láº¥y Ä‘á»§ 76 values káº¿ tiáº¿p
                    try:
                        advanced_features.append(float(val) if val not in [None, ''] else 0.0)
                    except Exception:
                        advanced_features.append(0.0)
                        
                # Padding hoáº·c trim Ä‘á»ƒ khá»›p chĂ­nh xĂ¡c 79 features
                while len(advanced_features) < 79:
                    advanced_features.append(0.0)
                return advanced_features[:79]
            except Exception as e:
                logger.error(f"Error parsing raw_ml_features: {e}")
                # Fallback xuá»‘ng dummy features náº¿u lá»—i

        payload_length = len(flow.payload_content) if flow.payload_content else 0
        
        # Calculate some basic metrics from payload
        # In a real scenario, these would come from packet capture timing
        payload_entropy = self.calculate_entropy(flow.payload_content if flow.payload_content else b'')
        
        features = [
            # Basic network features (3) - indices 0-2
            flow.src_port or 0,           # 0: Source Port
            flow.dst_port or 0,           # 1: Destination Port
            {'TCP': 1, 'UDP': 2, 'ICMP': 3}.get(flow.protocol, 0),  # 2: Protocol
            
            # Flow Duration and packet counts (3) - indices 3-5
            0,  # 3: Flow Duration
            1 if payload_length > 0 else 0,  # 4: Total Fwd Packets
            0,  # 5: Total Backward Packets
            
            # Total lengths (2) - indices 6-7
            payload_length,  # 6: Total Length of Fwd Packets
            0,  # 7: Total Length of Bwd Packets
            
            # Fwd Packet Length statistics (4) - indices 8-11
            payload_length if payload_length > 0 else 0,  # 8: Fwd Packet Length Max
            0,  # 9: Fwd Packet Length Min
            payload_length if payload_length > 0 else 0,  # 10: Fwd Packet Length Mean
            0,  # 11: Fwd Packet Length Std
            
            # Bwd Packet Length statistics (4) - indices 12-15
            0,  # 12: Bwd Packet Length Max
            0,  # 13: Bwd Packet Length Min
            0,  # 14: Bwd Packet Length Mean
            0,  # 15: Bwd Packet Length Std
            
            # Flow rates (2) - indices 16-17
            0,  # 16: Flow Bytes/s
            0,  # 17: Flow Packets/s
            
            # Flow IAT metrics (4) - indices 18-21
            0,  # 18: Flow IAT Mean
            0,  # 19: Flow IAT Std
            0,  # 20: Flow IAT Max
            0,  # 21: Flow IAT Min
            
            # Forward IAT metrics (5) - indices 22-26
            0,  # 22: Fwd IAT Total
            0,  # 23: Fwd IAT Mean
            0,  # 24: Fwd IAT Std
            0,  # 25: Fwd IAT Max
            0,  # 26: Fwd IAT Min
            
            # Backward IAT metrics (5) - indices 27-31
            0,  # 27: Bwd IAT Total
            0,  # 28: Bwd IAT Mean
            0,  # 29: Bwd IAT Std
            0,  # 30: Bwd IAT Max
            0,  # 31: Bwd IAT Min
            
            # PSH/URG Flags (4) - indices 32-35
            0,  # 32: Fwd PSH Flags
            0,  # 33: Bwd PSH Flags
            0,  # 34: Fwd URG Flags
            0,  # 35: Bwd URG Flags
            
            # Header Length (2) - indices 36-37
            0,  # 36: Fwd Header Length
            0,  # 37: Bwd Header Length
            
            # Packets per second (2) - indices 38-39
            0,  # 38: Fwd Packets/s
            0,  # 39: Bwd Packets/s
            
            # Packet Length statistics (5) - indices 40-44
            payload_length if payload_length > 0 else 0,  # 40: Min Packet Length
            payload_length if payload_length > 0 else 0,  # 41: Max Packet Length
            payload_length if payload_length > 0 else 0,  # 42: Packet Length Mean
            0,  # 43: Packet Length Std
            0,  # 44: Packet Length Variance
            
            # TCP Flags (8) - indices 45-52
            0,  # 45: FIN Flag Count
            0,  # 46: SYN Flag Count
            0,  # 47: RST Flag Count
            0,  # 48: PSH Flag Count
            0,  # 49: ACK Flag Count
            0,  # 50: URG Flag Count
            0,  # 51: CWE Flag Count
            0,  # 52: ECE Flag Count
            
            # Network metrics (9) - indices 53-61
            0,  # 53: Down/Up Ratio
            payload_length if payload_length > 0 else 0,  # 54: Average Packet Size
            payload_length if payload_length > 0 else 0,  # 55: Avg Fwd Segment Size
            0,  # 56: Avg Bwd Segment Size
            0,  # 57: Fwd Avg Bytes/Bulk
            0,  # 58: Fwd Avg Packets/Bulk
            0,  # 59: Fwd Avg Bulk Rate
            0,  # 60: Bwd Avg Bytes/Bulk
            0,  # 61: Bwd Avg Packets/Bulk
            
            # Subflow metrics (4) - indices 62-65
            1 if payload_length > 0 else 0,  # 62: Subflow Fwd Packets
            payload_length,  # 63: Subflow Fwd Bytes
            0,  # 64: Subflow Bwd Packets
            0,  # 65: Subflow Bwd Bytes
            
            # Window and data packet metrics (2) - indices 66-67
            0,  # 66: Init_Win_bytes_forward
            0,  # 67: Init_Win_bytes_backward
            
            # === Extended features (69-79): Not used in model but collected === 
            1 if payload_length > 0 else 0,  # 68: act_data_pkt_fwd (active data packets forward)
            payload_length if payload_length > 0 else 1,  # 69: min_seg_size_forward (min segment size)
            0,  # 70: Bwd Avg Bulk Rate (calculated from backward packets)
            
            # Active time statistics (4) - indices 71-74
            payload_length / 100.0 if payload_length > 0 else 0,  # 71: Active Mean (estimated from payload)
            payload_length / 200.0 if payload_length > 0 else 0,  # 72: Active Std
            payload_length if payload_length > 0 else 0,  # 73: Active Max
            0,  # 74: Active Min
            
            # Idle time statistics (4) - indices 75-78
            0,  # 75: Idle Mean
            0,  # 76: Idle Std
            0,  # 77: Idle Max
            0,  # 78: Idle Min
        ]
        
        # Ensure exactly 79 features
        assert len(features) == 79, f"Feature count mismatch: expected 79, got {len(features)}"
        return features
    
    def calculate_entropy(self, data):
        """Calculate Shannon entropy of data"""
        if len(data) == 0:
            return 0
        
        char_counts = defaultdict(int)
        for char in data:
            char_counts[char] += 1
        
        entropy = 0
        for count in char_counts.values():
            prob = count / len(data)
            if prob > 0:
                entropy -= prob * np.log2(prob)
        
        return entropy
    
    def train_model(self, flows):
        """Model is already trained - this is a placeholder for compatibility"""
        logger.info("Using pre-trained model from best_model.pkl - no additional training needed")
    
    def predict_threat(self, flow, raw_ml_features=None):
        """Predict if a flow is a threat using ML model + Payload/Port Signatures"""
        threats_found = []
        threat_score = 0.0
        scaler_used = False
        encoder_used = False
        
        # ---------------------------------------------------------
        # Táº¦NG 1: MACHINE LEARNING DETECTION (LĂµi phĂ¢n tĂ­ch hĂ nh vi máº¡ng)
        # Báº¯t cĂ¡c thay Ä‘á»•i dá»‹ thÆ°á»ng vá» luá»“ng dá»¯ liá»‡u trÆ°á»›c tiĂªn
        # ---------------------------------------------------------
        if self.is_trained and self.model is not None:
            try:
                # Extract all features from flow
                all_features = self.extract_flow_features(flow, raw_ml_features)
                model_features = all_features[:68]

                X_df = pd.DataFrame([model_features], columns=self.FEATURE_NAMES[:68])
                X_np = np.array([model_features])

                X_scaled = None
                if self.scaler is not None and hasattr(self.scaler, 'transform'):
                    try:
                        X_scaled = self.scaler.transform(X_df)
                        scaler_used = True
                    except Exception:
                        try:
                            X_scaled = self.scaler.transform(X_np)
                            scaler_used = True
                        except Exception:
                            X_scaled = None

                prediction_inputs = [X for X in (X_scaled, X_df, X_np) if X is not None]

                prediction = None
                for X in prediction_inputs:
                    try:
                        prediction = self.model.predict(X)
                        break
                    except Exception:
                        continue

                if prediction is not None:
                    pred_label = prediction[0]
                    decoded_label = pred_label

                    if self.label_encoder is not None and hasattr(self.label_encoder, 'inverse_transform'):
                        try:
                            decoded = self.label_encoder.inverse_transform(np.array([pred_label]))
                            decoded_label = decoded[0]
                            encoder_used = True
                        except Exception:
                            pass

                    is_malicious = self._is_malicious_label(decoded_label) or self._is_malicious_label(pred_label)
                    # Ă‰p cá»©ng quy táº¯c 0 / 1 (0% hoáº·c 100%) dá»©t khoĂ¡t
                    ml_score = 1.0 if is_malicious else 0.0

                    threat_score = max(threat_score, ml_score)
                    if is_malicious:
                        threats_found.append(f"Threat detected by ML model (Score: {ml_score:.2f})")
                    
                    self.prediction_count += 1
                    if scaler_used:
                        self.scaler_used_count += 1
                    if encoder_used:
                        self.encoder_used_count += 1
            except Exception as e:
                logger.error(f"Error in ML prediction: {e}")

        # ---------------------------------------------------------
        # Táº¦NG 3: PORT SIGNATURE (Fallback Known C2)
        # Báº¯t cĂ¡c port tÄ©nh thÆ°á»ng Ä‘Æ°á»£c Trojan sá»­ dá»¥ng náº¿u lá»t qua 2 táº§ng Ä‘áº§u
        # ---------------------------------------------------------
        suspicious_ports = {2404, 6606, 7707, 8808, 4444, 4782, 4445, 1337, 31337, 5555, 6666, 7777, 8888, 9999, 1177}
        if flow.src_port in suspicious_ports or flow.dst_port in suspicious_ports:
            susp_port = flow.dst_port if flow.dst_port in suspicious_ports else flow.src_port
            threats_found.append(f"Suspicious Port {susp_port} (Known C2 Indicator)")
            threat_score = max(threat_score, 0.85)
            
        # ---------------------------------------------------------
        # Káº¾T LUáº¬N CUá»I CĂ™NG
        # ---------------------------------------------------------
        if not threats_found and threat_score < 0.7:
            threats_found.append("Normal traffic detected")

        self.last_threat_score = float(threat_score)
        return threat_score, threats_found

# Initialize threat detector
threat_detector = ThreatDetector()

@app.route('/api/model_pipeline_status', methods=['GET'])
def model_pipeline_status():
    """Inspect whether inference pipeline uses accompanying PKL artifacts."""
    try:
        return jsonify(threat_detector.get_pipeline_status()), 200
    except Exception as e:
        logger.error(f"Error getting model pipeline status: {e}")
        return jsonify({'error': str(e)}), 500

# ==================== API ENDPOINTS ====================

@app.route('/api/models', methods=['GET'])
def list_models():
    """Find all .pkl files in the model directory"""
    app_dir = os.path.dirname(os.path.abspath(__file__))
    project_dir = os.path.dirname(app_dir)
    model_dir = os.path.join(project_dir, 'model') # Point strictly to the 'model' directory
    
    models = set()
    # Danh sĂ¡ch cĂ¡c file pkl ná»™i bá»™/Ä‘Ă³ng vai trĂ² phá»¥ trá»£ khĂ´ng Ä‘Æ°á»£c phĂ©p chá»n
    ignore_list = {'scaler.pkl', 'mahoa_nhan.pkl', 'processed_data.pkl'}
    
    # Chá»‰ quĂ©t bĂªn trong thÆ° má»¥c model
    if os.path.exists(model_dir):
        for file in os.listdir(model_dir):
            if file.endswith('.pkl') and file not in ignore_list:
                models.add(file)
    else:
        logger.warning(f"Model directory not found at: {model_dir}")
                
    return jsonify({
        'current_model': threat_detector.model_filename,
        'available_models': list(models)
    })

@app.route('/api/select_model', methods=['POST'])
@csrf.exempt
def select_model():
    """Load a new model file"""
    data = request.get_json()
    model_name = data.get('model_name')
    if not model_name or not model_name.endswith('.pkl'):
        return jsonify({'error': 'Invalid model name'}), 400
        
    success = threat_detector.change_model(model_name)
    if success:
        return jsonify({'message': f'Successfully switched to {model_name}', 'current_model': model_name})
    else:
        return jsonify({'error': f'Failed to load {model_name}. Check logs.'}), 500

@app.route('/api/register_agent', methods=['POST'])
@csrf.exempt
def register_agent():
    """Register a new agent"""
    try:
        data = request.get_json()
        
        agent_id = data.get('agent_id')
        hostname = data.get('hostname', 'Unknown')
        ip_address = data.get('ip_address', request.remote_addr)
        os_info = data.get('os_info', '')
        
        if not agent_id:
            return jsonify({'error': 'agent_id is required'}), 400
        
        # Check if agent exists
        agent = Agent.query.filter_by(agent_id=agent_id).first()
        
        if agent:
            # Update existing agent
            agent.hostname = hostname
            agent.ip_address = ip_address
            agent.os_info = os_info
            agent.last_seen = get_utc7_now()
            agent.status = 'active'
        else:
            # Create new agent
            agent = Agent(
                agent_id=agent_id,
                hostname=hostname,
                ip_address=ip_address,
                os_info=os_info,
                status='active'
            )
            db.session.add(agent)
        
        db.session.commit()
        logger.info(f"Agent registered/updated: {agent_id} ({hostname})")
        
        return jsonify({'message': 'Agent registered successfully', 'agent_id': agent_id}), 200
        
    except Exception as e:
        logger.error(f"Error registering agent: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/submit_flow', methods=['POST'])
@csrf.exempt
def submit_flow():
    """Receive network flow data from agents"""
    try:
        data = request.get_json()
        
        agent_id = data.get('agent_id')
        flows = data.get('flows', [])
        
        if not agent_id:
            return jsonify({'error': 'agent_id is required'}), 400
        
        # Update agent last seen
        agent = Agent.query.filter_by(agent_id=agent_id).first()
        if not agent:
            return jsonify({'error': 'Agent not registered'}), 404
        
        agent.last_seen = get_utc7_now()
        
        # Process each flow
        threats_detected = 0
        
        for flow_data in flows:
            try:
                # Create flow record
                flow = NetworkFlow(
                    agent_id=agent_id,
                    flow_id=flow_data.get('flow_id', ''),
                    src_ip=flow_data.get('src_ip', ''),
                    dst_ip=flow_data.get('dst_ip', ''),
                    src_port=flow_data.get('src_port', 0),
                    dst_port=flow_data.get('dst_port', 0),
                    protocol=flow_data.get('protocol', ''),
                    payload_content=flow_data.get('payload_content', ''),
                    timestamp=datetime.fromisoformat(flow_data.get('timestamp', get_utc7_now().isoformat()))
                )
                
                # Threat analysis
                raw_ml_features = flow_data.get('ml_features', None)
                threat_score, payload_threats = threat_detector.predict_threat(flow, raw_ml_features)
                if is_icmp_echo_traffic(flow.protocol, flow.payload_content, flow.src_port, flow.dst_port):
                    # Ignore ping request/reply from alerting pipeline to avoid false positives.
                    flow.threat_score = 0.0
                    flow.is_malicious = False
                    flow.classification = 'Benign'
                else:
                    flow.threat_score = threat_score
                    flow.is_malicious = threat_score > 0.7
                    flow.classification = 'Threat' if flow.is_malicious else 'Benign'
                
                db.session.add(flow)
                
                # Create security alert if high threat
                if flow.is_malicious:
                    threats_detected += 1
                    severity = 'critical' if threat_score > 0.9 else 'high'
                    
                    alert = SecurityAlert(
                        agent_id=agent_id,
                        alert_type='suspicious_traffic',
                        severity=severity,
                        title=f"Threat detected from {flow.src_ip}",
                        description=f"Threat score: {threat_score:.2f}. Threats: {', '.join(payload_threats)}",
                        flow_id=flow.flow_id,
                        payload_signature=flow.payload_content[:200]  # First 200 chars
                    )
                    db.session.add(alert)
                    
                    # Update agent threat level
                    if threat_score > 0.9:
                        agent.threat_level = 'critical'
                    elif threat_score > 0.7:
                        agent.threat_level = 'high'
                    elif agent.threat_level in ['low', 'medium']:
                        agent.threat_level = 'medium'
                
            except Exception as flow_error:
                logger.error(f"Error processing flow: {flow_error}")
                continue
        
        db.session.commit()
        
        # Tá»± Ä‘á»™ng cĂ¡ch ly ngay láº­p tá»©c khi phĂ¡t hiá»‡n báº¥t ká»³ má»‘i Ä‘e dá»a nĂ o >= 0.85 (Trojan)
        if threats_detected > 0 and agent.threat_level in ['high', 'critical']:
            isolate_agent_network(agent_id, f"Auto-isolation: {threats_detected} threats detected (Score >= 0.85)")
        
        logger.info(f"Processed {len(flows)} flows from agent {agent_id}, {threats_detected} threats detected")
        
        return jsonify({
            'message': 'Flows processed successfully',
            'threats_detected': threats_detected,
            'agent_status': agent.status
        }), 200
        
    except Exception as e:
        logger.error(f"Error processing flows: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/agent_status/<agent_id>')
@csrf.exempt
def get_agent_status(agent_id):
    """Get agent status and instructions"""
    agent = Agent.query.filter_by(agent_id=agent_id).first()
    
    if not agent:
        return jsonify({'error': 'Agent not found'}), 404
    
    # Check if agent should be isolated
    recent_alerts = SecurityAlert.query.filter_by(agent_id=agent_id)\
        .filter(SecurityAlert.created_at > get_utc7_now() - timedelta(hours=1))\
        .filter_by(is_resolved=False).count()
    
    # Check for isolation expiry
    if agent.status == 'isolated' and agent.isolated_until:
        if get_utc7_now() > agent.isolated_until:
            logger.info(f"Isolation for agent {agent_id} expired. Triggering restoration.")
            agent.status = 'active'
            agent.isolated_until = None
            db.session.commit()
    
    instructions = []
    if agent.status == 'isolated':
        instructions.append("NETWORK_ISOLATED")
    elif recent_alerts > 10:
        instructions.append("INCREASE_MONITORING")
    else:
        # If agent was isolated but status is now active (restored), send instruction
        # We can use a simple check or more complex session-based instruction queue
        # For now, let's assume the agent polls and switches based on status
        pass
    
    return jsonify({
        'agent_id': agent_id,
        'status': agent.status,
        'threat_level': agent.threat_level,
        'last_seen': agent.last_seen.isoformat(),
        'instructions': instructions,
        'recent_alerts': recent_alerts
    })

@app.route('/api/agent/<agent_id>/pending_command', methods=['GET'])
@csrf.exempt
def get_pending_command(agent_id):
    """Get pending command for agent (used for polling network isolation commands)"""
    try:
        agent = Agent.query.filter_by(agent_id=agent_id).first()
        
        if agent.pending_command:
            # Return the pending command and immediately clear it
            command = json.loads(agent.pending_command)
            agent.pending_command = None  # Clear so it doesn't repeat on next poll
            response = {
                'has_command': True,
                'command': command
            }
            db.session.commit()
            return jsonify(response), 200
        else:
            # No pending command
            db.session.commit()
            return jsonify({'has_command': False}), 200
            
    except Exception as e:
        logger.error(f"Error retrieving pending command for agent {agent_id}: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/agent/<agent_id>/command_result', methods=['POST'])
@csrf.exempt
def report_command_result(agent_id):
    """Agent reports result of executing isolation/restoration command"""
    try:
        data = request.get_json()
        agent = Agent.query.filter_by(agent_id=agent_id).first()
        
        if not agent:
            return jsonify({'error': 'Agent not found'}), 404
        
        # Update last seen
        agent.last_seen = get_utc7_now()
        
        action = data.get('action', 'unknown')
        success = data.get('success', False)
        error_msg = data.get('error', '')
        adapter_name = data.get('adapter_name', '')
        
        # Store adapter name for future use
        if adapter_name:
            agent.network_adapter_name = adapter_name
        
        if success:
            # Clear pending command only if execution was successful
            agent.pending_command = None
            
            if action == 'isolate':
                agent.status = 'isolated'
                logger.critical(f"âœ“ Agent {agent_id} SUCCESSFULLY ISOLATED - Network adapter disabled: {adapter_name}")
            elif action == 'restore':
                agent.status = 'active'
                logger.info(f"âœ“ Agent {agent_id} SUCCESSFULLY RESTORED - Network adapter enabled: {adapter_name}")
        else:
            # Command failed - keep pending so agent can retry
            logger.error(f"âœ— Agent {agent_id} failed to execute {action} command: {error_msg}")
        
        db.session.commit()
        
        return jsonify({
            'acknowledged': True,
            'action': action,
            'success': success
        }), 200
        
    except Exception as e:
        logger.error(f"Error processing command result for agent {agent_id}: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/agent/<agent_id>/process_request', methods=['GET'])
@csrf.exempt
def get_process_request(agent_id):
    """Agent polls this endpoint to see if server requested process collection."""
    try:
        agent = Agent.query.filter_by(agent_id=agent_id).first()
        if not agent:
            return jsonify({'has_request': False}), 200

        # Update heartbeat when agent calls this endpoint
        agent.last_seen = get_utc7_now()
        db.session.commit()

        now = get_utc7_now()
        with PROCESS_LOCK:
            req = PROCESS_REQUESTS.get(agent_id)
            if not req:
                return jsonify({'has_request': False}), 200

            # Expire stale requests after 30s
            if (now - req['created_at']).total_seconds() > 30:
                PROCESS_REQUESTS.pop(agent_id, None)
                return jsonify({'has_request': False}), 200

            return jsonify({
                'has_request': True,
                'request_id': req['request_id'],
                'path': req.get('path', 'C:\\')
            }), 200

    except Exception as e:
        logger.error(f"Error getting process request for agent {agent_id}: {e}")
        return jsonify({'has_request': False}), 200


@app.route('/api/agent/<agent_id>/process_result', methods=['POST'])
@csrf.exempt
def submit_process_result(agent_id):
    """Agent submits collected process list for a previously issued request."""
    try:
        data = request.get_json() or {}
        request_id = data.get('request_id')
        success = bool(data.get('success', False))
        processes = data.get('processes', [])

        if not request_id:
            return jsonify({'ok': False, 'error': 'missing request_id'}), 400

        if isinstance(processes, dict):
            processes = [processes]
        if not isinstance(processes, list):
            processes = []

        # Keep only expected fields for UI safety
        normalized = []
        for proc in processes:
            normalized.append({
                'ProcessName': str(proc.get('ProcessName', 'Unknown') or 'Unknown'),
                'PID': int(proc.get('PID') or 0),
                'LocalAddress': str(proc.get('LocalAddress', '0.0.0.0') or '0.0.0.0'),
                'LocalPort': int(proc.get('LocalPort') or 0),
                'RemoteAddress': str(proc.get('RemoteAddress', '0.0.0.0') or '0.0.0.0'),
                'RemotePort': int(proc.get('RemotePort') or 0),
                'State': str(proc.get('State', 'Unknown') or 'Unknown')
            })

        with PROCESS_LOCK:
            req = PROCESS_REQUESTS.get(agent_id)
            if req and req['request_id'] == request_id:
                PROCESS_RESULTS[request_id] = {
                    'success': success,
                    'processes': normalized,
                    'created_at': get_utc7_now()
                }
                PROCESS_REQUESTS.pop(agent_id, None)

        agent = Agent.query.filter_by(agent_id=agent_id).first()
        if agent:
            agent.last_seen = get_utc7_now()
            db.session.commit()

        return jsonify({'ok': True}), 200

    except Exception as e:
        logger.error(f"Error submitting process result for agent {agent_id}: {e}")
        return jsonify({'ok': False, 'error': 'internal error'}), 500


@app.route('/api/kill_process/<agent_id>', methods=['POST'])
@csrf.exempt
def kill_process(agent_id):
    """Send kill process command to agent"""
    try:
        data = request.get_json() or {}
        pid = data.get('pid')
        process_name = data.get('process_name', 'unknown')
        
        if not pid:
            return jsonify({'success': False, 'error': 'PID required'}), 400
        
        agent = Agent.query.filter_by(agent_id=agent_id).first()
        if not agent:
            return jsonify({'success': False, 'error': 'Agent not found'}), 404
        
        # Check if agent is online
        last_seen_threshold = get_utc7_now() - timedelta(seconds=120)
        if not agent.last_seen or agent.last_seen < last_seen_threshold:
            return jsonify({'success': False, 'error': 'Agent Ä‘ang ngoáº¡i tuyáº¿n.'}), 503
        
        # Send kill_process command via pending_command
        command = {
            'action': 'kill_process',
            'pid': int(pid),
            'process_name': process_name,
            'timestamp': get_utc7_now().isoformat()
        }
        
        agent.pending_command = json.dumps(command)
        db.session.commit()
        
        logger.info(f"Kill process command sent to agent {agent_id}: {process_name} (PID: {pid})")
        
        return jsonify({
            'success': True,
            'message': f'Kill command sent for {process_name} (PID: {pid})',
            'agent_id': agent_id
        }), 200
        
    except Exception as e:
        logger.error(f"Error killing process on agent {agent_id}: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': str(e)}), 500

# ==================== NETWORK ISOLATION ====================

def isolate_agent_network(agent_id, reason, duration_minutes=None):
    """Isolate agent from network by setting network adapter disable command
    
    Only sends isolation command ONCE. If agent is already isolated, new threats won't 
    trigger repeated isolation commands. System must boot/restart to clear isolation status.
    """
    try:
        agent = Agent.query.filter_by(agent_id=agent_id).first()
        if not agent:
            return False
        
        # NEW: Check if agent is already isolated
        if agent.status == 'isolated':
            logger.warning(f"Agent {agent_id} is ALREADY ISOLATED. Not sending duplicate isolation command.")
            logger.warning(f"  Reason: Only ONE isolation command per session. System must restart/restore to clear.")
            return False
            
        # Calculate expiry if duration provided
        isolated_until = None
        if duration_minutes and duration_minutes > 0:
            isolated_until = get_utc7_now() + timedelta(minutes=duration_minutes)
        
        # Update agent status and set pending command
        agent.status = 'isolated'
        agent.isolated_until = isolated_until
        
        # Get server IP from request to tell agent what to allow
        server_ip = socket.gethostbyname(socket.gethostname()) # Default to local hostname
        try:
            # Try to get the actual IP the agent uses to reach the server
            server_ip = request.host.split(':')[0]
            # If it's a hostname, try to resolve it
            server_ip = socket.gethostbyname(server_ip)
        except:
            pass

        # Create isolation command for agent to execute (firewall rules)
        isolation_command = {
            'action': 'isolate',
            'reason': reason,
            'duration_minutes': duration_minutes,
            'server_ip': server_ip,
            'timestamp': get_utc7_now().isoformat()
        }
        agent.pending_command = json.dumps(isolation_command)
        
        # Log isolation action
        isolation_action = IsolationAction(
            agent_id=agent_id,
            action_type='isolate',
            reason=f"{reason} (Duration: {duration_minutes if duration_minutes else 'Indefinite'})",
            success=True
        )
        db.session.add(isolation_action)
        
        db.session.commit()
        
        logger.critical(f"âœ“ Agent {agent_id} ISOLATION COMMAND SENT - {reason}")
        logger.critical(f"  Machine will be isolated on next poll. No repeated commands until system restart.")
        return True
        
    except Exception as e:
        logger.error(f"Error isolating agent {agent_id}: {e}")
        return False

def restore_agent_network(agent_id, reason):
    """Restore agent network access by queuing network adapter enable command"""
    try:
        agent = Agent.query.filter_by(agent_id=agent_id).first()
        if not agent:
            return False
        
        # Update agent status and set pending command
        agent.status = 'active'
        agent.threat_level = 'low'
        agent.isolated_until = None
        
        # Create restoration command for agent to execute (network adapter enable)
        restoration_command = {
            'action': 'restore',
            'reason': reason,
            'timestamp': get_utc7_now().isoformat()
        }
        agent.pending_command = json.dumps(restoration_command)
        
        # Log restoration action
        isolation_action = IsolationAction(
            agent_id=agent_id,
            action_type='restore',
            reason=reason,
            success=True
        )
        db.session.add(isolation_action)
        db.session.commit()
        
        logger.info(f"Agent {agent_id} restoration command queued: {reason}")
        return True
        
    except Exception as e:
        logger.error(f"Error queuing restoration for agent {agent_id}: {e}")
        return False

# ==================== WEB INTERFACE ====================

@app.route('/')
def dashboard():
    """Main dashboard"""
    # Get statistics
    total_agents = Agent.query.count()
    active_agents = Agent.query.filter_by(status='active').count()
    isolated_agents = Agent.query.filter_by(status='isolated').count()
    
    # Recent alerts
    recent_alerts = SecurityAlert.query.filter_by(is_resolved=False)\
        .order_by(SecurityAlert.created_at.desc()).limit(10).all()
    
    # Critical agents
    critical_agents = Agent.query.filter_by(threat_level='critical').all()
    
    # Recent flows with threats
    threat_flows = NetworkFlow.query.filter_by(is_malicious=True)\
        .order_by(NetworkFlow.created_at.desc()).limit(5).all()
    
    # Total flows since installation
    total_flows_collected = NetworkFlow.query.count()
    
    # Calculate protocol percentages
    protocol_percentages = {'tcp': 0, 'udp': 0, 'rdp': 0, 'other': 100}
    protocol_stats = {'tcp': 0, 'udp': 0, 'rdp': 0, 'other': 0}
    total_proto_flows = total_flows_collected
    
    if total_flows_collected > 0:
        # Cast to text and then use ilike for protocol because protocol is string
        tcp_count = NetworkFlow.query.filter(
            db.or_(NetworkFlow.protocol.ilike('%tcp%'), NetworkFlow.protocol == '6')
        ).count()
        
        udp_count = NetworkFlow.query.filter(
            db.or_(NetworkFlow.protocol.ilike('%udp%'), NetworkFlow.protocol == '17')
        ).count()
        
        rdp_count = NetworkFlow.query.filter(
            db.or_(
                NetworkFlow.dst_port == 3389,
                NetworkFlow.protocol.ilike('%icmp%'), 
                NetworkFlow.protocol == '1'
            )
        ).count()
        
        other_count = max(0, total_flows_collected - (tcp_count + udp_count + rdp_count))
        
        protocol_stats = {
            'tcp': tcp_count,
            'udp': udp_count,
            'rdp': rdp_count,
            'other': other_count
        }
        
        protocol_percentages['tcp'] = round((tcp_count / total_flows_collected) * 100)
        protocol_percentages['udp'] = round((udp_count / total_flows_collected) * 100)
        protocol_percentages['rdp'] = round((rdp_count / total_flows_collected) * 100)
        protocol_percentages['other'] = max(0, 100 - (protocol_percentages['tcp'] + protocol_percentages['udp'] + protocol_percentages['rdp']))
    
    # Calculate top traffic sources
    top_sources_query = db.session.query(
        NetworkFlow.src_ip, db.func.count(NetworkFlow.id).label('count')
    ).group_by(NetworkFlow.src_ip).order_by(db.desc('count')).limit(5).all()
    
    top_sources = [(row.src_ip, row.count) for row in top_sources_query]
    
    return render_template('dashboard.html',
                         total_agents=total_agents,
                         active_agents=active_agents,
                         isolated_agents=isolated_agents,
                         recent_alerts=recent_alerts,
                         critical_agents=critical_agents,
                         threat_flows=threat_flows,
                         total_flows_collected=total_flows_collected,
                         protocol_percentages=protocol_percentages,
                         protocol_stats=protocol_stats,
                         total_proto_flows=total_proto_flows,
                         top_sources=top_sources)

@app.route('/agents')
def agents_list():
    """List all agents"""
    agents = Agent.query.order_by(Agent.last_seen.desc()).all()
    return render_template('agents.html', agents=agents)

@app.route('/debug/agents')
@csrf.exempt
def debug_agents():
    """Debug endpoint to check agents in database"""
    try:
        agents = Agent.query.all()
        agents_list = []
        
        for agent in agents:
            agents_list.append({
                'id': agent.id,
                'agent_id': agent.agent_id,
                'hostname': agent.hostname,
                'ip_address': agent.ip_address,
                'status': agent.status,
                'last_seen': agent.last_seen.isoformat() if agent.last_seen else None,
                'threat_level': agent.threat_level
            })
        
        return jsonify({
            'total_agents': len(agents_list),
            'agents': agents_list
        }), 200
    except Exception as e:
        logger.error(f"Error in debug endpoint: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/process')
def process_monitor():
    """Process monitoring page"""
    agents = Agent.query.order_by(Agent.last_seen.desc()).all()
    return render_template('process.html', agents=agents)

@app.route('/agent/<agent_id>')
def agent_detail(agent_id):
    """Agent detail page"""
    agent = Agent.query.filter_by(agent_id=agent_id).first_or_404()
    
    # Get current page from query parameter, default to 1
    page = request.args.get('page', 1, type=int)
    per_page = 10  # 10 flows per page for display
    
    # Get agent flows for current page (for display)
    flows_pagination = NetworkFlow.query.filter_by(agent_id=agent_id)\
        .order_by(NetworkFlow.created_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    flows = flows_pagination.items
    
    # Get ALL flows (up to 2000) for client-side filtering
    all_flows_query = NetworkFlow.query.filter_by(agent_id=agent_id)\
        .order_by(NetworkFlow.created_at.desc())
    all_flows = all_flows_query.limit(2000).all()
    
    # Convert all flows to JSON format for client-side filtering
    import json
    all_flows_json = json.dumps([{
        'id': f.id,
        'threat_score': float(f.threat_score),
        'timestamp': f.timestamp.strftime('%H:%M:%S'),
        'dst_ip': f.dst_ip,
        'protocol': f.protocol,
        'payload_content': f.payload_content or 'No encrypted payload',
        'status': 'trojan' if f.threat_score > 0.7 else ('suspicious' if f.threat_score > 0.4 else 'benign')
    } for f in all_flows])
    
    # Get agent alerts
    alerts = SecurityAlert.query.filter_by(agent_id=agent_id)\
        .order_by(SecurityAlert.created_at.desc()).limit(20).all()
    
    return render_template('agent_detail.html', 
                         agent=agent, 
                         flows=flows, 
                         flows_pagination=flows_pagination,
                         all_flows_json=all_flows_json,
                         total_flows_count=all_flows_query.count(),
                         alerts=alerts)

@app.route('/flow/<int:flow_id>')
def flow_detail(flow_id):
    """Flow detail page"""
    flow = NetworkFlow.query.filter_by(id=flow_id).first_or_404()
    agent = Agent.query.filter_by(agent_id=flow.agent_id).first_or_404()
    
    # Calculate anomaly indicators
    anomalies = {
        'is_large_flow': False,
        'is_long_duration': False,
        'is_high_packet_rate': False,
        'is_windows_port': False,
        'is_suspicious_port': False,
        'reason': []
    }
    
    # Get all flows from same agent to calculate percentiles
    all_agent_flows = NetworkFlow.query.filter_by(agent_id=flow.agent_id).all()
    
    if all_agent_flows:
        # For percentile calculation - since we don't have all fields, use what we have
        # Check if threat_score is high
        max_threat = max([f.threat_score for f in all_agent_flows])
        min_threat = min([f.threat_score for f in all_agent_flows])
        
        # Anomaly Detection
        if flow.threat_score > 0.7:
            anomalies['is_large_threat'] = True
            anomalies['reason'].append('High threat score (>70%)')
        
        # Windows service ports (common targets)
        windows_ports = [135, 139, 445, 3389, 5985, 5986]
        if flow.dst_port and flow.dst_port in windows_ports:
            anomalies['is_windows_port'] = True
            anomalies['reason'].append(f'Windows service port {flow.dst_port}')
        
        # Suspicious ports (common for exploit/scanning)
        suspicious_ports = [1433, 3306, 5432, 27017, 6379, 9200]  # Databases
        if flow.dst_port and flow.dst_port in suspicious_ports:
            anomalies['is_suspicious_port'] = True
            anomalies['reason'].append(f'Suspicious database port {flow.dst_port}')
        
        # Protocol anomalies
        if flow.protocol and flow.protocol.upper() == 'ICMP':
            anomalies['reason'].append('ICMP protocol (used in reconnaissance)')
    
    return render_template('flow_detail.html', 
                         flow=flow, 
                         agent=agent,
                         anomalies=anomalies)

@app.route('/alerts')
def alerts_list():
    """List all security alerts"""
    alerts = SecurityAlert.query.order_by(SecurityAlert.created_at.desc()).all()
    return render_template('alerts.html', alerts=alerts)

@app.route('/isolate_form/<agent_id>', methods=['GET'])
def isolate_form(agent_id):
    """Show isolation form"""
    agent = Agent.query.filter_by(agent_id=agent_id).first_or_404()
    return render_template('isolate.html', agent=agent)

@app.route('/isolate/<agent_id>', methods=['POST'])
def isolate_agent_web(agent_id):
    """Isolate agent via web interface"""
    agent = Agent.query.filter_by(agent_id=agent_id).first()
    
    # Check if already isolated
    if agent and agent.status == 'isolated':
        flash(f'Agent {agent_id} is ALREADY ISOLATED. Cannot send duplicate isolation command. '
              f'System must restart/restore to clear isolation status.', 'warning')
        return redirect(url_for('agent_detail', agent_id=agent_id))
    
    reason = request.form.get('reason', 'Manual isolation via web interface')
    duration = request.form.get('duration', 'indefinite')
    
    # Map duration string to minutes
    duration_map = {
        '1m': 1,
        '1h': 60,
        '1d': 1440,
        'indefinite': None
    }
    duration_minutes = duration_map.get(duration)
    
    success = isolate_agent_network(agent_id, reason, duration_minutes)
    
    if success:
        flash(f'Agent {agent_id} isolation command SENT - Machine will be isolated on next poll.', 'success')
    else:
        flash(f'Failed to isolate agent {agent_id}. Check logs for details.', 'error')
    
    return redirect(url_for('agent_detail', agent_id=agent_id))

@app.route('/restore/<agent_id>', methods=['POST'])
def restore_agent_web(agent_id):
    """Restore agent via web interface"""
    reason = request.form.get('reason', 'Manual restoration via web interface')
    
    success = restore_agent_network(agent_id, reason)
    
    if success:
        flash(f'Agent {agent_id} network access has been restored.', 'success')
    else:
        flash(f'Failed to restore agent {agent_id}.', 'error')
    
    return redirect(url_for('agent_detail', agent_id=agent_id))

@app.route('/resolve_alert/<int:alert_id>', methods=['POST'])
@csrf.exempt
def resolve_alert(alert_id):
    """Mark alert as resolved"""
    alert = SecurityAlert.query.get_or_404(alert_id)
    alert.is_resolved = True
    db.session.commit()
    
    if request.is_json or request.headers.get('Accept', '').find('application/json') != -1 or request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.content_type == 'application/json':
        return jsonify({'success': True, 'message': 'ÄĂ£ Ä‘Ă¡nh dáº¥u Ä‘Ă£ giáº£i quyáº¿t'})
        
    flash('ÄĂ£ Ä‘Ă¡nh dáº¥u Ä‘Ă£ giáº£i quyáº¿t.', 'success')
    return redirect(url_for('alerts_list'))

@app.route('/resolve_all_alerts', methods=['POST'])
@csrf.exempt
def resolve_all_alerts():
    """Mark all active alerts as resolved"""
    alerts = SecurityAlert.query.filter_by(is_resolved=False).all()
    count = len(alerts)
    for alert in alerts:
        alert.is_resolved = True
    db.session.commit()
    
    if request.is_json or request.headers.get('Accept', '').find('application/json') != -1 or request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.content_type == 'application/json':
        return jsonify({'success': True, 'message': f'ÄĂ£ giáº£i quyáº¿t {count} cáº£nh bĂ¡o'})
        
    flash(f'ÄĂ£ giáº£i quyáº¿t {count} cáº£nh bĂ¡o.', 'success')
    return redirect(url_for('alerts_list'))

# ==================== API ENDPOINTS FOR REAL-TIME FEATURES ====================

@app.route('/api/dashboard/stats')
@csrf.exempt
def api_dashboard_stats():
    """Get real-time dashboard statistics"""
    try:
        stats = {
            'total_agents': Agent.query.count(),
            'active_agents': Agent.query.filter_by(status='active').count(),
            'isolated_agents': Agent.query.filter_by(status='isolated').count(),
            'pending_alerts': SecurityAlert.query.filter_by(is_resolved=False).count(),
            'critical_alerts': SecurityAlert.query.filter_by(
                is_resolved=False, severity='critical'
            ).count(),
            'threat_flows_today': NetworkFlow.query.filter(
                NetworkFlow.is_malicious == True,
                NetworkFlow.created_at >= get_utc7_now().replace(hour=0, minute=0, second=0)
            ).count(),
            'last_updated': get_utc7_now().isoformat()
        }
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error fetching dashboard stats: {e}")
        return jsonify({'error': 'Unable to fetch stats'}), 500

@app.route('/api/agents/<agent_id>/status')
@csrf.exempt
def api_agent_status(agent_id):
    """Get real-time agent status"""
    try:
        agent = Agent.query.filter_by(agent_id=agent_id).first_or_404()
        
        # Check if agent is recently seen (within last 2 minutes)
        last_seen_threshold = get_utc7_now() - timedelta(minutes=2)
        is_online = agent.last_seen and agent.last_seen > last_seen_threshold
        
        # IMPORTANT: Never overwrite 'isolated' status based on heartbeat alone.
        # Isolation is only cleared by explicit restore command.
        if agent.status == 'isolated':
            display_status = 'isolated'
        else:
            display_status = 'online' if is_online else 'offline'
            # Only update DB status when NOT isolated
            if display_status != agent.status:
                agent.status = display_status
                db.session.commit()
        
        return jsonify({
            'agent_id': agent.agent_id,
            'hostname': agent.hostname,
            'status': display_status,
            'last_seen': agent.last_seen.strftime('%Y-%m-%d %H:%M:%S') if agent.last_seen else 'Never',
            'threat_level': agent.threat_level,
            'status_changed': False
        })
    except Exception as e:
        logger.error(f"Error fetching agent status: {e}")
        return jsonify({'error': 'Unable to fetch agent status'}), 500

@app.route('/api/activity/latest')
@csrf.exempt
def api_latest_activity():
    """Get latest system activities"""
    try:
        activities = []
        
        # Recent alerts (last 10)
        recent_alerts = SecurityAlert.query.filter(
            SecurityAlert.created_at >= get_utc7_now() - timedelta(hours=1)
        ).order_by(SecurityAlert.created_at.desc()).limit(5).all()
        
        for alert in recent_alerts:
            activities.append({
                'type': 'alert',
                'title': f'Security Alert: {alert.alert_type}',
                'description': f'{alert.title} on {alert.agent.hostname}',
                'time': alert.created_at.strftime('%H:%M:%S'),
                'severity': alert.severity,
                'timestamp': alert.created_at.isoformat()
            })
        
        # Recent agent connections
        recent_agents = Agent.query.filter(
            Agent.last_seen >= get_utc7_now() - timedelta(minutes=10)
        ).order_by(Agent.last_seen.desc()).limit(5).all()
        
        for agent in recent_agents:
            activities.append({
                'type': 'connection',
                'title': f'Agent Connected',
                'description': f'{agent.hostname} ({agent.ip_address})',
                'time': agent.last_seen.strftime('%H:%M:%S') if agent.last_seen else 'Unknown',
                'severity': 'info',
                'timestamp': agent.last_seen.isoformat() if agent.last_seen else ''
            })
        
        # Sort by timestamp
        activities.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        return jsonify(activities[:10])  # Return max 10 activities
        
    except Exception as e:
        logger.error(f"Error fetching latest activity: {e}")
        return jsonify([])

@app.route('/api/threats/summary')
@csrf.exempt
def api_threats_summary():
    """Get threat summary for dashboard"""
    try:
        # Count threats by severity
        threats_by_severity = {
            'critical': SecurityAlert.query.filter_by(
                is_resolved=False, severity='critical'
            ).count(),
            'high': SecurityAlert.query.filter_by(
                is_resolved=False, severity='high'  
            ).count(),
            'medium': SecurityAlert.query.filter_by(
                is_resolved=False, severity='medium'
            ).count(),
            'low': SecurityAlert.query.filter_by(
                is_resolved=False, severity='low'
            ).count()
        }
        
        # Recent threats
        recent_threats = NetworkFlow.query.filter_by(is_malicious=True)\
            .order_by(NetworkFlow.created_at.desc()).limit(5).all()
        
        threat_flows = []
        for flow in recent_threats:
            threat_flows.append({
                'id': flow.id,
                'src_ip': flow.src_ip,
                'dst_ip': flow.dst_ip,
                'protocol': flow.protocol,
                'threat_score': flow.threat_score,
                'timestamp': flow.timestamp.strftime('%H:%M:%S')
            })
        
        return jsonify({
            'threats_by_severity': threats_by_severity,
            'recent_threats': threat_flows,
            'total_threats': sum(threats_by_severity.values()),
            'last_updated': get_utc7_now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error fetching threats summary: {e}")
        return jsonify({'error': 'Unable to fetch threats summary'}), 500

# ==================== REAL-TIME UPDATE API ENDPOINTS ====================

@app.route('/api/alerts/recent')
@csrf.exempt
def api_recent_alerts():
    """Get recent alerts for real-time updates (no page reload)"""
    try:
        alerts = SecurityAlert.query.filter_by(is_resolved=False)\
            .order_by(SecurityAlert.created_at.desc()).limit(15).all()
        
        alerts_data = []
        for alert in alerts:
            alerts_data.append({
                'id': alert.id,
                'alert_type': alert.alert_type,
                'severity': alert.severity,
                'title': alert.title,
                'description': alert.description,
                'agent_id': alert.agent_id,
                'flow_id': alert.flow_id,
                'is_resolved': alert.is_resolved,
                'created_at': alert.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'time_ago': get_time_ago(alert.created_at)
            })
        
        return jsonify(alerts_data)
        
    except Exception as e:
        logger.error(f"Error fetching recent alerts: {e}")
        return jsonify([])

@app.route('/api/agents/status')
@csrf.exempt
def api_agents_status():
    """Get all agents status for real-time updates"""
    try:
        agents = Agent.query.all()
        agents_data = []
        
        for agent in agents:
            # Check if agent is online (seen within last 2 minutes)
            last_seen_threshold = get_utc7_now() - timedelta(minutes=2)
            is_online = agent.last_seen and agent.last_seen > last_seen_threshold
            
            agents_data.append({
                'id': agent.id,
                'agent_id': agent.agent_id,
                'hostname': agent.hostname,
                'ip_address': agent.ip_address,
                'status': 'active' if is_online else 'disconnected',
                'threat_level': agent.threat_level,
                'last_seen': agent.last_seen.strftime('%Y-%m-%d %H:%M:%S') if agent.last_seen else None
            })
        
        return jsonify(agents_data)
        
    except Exception as e:
        logger.error(f"Error fetching agents status: {e}")
        return jsonify([])

@app.route('/api/get_processes/<agent_id>')
@csrf.exempt
def get_agent_processes(agent_id):
    """Request process list from agent and wait briefly for result."""
    try:
        agent = Agent.query.filter_by(agent_id=agent_id).first()
        if not agent:
            return jsonify({
                'success': False,
                'message': 'Agent not found'
            }), 404

        # Only serve online agents
        if not agent.is_online:
            return jsonify({
                'success': False,
                'message': 'Agent Ä‘ang ngoáº¡i tuyáº¿n.'
            }), 503

        request_id = uuid.uuid4().hex
        with PROCESS_LOCK:
            PROCESS_REQUESTS[agent_id] = {
                'request_id': request_id,
                'created_at': get_utc7_now()
            }

        # Wait up to 12s for agent heartbeat loop to return results
        timeout_at = time.time() + 12
        while time.time() < timeout_at:
            with PROCESS_LOCK:
                result = PROCESS_RESULTS.pop(request_id, None)
            if result:
                return jsonify({
                    'success': True,
                    'agent_id': agent_id,
                    'hostname': agent.hostname,
                    'processes': result.get('processes', []),
                    'process_count': len(result.get('processes', [])),
                    'timestamp': get_utc7_now().isoformat()
                }), 200
            time.sleep(0.5)

        return jsonify({
            'success': False,
            'agent_id': agent_id,
            'hostname': agent.hostname,
            'message': 'Timed out waiting for agent process data',
            'processes': [],
            'process_count': 0,
            'timestamp': get_utc7_now().isoformat()
        }), 504
        
    except Exception as e:
        logger.error(f"Error fetching processes for agent {agent_id}: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return jsonify({
            'success': False,
            'message': f'Error fetching processes: {str(e)}'
        }), 500


def guess_process_name(port, protocol):
    """Guess process name based on port and protocol
    
    This is a simplified mapping of well-known ports to process names.
    In production, you would query the agent for actual process names.
    """
    common_ports = {
        20: 'ftp',
        21: 'ftp',
        22: 'ssh',
        23: 'telnet',
        25: 'smtp',
        53: 'dns',
        80: 'http',
        110: 'pop3',
        135: 'services',
        139: 'netbios',
        143: 'imap',
        443: 'https',
        445: 'samba',
        465: 'smtp',
        587: 'smtp',
        993: 'imaps',
        995: 'pop3s',
        1433: 'sqlserver',
        3306: 'mysql',
        3389: 'rdp',
        5432: 'postgresql',
        5985: 'winrm',
        5986: 'winrm',
        6379: 'redis',
        8080: 'http-alt',
        8443: 'https-alt',
        9200: 'elasticsearch',
        27017: 'mongodb'
    }
    
    if port in common_ports:
        return common_ports[port]
    elif port < 1024:
        return f'system_service_{port}'
    else:
        return f'app_process_{port}'

@app.route('/api/dashboard/metrics')
@csrf.exempt
def api_dashboard_metrics():
    """Enhanced dashboard metrics for smooth updates"""
    try:
        # Get current time for relative calculations
        now = get_utc7_now()
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        
        # Calculate comprehensive metrics
        total_agents = Agent.query.count()
        active_agents = Agent.query.filter(
            Agent.last_seen >= now - timedelta(minutes=2)
        ).count()
        
        # Alert metrics
        all_alerts = SecurityAlert.query.filter_by(is_resolved=False).count()
        critical_alerts = SecurityAlert.query.filter_by(
            is_resolved=False, severity='critical'
        ).count()
        
        # Flow metrics
        total_flows_today = NetworkFlow.query.filter(
            NetworkFlow.created_at >= today_start
        ).count()
        
        threat_flows = NetworkFlow.query.filter(
            NetworkFlow.is_malicious == True,
            NetworkFlow.created_at >= today_start
        ).count()
        
        # Network activity (last hour)
        recent_activity = NetworkFlow.query.filter(
            NetworkFlow.created_at >= now - timedelta(hours=1)
        ).count()
        
        metrics = {
            'agents': {
                'total': total_agents,
                'active': active_agents,
                'offline': total_agents - active_agents,
                'percentage': round((active_agents / total_agents * 100) if total_agents > 0 else 0, 1)
            },
            'alerts': {
                'total': all_alerts,
                'critical': critical_alerts,
                'recent_alerts_count': all_alerts
            },
            'flows': {
                'total_today': total_flows_today,
                'threats': threat_flows,
                'recent_activity': recent_activity,
                'threat_percentage': round((threat_flows / total_flows_today * 100) if total_flows_today > 0 else 0, 1)
            },
            'system': {
                'uptime': '24h 15m',  # Mock data - replace with actual system uptime
                'cpu_usage': 65,      # Mock data - replace with actual CPU
                'memory_usage': 78,   # Mock data - replace with actual memory
                'disk_usage': 42      # Mock data - replace with actual disk
            },
            'last_updated': now.strftime('%Y-%m-%d %H:%M:%S'),
            'timestamp': now.isoformat()
        }
        
        return jsonify(metrics)
        
    except Exception as e:
        logger.error(f"Error fetching dashboard metrics: {e}")
        return jsonify({'error': 'Unable to fetch metrics'}), 500

def get_time_ago(timestamp):
    """Calculate human-readable time ago"""
    now = get_utc7_now()
    diff = now - timestamp
    
    seconds = diff.total_seconds()
    
    if seconds < 60:
        return "Just now"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        return f"{minutes}m ago"
    elif seconds < 86400:
        hours = int(seconds // 3600)
        return f"{hours}h ago"
    else:
        days = int(seconds // 86400)
        return f"{days}d ago"
def api_threats_summary():
    """Get threat summary for real-time updates"""
    try:
        now = get_utc7_now()
        today_start = now.replace(hour=0, minute=0, second=0)
        hour_ago = now - timedelta(hours=1)
        
        summary = {
            'threats_today': NetworkFlow.query.filter(
                NetworkFlow.is_malicious == True,
                NetworkFlow.created_at >= today_start
            ).count(),
            'threats_last_hour': NetworkFlow.query.filter(
                NetworkFlow.is_malicious == True,
                NetworkFlow.created_at >= hour_ago
            ).count(),
            'active_threats': SecurityAlert.query.filter_by(
                is_resolved=False
            ).count(),
            'critical_threats': SecurityAlert.query.filter_by(
                is_resolved=False,
                severity='critical'
            ).count(),
            'threat_trend': 'increasing',  # This could be calculated based on historical data
            'last_threat': None
        }
        
        # Get last threat
        last_threat_flow = NetworkFlow.query.filter_by(
            is_malicious=True
        ).order_by(NetworkFlow.created_at.desc()).first()
        
        if last_threat_flow:
            summary['last_threat'] = {
                'timestamp': last_threat_flow.created_at.isoformat(),
                'source': last_threat_flow.src_ip,
                'destination': last_threat_flow.dst_ip,
                'agent': last_threat_flow.agent_id
            }
        
        return jsonify(summary)
        
    except Exception as e:
        logger.error(f"Error fetching threats summary: {e}")
        return jsonify({'error': 'Unable to fetch threats summary'}), 500

@app.route('/api/delete_all_data', methods=['POST'])
@csrf.exempt
def delete_all_data():
    """Delete all data from database"""
    try:
        # Delete all records from all tables
        SecurityAlert.query.delete()
        NetworkFlow.query.delete()
        IsolationAction.query.delete()
        Agent.query.delete()
        
        # Commit the changes
        db.session.commit()
        
        logger.info("All data has been successfully deleted from the database")
        
        return jsonify({
            'success': True,
            'message': 'All data has been successfully deleted from the database'
        })
        
    except Exception as e:
        logger.error(f"Error deleting all data: {e}")
        db.session.rollback()
        
        return jsonify({
            'success': False,
            'message': f'Error deleting data: {str(e)}'
        }), 500

# ==================== BACKGROUND TASKS ====================

def train_detection_model():
    """Periodically retrain the detection model"""
    while True:
        try:
            time.sleep(3600)  # Train every hour
            
            # Get recent flows for training
            recent_flows = NetworkFlow.query.filter(
                NetworkFlow.created_at > get_utc7_now() - timedelta(days=7)
            ).all()
            
            if len(recent_flows) > 100:
                threat_detector.train_model(recent_flows)
                logger.info("Detection model retrained")
            
        except Exception as e:
            logger.error(f"Error in model training: {e}")

def cleanup_old_data():
    """Clean up old data periodically"""
    while True:
        try:
            time.sleep(86400)  # Clean up daily
            
            # Delete old flows (older than 30 days)
            old_flows = NetworkFlow.query.filter(
                NetworkFlow.created_at < get_utc7_now() - timedelta(days=30)
            ).delete()
            
            # Delete resolved old alerts (older than 7 days)
            old_alerts = SecurityAlert.query.filter(
                SecurityAlert.created_at < get_utc7_now() - timedelta(days=7),
                SecurityAlert.is_resolved == True
            ).delete()
            
            db.session.commit()
            logger.info(f"Cleaned up {old_flows} old flows and {old_alerts} old alerts")
            
        except Exception as e:
            logger.error(f"Error in cleanup: {e}")

# ==================== DATABASE MIGRATION HELPER ====================

def migrate_database():
    """Handle database migrations for schema changes"""
    try:
        with db.engine.connect() as conn:
            # Detect database type
            db_url = str(db.engine.url)
            is_postgres = 'postgresql' in db_url
            
            if is_postgres:
                # PostgreSQL migration - check information_schema
                logger.info("Detected PostgreSQL database - skipping migration (tables created via db.create_all())")
                return
            else:
                # SQLite migration using PRAGMA
                # Check agent table for isolated_until column
                result = conn.execute(db.text("PRAGMA table_info(agent)")).fetchall()
                agent_columns = [row[1] for row in result]  # Column names are in index 1
                
                if 'isolated_until' not in agent_columns:
                    logger.info("Adding missing 'isolated_until' column to agent table")
                    conn.execute(db.text("ALTER TABLE agent ADD COLUMN isolated_until DATETIME"))
                    conn.commit()
                    logger.info("Successfully added 'isolated_until' column")
                else:
                    logger.info("Agent table 'isolated_until' column exists")
                    
                # Check network_flow table for classification column
                result = conn.execute(db.text("PRAGMA table_info(network_flow)")).fetchall()
                flow_columns = [row[1] for row in result]  # Column names are in index 1
                
                if 'classification' not in flow_columns:
                    logger.info("Adding missing 'classification' column to network_flow table")
                    conn.execute(db.text("ALTER TABLE network_flow ADD COLUMN classification VARCHAR(20) DEFAULT 'Benign'"))
                    conn.commit()
                    logger.info("Successfully added 'classification' column")
                else:
                    logger.info("Network flow table 'classification' column exists")
                
    except Exception as e:
        logger.error(f"Error during database migration: {e}")
        # Don't raise - migration is optional

import os
from werkzeug.utils import secure_filename
import math

FILE_MANAGER_DIR = os.path.join(app.root_path, 'storage')
os.makedirs(FILE_MANAGER_DIR, exist_ok=True)

def get_file_size(size_in_bytes):
    if size_in_bytes == 0:
        return '0B'
    size_name = ('B', 'KB', 'MB', 'GB', 'TB')
    i = int(math.floor(math.log(size_in_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_in_bytes / p, 2)
    return f'{s} {size_name[i]}'

@app.route('/file-manager/api/list', methods=['GET', 'POST'])
@csrf.exempt
def dummy_api_list():
    return jsonify({"success": True, "files": [], "folders": []})

@app.route('/file-manager/api/mkdir', methods=['POST'])
@csrf.exempt
def dummy_api_mkdir():
    return jsonify({"success": True})

@app.route('/file-manager/api/upload', methods=['POST'])
@csrf.exempt
def dummy_api_upload():
    return jsonify({"success": True})

@app.route('/file_manager')
def file_manager():
    agents = Agent.query.order_by(Agent.last_seen.desc()).all()
    return render_template('file_manager.html', agents=agents)

@app.route('/file_manager/snapshot', methods=['POST'])
@csrf.exempt
def create_snapshot():
    snapshot_path = os.path.join(app.instance_path, 'storage_snapshot.json')
    snapshot_data = {'files': {}, 'timestamp': get_utc7_now().strftime('%Y-%m-%d %H:%M:%S')}
    
    for filename in os.listdir(FILE_MANAGER_DIR):
        file_path = os.path.join(FILE_MANAGER_DIR, filename)
        if os.path.isfile(file_path):
            stat = os.stat(file_path)
            snapshot_data['files'][filename] = stat.st_mtime
            
    with open(snapshot_path, 'w', encoding='utf-8') as f:
        json.dump(snapshot_data, f)
        
    flash('Đã tạo mốc theo dõi mới. Hệ thống sẽ báo các file được thêm/sửa đổi sau thời điểm này.', 'success')
    return redirect(url_for('file_manager'))


@app.route('/file_manager/upload', methods=['POST'])
@csrf.exempt
def upload_file():
    if 'file' not in request.files:
        flash('Không tìm thấy tệp đính kèm.', 'danger')
        return redirect(url_for('file_manager'))
    
    file = request.files['file']
    if file.filename == '':
        flash('Chưa chọn tệp nào.', 'danger')
        return redirect(url_for('file_manager'))
        
    if file:
        filename = secure_filename(file.filename)
        file.save(os.path.join(FILE_MANAGER_DIR, filename))
        flash(f'Đã tải lên {filename} thành công!', 'success')
        
    return redirect(url_for('file_manager'))

@app.route('/file_manager/delete/<filename>', methods=['POST'])
@csrf.exempt
def delete_file(filename):
    file_path = os.path.join(FILE_MANAGER_DIR, secure_filename(filename))
    if os.path.exists(file_path):
        os.remove(file_path)
        flash(f'Đã xoá {filename}.', 'success')
    else:
        flash('Tệp không tồn tại.', 'danger')
    return redirect(url_for('file_manager'))

@app.route('/file_manager/download/<filename>')
def download_file(filename):
    return send_from_directory(FILE_MANAGER_DIR, secure_filename(filename), as_attachment=True)


@app.route('/api/agent/<agent_id>/file_request', methods=['GET'])
def get_file_request(agent_id):
    try:
        now = get_utc7_now()
        with FILE_LOCK:
            req = FILE_REQUESTS.get(agent_id)
            if not req:
                return jsonify({'has_request': False}), 200
            
            if (now - req['created_at']).total_seconds() > 30:
                FILE_REQUESTS.pop(agent_id, None)
                return jsonify({'has_request': False}), 200

            return jsonify({
                'has_request': True,
                'request_id': req['request_id'],
                'path': req.get('path', 'C:\\')
            }), 200
    except Exception as e:
        return jsonify({'has_request': False}), 200

@app.route('/api/agent/<agent_id>/file_result', methods=['POST'])
@csrf.exempt
def submit_file_result(agent_id):
    try:
        data = request.get_json() or {}
        request_id = data.get('request_id')
        success = bool(data.get('success', False))
        files = data.get('files', [])

        if not request_id:
            return jsonify({'ok': False, 'error': 'missing request_id'}), 400

        with FILE_LOCK:
            req = FILE_REQUESTS.get(agent_id)
            if req and req['request_id'] == request_id:
                FILE_RESULTS[request_id] = {
                    'success': success,
                    'path': data.get('path', ''),
                    'files': files,
                    'created_at': get_utc7_now()
                }
                FILE_REQUESTS.pop(agent_id, None)

        agent = Agent.query.filter_by(agent_id=agent_id).first()
        if agent:
            agent.last_seen = get_utc7_now()
            db.session.commit()

        return jsonify({'ok': True}), 200
    except Exception as e:
        return jsonify({'ok': False, 'error': 'internal error'}), 500

@app.route('/api/get_files/<agent_id>')
@csrf.exempt
def get_agent_files(agent_id):
    try:
        agent = Agent.query.filter_by(agent_id=agent_id).first()
        if not agent:
            return jsonify({'success': False, 'message': 'Agent not found'}), 404
            
        request_id = uuid.uuid4().hex
        requested_path = request.args.get('path', 'C:\\')
        if not requested_path:
            requested_path = 'C:\\'
        with FILE_LOCK:
            FILE_REQUESTS[agent_id] = {
                'request_id': request_id,
                'path': requested_path,
                'created_at': get_utc7_now()
            }
            
        timeout_at = time.time() + 12
        while time.time() < timeout_at:
            with FILE_LOCK:
                result = FILE_RESULTS.pop(request_id, None)
            if result:
                files = result.get('files', [])
                
                # Apply snapshot logic
                snapshot_path = os.path.join(app.instance_path, f'storage_snapshot_{agent_id}.json')
                last_snapshot = None
                snapshot_data = {}
                
                if os.path.exists(snapshot_path):
                    try:
                        with open(snapshot_path, 'r', encoding='utf-8') as sf:
                            data = json.load(sf)
                            snapshot_data = data.get('files', {})
                            last_snapshot = data.get('timestamp')
                    except Exception:
                        pass
                
                for f in files:
                    is_new = False
                    if last_snapshot:
                        if f['name'] not in snapshot_data:
                            is_new = True
                        elif f['modified'] > snapshot_data[f['name']]: # Basic string comparison works for YYYY-MM-DD HH:MM:SS
                            is_new = True
                    f['is_new'] = is_new
                
                files = sorted(files, key=lambda x: (not x['is_new'], x['name']))
                
                return jsonify({
                    'success': True,
                    'agent_id': agent_id,
                    'hostname': agent.hostname,
                    'current_path': result.get('path', requested_path),
                    'files': files,
                    'last_snapshot': last_snapshot
                }), 200
            time.sleep(0.5)
            
        return jsonify({
            'success': False,
            'message': 'Timed out waiting for agent file data',
            'files': []
        }), 504
        
    except Exception as e:
        logger.error(f"Error fetching files for agent {agent_id}: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/snapshot_files/<agent_id>', methods=['POST'])
@csrf.exempt
def snapshot_agent_files(agent_id):
    try:
        data = request.get_json() or {}
        files = data.get('files', [])
        
        snapshot_path = os.path.join(app.instance_path, f'storage_snapshot_{agent_id}.json')
        snapshot_data = {'files': {}, 'timestamp': get_utc7_now().strftime('%Y-%m-%d %H:%M:%S')}
        
        for f in files:
            snapshot_data['files'][f['name']] = f['modified']
            
        with open(snapshot_path, 'w', encoding='utf-8') as sf:
            json.dump(snapshot_data, sf)
            
        return jsonify({'success': True, 'message': 'Snapshot created'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/file-manager/api/list', methods=['POST'])
@csrf.exempt
def file_manager_list():
    return jsonify({"success": True, "files": []})

# ==================== APPLICATION STARTUP ====================

if __name__ == '__main__':
    # Create database tables
    with app.app_context():
        db.create_all()
        # Run database migrations
        migrate_database()
        logger.info("Database initialized and migrated")
    
    # Start background threads
    model_thread = threading.Thread(target=train_detection_model, daemon=True)
    model_thread.start()
    
    cleanup_thread = threading.Thread(target=cleanup_old_data, daemon=True)
    cleanup_thread.start()
    
    logger.info("Network Security Management System started")
    
    # Run Flask app
    app.run(host='0.0.0.0', port=5000, debug=True)
