#!/usr/bin/env python3
"""
Network Security Management System
Collects data from agents and detects trojans/malware
"""

from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import json
import sqlite3
import threading
import time
import os
import hashlib
import socket
import subprocess
from collections import defaultdict
import logging
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///network_security.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Template context processor to make utility functions available in templates
@app.context_processor
def inject_datetime():
    return {
        'datetime': datetime,
        'min': min,
        'max': max,
        'len': len,
        'abs': abs,
        'round': round,
        'int': int,
        'str': str
    }

# ==================== DATABASE MODELS ====================

class Agent(db.Model):
    """Agent devices running network collectors"""
    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.String(100), unique=True, nullable=False)
    hostname = db.Column(db.String(200), nullable=False)
    ip_address = db.Column(db.String(50), nullable=False)
    os_info = db.Column(db.Text)
    status = db.Column(db.String(20), default='active')  # active, disconnected, isolated
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    threat_level = db.Column(db.String(20), default='low')  # low, medium, high, critical
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    isolated_until = db.Column(db.DateTime, nullable=True) # For timed isolation
    
    # Relationships
    flows = db.relationship('NetworkFlow', backref='agent', lazy=True, cascade='all, delete-orphan')
    alerts = db.relationship('SecurityAlert', backref='agent', lazy=True, cascade='all, delete-orphan')

class NetworkFlow(db.Model):
    """Network flow data from agents"""
    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.String(100), db.ForeignKey('agent.agent_id'), nullable=False)
    flow_id = db.Column(db.String(200), nullable=False)
    src_ip = db.Column(db.String(50), nullable=False)
    dst_ip = db.Column(db.String(50), nullable=False)
    src_port = db.Column(db.Integer)
    dst_port = db.Column(db.Integer)
    protocol = db.Column(db.String(10))
    payload_content = db.Column(db.Text)  # Hex dump content
    threat_score = db.Column(db.Float, default=0.0)
    is_malicious = db.Column(db.Boolean, default=False)
    classification = db.Column(db.String(20), default='Benign') # Benign, Trojan
    timestamp = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

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
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class IsolationAction(db.Model):
    """Network isolation actions"""
    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.String(100), nullable=False)
    action_type = db.Column(db.String(50), nullable=False)  # isolate, restore
    reason = db.Column(db.Text)
    executed_at = db.Column(db.DateTime, default=datetime.utcnow)
    success = db.Column(db.Boolean, default=False)

# ==================== THREAT DETECTION ENGINE ====================

class ThreatDetector:
    """AI-powered threat detection system"""
    
    def __init__(self):
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.scaler = StandardScaler()
        self.trojan_signatures = self.load_trojan_signatures()
        self.is_trained = False
        
    def load_trojan_signatures(self):
        """Load known trojan/malware signatures"""
        return {
            # Common trojan patterns in hex
            'backdoor_pattern_1': '4d5a90000300000004000000ffff0000',
            'backdoor_pattern_2': '00000000000000000000000000000000',
            'trojan_connect_back': '636f6e6e656374206261636b',  # "connect back" in hex
            'remote_shell': '2f62696e2f7368',  # "/bin/sh" in hex
            'cmd_exe': '636d642e657865',  # "cmd.exe" in hex
            'powershell': '706f7765727368656c6c',  # "powershell" in hex
            'suspicious_dns': '74756e6e656c',  # "tunnel" in hex
            'botnet_command': '626f746e6574',  # "botnet" in hex
        }
    
    def extract_flow_features(self, flow):
        """Extract features from network flow for ML analysis"""
        features = []
        
        # Basic flow features
        features.append(flow.src_port or 0)
        features.append(flow.dst_port or 0)
        features.append(len(flow.payload_content) if flow.payload_content else 0)
        
        # Protocol encoding
        protocol_map = {'TCP': 1, 'UDP': 2, 'ICMP': 3}
        features.append(protocol_map.get(flow.protocol, 0))
        
        # Time-based features
        hour = flow.timestamp.hour if flow.timestamp else 0
        features.append(hour)
        features.append(1 if 22 <= hour <= 6 else 0)  # Suspicious hours
        
        # Payload analysis
        if flow.payload_content:
            hex_content = flow.payload_content.replace(' ', '').lower()
            
            # Entropy calculation (simplified)
            if len(hex_content) > 0:
                entropy = self.calculate_entropy(hex_content)
                features.append(entropy)
            else:
                features.append(0)
                
            # Signature matches
            signature_matches = sum(1 for sig in self.trojan_signatures.values() 
                                  if sig in hex_content)
            features.append(signature_matches)
            
            # Suspicious patterns
            features.append(1 if 'exe' in hex_content else 0)
            features.append(1 if 'dll' in hex_content else 0)
            features.append(1 if len(set(hex_content)) < len(hex_content) * 0.3 else 0)  # Low entropy
        else:
            features.extend([0, 0, 0, 0, 0])
        
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
    
    def detect_payload_threats(self, payload_content):
        """Detect threats in payload content"""
        if not payload_content:
            return 0.0, []
        
        threats_found = []
        threat_score = 0.0
        
        hex_content = payload_content.replace(' ', '').lower()
        
        # Check for known signatures
        for name, signature in self.trojan_signatures.items():
            if signature in hex_content:
                threats_found.append(f"Trojan signature detected: {name}")
                threat_score += 0.8
        
        # Check suspicious patterns
        if 'reverse' in hex_content:
            threats_found.append("Reverse shell pattern detected")
            threat_score += 0.6
            
        if len(set(hex_content)) < len(hex_content) * 0.2:
            threats_found.append("Encrypted/packed payload detected")
            threat_score += 0.4
            
        # Check for executable headers
        exe_patterns = ['4d5a', '7f454c46', 'cafebabe', 'feedface']
        for pattern in exe_patterns:
            if hex_content.startswith(pattern):
                threats_found.append(f"Executable header detected: {pattern}")
                threat_score += 0.7
        
        return min(threat_score, 1.0), threats_found
    
    def train_model(self, flows):
        """Train the anomaly detection model"""
        if len(flows) < 10:
            logger.warning("Not enough data to train model")
            return
        
        try:
            features_list = []
            for flow in flows:
                features = self.extract_flow_features(flow)
                features_list.append(features)
            
            if features_list:
                X = np.array(features_list)
                X_scaled = self.scaler.fit_transform(X)
                self.isolation_forest.fit(X_scaled)
                self.is_trained = True
                logger.info(f"Model trained with {len(features_list)} samples")
        except Exception as e:
            logger.error(f"Error training model: {e}")
    
    def predict_threat(self, flow):
        """Predict if a flow is malicious"""
        # Payload-based detection
        payload_score, payload_threats = self.detect_payload_threats(flow.payload_content)
        
        # ML-based anomaly detection
        ml_score = 0.0
        if self.is_trained:
            try:
                features = self.extract_flow_features(flow)
                X = np.array([features])
                X_scaled = self.scaler.transform(X)
                anomaly_score = self.isolation_forest.decision_function(X_scaled)[0]
                # Convert to 0-1 range
                ml_score = max(0, min(1, (0.5 - anomaly_score) * 2))
            except Exception as e:
                logger.error(f"Error in ML prediction: {e}")
        
        # Combine scores
        combined_score = max(payload_score, ml_score)
        
        return combined_score, payload_threats

# Initialize threat detector
threat_detector = ThreatDetector()

# ==================== API ENDPOINTS ====================

@app.route('/api/register_agent', methods=['POST'])
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
            agent.last_seen = datetime.utcnow()
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
        
        agent.last_seen = datetime.utcnow()
        
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
                    timestamp=datetime.fromisoformat(flow_data.get('timestamp', datetime.utcnow().isoformat()))
                )
                
                # Threat analysis
                threat_score, payload_threats = threat_detector.predict_threat(flow)
                flow.threat_score = threat_score
                flow.is_malicious = threat_score > 0.7
                flow.classification = 'Trojan' if flow.is_malicious else 'Benign'
                
                db.session.add(flow)
                
                # Create security alert if high threat
                if flow.is_malicious:
                    threats_detected += 1
                    severity = 'critical' if threat_score > 0.9 else 'high'
                    
                    alert = SecurityAlert(
                        agent_id=agent_id,
                        alert_type='trojan' if 'trojan' in ' '.join(payload_threats).lower() else 'suspicious_traffic',
                        severity=severity,
                        title=f"Malicious traffic detected from {flow.src_ip}",
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
        
        # Auto-isolation for critical threats
        if threats_detected > 5 or agent.threat_level == 'critical':
            isolate_agent_network(agent_id, f"Auto-isolation: {threats_detected} threats detected")
        
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
def get_agent_status(agent_id):
    """Get agent status and instructions"""
    agent = Agent.query.filter_by(agent_id=agent_id).first()
    
    if not agent:
        return jsonify({'error': 'Agent not found'}), 404
    
    # Check if agent should be isolated
    recent_alerts = SecurityAlert.query.filter_by(agent_id=agent_id)\
        .filter(SecurityAlert.created_at > datetime.utcnow() - timedelta(hours=1))\
        .filter_by(is_resolved=False).count()
    
    # Check for isolation expiry
    if agent.status == 'isolated' and agent.isolated_until:
        if datetime.utcnow() > agent.isolated_until:
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

# ==================== NETWORK ISOLATION ====================

def isolate_agent_network(agent_id, reason, duration_minutes=None):
    """Isolate agent from network by setting status in database"""
    try:
        agent = Agent.query.filter_by(agent_id=agent_id).first()
        if not agent:
            return False
            
        # Calculate expiry if duration provided
        isolated_until = None
        if duration_minutes and duration_minutes > 0:
            isolated_until = datetime.utcnow() + timedelta(minutes=duration_minutes)
        
        # Update agent status
        agent.status = 'isolated'
        agent.isolated_until = isolated_until
        
        # Log isolation action
        isolation_action = IsolationAction(
            agent_id=agent_id,
            action_type='isolate',
            reason=f"{reason} (Duration: {duration_minutes if duration_minutes else 'Indefinite'})",
            success=True
        )
        db.session.add(isolation_action)
        db.session.commit()
        
        logger.info(f"Agent {agent_id} flagged for isolation: {reason}")
        return True
        
    except Exception as e:
        logger.error(f"Error flagging agent {agent_id} for isolation: {e}")
        return False

def restore_agent_network(agent_id, reason):
    """Restore agent network access by updating database status"""
    try:
        agent = Agent.query.filter_by(agent_id=agent_id).first()
        if not agent:
            return False
        
        # Update agent status
        agent.status = 'active'
        agent.threat_level = 'low'
        agent.isolated_until = None
        
        # Log restoration action
        isolation_action = IsolationAction(
            agent_id=agent_id,
            action_type='restore',
            reason=reason,
            success=True
        )
        db.session.add(isolation_action)
        db.session.commit()
        
        logger.info(f"Agent {agent_id} flag cleared: {reason}")
        return True
        
    except Exception as e:
        logger.error(f"Error clearing isolation flag for agent {agent_id}: {e}")
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
    
    return render_template('dashboard.html',
                         total_agents=total_agents,
                         active_agents=active_agents,
                         isolated_agents=isolated_agents,
                         recent_alerts=recent_alerts,
                         critical_agents=critical_agents,
                         threat_flows=threat_flows)

@app.route('/agents')
def agents_list():
    """List all agents"""
    agents = Agent.query.order_by(Agent.last_seen.desc()).all()
    return render_template('agents.html', agents=agents)

@app.route('/agent/<agent_id>')
def agent_detail(agent_id):
    """Agent detail page"""
    agent = Agent.query.filter_by(agent_id=agent_id).first_or_404()
    
    # Get agent flows
    flows = NetworkFlow.query.filter_by(agent_id=agent_id)\
        .order_by(NetworkFlow.created_at.desc()).limit(50).all()
    
    # Get agent alerts
    alerts = SecurityAlert.query.filter_by(agent_id=agent_id)\
        .order_by(SecurityAlert.created_at.desc()).limit(20).all()
    
    return render_template('agent_detail.html', agent=agent, flows=flows, alerts=alerts)

@app.route('/alerts')
def alerts_list():
    """List all security alerts"""
    alerts = SecurityAlert.query.order_by(SecurityAlert.created_at.desc()).all()
    return render_template('alerts.html', alerts=alerts)

@app.route('/isolate/<agent_id>', methods=['POST'])
def isolate_agent_web(agent_id):
    """Isolate agent via web interface"""
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
        flash(f'Agent {agent_id} has been isolated from the network.', 'success')
    else:
        flash(f'Failed to isolate agent {agent_id}.', 'error')
    
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
def resolve_alert(alert_id):
    """Mark alert as resolved"""
    alert = SecurityAlert.query.get_or_404(alert_id)
    alert.is_resolved = True
    db.session.commit()
    
    flash('Alert marked as resolved.', 'success')
    return redirect(url_for('alerts_list'))

# ==================== API ENDPOINTS FOR REAL-TIME FEATURES ====================

@app.route('/api/dashboard/stats')
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
                NetworkFlow.created_at >= datetime.utcnow().replace(hour=0, minute=0, second=0)
            ).count(),
            'last_updated': datetime.utcnow().isoformat()
        }
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error fetching dashboard stats: {e}")
        return jsonify({'error': 'Unable to fetch stats'}), 500

@app.route('/api/agents/<agent_id>/status')
def api_agent_status(agent_id):
    """Get real-time agent status"""
    try:
        agent = Agent.query.filter_by(agent_id=agent_id).first_or_404()
        
        # Check if agent is recently seen (within last 2 minutes)
        last_seen_threshold = datetime.utcnow() - timedelta(minutes=2)
        is_online = agent.last_seen and agent.last_seen > last_seen_threshold
        
        current_status = 'online' if is_online else 'offline'
        status_changed = current_status != agent.status
        
        # Update status if changed
        if status_changed:
            agent.status = current_status
            db.session.commit()
        
        return jsonify({
            'agent_id': agent.agent_id,
            'hostname': agent.hostname,
            'status': current_status,
            'last_seen': agent.last_seen.strftime('%Y-%m-%d %H:%M:%S') if agent.last_seen else 'Never',
            'threat_level': agent.threat_level,
            'status_changed': status_changed
        })
    except Exception as e:
        logger.error(f"Error fetching agent status: {e}")
        return jsonify({'error': 'Unable to fetch agent status'}), 500

@app.route('/api/activity/latest')
def api_latest_activity():
    """Get latest system activities"""
    try:
        activities = []
        
        # Recent alerts (last 10)
        recent_alerts = SecurityAlert.query.filter(
            SecurityAlert.created_at >= datetime.utcnow() - timedelta(hours=1)
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
            Agent.last_seen >= datetime.utcnow() - timedelta(minutes=10)
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
def api_threats_summary():
    """Get threat summary for real-time updates"""
    try:
        now = datetime.utcnow()
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

# ==================== BACKGROUND TASKS ====================

def train_detection_model():
    """Periodically retrain the detection model"""
    while True:
        try:
            time.sleep(3600)  # Train every hour
            
            # Get recent flows for training
            recent_flows = NetworkFlow.query.filter(
                NetworkFlow.created_at > datetime.utcnow() - timedelta(days=7)
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
                NetworkFlow.created_at < datetime.utcnow() - timedelta(days=30)
            ).delete()
            
            # Delete resolved old alerts (older than 7 days)
            old_alerts = SecurityAlert.query.filter(
                SecurityAlert.created_at < datetime.utcnow() - timedelta(days=7),
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
        raise e

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