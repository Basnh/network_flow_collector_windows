#!/usr/bin/env python3
"""
Security Management Agent Client
Integrates with network flow collector to send data to central management server
"""

import requests
import json
import time
import threading
import logging
import socket
import platform
import hashlib
import uuid
from datetime import datetime, timedelta
from collections import deque
import os

class SecurityAgentClient:
    """Client to communicate with Security Management Server"""
    
    def __init__(self, server_url='http://localhost:5000', agent_id=None, batch_size=50, upload_interval=30):
        self.server_url = server_url.rstrip('/')
        self.agent_id = agent_id or self.generate_agent_id()
        self.batch_size = batch_size
        self.upload_interval = upload_interval
        
        # Data queues
        self.flow_queue = deque(maxlen=1000)  # Store max 1000 flows
        self.is_running = True
        self.registered = False
        
        # Setup logging
        self.logger = logging.getLogger(f'SecurityAgent-{self.agent_id[:8]}')
        
        # System info
        self.hostname = socket.gethostname()
        self.ip_address = self.get_local_ip()
        self.os_info = self.get_system_info()
        
        # Start background threads
        self.upload_thread = threading.Thread(target=self.upload_worker, daemon=True)
        self.heartbeat_thread = threading.Thread(target=self.heartbeat_worker, daemon=True)
        
    def generate_agent_id(self):
        """Generate unique agent ID based on system characteristics"""
        system_info = f"{socket.gethostname()}-{platform.node()}-{platform.machine()}"
        return hashlib.md5(system_info.encode()).hexdigest()
    
    def get_local_ip(self):
        """Get local IP address"""
        try:
            # Connect to a remote address to get the local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
    
    def get_system_info(self):
        """Gather system information"""
        info = {
            'platform': platform.platform(),
            'system': platform.system(),
            'release': platform.release(),
            'version': platform.version(),
            'machine': platform.machine(),
            'processor': platform.processor(),
            'python_version': platform.python_version(),
        }
        return json.dumps(info, indent=2)
    
    def register_agent(self):
        """Register agent with the management server"""
        try:
            data = {
                'agent_id': self.agent_id,
                'hostname': self.hostname,
                'ip_address': self.ip_address,
                'os_info': self.os_info
            }
            
            response = requests.post(
                f"{self.server_url}/api/register_agent",
                json=data,
                timeout=10
            )
            
            if response.status_code == 200:
                self.registered = True
                self.logger.info(f"Agent registered successfully: {self.agent_id}")
                return True
            else:
                self.logger.error(f"Failed to register agent: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error registering agent: {e}")
            return False
    
    def add_flow(self, flow_data):
        """Add network flow to upload queue"""
        try:
            # Convert flow data to format expected by server
            formatted_flow = {
                'flow_id': flow_data.get('Flow ID', ''),
                'src_ip': flow_data.get('Source IP', ''),
                'dst_ip': flow_data.get('Destination IP', ''),
                'src_port': int(flow_data.get('Source Port', 0)) if flow_data.get('Source Port') else 0,
                'dst_port': int(flow_data.get('Destination Port', 0)) if flow_data.get('Destination Port') else 0,
                'protocol': flow_data.get('Protocol', ''),
                'payload_content': flow_data.get('Payload Content', ''),
                'timestamp': flow_data.get('Timestamp', datetime.utcnow().isoformat())
            }
            
            self.flow_queue.append(formatted_flow)
            self.logger.debug(f"Added flow to queue: {formatted_flow['flow_id']}")
            
        except Exception as e:
            self.logger.error(f"Error adding flow to queue: {e}")
    
    def upload_flows(self, flows):
        """Upload flows to management server"""
        try:
            if not flows:
                return True
                
            data = {
                'agent_id': self.agent_id,
                'flows': flows
            }
            
            response = requests.post(
                f"{self.server_url}/api/submit_flow",
                json=data,
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                threats_detected = result.get('threats_detected', 0)
                if threats_detected > 0:
                    self.logger.warning(f"Threats detected: {threats_detected}")
                
                # Check for isolation instructions
                agent_status = result.get('agent_status', 'active')
                if agent_status == 'isolated':
                    self.logger.critical("Agent has been isolated by security server!")
                
                return True
            else:
                self.logger.error(f"Failed to upload flows: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error uploading flows: {e}")
            return False
    
    def check_agent_status(self):
        """Check agent status and get instructions from server"""
        try:
            response = requests.get(
                f"{self.server_url}/api/agent_status/{self.agent_id}",
                timeout=10
            )
            
            if response.status_code == 200:
                status_data = response.json()
                
                # Log status changes
                status = status_data.get('status', 'unknown')
                threat_level = status_data.get('threat_level', 'unknown')
                instructions = status_data.get('instructions', [])
                
                self.logger.info(f"Agent status: {status}, Threat level: {threat_level}")
                
                # Handle instructions
                if 'NETWORK_ISOLATED' in instructions:
                    self.logger.critical("NETWORK ISOLATION ACTIVE - Agent is isolated from network")
                
                if 'INCREASE_MONITORING' in instructions:
                    self.logger.warning("Increasing monitoring frequency due to security concerns")
                
                return status_data
            else:
                self.logger.error(f"Failed to check status: {response.status_code}")
                return None
                
        except Exception as e:
            self.logger.error(f"Error checking agent status: {e}")
            return None
    
    def upload_worker(self):
        """Background worker to upload flows periodically"""
        while self.is_running:
            try:
                if not self.registered:
                    if self.register_agent():
                        self.logger.info("Agent registration successful")
                    else:
                        self.logger.warning("Agent registration failed, retrying in 30 seconds")
                        time.sleep(30)
                        continue
                
                # Collect flows to upload
                flows_to_upload = []
                while len(flows_to_upload) < self.batch_size and self.flow_queue:
                    flows_to_upload.append(self.flow_queue.popleft())
                
                if flows_to_upload:
                    success = self.upload_flows(flows_to_upload)
                    if success:
                        self.logger.info(f"Successfully uploaded {len(flows_to_upload)} flows")
                    else:
                        # Put flows back in queue if upload failed
                        for flow in reversed(flows_to_upload):
                            self.flow_queue.appendleft(flow)
                        self.logger.error("Failed to upload flows, will retry")
                
                time.sleep(self.upload_interval)
                
            except Exception as e:
                self.logger.error(f"Error in upload worker: {e}")
                time.sleep(30)
    
    def heartbeat_worker(self):
        """Background worker to send heartbeat and check status"""
        while self.is_running:
            try:
                if self.registered:
                    self.check_agent_status()
                
                time.sleep(60)  # Check every minute
                
            except Exception as e:
                self.logger.error(f"Error in heartbeat worker: {e}")
                time.sleep(60)
    
    def start(self):
        """Start the security agent client"""
        self.logger.info(f"Starting Security Agent Client: {self.agent_id}")
        self.logger.info(f"Server URL: {self.server_url}")
        self.logger.info(f"Hostname: {self.hostname} ({self.ip_address})")
        
        # Register agent immediately
        if self.register_agent():
            self.logger.info("Initial registration successful")
        
        # Start background threads
        self.upload_thread.start()
        self.heartbeat_thread.start()
        
        self.logger.info("Security Agent Client started successfully")
    
    def stop(self):
        """Stop the security agent client"""
        self.logger.info("Stopping Security Agent Client...")
        self.is_running = False
        
        # Upload any remaining flows
        remaining_flows = list(self.flow_queue)
        if remaining_flows:
            self.logger.info(f"Uploading {len(remaining_flows)} remaining flows...")
            self.upload_flows(remaining_flows)
        
        self.logger.info("Security Agent Client stopped")

# Integration function for network flow collector
def integrate_with_flow_collector(collector_instance, server_url='http://localhost:5000'):
    """
    Integrate SecurityAgentClient with WindowsNetworkFlowCollector
    
    Usage:
    collector = WindowsNetworkFlowCollector(...)
    agent_client = integrate_with_flow_collector(collector, 'http://your-server:5000')
    collector.start_collection()
    """
    
    # Create agent client
    agent_client = SecurityAgentClient(server_url)
    
    # Start agent client
    agent_client.start()
    
    # Override the save_individual_flow method to also send to server
    original_save_method = collector_instance.save_individual_flow
    
    def enhanced_save_flow(flow_id):
        """Enhanced save method that also sends data to security server"""
        try:
            # Call original save method first
            original_save_method(flow_id)
            
            # Extract flow data for agent client
            if flow_id in collector_instance.flows:
                flow = collector_instance.flows[flow_id]['first_packet']
                
                # Create flow data similar to CSV format
                flow_data = {
                    'Flow ID': flow_id,
                    'Source IP': flow.get('src_ip', ''),
                    'Destination IP': flow.get('dst_ip', ''),
                    'Source Port': flow.get('src_port', 0),
                    'Destination Port': flow.get('dst_port', 0),
                    'Protocol': flow.get('protocol', ''),
                    'Payload Content': collector_instance.flow_content.get(flow_id, ''),
                    'Timestamp': flow.get('timestamp', time.time())
                }
                
                # Convert timestamp to ISO format
                if isinstance(flow_data['Timestamp'], (int, float)):
                    flow_data['Timestamp'] = datetime.fromtimestamp(flow_data['Timestamp']).isoformat()
                
                # Send to agent client
                agent_client.add_flow(flow_data)
                
        except Exception as e:
            collector_instance.logger.error(f"Error in enhanced save flow: {e}")
    
    # Replace the save method
    collector_instance.save_individual_flow = enhanced_save_flow
    
    # Store agent client reference
    collector_instance.security_agent = agent_client
    
    return agent_client

# Example usage script
if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Security Agent Client')
    parser.add_argument('--server', default='http://localhost:5000', help='Security management server URL')
    parser.add_argument('--agent-id', help='Custom agent ID')
    parser.add_argument('--test-flows', type=int, default=0, help='Generate test flows for testing')
    
    args = parser.parse_args()
    
    # Setup logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    # Create and start agent
    agent = SecurityAgentClient(args.server, args.agent_id)
    agent.start()
    
    # Generate test flows if requested
    if args.test_flows > 0:
        print(f"Generating {args.test_flows} test flows...")
        for i in range(args.test_flows):
            test_flow = {
                'flow_id': f'test-flow-{i}',
                'src_ip': f'192.168.1.{100 + (i % 50)}',
                'dst_ip': f'10.0.0.{1 + (i % 10)}',
                'src_port': 1000 + (i % 65000),
                'dst_port': 80 if i % 2 else 443,
                'protocol': 'TCP',
                'payload_content': f'TCP: {i:04x} {i+1:04x} test payload data',
                'timestamp': datetime.utcnow().isoformat()
            }
            agent.add_flow(test_flow)
            time.sleep(0.1)
        
        print("Test flows generated")
    
    try:
        print("Agent running... Press Ctrl+C to stop")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping agent...")
        agent.stop()
        print("Agent stopped")