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
import subprocess
import uuid
import ctypes
from datetime import datetime, timedelta
from pytz import timezone
from collections import deque
import os
import sys

# UTC+7 timezone
UTC_PLUS_7 = timezone('Asia/Bangkok')

def is_admin():
    """Check if running with Administrator privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def request_elevation():
    """Re-launch current script with UAC elevation prompt"""
    try:
        # Get the script path and arguments
        script = sys.argv[0]
        params = ' '.join(sys.argv[1:])
        # ShellExecute with 'runas' triggers UAC prompt
        ret = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, f'"{script}" {params}', None, 1
        )
        if ret <= 32:
            print(f"[!] Failed to elevate (code {ret}). Please run as Administrator manually.")
        sys.exit(0)
    except Exception as e:
        print(f"[!] Could not request elevation: {e}")
        print("    Please right-click and run as Administrator.")
        sys.exit(1)

# UTC+7 timezone
UTC_PLUS_7 = timezone('Asia/Bangkok')

def get_utc7_now():
    """Get current datetime in UTC+7 timezone"""
    return datetime.now(UTC_PLUS_7).replace(tzinfo=None)

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
                'timestamp': flow_data.get('Timestamp', get_utc7_now().isoformat())
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
                
                # Handle instructions - only act on explicit server instructions
                if 'INCREASE_MONITORING' in instructions:
                    self.logger.warning("Increasing monitoring frequency due to security concerns")
                    self.upload_interval = 10  # Faster updates
                else:
                    self.upload_interval = 30  # Normal updates
                
                return status_data
            else:
                self.logger.error(f"Failed to check status: {response.status_code}")
                return None
                
        except Exception as e:
            self.logger.error(f"Error checking agent status: {e}")
            return None

    def execute_isolation(self):
        """Execute network isolation using Windows Firewall"""
        try:
            # Check if already isolated (we can use a flag or check if rule exists)
            # For simplicity, we'll try to add rules; netsh will handle if they exist
            
            # Get server IP to allow communication
            server_host = self.server_url.split('//')[-1].split(':')[0]
            try:
                server_ip = socket.gethostbyname(server_host)
            except:
                server_ip = None

            # Isolation commands: Block all except management server
            commands = [
                # Block all inbound by default
                f'netsh advfirewall firewall add rule name="Manager_Isolation_In" dir=in action=block remoteip=any',
                # Block all outbound by default
                f'netsh advfirewall firewall add rule name="Manager_Isolation_Out" dir=out action=block remoteip=any'
            ]
            
            # Add allow rules for the server BEFORE the block rules or with higher priority
            # In Windows Firewall, Block rules usually take precedence unless we use specific allow rules
            # Actually, a better way is to allow the specific IP
            if server_ip and server_ip != '127.0.0.1':
                commands.insert(0, f'netsh advfirewall firewall add rule name="Manager_Allow_In" dir=in action=allow remoteip={server_ip}')
                commands.insert(1, f'netsh advfirewall firewall add rule name="Manager_Allow_Out" dir=out action=allow remoteip={server_ip}')
            
            for cmd in commands:
                subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            self.logger.critical("NETWORK ISOLATION ENFORCED - Only management communication allowed")
            
        except Exception as e:
            self.logger.error(f"Error enforcing isolation: {e}")

    def execute_restoration(self):
        """Remove network isolation rules"""
        try:
            commands = [
                'netsh advfirewall firewall delete rule name="Manager_Isolation_In"',
                'netsh advfirewall firewall delete rule name="Manager_Isolation_Out"',
                'netsh advfirewall firewall delete rule name="Manager_Allow_In"',
                'netsh advfirewall firewall delete rule name="Manager_Allow_Out"'
            ]
            
            for cmd in commands:
                subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
            self.logger.info("Network connectivity restored")
            
        except Exception as e:
            self.logger.error(f"Error restoring connectivity: {e}")

    def get_network_adapters(self):
        """Get list of active network adapters"""
        try:
            cmd = 'Get-NetAdapter -Physical | Select-Object -Property Name, InterfaceDescription, Status | ConvertTo-Json'
            result = subprocess.run(
                ['powershell', '-Command', cmd],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                try:
                    adapters = json.loads(result.stdout)
                    # Handle single adapter case (returns dict instead of list)
                    if isinstance(adapters, dict):
                        adapters = [adapters]
                    return adapters
                except:
                    self.logger.warning(f"Failed to parse adapters: {result.stdout}")
                    return []
            else:
                self.logger.error(f"Failed to get adapters: {result.stderr}")
                return []
        except Exception as e:
            self.logger.error(f"Error getting network adapters: {e}")
            return []

    def disable_network_adapter(self, adapter_name=None):
        """Disable network adapter - actual network isolation"""
        try:
            if not adapter_name:
                # Get the first active adapter
                adapters = self.get_network_adapters()
                if adapters:
                    adapter_name = adapters[0].get('Name') or adapters[0].get('name')
                
                if not adapter_name:
                    self.logger.error("Could not find network adapter to disable")
                    return False, None
            
            cmd = f'Disable-NetAdapter -Name "{adapter_name}" -Confirm:$false'
            self.logger.critical(f">>> Executing: Disable-NetAdapter -Name '{adapter_name}'")
            result = subprocess.run(
                ['powershell', '-Command', cmd],
                capture_output=True,
                text=True,
                shell=False
            )
            
            self.logger.critical(f"PowerShell stdout: {result.stdout}")
            if result.stderr:
                self.logger.error(f"PowerShell stderr: {result.stderr}")
            
            if result.returncode == 0:
                self.logger.critical(f"NETWORK ISOLATED - Adapter '{adapter_name}' DISABLED")
                return True, adapter_name
            else:
                self.logger.error(f"Failed to disable adapter '{adapter_name}' (rc={result.returncode}): {result.stderr}")
                self.logger.error("Hint: The agent must be run as Administrator to disable network adapters.")
                return False, adapter_name
                
        except Exception as e:
            self.logger.error(f"Error disabling network adapter: {e}")
            return False, None

    def enable_network_adapter(self, adapter_name=None):
        """Enable network adapter - restore connectivity"""
        try:
            if not adapter_name:
                # Try to find disabled adapters
                adapters = self.get_network_adapters()
                if adapters:
                    adapter_name = adapters[0].get('Name') or adapters[0].get('name')
                
                if not adapter_name:
                    self.logger.error("Could not find network adapter to enable")
                    return False, None
            
            cmd = f'Enable-NetAdapter -Name "{adapter_name}" -Confirm:$false'
            result = subprocess.run(
                ['powershell', '-Command', cmd],
                capture_output=True,
                text=True,
                shell=False
            )
            
            if result.returncode == 0:
                self.logger.info(f"Network connectivity RESTORED - Adapter '{adapter_name}' ENABLED")
                return True, adapter_name
            else:
                self.logger.error(f"Failed to enable adapter: {result.stderr}")
                return False, adapter_name
                
        except Exception as e:
            self.logger.error(f"Error enabling network adapter: {e}")
            return False, None

    def auto_restore_network(self, adapter_name):
        """Callback to automatically restore network after isolation duration expires"""
        self.logger.warning(f"Auto-restoring network for adapter: {adapter_name}")
        success, used_adapter = self.enable_network_adapter(adapter_name)
        
        if success:
            self.logger.info("Auto-restoration successful")
        else:
            self.logger.error("Auto-restoration failed")
            
    def handle_isolation_command(self, command):
        """Handle isolation commands from server"""
        try:
            action = command.get('action', '').lower()
            adapter_name = command.get('adapter_name')
            duration_minutes = command.get('duration_minutes')
            
            if action == 'isolate':
                success, used_adapter = self.disable_network_adapter(adapter_name)
                
                # Setup auto-restore if duration provided
                if success and duration_minutes and duration_minutes > 0:
                    self.logger.warning(f"Auto-restoration scheduled in {duration_minutes} minute(s)")
                    restore_timer = threading.Timer(duration_minutes * 60, self.auto_restore_network, args=[used_adapter])
                    restore_timer.daemon = True
                    restore_timer.start()

                return {
                    'success': success,
                    'action': 'isolate',
                    'adapter_name': used_adapter,
                    'error': '' if success else 'Failed to disable network adapter',
                    'timestamp': get_utc7_now().isoformat()
                }
            elif action == 'restore':
                success, used_adapter = self.enable_network_adapter(adapter_name)
                return {
                    'success': success,
                    'action': 'restore',
                    'adapter_name': used_adapter,
                    'error': '' if success else 'Failed to enable network adapter',
                    'timestamp': get_utc7_now().isoformat()
                }
            else:
                self.logger.error(f"Unknown isolation command: {action}")
                return {
                    'success': False,
                    'action': action,
                    'error': 'Unknown command',
                    'adapter_name': '',
                    'timestamp': get_utc7_now().isoformat()
                }
                
        except Exception as e:
            self.logger.error(f"Error handling isolation command: {e}")
            return {
                'success': False,
                'action': 'unknown',
                'error': str(e),
                'adapter_name': '',
                'timestamp': get_utc7_now().isoformat()
            }
    
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
        """Background worker to send heartbeat, check status, and poll for commands"""
        while self.is_running:
            try:
                if self.registered:
                    # Check agent status
                    self.check_agent_status()
                    
                    # Poll for pending commands (isolation/restoration)
                    self.poll_and_execute_commands()
                
                time.sleep(10)  # Check every 10 seconds for fast command delivery
                
            except Exception as e:
                self.logger.error(f"Error in heartbeat worker: {e}")
                time.sleep(10)
    
    def poll_and_execute_commands(self):
        """Poll server for pending commands and execute them"""
        try:
            response = requests.get(
                f"{self.server_url}/api/agent/{self.agent_id}/pending_command",
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('has_command'):
                    command = data.get('command', {})
                    self.logger.critical(f"====== COMMAND RECEIVED: {command.get('action')} ======")
                    self.logger.critical(f"Full command: {command}")
                    
                    # Execute the command
                    result = self.handle_isolation_command(command)
                    self.logger.critical(f"RESULT: success={result.get('success')}, adapter={result.get('adapter_name')}, error={result.get('error')}")
                    
                    # Report result back to server
                    self.report_command_result(result)
                    
        except Exception as e:
            self.logger.error(f"Error polling for commands: {e}")
    
    def report_command_result(self, result):
        """Report command execution result back to server"""
        try:
            data = {
                'agent_id': self.agent_id,
                'action': result.get('action'),
                'success': result.get('success'),
                'error': result.get('error', ''),
                'adapter_name': result.get('adapter_name', ''),
                'timestamp': result.get('timestamp')
            }
            
            response = requests.post(
                f"{self.server_url}/api/agent/{self.agent_id}/command_result",
                json=data,
                timeout=10
            )
            
            if response.status_code == 200:
                self.logger.info(f"Command result reported to server: {result.get('action')} = {result.get('success')}")
            else:
                self.logger.error(f"Failed to report command result: {response.status_code}")
                
        except Exception as e:
            self.logger.error(f"Error reporting command result: {e}")
    
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
    
    # Auto-elevate to Administrator if needed (required for Disable-NetAdapter)
    if not is_admin():
        print("[!] Not running as Administrator.")
        print("[*] Requesting elevation via UAC...")
        request_elevation()
        # request_elevation() calls sys.exit() so code below only runs if elevated
    
    print("[✓] Running as Administrator - network isolation will work.")
    
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
                'timestamp': get_utc7_now().isoformat()
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