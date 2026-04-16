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
import configparser
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

def get_file_size(size_in_bytes):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_in_bytes < 1024.0:
            return f"{size_in_bytes:.1f} {unit}"
        size_in_bytes /= 1024.0
    return f"{size_in_bytes:.1f} PB"

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
        
        # Isolation state tracking
        self.icmp_echo_initial_state = None  # Track initial state of Echo Request rules
        
        # Setup logging
        self.logger = logging.getLogger(f'SecurityAgent-{self.agent_id[:8]}')
        
        # Load constraints from config file
        self.load_config()
        
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
    
    def load_config(self, config_path='config.ini'):
        """Load optional configuration file if it exists"""
        if os.path.exists(config_path):
            try:
                config = configparser.ConfigParser()
                config.read(config_path)
                
                if 'Agent' in config:
                    if 'server_url' in config['Agent'] and config['Agent']['server_url']:
                        # Prefer config's server_url if the instance was initialized with default
                        if self.server_url == 'http://localhost:5000':
                            self.server_url = config['Agent']['server_url'].rstrip('/')
                    if 'agent_id' in config['Agent'] and config['Agent']['agent_id']:
                        self.agent_id = config['Agent']['agent_id']
                    if 'batch_size' in config['Agent'] and config['Agent']['batch_size'].isdigit():
                        self.batch_size = int(config['Agent']['batch_size'])
                    if 'upload_interval' in config['Agent'] and config['Agent']['upload_interval'].isdigit():
                        self.upload_interval = int(config['Agent']['upload_interval'])
                        
                self.logger.info(f"Loaded config parameters from {config_path}")
                return True
            except Exception as e:
                self.logger.error(f"Failed to load config: {e}")
        return False
    
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
            
            # Khôi phục việc gửi mảng 80+ features từ Agent lên Server thay vì bị drop
            if 'ml_features' in flow_data:
                formatted_flow['ml_features'] = flow_data['ml_features']
            
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
    
    def get_icmp_echo_current_state(self):
        """Check current state of ICMP Echo Request rules
        
        Returns tuple: (has_enabled, has_disabled)
        - has_enabled: True if any Echo Request rule is enabled
        - has_disabled: True if any Echo Request rule is disabled
        """
        try:
            ps_cmd = """
            $rules = Get-NetFirewallRule -DisplayName "*Echo Request*" -ErrorAction SilentlyContinue
            if ($rules) {
                $enabled = @($rules | Where-Object { $_.Enabled -eq $true } ).Count
                $disabled = @($rules | Where-Object { $_.Enabled -eq $false } ).Count
                Write-Output "$enabled,$disabled"
            } else {
                Write-Output "0,0"
            }
            """
            result = subprocess.run(['powershell', '-Command', ps_cmd], capture_output=True, text=True)
            
            if result.returncode == 0:
                counts = result.stdout.strip().split(',')
                enabled_count = int(counts[0]) if len(counts) > 0 else 0
                disabled_count = int(counts[1]) if len(counts) > 1 else 0
                
                has_enabled = enabled_count > 0
                has_disabled = disabled_count > 0
                
                self.logger.debug(f"ICMP Echo State: {enabled_count} enabled, {disabled_count} disabled")
                return (has_enabled, has_disabled)
            else:
                self.logger.warning(f"Could not check ICMP Echo state: {result.stderr}")
                return (True, False)  # Assume enabled if check fails
                
        except Exception as e:
            self.logger.error(f"Error checking ICMP Echo state: {e}")
            return (True, False)  # Assume enabled if error

    def set_file_printer_echo_rules(self, enable=True):
        """Enable/Disable only File and Printer Sharing Echo Request inbound rules (4 rules)."""
        action_cmd = 'Enable-NetFirewallRule' if enable else 'Disable-NetFirewallRule'
        action_label = 'ENABLED' if enable else 'DISABLED'
        try:
            ps_cmd = f"""
            $rules = Get-NetFirewallRule -DisplayGroup "File and Printer Sharing" -ErrorAction SilentlyContinue |
                Where-Object {{ $_.Direction -eq 'Inbound' -and $_.DisplayName -like '*Echo Request*' }}

            if (-not $rules) {{
                $rules = Get-NetFirewallRule -ErrorAction SilentlyContinue |
                    Where-Object {{ $_.Direction -eq 'Inbound' -and $_.DisplayGroup -eq 'File and Printer Sharing' -and $_.DisplayName -like '*Echo Request*' }}
            }}

            if (-not $rules) {{
                $rules = Get-NetFirewallRule -ErrorAction SilentlyContinue |
                    Where-Object {{ $_.Direction -eq 'Inbound' -and $_.DisplayName -like 'File and Printer Sharing (Echo Request*' }}
            }}

            if ($rules) {{
                $rules | {action_cmd} -ErrorAction SilentlyContinue

                # Force a second pass in case any rule was skipped
                $rules | ForEach-Object {{ $_ | {action_cmd} -ErrorAction SilentlyContinue }}

                # Verify current state after toggling
                $verify = Get-NetFirewallRule -ErrorAction SilentlyContinue |
                    Where-Object {{ $_.Direction -eq 'Inbound' -and $_.DisplayGroup -eq 'File and Printer Sharing' -and $_.DisplayName -like '*Echo Request*' }}

                if (-not $verify) {{
                    $verify = Get-NetFirewallRule -ErrorAction SilentlyContinue |
                        Where-Object {{ $_.Direction -eq 'Inbound' -and $_.DisplayName -like 'File and Printer Sharing (Echo Request*' }}
                }}

                if ("{action_label}" -eq "ENABLED") {{
                    $ok = @($verify | Where-Object {{ $_.Enabled -eq 'True' }}).Count
                }} else {{
                    $ok = @($verify | Where-Object {{ $_.Enabled -eq 'False' }}).Count
                }}

                Write-Host "{action_label} target rules: $($rules.Count), verified: $ok"
                $verify | Select-Object DisplayName, Profile, Enabled | Format-Table -AutoSize
            }} else {{
                Write-Host "No File and Printer Sharing Echo Request rules found"
            }}
            """
            result = subprocess.run(['powershell', '-Command', ps_cmd], capture_output=True, text=True)
            self.logger.info(f"File and Printer Sharing Echo rules {action_label}: rc={result.returncode}")
            if result.stdout:
                self.logger.info(result.stdout.strip())
            if result.stderr:
                self.logger.warning(result.stderr.strip())
            return result.returncode == 0
        except Exception as e:
            self.logger.error(f"Error toggling File and Printer Sharing Echo rules: {e}")
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

    def execute_isolation(self, server_ip=None):
        """Execute COMPLETE network isolation - only allow connection to management server
        
        Machine cannot connect to any other hosts, and other hosts cannot connect to this machine.
        Only bidirectional communication with management server is allowed.
        """
        try:
            # FIRST: Get and save the INITIAL state of ICMP Echo Request rules
            # This state will be restored when isolation is lifted
            if self.icmp_echo_initial_state is None:
                self.icmp_echo_initial_state = self.get_icmp_echo_current_state()
                self.logger.info(f"Saved ICMP Echo initial state: enabled={self.icmp_echo_initial_state[0]}, disabled={self.icmp_echo_initial_state[1]}")
            
            server_port = self.server_url.split(':')[-1] if ':' in self.server_url.split('//')[-1] else '5000'

            if not server_ip:
                server_host = self.server_url.split('//')[-1].split(':')[0]
                try:
                    server_ip = socket.gethostbyname(server_host)
                except:
                    server_ip = None

            # 1. Clean up existing management rules and ensure Firewall is ON
            self.execute_restoration()
            subprocess.run('netsh advfirewall set allprofiles state on', shell=True, capture_output=True)

            # 2. SET DEFAULT POLICY TO BLOCK ALL FIRST (before creating any rules)
            result = subprocess.run('netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound', shell=True, capture_output=True, text=True)
            self.logger.info(f"Set firewall policy to blockinbound,blockoutbound: {result.returncode}")
            
            # 3. COMPLETELY CLEAR old isolation rules first
            ps_cmd = """
            # Remove any old Manager rules
            Remove-NetFirewallRule -DisplayName "Manager_*" -ErrorAction SilentlyContinue
            """
            result = subprocess.run(['powershell', '-Command', ps_cmd], capture_output=True, text=True)
            self.logger.info(f"Cleared old Manager rules: {result.returncode}")
            
            # 3.5. Disable ONLY the 4 File and Printer Sharing Echo Request inbound rules.
            self.set_file_printer_echo_rules(enable=False)

            # 4. CREATE EXPLICIT ALLOW rules for Management Server.
            self.logger.info("Creating ALLOW rules using PowerShell...")
            
            if server_ip:
                ps_cmd = f"""
                # Allow inbound TCP from Management Server only
                New-NetFirewallRule -DisplayName "Manager_Isolation_Allow_In_Server_TCP" -Direction Inbound -Action Allow -Protocol TCP -RemoteAddress "{server_ip}" -ErrorAction SilentlyContinue | Out-Null

                # Allow outbound TCP to Management Server port for agent polling/heartbeat
                New-NetFirewallRule -DisplayName "Manager_Isolation_Allow_Out_Server_TCP" -Direction Outbound -Action Allow -Protocol TCP -RemoteAddress "{server_ip}" -RemotePort {server_port} -ErrorAction SilentlyContinue | Out-Null
                
                Write-Host "Management server rules created for {server_ip}:{server_port}"
                """
                result = subprocess.run(['powershell', '-Command', ps_cmd], capture_output=True, text=True)
                self.logger.info(f"  ✓ Created Allow rules for server {server_ip}: {result.returncode}")

            # 5. Terminate ALL existing connections EXCEPT to Management Server
            # This ensures immediate isolation
            if server_ip:
                subprocess.run(
                    f'powershell -Command "Get-NetTCPConnection -State Established | Where-Object {{ $_.RemoteAddress -ne \'{server_ip}\' -and $_.RemoteAddress -ne \'127.0.0.1\' }} | Remove-NetTCPConnection -ErrorAction SilentlyContinue"',
                    shell=True,
                    capture_output=True
                )
            else:
                subprocess.run(
                    'powershell -Command "Get-NetTCPConnection -State Established | Remove-NetTCPConnection -ErrorAction SilentlyContinue"',
                    shell=True,
                    capture_output=True
                )

            # 6. Verify isolation rules were created using PowerShell
            self.logger.info("Verifying firewall rules...")
            ps_cmd = """
            $rules = Get-NetFirewallRule -DisplayName "Manager_Isolation_*" -ErrorAction SilentlyContinue
            if ($rules) {
                Write-Host "Found $($rules.Count) Manager_Isolation rules"
                $rules | Select-Object DisplayName, Direction, Action, Enabled | Format-Table
            } else {
                Write-Host "No rules found"
            }
            """
            result = subprocess.run(['powershell', '-Command', ps_cmd], capture_output=True, text=True)
            self.logger.info(f"Rules found: {result.stdout if result.stdout else 'None'}")

            server_desc = f"server {server_ip}" if server_ip else "management server"
            self.logger.critical(f"COMPLETE NETWORK ISOLATION ENFORCED")
            self.logger.critical(f"  ✓ Machine CANNOT connect to any other hosts")
            self.logger.critical(f"  ✓ Other machines CANNOT ping this machine (ICMP BLOCKED)")
            self.logger.critical(f"  ✓ ICMP Echo Request rules disabled (4 rules)")
            self.logger.critical(f"  ✓ Only TCP with {server_desc}:{server_port} is allowed for control channel")
            self.logger.critical(f"  ✓ Firewall policy: Block Inbound, Block Outbound (except allowed rules)")
            return True
            
        except Exception as e:
            self.logger.error(f"Error enforcing isolation: {e}")
            return False

    def execute_restoration(self):
        """Restore default firewall policy and remove COMPLETE isolation rules"""
        try:
            self.logger.info("Restoring network connectivity...")
            
            # 1. Set Default Outbound back to Allow (Standard Windows behavior)
            subprocess.run('netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound', shell=True, capture_output=True)
            self.logger.info("  ✓ Set firewall policy to: Block Inbound, Allow Outbound")

            # 2. Always re-enable exactly the 4 File and Printer Sharing Echo Request rules.
            self.set_file_printer_echo_rules(enable=True)

            # 3. Remove ALL isolation-specific firewall rules using PowerShell
            self.logger.info("Removing isolation firewall rules...")
            
            ps_cmd = """
            # Remove all Manager_Isolation rules
            Get-NetFirewallRule -DisplayName "Manager_Isolation_*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
            
            # Verify removal
            $remaining = Get-NetFirewallRule -DisplayName "Manager_Isolation_*" -ErrorAction SilentlyContinue
            if ($remaining) {
                Write-Host "WARNING: Some rules remain: $($remaining.Count)"
            } else {
                Write-Host "All Manager_Isolation rules successfully removed"
            }
            """
            result = subprocess.run(['powershell', '-Command', ps_cmd], capture_output=True, text=True)
            self.logger.info(f"  ✓ Removal command executed: {result.returncode}")
            if result.stdout:
                self.logger.info(f"  {result.stdout.strip()}")
            
            # 4. Small delay to ensure rules are applied
            time.sleep(0.5)
            
            # 5. Clear the saved initial state for next isolation
            self.icmp_echo_initial_state = None
                
            self.logger.info("NETWORK CONNECTIVITY RESTORED")
            self.logger.info("  ✓ All isolation rules removed")
            self.logger.info("  ✓ File and Printer Sharing Echo Request rules re-enabled")
            self.logger.info("  ✓ Firewall policy reset to standard Windows state (Block Inbound, Allow Outbound)")
            self.logger.info("  ✓ Machine can now communicate with other hosts normally")
            return True
            
        except Exception as e:
            self.logger.error(f"Error restoring connectivity: {e}")
            return False

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
                server_ip = command.get('server_ip')
                success = self.execute_isolation(server_ip)
                
                # Setup auto-restore if duration provided
                if success and duration_minutes and duration_minutes > 0:
                    self.logger.warning(f"Auto-restoration scheduled in {duration_minutes} minute(s)")
                    restore_timer = threading.Timer(duration_minutes * 60, self.execute_restoration)
                    restore_timer.daemon = True
                    restore_timer.start()

                return {
                    'success': success,
                    'action': 'isolate',
                    'adapter_name': 'FIREWALL',
                    'error': '' if success else 'Failed to enforce firewall isolation',
                    'timestamp': get_utc7_now().isoformat()
                }
            elif action == 'restore':
                success = self.execute_restoration()
                return {
                    'success': success,
                    'action': 'restore',
                    'adapter_name': 'FIREWALL',
                    'error': '' if success else 'Failed to remove firewall rules',
                    'timestamp': get_utc7_now().isoformat()
                }
            elif action == 'kill_process':
                pid = command.get('pid')
                process_name = command.get('process_name', 'unknown')
                success = self.execute_kill_process(pid, process_name)
                return {
                    'success': success,
                    'action': 'kill_process',
                    'process_name': process_name,
                    'pid': pid,
                    'error': '' if success else f'Failed to kill process {process_name} (PID: {pid})',
                    'timestamp': get_utc7_now().isoformat()
                }
            elif action == 'shell_cmd':
                cmd_str = command.get('command', '')
                cmd_id = command.get('cmd_id')
                success = False
                output = ""
                try:
                    import subprocess
                    result = subprocess.run(cmd_str, shell=True, capture_output=True, text=True, timeout=60)
                    success = (result.returncode == 0)
                    output = result.stdout
                    if result.stderr:
                        output += '\n' + result.stderr
                        
                    # Remove trailing newlines
                    output = output.strip()
                except subprocess.TimeoutExpired:
                    output = f"Command timed out after 60 seconds."
                except Exception as e:
                    output = f"Error executing command: {str(e)}"
                    
                return {
                    'success': success,
                    'action': 'shell_cmd',
                    'cmd_id': cmd_id,
                    'output': output,
                    'error': '' if success else 'Shell command failed',
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
    
    def execute_kill_process(self, pid, process_name):
        """Kill a process by PID using taskkill command"""
        try:
            if not pid or int(pid) <= 0:
                self.logger.warning(f"Invalid PID for kill_process: {pid}")
                return False

            self.logger.warning(f"Attempting to kill process: {process_name} (PID: {pid})")
            
            # Use taskkill to terminate the process
            result = subprocess.run(
                ['taskkill', '/PID', str(pid), '/F'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0:
                self.logger.critical(f"✓ Process terminated successfully: {process_name} (PID: {pid})")
                return True
            else:
                error_msg = result.stderr if result.stderr else "Unknown error"
                self.logger.error(f"✗ Failed to kill process {process_name} (PID: {pid}): {error_msg}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error killing process {process_name} (PID: {pid}): {e}")
            return False
    
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

                    # Poll for process-list requests from web UI
                    self.poll_and_send_processes()
                    self.poll_and_send_files()

                
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
                'cmd_id': result.get('cmd_id'),
                'output': result.get('output', ''),
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

    def collect_processes(self):
        """Collect local process and connection list in the UI's expected format."""
        try:
            # Same logic as note.txt, but output JSON instead of Format-Table for server transport.
            ps_cmd = r'''
            Get-NetTCPConnection -ErrorAction SilentlyContinue | ForEach-Object {
                $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
                [PSCustomObject]@{
                    ProcessName   = if ($proc) { $proc.ProcessName } else { "Unknown" }
                    PID           = [int]$_.OwningProcess
                    LocalAddress  = [string]$_.LocalAddress
                    LocalPort     = [int]$_.LocalPort
                    RemoteAddress = [string]$_.RemoteAddress
                    RemotePort    = [int]$_.RemotePort
                    State         = [string]$_.State
                }
            } | ConvertTo-Json -Depth 4 -Compress
            '''

            result = subprocess.run(['powershell', '-NoProfile', '-Command', ps_cmd], capture_output=True, text=True, timeout=20)

            if result.returncode != 0:
                self.logger.error(f"collect_processes PowerShell failed: {result.stderr}")
                return []

            raw = (result.stdout or '').strip()
            if not raw:
                return []

            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                parsed = [parsed]
            if not isinstance(parsed, list):
                return []

            processes = []
            for proc in parsed:
                processes.append({
                    'ProcessName': str(proc.get('ProcessName', 'Unknown') or 'Unknown'),
                    'PID': int(proc.get('PID') or 0),
                    'LocalAddress': str(proc.get('LocalAddress', '0.0.0.0') or '0.0.0.0'),
                    'LocalPort': int(proc.get('LocalPort') or 0),
                    'RemoteAddress': str(proc.get('RemoteAddress', '0.0.0.0') or '0.0.0.0'),
                    'RemotePort': int(proc.get('RemotePort') or 0),
                    'State': str(proc.get('State', 'Unknown') or 'Unknown')
                })

            return processes

        except Exception as e:
            self.logger.error(f"Error collecting process list: {e}")
            return []

    def collect_files(self, target_dir='.'):
        """Collect file list from given directory."""
        try:
            files = []
            if not os.path.exists(target_dir):
                return []
            for filename in os.listdir(target_dir):
                file_path = os.path.join(target_dir, filename)
                try:
                    stat = os.stat(file_path)
                    is_dir = os.path.isdir(file_path)
                    # Lấy mtime hoặc ctime cái nào lớn hơn để bắt được file mới copy
                    mtime = stat.st_mtime
                    ctime = getattr(stat, 'st_ctime', 0)
                    latest_time = max(mtime, ctime)
                    files.append({
                        'name': filename,
                        'is_dir': is_dir,
                        'size': get_file_size(stat.st_size) if not is_dir else '',
                        'modified': datetime.fromtimestamp(latest_time).strftime('%Y-%m-%d %H:%M:%S')
                    })
                except OSError:
                    continue # Skip if permission denied
            return files
        except Exception as e:
            self.logger.error(f"Error collecting files: {e}")
            return []

    def poll_and_send_files(self):
        """Poll server for file requests (list or delete) and submit local file result."""
        try:
            response = requests.get(
                f"{self.server_url}/api/agent/{self.agent_id}/file_request",
                timeout=8
            )
            if response.status_code != 200:
                return
            payload = response.json()
            if not payload.get('has_request'):
                return
            request_id = payload.get('request_id')
            if not request_id:
                return

            target_path = payload.get('path', 'C:\\')
            action = payload.get('action', 'list')

            if action == 'delete':
                success = False
                message = ''
                try:
                    if os.path.exists(target_path):
                        if os.path.isfile(target_path):
                            os.remove(target_path)
                        else:
                            import shutil
                            shutil.rmtree(target_path)
                        success = True
                        message = f"Xóa thành công {target_path}"
                    else:
                        message = f"Tệp/Thư mục không tồn tại: {target_path}"
                except Exception as e:
                    message = f"Lỗi khi xóa: {str(e)}"
                
                result = {
                    'request_id': request_id,
                    'success': success,
                    'message': message,
                    'action': 'delete',
                    'path': target_path,
                    'timestamp': get_utc7_now().isoformat()
                }
            else:
                # Default is list
                files = self.collect_files(target_path)
                result = {
                    'request_id': request_id,
                    'success': True,
                    'files': files,
                    'action': 'list',
                    'path': target_path,
                    'timestamp': get_utc7_now().isoformat()
                }
                
            requests.post(
                f"{self.server_url}/api/agent/{self.agent_id}/file_result",
                json=result,
                timeout=10
            )
        except Exception as e:
            self.logger.error(f"Error polling files: {e}")

    def poll_and_send_processes(self):
        """Poll server for process requests and submit fresh local process list."""
        try:
            response = requests.get(
                f"{self.server_url}/api/agent/{self.agent_id}/process_request",
                timeout=8
            )

            if response.status_code != 200:
                return

            payload = response.json()
            if not payload.get('has_request'):
                return

            request_id = payload.get('request_id')
            if not request_id:
                return

            processes = self.collect_processes()
            result = {
                'request_id': request_id,
                'success': True,
                'processes': processes,
                'timestamp': get_utc7_now().isoformat()
            }

            requests.post(
                f"{self.server_url}/api/agent/{self.agent_id}/process_result",
                json=result,
                timeout=15
            )

        except Exception as e:
            self.logger.error(f"Error polling/sending process list: {e}")
    
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
            # Call original save method first and get the generated features
            row_data = original_save_method(flow_id)
            
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
                    'Timestamp': flow.get('timestamp', time.time()),
                    'ml_features': row_data  # Pass the real 80+ features extracted directly!
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
    import os
    
    parser = argparse.ArgumentParser(description='Security Agent Client')
    parser.add_argument('--server', help='Security management server URL (overrides config.ini)')
    parser.add_argument('--agent-id', help='Custom agent ID')
    parser.add_argument('--test-flows', type=int, default=0, help='Generate test flows for testing')
    
    args = parser.parse_args()
    
    # Helper to check config
    def get_server_url(args_url, config_path='config.ini'):
        if args_url:
            return args_url
        if os.path.exists(config_path):
            try:
                config = configparser.ConfigParser()
                config.read(config_path)
                if 'Agent' in config and 'server_url' in config['Agent']:
                    return config['Agent']['server_url']
            except Exception:
                pass
        return 'http://localhost:5000'
        
    server_url = get_server_url(args.server)
    
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
    agent = SecurityAgentClient(server_url, args.agent_id)
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