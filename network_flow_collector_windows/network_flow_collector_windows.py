#!/usr/bin/env python3


import time
import csv

import statistics
import threading
from collections import defaultdict
from datetime import datetime
import argparse
import logging
import signal
import sys
import os
import platform as platform_module
import subprocess

# Windows-specific imports
try:
    import winreg
except ImportError:
    print("winreg not available - not on Windows")
    winreg = None

try:
    from scapy.all import *
    from scapy.arch.windows import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP

except ImportError:
    print("Scapy library not found. Please install it: pip install scapy")
    print("Also install Npcap from: https://nmap.org/npcap/")
    sys.exit(1)


import numpy as np

class WindowsNetworkFlowCollector:
    def __init__(self, output_file="network_flows.csv", interface=None, timeout=300, add_timestamp=True, promiscuous=True):
        # Add timestamp to output file if requested
        if add_timestamp and output_file:
            self.output_file = self.add_timestamp_to_filename(output_file)
        else:
            self.output_file = output_file
            
        self.original_output_file = output_file  # Keep original for reference
        self.interface = interface
        self.timeout = timeout
        self.promiscuous = promiscuous  # Enable promiscuous mode for network-wide capture
        self.flows = defaultdict(dict)
        self.flow_timeouts = defaultdict(float)
        self.packet_timestamps = defaultdict(list)
        self.running = True
        
        # Flow tracking (same as Linux version)
        self.flow_packets = defaultdict(list)
        self.flow_bytes = defaultdict(lambda: {'fwd': 0, 'bwd': 0})
        self.flow_packet_lengths = defaultdict(lambda: {'fwd': [], 'bwd': []})
        self.flow_flags = defaultdict(lambda: {'fwd': defaultdict(int), 'bwd': defaultdict(int)})
        self.flow_iat = defaultdict(lambda: {'fwd': [], 'bwd': []})
        self.flow_last_packet_time = defaultdict(lambda: {'fwd': None, 'bwd': None})
        self.flow_header_lengths = defaultdict(lambda: {'fwd': [], 'bwd': []})
        self.flow_window_sizes = defaultdict(lambda: {'fwd': [], 'bwd': []})
        self.flow_active_times = defaultdict(list)
        self.flow_idle_times = defaultdict(list)
        self.flow_last_active_time = defaultdict(float)
        
        # Debug and statistics
        self.packet_capture_count = 0
        self.flow_creation_count = 0
        self.last_stats_time = time.time()
        
        # Setup logging with UTF-8 encoding for Windows compatibility
        log_format = '%(asctime)s - %(levelname)s - %(message)s'
        
        # Configure file handler with UTF-8 encoding
        file_handler = logging.FileHandler('network_collector.log', encoding='utf-8')
        file_handler.setFormatter(logging.Formatter(log_format))
        
        # Configure console handler with safe encoding
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter(log_format))
        
        # Setup root logger
        logging.basicConfig(
            level=logging.INFO,
            handlers=[file_handler, console_handler]
        )
        self.logger = logging.getLogger(__name__)
        
        # Windows-specific setup
        self.check_windows_requirements()
        
        # Setup signal handlers (Windows compatible)
        try:
            signal.signal(signal.SIGINT, self.signal_handler)
            signal.signal(signal.SIGTERM, self.signal_handler)
        except:
            pass  # Some signals may not be available on Windows
        
        # Initialize CSV file
        self.init_csv_file()
    
    def add_timestamp_to_filename(self, filename):
        """Add timestamp to filename before extension"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if '.' in filename:
            name, ext = filename.rsplit('.', 1)
            return f"{name}_{timestamp}.{ext}"
        else:
            return f"{filename}_{timestamp}"
    
    def check_windows_requirements(self):
        """Check Windows-specific requirements"""
        self.logger.info("Checking Windows requirements...")
        
        # Check if running on Windows
        if platform_module.system() != 'Windows':
            self.logger.warning("This is the Windows version. Use the Linux version for non-Windows systems.")
        
        # Check for Npcap installation
        npcap_installed = self.check_npcap_installation()
        if not npcap_installed:
            self.logger.error("Npcap not found. Please install Npcap from https://nmap.org/npcap/")
            self.logger.error("Npcap is required for packet capture on Windows")
        
        # Check administrator privileges
        if not self.is_admin():
            self.logger.warning("Administrator privileges recommended for best packet capture performance")
    
    def check_npcap_installation(self):
        """Check if Npcap is installed using multiple methods"""
        if winreg is None:
            self.logger.warning("Not running on Windows - winreg not available")
            return True
        
        # Method 1: Check Npcap service
        try:
            import subprocess
            result = subprocess.run(['sc', 'query', 'npcap'], 
                                  capture_output=True, text=True, shell=True)
            if result.returncode == 0 and 'RUNNING' in result.stdout:
                self.logger.info("Npcap service is running")
                return True
        except Exception:
            pass
        
        # Method 2: Check Npcap files
        try:
            import os
            npcap_paths = [
                os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32', 'Npcap'),
                os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32', 'drivers', 'npcap.sys'),
                os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'SysWOW64', 'Npcap', 'wpcap.dll')
            ]
            
            files_found = 0
            for path in npcap_paths:
                if os.path.exists(path):
                    files_found += 1
            
            if files_found >= 2:
                self.logger.info("Npcap files found")
                return True
        except Exception:
            pass
            
        # Method 3: Check registry for Npcap
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                               "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\NpcapInst")
            winreg.CloseKey(key)
            self.logger.info("Npcap installation found in registry")
            return True
        except FileNotFoundError:
            try:
                # Check for WinPcap as fallback
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                   "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\WinPcapInst")
                winreg.CloseKey(key)
                self.logger.info("WinPcap found (Npcap preferred)")
                return True
            except FileNotFoundError:
                pass
        except Exception as e:
            self.logger.warning(f"Could not check for Npcap: {e}")
            
        return False
    
    def is_admin(self):
        """Check if running with administrator privileges"""
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            return False
    
    def get_windows_interfaces(self):
        """Get available network interfaces on Windows"""
        try:
            # Import scapy interface functions
            from scapy.arch.windows import get_windows_if_list
            
            # Try to get Windows specific interface list first
            try:
                interfaces = get_windows_if_list()
                self.logger.info(f"Found {len(interfaces)} interfaces using get_windows_if_list")
            except:
                # Fallback to regular get_if_list
                interfaces = get_if_list()
                self.logger.info(f"Found {len(interfaces)} interfaces using get_if_list")
            
            interface_info = []
            for i, iface in enumerate(interfaces):
                try:
                    # For Windows interface dict from get_windows_if_list
                    if isinstance(iface, dict):
                        name = iface.get('name', f'Interface_{i}')
                        desc = iface.get('description', name)
                        guid = iface.get('guid', name)
                    else:
                        # For simple interface names from get_if_list
                        name = iface
                        desc = name
                        guid = name
                    
                    interface_info.append({
                        'name': name,
                        'description': desc,
                        'guid': guid,
                        'active': True
                    })
                except Exception as e:
                    self.logger.warning(f"Error processing interface {iface}: {e}")
                    continue
            
            return interface_info
            
        except Exception as e:
            self.logger.error(f"Error getting Windows interfaces: {e}")
            # Last resort - try basic scapy
            try:
                interfaces = get_if_list()
                return [{'name': iface, 'description': iface, 'guid': iface, 'active': True} 
                       for iface in interfaces]
            except:
                return []
    
    def signal_handler(self, sig, frame):
        """Handle shutdown signals (Windows compatible)"""
        self.logger.info("Received shutdown signal. Saving data...")
        self.running = False
        self.save_flows()
        sys.exit(0)
    
    def init_csv_file(self):
        """Initialize CSV file with complete flow feature headers"""
        headers = [
            'Flow ID', 'Source IP', 'Source Port', 'Destination IP', 'Destination Port', 'Protocol', 
            'Timestamp', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
            'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Fwd Packet Length Max', 
            'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
            'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std',
            'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
            'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
            'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
            'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length', 'Bwd Header Length',
            'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length', 'Max Packet Length', 'Packet Length Mean', 
            'Packet Length Std', 'Packet Length Variance',
            'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count', 
            'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio', 'Average Packet Size', 'Avg Fwd Segment Size', 
            'Avg Bwd Segment Size', 'Fwd Header Length.1',
            'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 
            'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate',
            'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes',
            'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward',
            'Active Mean', 'Active Std', 'Active Max', 'Active Min',
            'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
        ]
        
        with open(self.output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(headers)
    
    # Feature extraction methods (same as Linux version)
    def generate_flow_id(self, src_ip, src_port, dst_ip, dst_port, protocol):
        """Generate unique flow ID and return both forward and reverse IDs"""
        forward_id = f"{src_ip}-{dst_ip}-{src_port}-{dst_port}-{protocol}"
        reverse_id = f"{dst_ip}-{src_ip}-{dst_port}-{src_port}-{protocol}"
        
        # Return the lexicographically smaller one as the canonical flow ID
        if forward_id <= reverse_id:
            return forward_id
        else:
            return reverse_id
    
    def get_flow_direction(self, flow_id, src_ip, src_port, dst_ip, dst_port, protocol):
        """Determine if packet is forward or backward"""
        if flow_id not in self.flows:
            return 'fwd'
        
        first_packet = self.flows[flow_id].get('first_packet')
        if first_packet:
            if (src_ip == first_packet['src_ip'] and src_port == first_packet['src_port']):
                return 'fwd'
            else:
                return 'bwd'
        
        return 'fwd'
    
    def extract_features(self, packet):
        """Extract features from packet (IPv4 only)"""
        # ONLY process IPv4 packets
        if not packet.haslayer(IP):
            return None
        
        ip_layer = packet[IP]
        
        # Check if it's actually IPv4 (not IPv6)
        if ip_layer.version != 4:
            return None

        timestamp = float(packet.time)
        
        # Extract IPv4 layer info
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto
        ip_header_len = ip_layer.ihl * 4
        src_port = dst_port = 0
        tcp_flags = {}
        window_size = 0
        header_length = ip_header_len
        
        # Only allow TCP, UDP, and ICMP protocols over IPv4
        if packet.haslayer(TCP) and protocol == 6:
            tcp_layer = packet[TCP]
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            protocol = 6  # TCP
            tcp_flags = {
                'FIN': int(tcp_layer.flags.F),
                'SYN': int(tcp_layer.flags.S),
                'RST': int(tcp_layer.flags.R),
                'PSH': int(tcp_layer.flags.P),
                'ACK': int(tcp_layer.flags.A),
                'URG': int(tcp_layer.flags.U),
                'ECE': int(tcp_layer.flags.E),
                'CWE': int(tcp_layer.flags.C)
            }
            window_size = tcp_layer.window
            header_length += tcp_layer.dataofs * 4
            
        elif packet.haslayer(UDP) and protocol == 17:
            udp_layer = packet[UDP]
            src_port = udp_layer.sport
            dst_port = udp_layer.dport
            protocol = 17  # UDP
            tcp_flags = {}
            header_length += 8
        
        elif packet.haslayer(ICMP) and protocol == 1:
            protocol = 1  # ICMP
            tcp_flags = {}
            header_length += 8
        
        else:
            # Skip all other IPv4 protocols (not TCP/UDP/ICMP)
            return None
        
        # Use IP packet length (not including Layer 2 headers like Ethernet)
        # This is standard practice in network flow analysis
        packet_length = ip_layer.len  # IP total length field
        
        return {
            'timestamp': timestamp,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol,
            'packet_length': packet_length,
            'header_length': header_length,
            'tcp_flags': tcp_flags,
            'window_size': window_size
        }
    

    
    def process_packet(self, packet):
        """Process individual packet and update flow statistics"""
        self.packet_capture_count += 1
        
        # Log periodic statistics
        current_time = time.time()
        if current_time - self.last_stats_time >= 10:  # Every 10 seconds
            self.logger.info(f"[DEBUG] Captured {self.packet_capture_count} packets, created {len(self.flows)} flows")
            self.last_stats_time = current_time
        
        features = self.extract_features(packet)
        if not features:
            return
        
        flow_id = self.generate_flow_id(
            features['src_ip'], features['src_port'],
            features['dst_ip'], features['dst_port'],
            features['protocol']
        )
        
        direction = self.get_flow_direction(
            flow_id, features['src_ip'], features['src_port'],
            features['dst_ip'], features['dst_port'], features['protocol']
        )
        
        timestamp = features['timestamp']
        packet_length = features['packet_length']
        header_length = features['header_length']
        
        # Initialize flow if new
        if flow_id not in self.flows:
            self.flow_creation_count += 1
            self.logger.info(f"[DEBUG] Created new flow #{self.flow_creation_count}: {features['src_ip']}:{features['src_port']} -> {features['dst_ip']}:{features['dst_port']} ({features['protocol']})")
            
            self.flows[flow_id] = {
                'first_packet': {
                    'src_ip': features['src_ip'],
                    'src_port': features['src_port'],
                    'dst_ip': features['dst_ip'],
                    'dst_port': features['dst_port'],
                    'protocol': features['protocol'],
                    'timestamp': timestamp
                },
                'last_timestamp': timestamp,
                'packet_count': {'fwd': 0, 'bwd': 0}
            }
            self.flow_last_active_time[flow_id] = timestamp
        
        # Update flow timeout
        self.flow_timeouts[flow_id] = timestamp + self.timeout
        
        # Update basic counters
        self.flows[flow_id]['packet_count'][direction] += 1
        self.flows[flow_id]['last_timestamp'] = timestamp
        
        # Update bytes
        self.flow_bytes[flow_id][direction] += packet_length
        
        # Update packet lengths
        self.flow_packet_lengths[flow_id][direction].append(packet_length)
        
        # Update header lengths
        self.flow_header_lengths[flow_id][direction].append(header_length)
        
        # Update window sizes
        if features['protocol'] == 6:  # TCP
            self.flow_window_sizes[flow_id][direction].append(features.get('window_size', 0))
        
        # Update flags by direction
        for flag, value in features['tcp_flags'].items():
            self.flow_flags[flow_id][direction][flag] += value
        
        # Calculate IAT
        last_time = self.flow_last_packet_time[flow_id][direction]
        if last_time is not None:
            iat = timestamp - last_time
            self.flow_iat[flow_id][direction].append(iat)
        self.flow_last_packet_time[flow_id][direction] = timestamp
        
        # Track active/idle times using packet timestamp consistently
        if flow_id in self.flow_last_active_time:
            time_diff = timestamp - self.flow_last_active_time[flow_id]
            if time_diff > 1.0:  # More than 1 second idle
                self.flow_idle_times[flow_id].append(time_diff)
            elif time_diff > 0:
                self.flow_active_times[flow_id].append(time_diff)
        
        self.flow_last_active_time[flow_id] = timestamp
        self.flow_packets[flow_id].append(features)
    

    
    def calculate_stats(self, data):
        """Calculate statistical measures for a list of values"""
        if not data:
            return {'min': 0, 'max': 0, 'mean': 0, 'std': 0, 'variance': 0}
        
        return {
            'min': min(data),
            'max': max(data),
            'mean': statistics.mean(data),
            'std': statistics.stdev(data) if len(data) > 1 else 0,
            'variance': statistics.variance(data) if len(data) > 1 else 0
        }
    
    def calculate_flow_features(self, flow_id):
        flow = self.flows[flow_id]
        first_packet = flow['first_packet']
        
        # Basic flow info
        src_ip = first_packet['src_ip']
        src_port = first_packet['src_port']
        dst_ip = first_packet['dst_ip']
        dst_port = first_packet['dst_port']
        protocol = first_packet['protocol']
        start_time = first_packet['timestamp']
        end_time = flow['last_timestamp']
        duration = max(end_time - start_time, 0.000001)
        
        # Packet counts
        fwd_packets = flow['packet_count']['fwd']
        bwd_packets = flow['packet_count']['bwd']
        total_packets = fwd_packets + bwd_packets
        
        # Byte counts
        fwd_bytes = self.flow_bytes[flow_id]['fwd']
        bwd_bytes = self.flow_bytes[flow_id]['bwd']
        total_bytes = fwd_bytes + bwd_bytes
        
        # Packet length statistics
        fwd_lengths = self.flow_packet_lengths[flow_id]['fwd']
        bwd_lengths = self.flow_packet_lengths[flow_id]['bwd']
        all_lengths = fwd_lengths + bwd_lengths
        
        # Calculate stats
        fwd_len_stats = self.calculate_stats(fwd_lengths)
        bwd_len_stats = self.calculate_stats(bwd_lengths)
        all_len_stats = self.calculate_stats(all_lengths)
        
        # Flow rates
        flow_bytes_per_sec = total_bytes / duration if duration > 0 else 0
        flow_packets_per_sec = total_packets / duration if duration > 0 else 0
        fwd_packets_per_sec = fwd_packets / duration if duration > 0 else 0
        bwd_packets_per_sec = bwd_packets / duration if duration > 0 else 0
        
        # IAT statistics
        all_iat = self.flow_iat[flow_id]['fwd'] + self.flow_iat[flow_id]['bwd']
        fwd_iat = self.flow_iat[flow_id]['fwd']
        bwd_iat = self.flow_iat[flow_id]['bwd']
        
        flow_iat_stats = self.calculate_stats(all_iat)
        fwd_iat_stats = self.calculate_stats(fwd_iat)
        bwd_iat_stats = self.calculate_stats(bwd_iat)
        
        # Header lengths
        fwd_headers = self.flow_header_lengths[flow_id]['fwd']
        bwd_headers = self.flow_header_lengths[flow_id]['bwd']
        
        # Window sizes
        fwd_windows = self.flow_window_sizes[flow_id]['fwd']
        bwd_windows = self.flow_window_sizes[flow_id]['bwd']
        
        # Active/Idle times
        active_times = self.flow_active_times[flow_id]
        idle_times = self.flow_idle_times[flow_id]
        
        active_stats = self.calculate_stats(active_times)
        idle_stats = self.calculate_stats(idle_times)
        
        # Flag counts (aggregate and direction-specific)
        fwd_flags = self.flow_flags[flow_id]['fwd']
        bwd_flags = self.flow_flags[flow_id]['bwd']
        
        # Build feature vector with corrected flag calculations
        features = [
            flow_id, src_ip, src_port, dst_ip, dst_port, protocol,
            datetime.fromtimestamp(start_time).strftime('%Y-%m-%d %H:%M:%S'),
            duration * 1000000, fwd_packets, bwd_packets, fwd_bytes, bwd_bytes,
            fwd_len_stats['max'], fwd_len_stats['min'], fwd_len_stats['mean'], fwd_len_stats['std'],
            bwd_len_stats['max'], bwd_len_stats['min'], bwd_len_stats['mean'], bwd_len_stats['std'],
            flow_bytes_per_sec, flow_packets_per_sec, flow_iat_stats['mean'], flow_iat_stats['std'],
            flow_iat_stats['max'], flow_iat_stats['min'], sum(fwd_iat), fwd_iat_stats['mean'],
            fwd_iat_stats['std'], fwd_iat_stats['max'], fwd_iat_stats['min'], sum(bwd_iat),
            bwd_iat_stats['mean'], bwd_iat_stats['std'], bwd_iat_stats['max'], bwd_iat_stats['min'],
            fwd_flags.get('PSH', 0), bwd_flags.get('PSH', 0), fwd_flags.get('URG', 0), bwd_flags.get('URG', 0),
            sum(fwd_headers) if fwd_headers else 0, sum(bwd_headers) if bwd_headers else 0,
            fwd_packets_per_sec, bwd_packets_per_sec, all_len_stats['min'], all_len_stats['max'],
            all_len_stats['mean'], all_len_stats['std'], all_len_stats['variance'],
            fwd_flags.get('FIN', 0) + bwd_flags.get('FIN', 0),
            fwd_flags.get('SYN', 0) + bwd_flags.get('SYN', 0),
            fwd_flags.get('RST', 0) + bwd_flags.get('RST', 0),
            fwd_flags.get('PSH', 0) + bwd_flags.get('PSH', 0),
            fwd_flags.get('ACK', 0) + bwd_flags.get('ACK', 0),
            fwd_flags.get('URG', 0) + bwd_flags.get('URG', 0),
            fwd_flags.get('CWE', 0) + bwd_flags.get('CWE', 0),
            fwd_flags.get('ECE', 0) + bwd_flags.get('ECE', 0),
            bwd_packets / max(fwd_packets, 1), total_bytes / max(total_packets, 1),
            fwd_bytes / max(fwd_packets, 1), bwd_bytes / max(bwd_packets, 1),
            sum(fwd_headers) if fwd_headers else 0, 0, 0, 0, 0, 0, 0,
            fwd_packets, fwd_bytes, bwd_packets, bwd_bytes,
            fwd_windows[0] if fwd_windows else 0, bwd_windows[0] if bwd_windows else 0,
            fwd_packets, min(fwd_lengths) if fwd_lengths else 0,
            active_stats['mean'], active_stats['std'], active_stats['max'], active_stats['min'],
            idle_stats['mean'], idle_stats['std'], idle_stats['max'], idle_stats['min'],
            'BENIGN'
        ]
        
        return features
    
    def save_individual_flow(self, flow_id):
        """Save individual flow with complete accurate features"""
        try:
            flow = self.flows[flow_id]['first_packet']
            timestamp = flow['timestamp']
            
            # Calculate flow duration (from first packet to last packet)
            last_timestamp = self.flows[flow_id]['last_timestamp']
            flow_duration_seconds = max(last_timestamp - timestamp, 0.000001)
            # Convert to microseconds to match original format
            flow_duration = int(flow_duration_seconds * 1000000)
            
            # Packet counts
            fwd_packets = len(self.flow_packet_lengths[flow_id]['fwd'])
            bwd_packets = len(self.flow_packet_lengths[flow_id]['bwd'])
            total_packets = fwd_packets + bwd_packets
            
            # Packet lengths
            fwd_lengths = self.flow_packet_lengths[flow_id]['fwd']
            bwd_lengths = self.flow_packet_lengths[flow_id]['bwd']
            all_lengths = fwd_lengths + bwd_lengths
            
            # Forward packet stats
            fwd_length_max = max(fwd_lengths) if fwd_lengths else 0
            fwd_length_min = min(fwd_lengths) if fwd_lengths else 0
            fwd_length_mean = np.mean(fwd_lengths) if fwd_lengths else 0
            fwd_length_std = np.std(fwd_lengths) if len(fwd_lengths) > 1 else 0
            
            # Backward packet stats
            bwd_length_max = max(bwd_lengths) if bwd_lengths else 0
            bwd_length_min = min(bwd_lengths) if bwd_lengths else 0
            bwd_length_mean = np.mean(bwd_lengths) if bwd_lengths else 0
            bwd_length_std = np.std(bwd_lengths) if len(bwd_lengths) > 1 else 0
            
            # Total lengths - use flow_bytes as source of truth for consistency
            fwd_total_length = self.flow_bytes[flow_id]['fwd']
            bwd_total_length = self.flow_bytes[flow_id]['bwd']
            total_length = fwd_total_length + bwd_total_length
            
            # Flow rates
            flow_bytes_per_sec = total_length / flow_duration_seconds if flow_duration_seconds > 0 else 0
            flow_packets_per_sec = total_packets / flow_duration_seconds if flow_duration_seconds > 0 else 0
            fwd_packets_per_sec = fwd_packets / flow_duration_seconds if flow_duration_seconds > 0 else 0
            bwd_packets_per_sec = bwd_packets / flow_duration_seconds if flow_duration_seconds > 0 else 0
            
            # IAT calculations
            fwd_iats = self.flow_iat[flow_id]['fwd']
            bwd_iats = self.flow_iat[flow_id]['bwd']
            all_iats = fwd_iats + bwd_iats
            
            # Flow IAT stats
            flow_iat_mean = np.mean(all_iats) if all_iats else 0
            flow_iat_std = np.std(all_iats) if len(all_iats) > 1 else 0
            flow_iat_max = max(all_iats) if all_iats else 0
            flow_iat_min = min(all_iats) if all_iats else 0
            
            # Forward IAT stats
            fwd_iat_total = sum(fwd_iats)
            fwd_iat_mean = np.mean(fwd_iats) if fwd_iats else 0
            fwd_iat_std = np.std(fwd_iats) if len(fwd_iats) > 1 else 0
            fwd_iat_max = max(fwd_iats) if fwd_iats else 0
            fwd_iat_min = min(fwd_iats) if fwd_iats else 0
            
            # Backward IAT stats
            bwd_iat_total = sum(bwd_iats)
            bwd_iat_mean = np.mean(bwd_iats) if bwd_iats else 0
            bwd_iat_std = np.std(bwd_iats) if len(bwd_iats) > 1 else 0
            bwd_iat_max = max(bwd_iats) if bwd_iats else 0
            bwd_iat_min = min(bwd_iats) if bwd_iats else 0
            
            # Packet length stats
            min_packet_length = min(all_lengths) if all_lengths else 0
            max_packet_length = max(all_lengths) if all_lengths else 0
            packet_length_mean = np.mean(all_lengths) if all_lengths else 0
            packet_length_std = np.std(all_lengths) if len(all_lengths) > 1 else 0
            packet_length_variance = np.var(all_lengths) if len(all_lengths) > 1 else 0
            
            # Flag counts (aggregate for total counts)
            fin_flags = self.flow_flags[flow_id]['fwd']['FIN'] + self.flow_flags[flow_id]['bwd']['FIN']
            syn_flags = self.flow_flags[flow_id]['fwd']['SYN'] + self.flow_flags[flow_id]['bwd']['SYN']
            rst_flags = self.flow_flags[flow_id]['fwd']['RST'] + self.flow_flags[flow_id]['bwd']['RST']
            psh_flags = self.flow_flags[flow_id]['fwd']['PSH'] + self.flow_flags[flow_id]['bwd']['PSH']
            ack_flags = self.flow_flags[flow_id]['fwd']['ACK'] + self.flow_flags[flow_id]['bwd']['ACK']
            urg_flags = self.flow_flags[flow_id]['fwd']['URG'] + self.flow_flags[flow_id]['bwd']['URG']
            cwe_flags = self.flow_flags[flow_id]['fwd']['CWE'] + self.flow_flags[flow_id]['bwd']['CWE']
            ece_flags = self.flow_flags[flow_id]['fwd']['ECE'] + self.flow_flags[flow_id]['bwd']['ECE']
            
            # Direction-specific flag counts
            fwd_psh_flags = self.flow_flags[flow_id]['fwd']['PSH']
            bwd_psh_flags = self.flow_flags[flow_id]['bwd']['PSH']
            fwd_urg_flags = self.flow_flags[flow_id]['fwd']['URG']
            bwd_urg_flags = self.flow_flags[flow_id]['bwd']['URG']
            
            # Header lengths
            fwd_headers = self.flow_header_lengths[flow_id]['fwd']
            bwd_headers = self.flow_header_lengths[flow_id]['bwd']
            fwd_header_length = sum(fwd_headers)
            bwd_header_length = sum(bwd_headers)
            
            # Average sizes
            avg_packet_size = packet_length_mean
            avg_fwd_segment_size = fwd_length_mean
            avg_bwd_segment_size = bwd_length_mean
            
            # Down/Up ratio
            down_up_ratio = bwd_packets / fwd_packets if fwd_packets > 0 else 0
            
            # Window sizes
            fwd_windows = self.flow_window_sizes[flow_id]['fwd']
            bwd_windows = self.flow_window_sizes[flow_id]['bwd']
            init_win_bytes_forward = fwd_windows[0] if fwd_windows else -1
            init_win_bytes_backward = bwd_windows[0] if bwd_windows else -1
            
            # Activity stats
            active_times = self.flow_active_times[flow_id]
            idle_times = self.flow_idle_times[flow_id]
            
            active_mean = np.mean(active_times) if active_times else 0
            active_std = np.std(active_times) if len(active_times) > 1 else 0
            active_max = max(active_times) if active_times else 0
            active_min = min(active_times) if active_times else 0
            
            idle_mean = np.mean(idle_times) if idle_times else 0
            idle_std = np.std(idle_times) if len(idle_times) > 1 else 0
            idle_max = max(idle_times) if idle_times else 0
            idle_min = min(idle_times) if idle_times else 0
            
            # Convert timestamp to ISO format
            iso_timestamp = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
            
            # Create complete row data (full precision for AI training)
            row_data = [
                flow_id, flow['src_ip'], flow['src_port'], flow['dst_ip'], flow['dst_port'], flow['protocol'],
                iso_timestamp, flow_duration, fwd_packets, bwd_packets,
                fwd_total_length, bwd_total_length, fwd_length_max, fwd_length_min, fwd_length_mean, fwd_length_std,
                bwd_length_max, bwd_length_min, bwd_length_mean, bwd_length_std,
                flow_bytes_per_sec, flow_packets_per_sec, flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min,
                fwd_iat_total, fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min,
                bwd_iat_total, bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min,
                fwd_psh_flags, bwd_psh_flags, fwd_urg_flags, bwd_urg_flags, fwd_header_length, bwd_header_length,
                fwd_packets_per_sec, bwd_packets_per_sec, min_packet_length, max_packet_length, packet_length_mean,
                packet_length_std, packet_length_variance,
                fin_flags, syn_flags, rst_flags, psh_flags, ack_flags, urg_flags, cwe_flags, ece_flags,
                down_up_ratio, avg_packet_size, avg_fwd_segment_size, avg_bwd_segment_size, fwd_header_length,
                0, 0, 0, 0, 0, 0,  # Bulk features (not implemented)
                fwd_packets, fwd_total_length, bwd_packets, bwd_total_length,  # Subflow features (Bytes)
                init_win_bytes_forward, init_win_bytes_backward, fwd_packets, min_packet_length,
                active_mean, active_std, active_max, active_min,
                idle_mean, idle_std, idle_max, idle_min
            ]
            
            # Write to CSV
            with open(self.output_file, 'a', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(row_data)
            
            self.logger.info(f"[SAVE] Complete IPv4 Flow: {flow['src_ip']}:{flow['src_port']} -> {flow['dst_ip']}:{flow['dst_port']} ({flow['protocol']}) - {total_packets} packets")
            
        except Exception as e:
            self.logger.error(f"Error saving flow {flow_id}: {e}")
    
    def save_flows(self):
        """Save completed flows to CSV"""
        current_time = time.time()
        completed_flows = []
        
        for flow_id in list(self.flows.keys()):
            if (current_time > self.flow_timeouts.get(flow_id, 0) or 
                sum(self.flows[flow_id]['packet_count'].values()) >= 10):
                
                features = self.calculate_flow_features(flow_id)
                completed_flows.append(features)
                
                # Clean up memory
                del self.flows[flow_id]
                del self.flow_bytes[flow_id]
                del self.flow_packet_lengths[flow_id]
                del self.flow_flags[flow_id]
                del self.flow_iat[flow_id]
                del self.flow_last_packet_time[flow_id]
                del self.flow_header_lengths[flow_id]
                del self.flow_window_sizes[flow_id]
                del self.flow_active_times[flow_id]
                del self.flow_idle_times[flow_id]
                del self.flow_last_active_time[flow_id]
        
        # Write to CSV
        if completed_flows:
            with open(self.output_file, 'a', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                for flow_features in completed_flows:
                    writer.writerow(flow_features)
            
            self.logger.info(f"Saved {len(completed_flows)} completed flows")
    
    def start_collection(self):
        """Start packet collection with promiscuous mode (Windows-specific)"""
        self.logger.info(f"Starting Windows network flow collection on interface: {self.interface}")
        self.logger.info(f"Output file: {self.output_file}")
        self.logger.info(f"Flow timeout: {self.timeout} seconds")
        self.logger.info(f"Promiscuous mode: {'Enabled' if self.promiscuous else 'Disabled'}")
        
        if self.promiscuous:
            self.logger.info("[*] Promiscuous mode enabled - capturing ALL network traffic")
            self.logger.info("[*] Will capture traffic from all devices on the network segment")
        else:
            self.logger.info("[*] Normal mode - capturing only local machine traffic")
        
        # Start periodic saving thread
        save_thread = threading.Thread(target=self.periodic_save, daemon=True)
        save_thread.start()
        
        try:
            # Configure capture parameters for network-wide monitoring
            capture_params = {
                'prn': self.process_packet,
                'store': 0,
                'stop_filter': lambda x: not self.running
            }
            
            # Add promiscuous mode if enabled
            if self.promiscuous:
                # Set promiscuous mode and monitor mode for network-wide capture
                capture_params['monitor'] = False  # Monitor mode can interfere on some adapters
                # Note: Promiscuous mode is enabled by default in Scapy when no filter is specified
            
            # Windows-specific packet capture
            if self.interface:
                self.logger.info(f"Capturing on interface: {self.interface}")
                capture_params['iface'] = self.interface
                sniff(**capture_params)
            else:
                self.logger.info("Capturing on all interfaces")
                sniff(**capture_params)
                
        except Exception as e:
            self.logger.error(f"Error during packet capture: {e}")
            self.logger.error("Make sure Npcap is installed and you have Administrator privileges")
            self.logger.error("Some network adapters may not support promiscuous mode")
        finally:
            # Final statistics
            self.logger.info(f"[FINAL] Capture complete: {self.packet_capture_count} packets captured")
            self.logger.info(f"[FINAL] Total flows created: {len(self.flows)}")
            
            if self.packet_capture_count == 0:
                self.logger.warning("[WARNING] No packets captured! Check interface and permissions")
            elif len(self.flows) < 5 and self.packet_capture_count > 10:
                self.logger.warning(f"[WARNING] Only {len(self.flows)} flows from {self.packet_capture_count} packets")
                self.logger.warning("  Consider longer capture time or check promiscuous mode")
                
            self.save_flows()
    
    def save_flows(self):
        """Save all remaining flows with complete features"""
        self.logger.info("Saving all remaining flows...")
        saved_count = 0
        
        for flow_id in list(self.flows.keys()):
            try:
                self.save_individual_flow(flow_id)
                saved_count += 1
            except Exception as e:
                self.logger.error(f"Error saving flow {flow_id}: {e}")
        
        self.logger.info(f"Saved {saved_count} flows to {self.output_file}")
    
    def periodic_save(self):
        """Periodically save completed flows"""
        while self.running:
            time.sleep(30)
            self.save_flows()

def main():
    parser = argparse.ArgumentParser(description='Windows Network Flow Data Collector')
    parser.add_argument('-i', '--interface', help='Network interface to monitor')
    parser.add_argument('-o', '--output', default='network_flows.csv', help='Output CSV file (timestamp will be added)')
    parser.add_argument('-t', '--timeout', type=int, default=120, help='Flow timeout in seconds')
    parser.add_argument('--no-timestamp', action='store_true', help='Do not add timestamp to output filename')
    parser.add_argument('--no-promiscuous', action='store_true', help='Disable promiscuous mode (capture only local traffic)')
    parser.add_argument('--list-interfaces', action='store_true', help='List available network interfaces')
    
    args = parser.parse_args()
    
    if args.list_interfaces:
        collector = WindowsNetworkFlowCollector()
        interfaces = collector.get_windows_interfaces()
        
        print("Available network interfaces on Windows:")
        for i, iface in enumerate(interfaces):
            print(f"  {i+1}. {iface['name']}")
        return
    
    # Check administrator privileges
    collector = WindowsNetworkFlowCollector()
    if not collector.is_admin():
        print("Warning: Not running as Administrator.")
        print("For best results, run this script as Administrator (Run as Administrator)")
        print("Continuing anyway...")
        print()
    
    collector = WindowsNetworkFlowCollector(
        output_file=args.output,
        interface=args.interface,
        timeout=args.timeout,
        add_timestamp=not args.no_timestamp,
        promiscuous=not args.no_promiscuous
    )
    
    print(f"Starting Windows Network Flow Collection...")
    print(f"Output file: {collector.output_file}")
    print(f"Interface: {collector.interface or 'Auto-detect'}")
    print(f"Timeout: {collector.timeout} seconds")
    if collector.timeout < 60:
        print("[TIP] Short timeout may limit flow detection. Try -t 300 for better results")
    print(f"Promiscuous mode: {'Enabled' if collector.promiscuous else 'Disabled'}")
    if collector.promiscuous:
        print("[*] Will capture ALL network traffic (like Wireshark)")
        print("[*] Including traffic from other devices on the network")
    else:
        print("[*] Will capture only local machine traffic")
    print("Press Ctrl+C to stop...")
    print()
    
    collector.start_collection()

if __name__ == "__main__":
    main()