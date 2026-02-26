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
    def __init__(self, output_file="network_flows.csv", interface=None, timeout=300, add_timestamp=True, promiscuous=True, capture_packets=False):
        # Add timestamp to output file if requested
        if add_timestamp and output_file:
            self.output_file = self.add_timestamp_to_filename(output_file)
        else:
            self.output_file = output_file
            
        self.original_output_file = output_file  # Keep original for reference
        self.interface = interface
        self.timeout = timeout
        self.promiscuous = promiscuous  # Enable promiscuous mode for network-wide capture
        self.capture_packets = capture_packets  # Enable/disable per-packet Wireshark-style CSV
        
        # Packet-level CSV file (Wireshark-style)
        if capture_packets and output_file:
            base = output_file.rsplit('.', 1)
            if add_timestamp:
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                self.packet_csv_file = f"{base[0]}_packets_{ts}.csv" if len(base) > 1 else f"{base[0]}_packets_{ts}.csv"
            else:
                self.packet_csv_file = f"{base[0]}_packets.csv" if len(base) > 1 else f"{base[0]}_packets.csv"
        else:
            self.packet_csv_file = None
        self.packet_no = 0  # Packet counter for packet CSV
        
        self.flows = defaultdict(dict)
        self.flow_timeouts = defaultdict(float)
        self.packet_timestamps = defaultdict(list)
        self.running = True
        
        # Flow tracking (same as Linux version)
        self.flow_packets = defaultdict(list)
        self.flow_bytes = defaultdict(lambda: {'fwd': 0, 'bwd': 0})
        self.flow_packet_lengths = defaultdict(lambda: {'fwd': [], 'bwd': []})
        self.flow_flags = defaultdict(lambda: defaultdict(int))
        self.flow_iat = defaultdict(lambda: {'fwd': [], 'bwd': []})
        self.flow_last_packet_time = defaultdict(lambda: {'fwd': None, 'bwd': None})
        self.flow_header_lengths = defaultdict(lambda: {'fwd': [], 'bwd': []})
        self.flow_window_sizes = defaultdict(lambda: {'fwd': [], 'bwd': []})
        self.flow_active_times = defaultdict(list)
        self.flow_idle_times = defaultdict(list)
        self.flow_last_active_time = defaultdict(float)
        
        # Info string tracking (stores Wireshark-style Info of first packet per flow)
        self.flow_info = defaultdict(str)
        
        # DPI content tracking (stores application-layer content of first packet per flow)
        self.flow_content = defaultdict(str)
        
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
        
        # Initialize packet-level CSV if enabled
        if self.capture_packets:
            self.init_packet_csv_file()
    
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
            'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min',
            'Info', 'Payload Content'
        ]
        
        with open(self.output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(headers)
    
    def init_packet_csv_file(self):
        """Initialize Wireshark-style per-packet CSV file"""
        headers = [
            'No.', 'Time', 'Source', 'Src Port', 'Destination', 'Dst Port',
            'Protocol', 'Length', 'TTL', 'Info'
        ]
        with open(self.packet_csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(headers)
        self.logger.info(f"Packet CSV initialized: {self.packet_csv_file}")
    
    def generate_packet_info(self, packet):
        """Generate Wireshark-style Info string for a packet"""
        try:
            # ARP
            if packet.haslayer('ARP'):
                arp = packet['ARP']
                if arp.op == 1:
                    return f"Who has {arp.pdst}? Tell {arp.psrc}"
                elif arp.op == 2:
                    return f"{arp.hwsrc} is at {arp.psrc}"
                return f"ARP op={arp.op}"
            
            # ICMP
            if packet.haslayer(ICMP):
                icmp = packet[ICMP]
                icmp_types = {
                    0: "Echo Reply",
                    3: "Destination Unreachable",
                    8: "Echo Request (ping)",
                    11: "Time Exceeded",
                    5: "Redirect",
                }
                type_str = icmp_types.get(icmp.type, f"Type={icmp.type}")
                id_seq = ""
                if hasattr(icmp, 'id') and hasattr(icmp, 'seq'):
                    id_seq = f" id={icmp.id}, seq={icmp.seq}"
                return f"ICMP {type_str}{id_seq}"
            
            # TCP
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                sport = tcp.sport
                dport = tcp.dport
                seq = tcp.seq
                ack = tcp.ack
                win = tcp.window
                flags = tcp.flags
                
                flag_parts = []
                if flags.S and flags.A:
                    flag_parts.append("SYN, ACK")
                elif flags.S:
                    flag_parts.append("SYN")
                elif flags.F and flags.A:
                    flag_parts.append("FIN, ACK")
                elif flags.F:
                    flag_parts.append("FIN")
                elif flags.R:
                    flag_parts.append("RST")
                elif flags.A:
                    flag_parts.append("ACK")
                if flags.P:
                    flag_parts.append("PSH")
                if flags.U:
                    flag_parts.append("URG")
                
                flag_str = ", ".join(flag_parts) if flag_parts else "-"
                
                # Check for TLS (port 443 or 8443)
                payload_len = len(packet[TCP].payload) if packet[TCP].payload else 0
                if dport in (443, 8443, 993, 995, 465) or sport in (443, 8443, 993, 995, 465):
                    if payload_len > 0:
                        # Detect TLS record type
                        try:
                            raw = bytes(packet[TCP].payload)
                            tls_types = {20: "Change Cipher Spec", 21: "Alert",
                                         22: "Handshake", 23: "Application Data"}
                            tls_type = tls_types.get(raw[0], None)
                            if tls_type:
                                return f"TLSv1.x {tls_type}, {sport} -> {dport} [{flag_str}] Seq={seq} Ack={ack} Win={win} Len={payload_len}"
                        except Exception:
                            pass
                    return f"TLS {sport} -> {dport} [{flag_str}] Seq={seq} Ack={ack} Win={win} Len={payload_len}"
                
                # Check for HTTP
                if dport == 80 or sport == 80:
                    try:
                        raw = bytes(packet[TCP].payload)
                        first_line = raw.split(b'\r\n')[0].decode('utf-8', errors='replace')
                        if first_line.startswith(('GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'HTTP')):
                            return f"HTTP {first_line[:80]}"
                    except Exception:
                        pass
                
                return f"{sport} -> {dport} [{flag_str}] Seq={seq} Ack={ack} Win={win} Len={payload_len}"
            
            # UDP
            if packet.haslayer(UDP):
                udp = packet[UDP]
                sport = udp.sport
                dport = udp.dport
                length = udp.len
                
                # DNS / MDNS (port 53 or 5353)
                if dport in (53, 5353) or sport in (53, 5353):
                    try:
                        from scapy.layers.dns import DNS
                        if packet.haslayer(DNS):
                            dns = packet[DNS]
                            proto = "MDNS" if dport == 5353 or sport == 5353 else "DNS"
                            if dns.qr == 0:  # Query
                                qname = dns.qd.qname.decode('utf-8', errors='replace') if dns.qd else "?"
                                qtype = dns.qd.qtype if dns.qd else 0
                                type_map = {1: "A", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV"}
                                qtype_str = type_map.get(qtype, str(qtype))
                                return f"{proto} Standard query {hex(dns.id)} {qtype_str} {qname}"
                            else:  # Response
                                qname = dns.qd.qname.decode('utf-8', errors='replace') if dns.qd else "?"
                                return f"{proto} Standard query response {hex(dns.id)} {qname}"
                    except Exception:
                        pass
                    return f"DNS/MDNS {sport} -> {dport} Len={length}"
                
                # DHCP (port 67/68)
                if dport in (67, 68) or sport in (67, 68):
                    try:
                        from scapy.layers.dhcp import DHCP, BOOTP
                        if packet.haslayer(DHCP):
                            msg_type_map = {1: "Discover", 2: "Offer", 3: "Request", 5: "ACK", 6: "NAK"}
                            for opt in packet[DHCP].options:
                                if isinstance(opt, tuple) and opt[0] == 'message-type':
                                    return f"DHCP {msg_type_map.get(opt[1], str(opt[1]))} - Transaction ID {hex(packet[BOOTP].xid)}"
                    except Exception:
                        pass
                    return f"DHCP {sport} -> {dport}"
                
                return f"UDP {sport} -> {dport} Len={length}"
            
            # Fallback: use Scapy's own summary
            return packet.summary()
        
        except Exception:
            return "-"
    
    def save_packet_to_csv(self, packet, pkt_time):
        """Write a single packet as a row in the Wireshark-style CSV"""
        if not self.packet_csv_file:
            return
        try:
            self.packet_no += 1
            
            # Source / destination
            src = dst = src_port = dst_port = proto_name = ""
            ttl = 0
            
            if packet.haslayer(IP):
                ip = packet[IP]
                src = ip.src
                dst = ip.dst
                ttl = ip.ttl
                if packet.haslayer(TCP):
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    # Determine TLS or TCP
                    if dst_port in (443, 8443, 993, 995, 465) or src_port in (443, 8443, 993, 995, 465):
                        proto_name = "TLSv1.2"
                    else:
                        proto_name = "TCP"
                elif packet.haslayer(UDP):
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    if dst_port in (53, 5353) or src_port in (53, 5353):
                        proto_name = "MDNS" if (dst_port == 5353 or src_port == 5353) else "DNS"
                    elif dst_port in (67, 68) or src_port in (67, 68):
                        proto_name = "DHCP"
                    else:
                        proto_name = "UDP"
                elif packet.haslayer(ICMP):
                    proto_name = "ICMP"
                else:
                    proto_name = f"IPv4({ip.proto})"
            elif packet.haslayer('ARP'):
                arp = packet['ARP']
                src = arp.psrc
                dst = arp.pdst
                proto_name = "ARP"
            else:
                proto_name = packet.name if hasattr(packet, 'name') else "OTHER"
            
            info = self.generate_packet_info(packet)
            length = len(packet)
            fmt_time = datetime.fromtimestamp(pkt_time).strftime('%Y-%m-%d %H:%M:%S.%f')
            
            row = [self.packet_no, fmt_time, src, src_port, dst, dst_port, proto_name, length, ttl, info]
            
            with open(self.packet_csv_file, 'a', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(row)
        except Exception as e:
            self.logger.debug(f"Error saving packet {self.packet_no}: {e}")
    
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
        
        packet_length = len(packet)
        
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
            'window_size': window_size,
            'raw_packet': packet  # Keep reference for Info generation
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
            # Generate and store Wireshark-style Info for the first packet
            try:
                self.flow_info[flow_id] = self.generate_packet_info(features['raw_packet'])
            except Exception:
                self.flow_info[flow_id] = ''
            # DPI: detect application-layer content of the first packet
            try:
                self.flow_content[flow_id] = self.detect_payload_content(features['raw_packet'])
            except Exception:
                self.flow_content[flow_id] = ''
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
        if features.get('window_size', 0) > 0:
            self.flow_window_sizes[flow_id][direction].append(features['window_size'])
        
        # Update flags (aggregate by flow, not direction)
        for flag, value in features['tcp_flags'].items():
            self.flow_flags[flow_id][flag] += value
        
        # Calculate IAT
        last_time = self.flow_last_packet_time[flow_id][direction]
        if last_time is not None:
            iat = timestamp - last_time
            self.flow_iat[flow_id][direction].append(iat)
        self.flow_last_packet_time[flow_id][direction] = timestamp
        
        # Update activity tracking
        current_time = time.time()
        if flow_id in self.flow_last_active_time:
            idle_time = current_time - self.flow_last_active_time[flow_id]
            if idle_time > 1.0:  # More than 1 second idle
                self.flow_idle_times[flow_id].append(idle_time)
        
        self.flow_last_active_time[flow_id] = current_time
        

        
        # Track active/idle times
        if timestamp - self.flow_last_active_time[flow_id] > 1.0:
            idle_time = timestamp - self.flow_last_active_time[flow_id]
            self.flow_idle_times[flow_id].append(idle_time)
        else:
            active_time = timestamp - self.flow_last_active_time[flow_id]
            if active_time > 0:
                self.flow_active_times[flow_id].append(active_time)
        
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
        """Calculate all features for a flow (same logic as Linux version)"""
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
        
        # Flag counts
        flags = self.flow_flags[flow_id]
        
        # Build feature vector (same as Linux version)
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
            flags.get('fwd_PSH', 0), flags.get('bwd_PSH', 0), flags.get('fwd_URG', 0), flags.get('bwd_URG', 0),
            sum(fwd_headers) if fwd_headers else 0, sum(bwd_headers) if bwd_headers else 0,
            fwd_packets_per_sec, bwd_packets_per_sec, all_len_stats['min'], all_len_stats['max'],
            all_len_stats['mean'], all_len_stats['std'], all_len_stats['variance'],
            flags.get('fwd_FIN', 0) + flags.get('bwd_FIN', 0),
            flags.get('fwd_SYN', 0) + flags.get('bwd_SYN', 0),
            flags.get('fwd_RST', 0) + flags.get('bwd_RST', 0),
            flags.get('fwd_PSH', 0) + flags.get('bwd_PSH', 0),
            flags.get('fwd_ACK', 0) + flags.get('bwd_ACK', 0),
            flags.get('fwd_URG', 0) + flags.get('bwd_URG', 0),
            flags.get('fwd_CWE', 0) + flags.get('bwd_CWE', 0),
            flags.get('fwd_ECE', 0) + flags.get('bwd_ECE', 0),
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
            
            # Total lengths
            fwd_total_length = sum(fwd_lengths)
            bwd_total_length = sum(bwd_lengths)
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
            
            # Flag counts
            fin_flags = self.flow_flags[flow_id]['FIN']
            syn_flags = self.flow_flags[flow_id]['SYN']
            rst_flags = self.flow_flags[flow_id]['RST']
            psh_flags = self.flow_flags[flow_id]['PSH']
            ack_flags = self.flow_flags[flow_id]['ACK']
            urg_flags = self.flow_flags[flow_id]['URG']
            cwe_flags = self.flow_flags[flow_id]['CWE']
            ece_flags = self.flow_flags[flow_id]['ECE']
            
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
            
            # Get stored Wireshark-style Info for this flow
            flow_info_str = self.flow_info.get(flow_id, '')
            # Get DPI Payload Content for this flow
            flow_content_str = self.flow_content.get(flow_id, '')
            
            # Create complete row data
            row_data = [
                flow_id, flow['src_ip'], flow['src_port'], flow['dst_ip'], flow['dst_port'], flow['protocol'],
                iso_timestamp, flow_duration, fwd_packets, bwd_packets,
                fwd_total_length, bwd_total_length, fwd_length_max, fwd_length_min, fwd_length_mean, fwd_length_std,
                bwd_length_max, bwd_length_min, bwd_length_mean, bwd_length_std,
                flow_bytes_per_sec, flow_packets_per_sec, flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min,
                fwd_iat_total, fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min,
                bwd_iat_total, bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min,
                psh_flags, psh_flags, urg_flags, urg_flags, fwd_header_length, bwd_header_length,
                fwd_packets_per_sec, bwd_packets_per_sec, min_packet_length, max_packet_length, packet_length_mean,
                packet_length_std, packet_length_variance,
                fin_flags, syn_flags, rst_flags, psh_flags, ack_flags, urg_flags, cwe_flags, ece_flags,
                down_up_ratio, avg_packet_size, avg_fwd_segment_size, avg_bwd_segment_size, fwd_header_length,
                0, 0, 0, 0, 0, 0,  # Bulk features (not implemented)
                fwd_packets, fwd_total_length, bwd_packets, bwd_total_length,  # Subflow features (Bytes)
                init_win_bytes_forward, init_win_bytes_backward, fwd_packets, min_packet_length,
                active_mean, active_std, active_max, active_min,
                idle_mean, idle_std, idle_max, idle_min,
                flow_info_str, flow_content_str
            ]
            
            # Write to CSV
            with open(self.output_file, 'a', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(row_data)
            
            self.logger.info(f"[SAVE] Complete IPv4 Flow: {flow['src_ip']}:{flow['src_port']} -> {flow['dst_ip']}:{flow['dst_port']} ({flow['protocol']}) - {total_packets} packets")
            
        except Exception as e:
            self.logger.error(f"Error saving flow {flow_id}: {e}")
    
    def detect_payload_content(self, packet):
        """Deep Packet Inspection: detect and extract application-layer content"""
        try:
            # --- HTTP (port 80, 8080, 8000) ---
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                sport = tcp.sport
                dport = tcp.dport
                
                if dport in (80, 8080, 8000, 8888) or sport in (80, 8080, 8000, 8888):
                    try:
                        raw = bytes(tcp.payload)
                        if not raw:
                            return ''
                        text = raw.decode('utf-8', errors='replace')
                        first_line = text.split('\r\n')[0][:120]
                        # HTTP Request
                        if first_line.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ',
                                                   'HEAD ', 'PATCH ', 'OPTIONS ')):
                            method, path = first_line.split(' ', 1)[:2]
                            path = path.rsplit(' ', 1)[0]  # strip HTTP/1.x
                            # Extract Host header
                            host = ''
                            for line in text.split('\r\n')[1:10]:
                                if line.lower().startswith('host:'):
                                    host = line.split(':', 1)[1].strip()
                                    break
                            return f"HTTP Request: {method} http://{host}{path}"
                        # HTTP Response
                        elif first_line.startswith('HTTP/'):
                            status = first_line[:30]
                            content_type = ''
                            for line in text.split('\r\n')[1:15]:
                                if line.lower().startswith('content-type:'):
                                    content_type = line.split(':', 1)[1].strip()[:50]
                                    break
                            return f"HTTP Response: {status}" + (f" | {content_type}" if content_type else '')
                    except Exception:
                        pass
                
                # --- TLS / HTTPS ---
                if dport in (443, 8443, 993, 995, 465) or sport in (443, 8443, 993, 995, 465):
                    try:
                        raw = bytes(tcp.payload)
                        if raw:
                            record_types = {20: 'ChangeCipherSpec', 21: 'Alert',
                                            22: 'Handshake', 23: 'ApplicationData'}
                            handshake_types = {1: 'ClientHello', 2: 'ServerHello',
                                               11: 'Certificate', 12: 'ServerKeyExchange',
                                               14: 'ServerHelloDone', 16: 'ClientKeyExchange',
                                               20: 'Finished'}
                            rec = record_types.get(raw[0], None)
                            if rec:
                                if rec == 'Handshake' and len(raw) >= 6:
                                    hs = handshake_types.get(raw[5], f'type={raw[5]}')
                                    return f"TLS Handshake: {hs}"
                                return f"TLS: {rec} (encrypted)"
                    except Exception:
                        pass
                    return 'TLS: Encrypted application data'
                
                # --- FTP (port 21) ---
                if dport == 21 or sport == 21:
                    try:
                        raw = bytes(tcp.payload)
                        line = raw.decode('utf-8', errors='replace').split('\r\n')[0][:100]
                        return f"FTP: {line}"
                    except Exception:
                        pass
                
                # --- SMTP (port 25, 587) ---
                if dport in (25, 587) or sport in (25, 587):
                    try:
                        raw = bytes(tcp.payload)
                        line = raw.decode('utf-8', errors='replace').split('\r\n')[0][:100]
                        return f"SMTP: {line}"
                    except Exception:
                        pass
                
                # --- SSH (port 22) ---
                if dport == 22 or sport == 22:
                    try:
                        raw = bytes(tcp.payload)
                        if raw[:4] == b'SSH-':
                            banner = raw.decode('utf-8', errors='replace').split('\r\n')[0][:60]
                            return f"SSH Banner: {banner}"
                    except Exception:
                        pass
                    return 'SSH: Encrypted session'
                
                # Generic TCP: show first printable bytes only if mostly readable
                try:
                    raw = bytes(tcp.payload)
                    if raw:
                        printable_chars = sum(1 for b in raw if 32 <= b < 127)
                        ratio = printable_chars / len(raw)
                        if ratio >= 0.40:  # At least 40% printable
                            printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in raw[:80])
                            printable = printable.strip('.')
                            if printable:
                                return f"TCP Raw: {printable[:80]}"
                except Exception:
                    pass
            
            # --- DNS / MDNS ---
            if packet.haslayer(UDP):
                udp = packet[UDP]
                if udp.dport in (53, 5353) or udp.sport in (53, 5353):
                    try:
                        from scapy.layers.dns import DNS
                        if packet.haslayer(DNS):
                            dns = packet[DNS]
                            results = []
                            if dns.qr == 0 and dns.qd:  # Query
                                qname = dns.qd.qname.decode('utf-8', errors='replace').rstrip('.')
                                results.append(f"DNS Query: {qname}")
                            elif dns.qr == 1:  # Response
                                if dns.an:
                                    an = dns.an
                                    while an:
                                        name = an.rrname.decode('utf-8', errors='replace').rstrip('.')
                                        if hasattr(an, 'rdata'):
                                            rdata = str(an.rdata)
                                            results.append(f"{name} -> {rdata}")
                                        an = an.payload if hasattr(an, 'payload') and an.payload else None
                                        if not hasattr(an, 'rrname'):
                                            break
                                if results:
                                    return 'DNS Response: ' + '; '.join(results[:3])
                                return 'DNS Response (empty)'
                            return '; '.join(results) if results else ''
                    except Exception:
                        pass
                
                # --- SSDP / UPnP (port 1900) ---
                if udp.dport == 1900 or udp.sport == 1900:
                    try:
                        raw = bytes(udp.payload)
                        text = raw.decode('utf-8', errors='replace')
                        first_line = text.split('\r\n')[0][:100]
                        if first_line.startswith('M-SEARCH'):
                            # Extract ST (Search Target)
                            st = ''
                            for line in text.split('\r\n')[1:10]:
                                if line.upper().startswith('ST:'):
                                    st = line.split(':', 1)[1].strip()[:60]
                                    break
                            return f"SSDP M-SEARCH | ST: {st}" if st else "SSDP M-SEARCH"
                        elif first_line.startswith('NOTIFY'):
                            nt = ''
                            for line in text.split('\r\n')[1:10]:
                                if line.upper().startswith('NT:'):
                                    nt = line.split(':', 1)[1].strip()[:60]
                                    break
                            return f"SSDP NOTIFY | NT: {nt}" if nt else "SSDP NOTIFY"
                        elif first_line.startswith('HTTP/'):
                            return f"SSDP Response: {first_line[:80]}"
                        return f"SSDP: {first_line[:80]}"
                    except Exception:
                        pass
                
                # --- DHCP ---
                if udp.dport in (67, 68) or udp.sport in (67, 68):
                    try:
                        from scapy.layers.dhcp import DHCP, BOOTP
                        if packet.haslayer(DHCP):
                            msg_map = {1: 'Discover', 2: 'Offer', 3: 'Request',
                                       4: 'Decline', 5: 'ACK', 6: 'NAK', 7: 'Release', 8: 'Inform'}
                            for opt in packet[DHCP].options:
                                if isinstance(opt, tuple) and opt[0] == 'message-type':
                                    msg = msg_map.get(opt[1], str(opt[1]))
                                    xid = hex(packet[BOOTP].xid)
                                    client = packet[BOOTP].chaddr.hex()[:12] if packet[BOOTP].chaddr else ''
                                    return f"DHCP {msg} | xid={xid} | client={client}"
                    except Exception:
                        pass
                
                # Generic UDP: only show if payload is mostly printable text
                try:
                    raw = bytes(udp.payload)
                    if raw:
                        printable_chars = sum(1 for b in raw if 32 <= b < 127)
                        ratio = printable_chars / len(raw)
                        if ratio >= 0.40:  # At least 40% printable
                            printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in raw[:80])
                            printable = printable.strip('.')
                            if printable:
                                return f"UDP Raw: {printable[:80]}"
                except Exception:
                    pass
            
            # --- ICMP ---
            if packet.haslayer(ICMP):
                icmp = packet[ICMP]
                if icmp.type == 8:
                    try:
                        raw = bytes(icmp.payload)
                        printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in raw[:40])
                        return f"ICMP Ping data: {printable[:40]}"
                    except Exception:
                        pass
                    return 'ICMP Echo Request'
                elif icmp.type == 0:
                    return 'ICMP Echo Reply'
            
            return ''
        except Exception:
            return ''
    
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
        """Save all remaining flows with complete features, then clean up memory"""
        self.logger.info("Saving all remaining flows...")
        saved_count = 0
        
        for flow_id in list(self.flows.keys()):
            try:
                self.save_individual_flow(flow_id)
                saved_count += 1
            except Exception as e:
                self.logger.error(f"Error saving flow {flow_id}: {e}")
            finally:
                # Always clean up this flow from ALL tracking dicts after saving
                # so it never gets saved a second time with empty Info
                for store in [
                    self.flows, self.flow_timeouts, self.flow_bytes,
                    self.flow_packet_lengths, self.flow_flags, self.flow_iat,
                    self.flow_last_packet_time, self.flow_header_lengths,
                    self.flow_window_sizes, self.flow_active_times,
                    self.flow_idle_times, self.flow_last_active_time,
                    self.flow_packets, self.flow_info, self.flow_content
                ]:
                    try:
                        del store[flow_id]
                    except KeyError:
                        pass
        
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

