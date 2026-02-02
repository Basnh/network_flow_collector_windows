#!/usr/bin/env python3
"""
Data Labeling Tool for Network Flow Data - Windows Version
Tool để gán label cho dữ liệu network flow trên Windows
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import argparse
import json
import sys
import os

class WindowsFlowLabeler:
    def __init__(self, csv_file):
        self.csv_file = csv_file
        self.df = pd.read_csv(csv_file)
        
        # Convert timestamp
        if 'Timestamp' in self.df.columns:
            self.df['Timestamp'] = pd.to_datetime(self.df['Timestamp'])
        
        print(f"Loaded {len(self.df)} flows for labeling on Windows")
    
    def label_by_time(self, attack_periods):
        """Label flows based on time periods"""
        print("Labeling flows by time periods...")
        
        # Default to BENIGN
        self.df['Class'] = 'BENIGN'
        
        for period in attack_periods:
            start_time = pd.to_datetime(period['start'])
            end_time = pd.to_datetime(period['end'])
            label = period['label']
            
            mask = (self.df['Timestamp'] >= start_time) & (self.df['Timestamp'] <= end_time)
            labeled_count = mask.sum()
            
            self.df.loc[mask, 'Class'] = label
            print(f"Labeled {labeled_count} flows as {label} between {start_time} and {end_time}")
    
    def label_by_ip(self, ip_labels):
        """Label flows based on source/destination IPs"""
        print("Labeling flows by IP addresses...")
        
        if 'Class' not in self.df.columns:
            self.df['Class'] = 'BENIGN'
        
        for ip, label in ip_labels.items():
            mask = (self.df['Source IP'] == ip) | (self.df['Destination IP'] == ip)
            labeled_count = mask.sum()
            
            self.df.loc[mask, 'Class'] = label
            print(f"Labeled {labeled_count} flows involving IP {ip} as {label}")
    
    def label_by_port(self, port_labels):
        """Label flows based on ports"""
        print("Labeling flows by ports...")
        
        if 'Class' not in self.df.columns:
            self.df['Class'] = 'BENIGN'
        
        for port, label in port_labels.items():
            mask = (self.df['Source Port'] == port) | (self.df['Destination Port'] == port)
            labeled_count = mask.sum()
            
            self.df.loc[mask, 'Class'] = label
            print(f"Labeled {labeled_count} flows involving port {port} as {label}")
    
    def label_windows_services(self):
        """Automatically label flows based on Windows service patterns"""
        print("Labeling Windows service patterns...")
        
        if 'Class' not in self.df.columns:
            self.df['Class'] = 'BENIGN'
        
        # Windows service port mappings
        windows_services = {
            135: 'Windows_RPC',
            139: 'NetBIOS',
            445: 'SMB',
            3389: 'RDP',
            5985: 'WinRM_HTTP',
            5986: 'WinRM_HTTPS',
            1433: 'MSSQL',
            1434: 'MSSQL_Browser'
        }
        
        for port, service_name in windows_services.items():
            mask = (self.df['Source Port'] == port) | (self.df['Destination Port'] == port)
            labeled_count = mask.sum()
            
            if labeled_count > 0:
                self.df.loc[mask, 'Class'] = service_name
                print(f"Labeled {labeled_count} flows as {service_name} (port {port})")
    
    def label_rdp_attacks(self):
        """Detect potential RDP brute force attacks"""
        print("Detecting potential RDP attacks...")
        
        if 'Class' not in self.df.columns:
            self.df['Class'] = 'BENIGN'
        
        # RDP brute force indicators
        rdp_flows = self.df[self.df['Destination Port'] == 3389]
        
        if len(rdp_flows) > 0:
            # Multiple failed connections from same source
            rdp_stats = rdp_flows.groupby('Source IP').agg({
                'Flow ID': 'count',
                'Flow Duration': 'mean',
                'Total Fwd Packets': 'mean'
            })
            
            # Potential brute force: many short connections
            brute_force_mask = (
                (rdp_stats['Flow ID'] > 10) &  # Many connection attempts
                (rdp_stats['Flow Duration'] < 1000000) &  # Short duration
                (rdp_stats['Total Fwd Packets'] < 10)  # Few packets
            )
            
            brute_force_ips = rdp_stats[brute_force_mask].index
            
            for ip in brute_force_ips:
                mask = (self.df['Source IP'] == ip) & (self.df['Destination Port'] == 3389)
                labeled_count = mask.sum()
                
                self.df.loc[mask, 'Class'] = 'RDP_BruteForce'
                print(f"Labeled {labeled_count} flows from {ip} as RDP_BruteForce")
    
    def label_smb_anomalies(self):
        """Detect SMB-related anomalies"""
        print("Detecting SMB anomalies...")
        
        if 'Class' not in self.df.columns:
            self.df['Class'] = 'BENIGN'
        
        # SMB flows (port 445)
        smb_flows = self.df[self.df['Destination Port'] == 445]
        
        if len(smb_flows) > 0:
            # Large data transfers (potential data exfiltration)
            large_transfers = smb_flows[
                (smb_flows['Total Length of Fwd Packets'] > smb_flows['Total Length of Fwd Packets'].quantile(0.95)) |
                (smb_flows['Total Length of Bwd Packets'] > smb_flows['Total Length of Bwd Packets'].quantile(0.95))
            ]
            
            if len(large_transfers) > 0:
                large_transfer_mask = self.df['Flow ID'].isin(large_transfers['Flow ID'])
                labeled_count = large_transfer_mask.sum()
                
                self.df.loc[large_transfer_mask, 'Class'] = 'SMB_LargeTransfer'
                print(f"Labeled {labeled_count} flows as SMB_LargeTransfer")
            
            # Unusual access patterns
            smb_stats = smb_flows.groupby('Source IP')['Destination IP'].nunique()
            lateral_movement = smb_stats[smb_stats > 5]  # Accessing many different SMB servers
            
            for ip in lateral_movement.index:
                mask = (self.df['Source IP'] == ip) & (self.df['Destination Port'] == 445)
                labeled_count = mask.sum()
                
                self.df.loc[mask, 'Class'] = 'SMB_LateralMovement'
                print(f"Labeled {labeled_count} flows from {ip} as SMB_LateralMovement")
    
    def label_dns_anomalies(self):
        """Detect DNS-related anomalies"""
        print("Detecting DNS anomalies...")
        
        if 'Class' not in self.df.columns:
            self.df['Class'] = 'BENIGN'
        
        # DNS flows (port 53)
        dns_flows = self.df[self.df['Destination Port'] == 53]
        
        if len(dns_flows) > 0:
            # High volume DNS requests (potential DNS tunneling or DGA)
            dns_stats = dns_flows.groupby('Source IP')['Flow ID'].count()
            high_volume_dns = dns_stats[dns_stats > dns_stats.quantile(0.95)]
            
            for ip in high_volume_dns.index:
                mask = (self.df['Source IP'] == ip) & (self.df['Destination Port'] == 53)
                labeled_count = mask.sum()
                
                self.df.loc[mask, 'Class'] = 'DNS_HighVolume'
                print(f"Labeled {labeled_count} flows from {ip} as DNS_HighVolume")
    
    def interactive_labeling_windows(self):
        """Windows-specific interactive labeling mode"""
        print("\n=== Windows Interactive Labeling Mode ===")
        print("Commands:")
        print("  time <start> <end> <label> - Label by time period")
        print("  ip <ip_address> <label> - Label by IP address")
        print("  port <port> <label> - Label by port")
        print("  windows-services - Auto-label Windows services")
        print("  rdp-attacks - Detect RDP brute force")
        print("  smb-anomalies - Detect SMB anomalies")
        print("  dns-anomalies - Detect DNS anomalies")
        print("  show stats - Show current label distribution")
        print("  save <filename> - Save current state")
        print("  quit - Exit interactive mode")
        
        while True:
            command = input("\nWindows> ").strip()
            
            if command == 'quit':
                break
            elif command == 'show stats':
                self.show_label_stats()
            elif command == 'windows-services':
                self.label_windows_services()
            elif command == 'rdp-attacks':
                self.label_rdp_attacks()
            elif command == 'smb-anomalies':
                self.label_smb_anomalies()
            elif command == 'dns-anomalies':
                self.label_dns_anomalies()
            elif command.startswith('time '):
                parts = command.split()
                if len(parts) >= 4:
                    start_time = parts[1] + ' ' + parts[2]
                    end_time = parts[3] + ' ' + parts[4]
                    label = ' '.join(parts[5:]) if len(parts) > 5 else 'ATTACK'
                    
                    self.label_by_time([{
                        'start': start_time,
                        'end': end_time,
                        'label': label
                    }])
            elif command.startswith('ip '):
                parts = command.split()
                if len(parts) >= 3:
                    ip = parts[1]
                    label = ' '.join(parts[2:])
                    self.label_by_ip({ip: label})
            elif command.startswith('port '):
                parts = command.split()
                if len(parts) >= 3:
                    try:
                        port = int(parts[1])
                        label = ' '.join(parts[2:])
                        self.label_by_port({port: label})
                    except ValueError:
                        print("Invalid port number")
            elif command.startswith('save '):
                filename = command.split()[1]
                self.save_labeled_data(filename)
            else:
                print("Unknown command. Type 'quit' to exit.")
    
    def show_label_stats(self):
        """Show current label distribution"""
        if 'Class' in self.df.columns:
            print("\nCurrent label distribution:")
            label_counts = self.df['Class'].value_counts()
            for label, count in label_counts.items():
                print(f"  {label}: {count} flows ({count/len(self.df)*100:.2f}%)")
        else:
            print("No labels found in data")
    
    def save_labeled_data(self, output_file=None):
        """Save labeled data to CSV"""
        if output_file is None:
            output_file = self.csv_file.replace('.csv', '_windows_labeled.csv')
        
        # Use Windows-friendly file path
        output_file = os.path.abspath(output_file)
        
        self.df.to_csv(output_file, index=False)
        print(f"Labeled data saved to {output_file}")
    
    def create_windows_labeling_config(self, config_file="windows_labeling_config.json"):
        """Create Windows-specific labeling configuration"""
        config = {
            "time_periods": [
                {
                    "start": "2024-01-01 10:00:00",
                    "end": "2024-01-01 10:30:00", 
                    "label": "RDP_Attack"
                },
                {
                    "start": "2024-01-01 14:00:00",
                    "end": "2024-01-01 14:15:00",
                    "label": "SMB_Attack"
                }
            ],
            "ip_labels": {
                "192.168.1.100": "Attacker_Workstation",
                "10.0.0.50": "Compromised_Host"
            },
            "port_labels": {
                "3389": "RDP_Traffic",
                "445": "SMB_Traffic",
                "135": "RPC_Traffic"
            },
            "auto_windows_services": True,
            "auto_rdp_detection": True,
            "auto_smb_detection": True,
            "auto_dns_detection": True
        }
        
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        
        print(f"Windows labeling configuration saved to {config_file}")
    
    def load_windows_labeling_config(self, config_file):
        """Load Windows-specific labeling configuration"""
        with open(config_file, 'r') as f:
            config = json.load(f)
        
        # Apply time-based labels
        if 'time_periods' in config:
            self.label_by_time(config['time_periods'])
        
        # Apply IP-based labels
        if 'ip_labels' in config:
            self.label_by_ip(config['ip_labels'])
        
        # Apply port-based labels
        if 'port_labels' in config:
            port_labels = {int(k): v for k, v in config['port_labels'].items()}
            self.label_by_port(port_labels)
        
        # Apply Windows-specific automatic labeling
        if config.get('auto_windows_services', False):
            self.label_windows_services()
        
        if config.get('auto_rdp_detection', False):
            self.label_rdp_attacks()
        
        if config.get('auto_smb_detection', False):
            self.label_smb_anomalies()
        
        if config.get('auto_dns_detection', False):
            self.label_dns_anomalies()

def main():
    parser = argparse.ArgumentParser(description='Windows Network Flow Data Labeling Tool')
    parser.add_argument('csv_file', help='Input CSV file with network flow data')
    parser.add_argument('--config', help='JSON configuration file for automated labeling')
    parser.add_argument('--interactive', action='store_true', help='Run in interactive mode')
    parser.add_argument('--output', help='Output filename for labeled data')
    parser.add_argument('--auto-windows', action='store_true', help='Automatically detect Windows service patterns')
    parser.add_argument('--auto-rdp', action='store_true', help='Automatically detect RDP attacks')
    parser.add_argument('--auto-smb', action='store_true', help='Automatically detect SMB anomalies')
    parser.add_argument('--auto-dns', action='store_true', help='Automatically detect DNS anomalies')
    parser.add_argument('--create-config', action='store_true', help='Create Windows configuration file')
    
    args = parser.parse_args()
    
    if args.create_config:
        labeler = WindowsFlowLabeler("dummy.csv") if args.csv_file == "dummy.csv" else WindowsFlowLabeler(args.csv_file)
        labeler.create_windows_labeling_config()
        return
    
    if not args.csv_file:
        print("Please provide input CSV file")
        return
    
    if not os.path.exists(args.csv_file):
        print(f"File not found: {args.csv_file}")
        return
    
    print("=== Windows Network Flow Data Labeling Tool ===")
    print(f"Processing: {args.csv_file}")
    print()
    
    labeler = WindowsFlowLabeler(args.csv_file)
    
    # Apply automatic Windows-specific detection
    if args.auto_windows:
        labeler.label_windows_services()
    
    if args.auto_rdp:
        labeler.label_rdp_attacks()
    
    if args.auto_smb:
        labeler.label_smb_anomalies()
    
    if args.auto_dns:
        labeler.label_dns_anomalies()
    
    # Load configuration
    if args.config:
        labeler.load_windows_labeling_config(args.config)
    
    # Interactive mode
    if args.interactive:
        labeler.interactive_labeling_windows()
    
    # Show statistics
    labeler.show_label_stats()
    
    # Save results
    labeler.save_labeled_data(args.output)

if __name__ == "__main__":
    main()