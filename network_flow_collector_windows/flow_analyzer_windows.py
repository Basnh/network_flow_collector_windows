#!/usr/bin/env python3
"""
Network Flow Data Analyzer - Windows Version
Analyze and visualize collected network flow data on Windows
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
import argparse
import sys
import os

class WindowsFlowDataAnalyzer:
    def __init__(self, csv_file):
        self.csv_file = csv_file
        self.df = None
        self.load_data()
        
        # Set matplotlib backend for Windows
        try:
            import matplotlib
            matplotlib.use('TkAgg')  # Use TkAgg backend for Windows
        except:
            pass
    
    def load_data(self):
        """Load and preprocess CSV data"""
        try:
            self.df = pd.read_csv(self.csv_file)
            print(f"Loaded {len(self.df)} flows from {self.csv_file}")
            
            # Convert timestamp
            if 'Timestamp' in self.df.columns:
                self.df['Timestamp'] = pd.to_datetime(self.df['Timestamp'])
                print(f"Date range: {self.df['Timestamp'].min()} to {self.df['Timestamp'].max()}")
            
            # Convert Flow Duration from microseconds to seconds for better readability
            if 'Flow Duration' in self.df.columns:
                self.df['Flow Duration'] = self.df['Flow Duration'] / 1000000
                print(f"Flow Duration converted to seconds")
            
        except Exception as e:
            print(f"Error loading data: {e}")
            sys.exit(1)
    
    def get_timestamp_suffix(self):
        """Generate timestamp suffix for output files"""
        return datetime.now().strftime("%Y%m%d_%H%M%S")
    
    def basic_statistics(self):
        """Display basic statistics about the dataset"""
        print("\n=== Windows Dataset Overview ===")
        print(f"Total flows: {len(self.df)}")
        print(f"Total columns: {len(self.df.columns)}")
        
        print("\n=== Protocol Distribution ===")
        protocol_counts = self.df['Protocol'].value_counts()
        for protocol, count in protocol_counts.items():
            protocol_name = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(protocol, f'Protocol-{protocol}')
            print(f"{protocol_name}: {count} flows ({count/len(self.df)*100:.2f}%)")
        
        print("\n=== Traffic Direction ===")
        print(f"Total Forward Packets: {self.df['Total Fwd Packets'].sum()}")
        print(f"Total Backward Packets: {self.df['Total Backward Packets'].sum()}")
        print(f"Total Forward Bytes: {self.df['Total Length of Fwd Packets'].sum()}")
        print(f"Total Backward Bytes: {self.df['Total Length of Bwd Packets'].sum()}")
        
        print("\n=== Flow Duration Statistics ===")
        print(f"Mean duration: {self.df['Flow Duration'].mean():.3f}s")
        print(f"Max duration: {self.df['Flow Duration'].max():.3f}s")
        print(f"Min duration: {self.df['Flow Duration'].min():.3f}s")
        print(f"Median duration: {self.df['Flow Duration'].median():.3f}s")
        
        print("\n=== Class Distribution ===")
        if 'Class' in self.df.columns:
            class_counts = self.df['Class'].value_counts()
            for class_name, count in class_counts.items():
                print(f"{class_name}: {count} flows ({count/len(self.df)*100:.2f}%)")
    
    def top_talkers(self, top_n=10):
        """Identify top talking hosts"""
        print(f"\n=== Top {top_n} Source IPs (by packet count) ===")
        src_stats = self.df.groupby('Source IP').agg({
            'Total Fwd Packets': 'sum',
            'Total Backward Packets': 'sum',
            'Total Length of Fwd Packets': 'sum',
            'Total Length of Bwd Packets': 'sum',
            'Flow ID': 'count'
        }).rename(columns={'Flow ID': 'Flow Count'})
        
        src_stats['Total Packets'] = src_stats['Total Fwd Packets'] + src_stats['Total Backward Packets']
        src_stats['Total Bytes'] = src_stats['Total Length of Fwd Packets'] + src_stats['Total Length of Bwd Packets']
        
        top_sources = src_stats.nlargest(top_n, 'Total Packets')
        for ip, row in top_sources.iterrows():
            print(f"{ip}: {row['Total Packets']} packets, {row['Total Bytes']} bytes, {row['Flow Count']} flows")
        
        print(f"\n=== Top {top_n} Destination IPs (by packet count) ===")
        dst_stats = self.df.groupby('Destination IP').agg({
            'Total Fwd Packets': 'sum',
            'Total Backward Packets': 'sum',
            'Total Length of Fwd Packets': 'sum',
            'Total Length of Bwd Packets': 'sum',
            'Flow ID': 'count'
        }).rename(columns={'Flow ID': 'Flow Count'})
        
        dst_stats['Total Packets'] = dst_stats['Total Fwd Packets'] + dst_stats['Total Backward Packets']
        dst_stats['Total Bytes'] = dst_stats['Total Length of Fwd Packets'] + dst_stats['Total Length of Bwd Packets']
        
        top_destinations = dst_stats.nlargest(top_n, 'Total Packets')
        for ip, row in top_destinations.iterrows():
            print(f"{ip}: {row['Total Packets']} packets, {row['Total Bytes']} bytes, {row['Flow Count']} flows")
    
    def detect_anomalies(self):
        """Detect potential anomalies in the data"""
        print("\n=== Windows Anomaly Detection ===")
        
        # Large flows
        large_flows = self.df[
            (self.df['Total Fwd Packets'] > self.df['Total Fwd Packets'].quantile(0.95)) |
            (self.df['Total Backward Packets'] > self.df['Total Backward Packets'].quantile(0.95))
        ]
        print(f"Large flows (>95th percentile): {len(large_flows)}")
        
        # Long duration flows
        long_flows = self.df[self.df['Flow Duration'] > self.df['Flow Duration'].quantile(0.95)]
        print(f"Long duration flows (>95th percentile): {len(long_flows)}")
        
        # High packet rate flows
        self.df['Packet Rate'] = (self.df['Total Fwd Packets'] + self.df['Total Backward Packets']) / \
                                 (self.df['Flow Duration'] + 0.000001)
        high_rate = self.df[self.df['Packet Rate'] > self.df['Packet Rate'].quantile(0.95)]
        print(f"High packet rate flows (>95th percentile): {len(high_rate)}")
        
        # Windows-specific: Check for common Windows ports
        windows_ports = [135, 139, 445, 3389, 5985, 5986]  # RPC, NetBIOS, SMB, RDP, WinRM
        windows_flows = self.df[
            self.df['Source Port'].isin(windows_ports) | 
            self.df['Destination Port'].isin(windows_ports)
        ]
        print(f"Windows service flows: {len(windows_flows)}")
        
        # Port scanning indicators
        port_scan_indicators = self.df.groupby('Source IP')['Destination Port'].nunique()
        potential_scanners = port_scan_indicators[port_scan_indicators > 50]
        print(f"Potential port scanners (>50 dest ports): {len(potential_scanners)}")
    
    def generate_visualizations(self, output_dir="plots"):
        """Generate visualization plots (Windows-compatible)"""
        # Add timestamp to output directory
        timestamp = self.get_timestamp_suffix()
        timestamped_dir = f"{output_dir}_{timestamp}"
        
        if not os.path.exists(timestamped_dir):
            os.makedirs(timestamped_dir)
        
        print(f"Creating plots in: {timestamped_dir}")
        # Set Windows-friendly style
        plt.style.use('default')
        plt.rcParams['figure.figsize'] = (10, 6)
        plt.rcParams['savefig.dpi'] = 100
        
        try:
            # 1. Protocol distribution pie chart
            plt.figure(figsize=(10, 6))
            protocol_counts = self.df['Protocol'].value_counts()
            protocol_labels = []
            for p in protocol_counts.index:
                if p == 6:
                    protocol_labels.append('TCP')
                elif p == 17:
                    protocol_labels.append('UDP')
                elif p == 1:
                    protocol_labels.append('ICMP')
                else:
                    protocol_labels.append(f'Protocol {p}')
            
            plt.pie(protocol_counts.values, labels=protocol_labels, autopct='%1.1f%%')
            plt.title('Protocol Distribution (Windows)')
            plt.savefig(os.path.join(timestamped_dir, 'protocol_distribution.png'), bbox_inches='tight')
            plt.close()
            
            # 2. Flow duration histogram
            plt.figure(figsize=(12, 6))
            # Plot flows under 10 seconds and also show overall distribution
            fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
            
            # Short flows (< 10 seconds)
            short_flows = self.df['Flow Duration'][self.df['Flow Duration'] < 10]
            ax1.hist(short_flows, bins=50, alpha=0.7, color='skyblue')
            ax1.set_xlabel('Flow Duration (seconds)')
            ax1.set_ylabel('Frequency')
            ax1.set_title('Short Flows (< 10 seconds)')
            ax1.grid(True, alpha=0.3)
            
            # All flows (log scale for better view)
            ax2.hist(self.df['Flow Duration'], bins=100, alpha=0.7, color='lightcoral')
            ax2.set_xlabel('Flow Duration (seconds)')
            ax2.set_ylabel('Frequency')
            ax2.set_title('All Flows Distribution')
            ax2.set_yscale('log')
            ax2.grid(True, alpha=0.3)
            
            plt.tight_layout()
            plt.savefig(os.path.join(timestamped_dir, 'flow_duration_histogram.png'), bbox_inches='tight')
            plt.close()
            
            # 3. Packet size distribution
            plt.figure(figsize=(12, 6))
            all_packets = pd.concat([
                self.df['Total Fwd Packets'],
                self.df['Total Backward Packets']
            ])
            plt.hist(all_packets[all_packets < 1000], bins=50, alpha=0.7, color='lightgreen')
            plt.xlabel('Packet Count')
            plt.ylabel('Frequency')
            plt.title('Packet Count Distribution (< 1000 packets)')
            plt.grid(True, alpha=0.3)
            plt.savefig(os.path.join(timestamped_dir, 'packet_count_histogram.png'), bbox_inches='tight')
            plt.close()
            
            # 4. Windows-specific: Port analysis
            plt.figure(figsize=(15, 8))
            
            # Most common destination ports
            top_ports = self.df['Destination Port'].value_counts().head(20)
            
            plt.subplot(2, 1, 1)
            top_ports.plot(kind='bar', color='coral')
            plt.title('Top 20 Destination Ports')
            plt.xlabel('Port')
            plt.ylabel('Flow Count')
            plt.xticks(rotation=45)
            
            # Windows service ports specifically
            plt.subplot(2, 1, 2)
            windows_service_ports = {
                80: 'HTTP', 443: 'HTTPS', 53: 'DNS', 135: 'RPC', 139: 'NetBIOS',
                445: 'SMB', 3389: 'RDP', 5985: 'WinRM', 22: 'SSH', 21: 'FTP'
            }
            
            windows_port_counts = {}
            for port, name in windows_service_ports.items():
                count = len(self.df[self.df['Destination Port'] == port])
                if count > 0:
                    windows_port_counts[f"{name}\n({port})"] = count
            
            if windows_port_counts:
                plt.bar(windows_port_counts.keys(), windows_port_counts.values(), color='lightblue')
                plt.title('Windows Service Port Usage')
                plt.xlabel('Service (Port)')
                plt.ylabel('Flow Count')
                plt.xticks(rotation=45)
            
            plt.tight_layout()
            plt.savefig(os.path.join(timestamped_dir, 'windows_port_analysis.png'), bbox_inches='tight')
            plt.close()
            
            # 5. Time series plot (if timestamp available)
            if 'Timestamp' in self.df.columns:
                plt.figure(figsize=(15, 8))
                
                # Group by hour
                hourly_stats = self.df.set_index('Timestamp').resample('1H').agg({
                    'Flow ID': 'count',
                    'Total Length of Fwd Packets': 'sum',
                    'Total Length of Bwd Packets': 'sum'
                }).rename(columns={'Flow ID': 'Flow Count'})
                
                hourly_stats['Total Bytes'] = hourly_stats['Total Length of Fwd Packets'] + \
                                            hourly_stats['Total Length of Bwd Packets']
                
                fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(15, 10))
                
                # Flow count over time
                ax1.plot(hourly_stats.index, hourly_stats['Flow Count'], color='blue', linewidth=2)
                ax1.set_ylabel('Flows per Hour')
                ax1.set_title('Windows Network Activity Over Time')
                ax1.grid(True, alpha=0.3)
                
                # Bytes over time
                ax2.plot(hourly_stats.index, hourly_stats['Total Bytes'] / 1024 / 1024, color='red', linewidth=2)
                ax2.set_ylabel('MB per Hour')
                ax2.set_xlabel('Time')
                ax2.grid(True, alpha=0.3)
                
                plt.tight_layout()
                plt.savefig(os.path.join(timestamped_dir, 'windows_time_series.png'), bbox_inches='tight')
                plt.close()
            
            print(f"✓ Windows visualizations saved to {timestamped_dir}/")
            return timestamped_dir  # Return the actual directory used
            
        except Exception as e:
            print(f"Error generating visualizations: {e}")
            print("Make sure matplotlib is properly configured for Windows")
    
    def export_summary_report(self, output_file="windows_analysis_report.txt"):
        """Export analysis summary to text file"""
        # Add timestamp to filename
        timestamp = self.get_timestamp_suffix()
        base_name = output_file.rsplit('.', 1)[0]  # Remove extension
        extension = output_file.rsplit('.', 1)[1] if '.' in output_file else 'txt'
        timestamped_file = f"{base_name}_{timestamp}.{extension}"
        
        with open(timestamped_file, 'w', encoding='utf-8') as f:
            f.write("=== Windows Network Flow Data Analysis Report ===\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Source file: {self.csv_file}\n")
            f.write(f"Platform: Windows\n\n")
            
            f.write(f"Total flows: {len(self.df)}\n")
            if 'Timestamp' in self.df.columns:
                f.write(f"Date range: {self.df['Timestamp'].min()} to {self.df['Timestamp'].max()}\n\n")
            
            # Protocol stats
            f.write("Protocol Distribution:\n")
            protocol_counts = self.df['Protocol'].value_counts()
            for protocol, count in protocol_counts.items():
                protocol_name = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(protocol, f'Protocol-{protocol}')
                f.write(f"  {protocol_name}: {count} flows ({count/len(self.df)*100:.2f}%)\n")
            
            # Traffic stats
            f.write(f"\nTotal Forward Packets: {self.df['Total Fwd Packets'].sum()}\n")
            f.write(f"Total Backward Packets: {self.df['Total Backward Packets'].sum()}\n")
            f.write(f"Total Forward Bytes: {self.df['Total Length of Fwd Packets'].sum()}\n")
            f.write(f"Total Backward Bytes: {self.df['Total Length of Bwd Packets'].sum()}\n")
            
            # Windows-specific analysis
            f.write("\n=== Windows-Specific Analysis ===\n")
            
            # Common Windows ports
            windows_ports = [80, 443, 53, 135, 139, 445, 3389, 5985]
            windows_flows = self.df[
                self.df['Source Port'].isin(windows_ports) | 
                self.df['Destination Port'].isin(windows_ports)
            ]
            f.write(f"Windows service flows: {len(windows_flows)} ({len(windows_flows)/len(self.df)*100:.2f}%)\n")
            
            # Top ports
            f.write("\nTop 10 Destination Ports:\n")
            top_ports = self.df['Destination Port'].value_counts().head(10)
            for port, count in top_ports.items():
                f.write(f"  Port {port}: {count} flows\n")
            
            # Class distribution
            if 'Class' in self.df.columns:
                f.write("\nClass Distribution:\n")
                class_counts = self.df['Class'].value_counts()
                for class_name, count in class_counts.items():
                    f.write(f"  {class_name}: {count} flows ({count/len(self.df)*100:.2f}%)\n")
        
        print(f"✓ Windows analysis report saved to {timestamped_file}")
        return timestamped_file  # Return the actual filename used

def main():
    parser = argparse.ArgumentParser(description='Windows Network Flow Data Analyzer')
    parser.add_argument('csv_file', help='Input CSV file with network flow data')
    parser.add_argument('--plot-dir', default='plots', help='Directory prefix for output plots (timestamp will be added)')
    parser.add_argument('--report', default='windows_analysis_report.txt', help='Analysis report output file (timestamp will be added)')
    parser.add_argument('--no-plots', action='store_true', help='Skip generating plots')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.csv_file):
        print(f"Error: File {args.csv_file} not found")
        return
    
    print("=== Windows Network Flow Data Analyzer ===")
    print(f"Analyzing: {args.csv_file}")
    print()
    
    analyzer = WindowsFlowDataAnalyzer(args.csv_file)
    
    # Run analysis
    analyzer.basic_statistics()
    analyzer.top_talkers()
    analyzer.detect_anomalies()
    
    # Generate outputs
    plots_dir = None
    if not args.no_plots:
        print("\nGenerating Windows-optimized visualizations...")
        plots_dir = analyzer.generate_visualizations(args.plot_dir)
    
    report_file = analyzer.export_summary_report(args.report)
    
    print("\n=== Analysis Complete ===")
    print(f"Report: {report_file}")
    if plots_dir:
        print(f"Plots: {plots_dir}/")

if __name__ == "__main__":
    main()