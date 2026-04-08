#!/usr/bin/env python3


import pandas as pd
import argparse
import json
import sys
from datetime import datetime

class WiresharkValidator:
    def __init__(self):
        self.flow_data = None
        self.wireshark_data = None
        
    def load_flow_data(self, csv_file):
        """Load our network flow collector data"""
        try:
            self.flow_data = pd.read_csv(csv_file)
            print(f"✓ Loaded {len(self.flow_data)} flows from {csv_file}")
            return True
        except Exception as e:
            print(f"❌ Error loading flow data: {e}")
            return False
    
    def load_wireshark_data(self, wireshark_file):
        """Load Wireshark exported data (CSV format)"""
        try:
            # Wireshark export format can vary, try common formats
            self.wireshark_data = pd.read_csv(wireshark_file)
            print(f"✓ Loaded {len(self.wireshark_data)} packets from Wireshark export")
            return True
        except Exception as e:
            print(f"❌ Error loading Wireshark data: {e}")
            return False
    
    def compare_basic_stats(self):
        """Compare basic statistics between our data and Wireshark"""
        print("\n=== Basic Statistics Comparison ===")
        
        if self.flow_data is None:
            print("❌ No flow data loaded")
            return
        
        # Our data statistics
        total_flows = len(self.flow_data)
        total_fwd_packets = self.flow_data['Total Fwd Packets'].sum()
        total_bwd_packets = self.flow_data['Total Backward Packets'].sum()
        total_packets = total_fwd_packets + total_bwd_packets
        
        total_fwd_bytes = self.flow_data['Total Length of Fwd Packets'].sum()
        total_bwd_bytes = self.flow_data['Total Length of Bwd Packets'].sum()
        total_bytes = total_fwd_bytes + total_bwd_bytes
        
        print(f"Our Collector Data:")
        print(f"  Total Flows: {total_flows:,}")
        print(f"  Total Packets: {total_packets:,}")
        print(f"  Total Bytes: {total_bytes:,}")
        
        # Protocol distribution in our data
        protocol_dist = {}
        for protocol in self.flow_data['Protocol'].unique():
            count = len(self.flow_data[self.flow_data['Protocol'] == protocol])
            proto_name = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}.get(protocol, f'Protocol-{protocol}')
            protocol_dist[proto_name] = count
        
        print(f"  Protocol Distribution:")
        for proto, count in protocol_dist.items():
            print(f"    {proto}: {count} flows")
        
        # Wireshark comparison
        if self.wireshark_data is not None:
            wireshark_packets = len(self.wireshark_data)
            print(f"\nWireshark Data:")
            print(f"  Total Packets: {wireshark_packets:,}")
            
            # Compare packet counts
            if abs(total_packets - wireshark_packets) / max(total_packets, wireshark_packets) < 0.05:
                print(f"✅ Packet counts match well (difference: {abs(total_packets - wireshark_packets)})")
            else:
                print(f"⚠️ Packet count difference: {abs(total_packets - wireshark_packets)}")
                print(f"   This could be due to different capture periods or filtering")
        
        return {
            'flows': total_flows,
            'packets': total_packets,
            'bytes': total_bytes,
            'protocols': protocol_dist
        }
    
    def analyze_top_conversations(self, top_n=10):
        """Analyze top conversations for validation"""
        print(f"\n=== Top {top_n} Conversations ===")
        
        if self.flow_data is None:
            return
        
        # Calculate total traffic per conversation
        conversations = []
        for _, row in self.flow_data.iterrows():
            total_packets = row['Total Fwd Packets'] + row['Total Backward Packets']
            total_bytes = row['Total Length of Fwd Packets'] + row['Total Length of Bwd Packets']
            
            conversations.append({
                'src_ip': row['Source IP'],
                'dst_ip': row['Destination IP'],
                'src_port': row['Source Port'],
                'dst_port': row['Destination Port'],
                'protocol': row['Protocol'],
                'packets': total_packets,
                'bytes': total_bytes,
                'duration': row['Flow Duration']
            })
        
        # Sort by packet count
        conversations.sort(key=lambda x: x['packets'], reverse=True)
        
        print("Top conversations by packet count:")
        print("Src IP:Port → Dst IP:Port [Protocol] | Packets | Bytes | Duration")
        print("-" * 80)
        
        for i, conv in enumerate(conversations[:top_n]):
            proto_name = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}.get(conv['protocol'], f'P{conv["protocol"]}')
            print(f"{conv['src_ip']}:{conv['src_port']} → "
                  f"{conv['dst_ip']}:{conv['dst_port']} "
                  f"[{proto_name}] | {conv['packets']:,} | {conv['bytes']:,} | {conv['duration']:.3f}s")
        
        return conversations[:top_n]
    
    def generate_wireshark_filter(self, conversation):
        """Generate Wireshark filter for specific conversation"""
        protocol = conversation['protocol']
        src_ip = conversation['src_ip']
        dst_ip = conversation['dst_ip']
        src_port = conversation['src_port']
        dst_port = conversation['dst_port']
        
        if protocol == 6:  # TCP
            filter_str = f"tcp and ((ip.src=={src_ip} and tcp.srcport=={src_port} and ip.dst=={dst_ip} and tcp.dstport=={dst_port}) or (ip.src=={dst_ip} and tcp.srcport=={dst_port} and ip.dst=={src_ip} and tcp.dstport=={src_port}))"
        elif protocol == 17:  # UDP
            filter_str = f"udp and ((ip.src=={src_ip} and udp.srcport=={src_port} and ip.dst=={dst_ip} and udp.dstport=={dst_port}) or (ip.src=={dst_ip} and udp.srcport=={dst_port} and ip.dst=={src_ip} and udp.dstport=={src_port}))"
        else:
            filter_str = f"ip.src=={src_ip} and ip.dst=={dst_ip}"
        
        return filter_str
    
    def export_validation_instructions(self, output_file="wireshark_validation_guide.txt"):
        """Export detailed validation instructions for Wireshark"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        guide_file = f"wireshark_validation_guide_{timestamp}.txt"
        
        stats = self.compare_basic_stats()
        top_convs = self.analyze_top_conversations(5)
        
        with open(guide_file, 'w', encoding='utf-8') as f:
            f.write("=== Wireshark Validation Guide ===\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write("STEP-BY-STEP VALIDATION PROCESS:\n\n")
            
            f.write("1. CAPTURE COMPARISON:\n")
            f.write("   - Open Wireshark\n")
            f.write("   - Capture on the same interface used by our collector\n")
            f.write("   - Capture for the same time period\n")
            f.write("   - Compare basic statistics\n\n")
            
            f.write("2. BASIC STATISTICS VERIFICATION:\n")
            f.write("   In Wireshark: Statistics → Capture File Properties\n")
            f.write(f"   Expected packet count: ~{stats['packets']:,}\n")
            f.write(f"   Expected total bytes: ~{stats['bytes']:,}\n\n")
            
            f.write("3. PROTOCOL DISTRIBUTION CHECK:\n")
            f.write("   In Wireshark: Statistics → Protocol Hierarchy\n")
            f.write("   Expected distribution:\n")
            for proto, count in stats['protocols'].items():
                f.write(f"     {proto}: {count} flows\n")
            f.write("\n")
            
            f.write("4. TOP CONVERSATIONS VALIDATION:\n")
            f.write("   In Wireshark: Statistics → Conversations\n")
            f.write("   Use these filters to validate top flows:\n\n")
            
            for i, conv in enumerate(top_convs):
                f.write(f"   Conversation {i+1}:\n")
                f.write(f"     {conv['src_ip']}:{conv['src_port']} ↔ {conv['dst_ip']}:{conv['dst_port']}\n")
                f.write(f"     Expected packets: {conv['packets']}\n")
                f.write(f"     Wireshark filter: {self.generate_wireshark_filter(conv)}\n\n")
            
            f.write("5. FLOW DURATION VALIDATION:\n")
            f.write("   - In Wireshark, sort conversations by duration\n")
            f.write("   - Compare with our 'Flow Duration' column\n")
            f.write("   - Small differences (±1-2%) are normal\n\n")
            
            f.write("6. PACKET SIZE VALIDATION:\n")
            f.write("   - Use Wireshark's packet length statistics\n")
            f.write("   - Compare with our packet length features\n")
            f.write("   - Check min/max/mean packet sizes\n\n")
            
            f.write("EXPECTED DIFFERENCES:\n")
            f.write("- Wireshark shows individual packets, we aggregate into flows\n")
            f.write("- Timing differences of microseconds are normal\n")
            f.write("- Our flow timeout may group packets differently\n")
            f.write("- Packet counts should match within 1-5%\n")
            f.write("- Byte counts should match within 1%\n\n")
            
            f.write("TROUBLESHOOTING:\n")
            f.write("- If packet counts differ significantly:\n")
            f.write("  * Check capture interfaces match\n")
            f.write("  * Verify capture time periods\n")
            f.write("  * Check for packet loss indicators\n")
            f.write("- If protocols don't match:\n")
            f.write("  * Verify protocol detection logic\n")
            f.write("  * Check for encapsulation differences\n")
        
        print(f"✅ Validation guide saved to: {guide_file}")
        return guide_file

def main():
    parser = argparse.ArgumentParser(description='Validate Network Flow Collector data against Wireshark')
    parser.add_argument('flow_csv', help='Network flow collector CSV file')
    parser.add_argument('--wireshark-csv', help='Wireshark exported CSV file (optional)')
    parser.add_argument('--top-n', type=int, default=10, help='Number of top conversations to analyze')
    parser.add_argument('--export-guide', action='store_true', help='Export detailed validation guide')
    
    args = parser.parse_args()
    
    validator = WiresharkValidator()
    
    # Load our flow data
    if not validator.load_flow_data(args.flow_csv):
        sys.exit(1)
    
    # Load Wireshark data if provided
    if args.wireshark_csv:
        validator.load_wireshark_data(args.wireshark_csv)
    
    # Perform validation
    print("🔍 Starting validation analysis...")
    validator.compare_basic_stats()
    validator.analyze_top_conversations(args.top_n)
    
    if args.export_guide:
        validator.export_validation_instructions()
    
    print("\n✅ Validation analysis complete!")
    print("\n💡 To fully validate:")
    print("1. Run Wireshark capture parallel to our collector")
    print("2. Export Wireshark data to CSV")
    print("3. Use --wireshark-csv option to compare")
    print("4. Use --export-guide to get detailed instructions")

if __name__ == "__main__":
    main()