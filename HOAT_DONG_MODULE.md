# Chi Tiết Các Bước Hoạt động của Network Flow Collector Windows Module

## 📋 Tổng Quan Quá Trình

Module `WindowsNetworkFlowCollector` thực hiện 3 giai đoạn chính:
1. **KHỞI TẠO** - Chuẩn bị môi trường
2. **CAPTURE & PROCESS** - Thu thập và xử lý packets
3. **SAVE & CLEANUP** - Lưu và dọn dẹp dữ liệu

---

## 🚀 GIAI ĐOẠN 1: KHỞI TẠO (Initialization Phase)

### Bước 1.1: Khởi Tạo Class `WindowsNetworkFlowCollector`
```python
collector = WindowsNetworkFlowCollector(
    output_file="network_flows.csv",      # File lưu flows
    interface=None,                        # Auto-detect interface
    timeout=300,                          # Timeout (seconds)
    promiscuous=True,                     # Capture all traffic
    hex_payload=True                      # Hex dump format
)
```

**Các việc được thực hiện:**
- Tạo timestamp cho output file: `network_flows_20260324_181832.csv`
- Khởi tạo packet-level CSV file (Wireshark-style): `network_flows_packets_*.csv`
- Khởi tạo các data structures:
  - `self.flows` - Lưu thông tin flows
  - `self.flow_bytes` - Lưu bytes/fwd/bwd
  - `self.flow_packet_lengths` - Lưu độ dài packets
  - `self.flow_flags` - Lưu TCP flags
  - `self.flow_iat` - Lưu Inter-Arrival Time
  - Và nhiều structures khác để track statistics
  
### Bước 1.2: Kiểm Tra Windows Requirements
```python
def check_windows_requirements():
    ✓ Kiểm tra xem có phải Windows không
    ✓ Tìm và setup Npcap (Network Packet Capture)
    ✓ Kiểm tra WlanHelper.exe cho Wi-Fi support
    ✓ Kiểm tra admin privileges
    ✓ Kiểm tra Npcap installation (3 methods):
      - Method 1: Kiểm tra Npcap service chạy hay không
      - Method 2: Kiểm tra Npcap files tồn tại
      - Method 3: Kiểm tra Windows Registry
```

### Bước 1.3: Khởi Tạo CSV Files
```python
def init_csv_file():
    ✓ Tạo CSV file với 84 cột headers:
      - Flow ID, Source IP, Source Port, Destination IP, Destination Port
      - Protocol, Timestamp, Flow Duration
      - Forward/Backward packets statistics
      - TCP flags, Windows sizes, IAT (Inter-Arrival Time)
      - Payload content, Info fields
      - Và nhiều features khác...

def init_packet_csv_file():
    ✓ Tạo Wireshark-style packet CSV với 10 cột:
      - No., Time, Source, Src Port, Destination, Dst Port
      - Protocol, Length, TTL, Info
```

### Bước 1.4: Setup Logging & Signal Handlers
```python
✓ Setup logging file: network_collector.log
✓ UTF-8 encoding for Windows compatibility
✓ Setup signal handlers (Ctrl+C graceful shutdown)
✓ Tạo console + file handlers
```

---

## 📡 GIAI ĐOẠN 2: CAPTURE & PROCESS (Packet Capture Phase)

### Bước 2.1: Bắt Đầu Collection - `start_collection()`
```python
def start_collection():
    1️⃣ Log khởi động thông tin
    2️⃣ Bắt đầu periodic save thread (daemon)
    3️⃣ Cấu hình Scapy packet capture:
        - prn=self.process_packet      # Callback khi có packet
        - store=0                       # Không lưu packets vào memory
        - stop_filter=lambda x: ...     # Dừng khi self.running=False
        - monitor=False                 # Wi-Fi monitoring mode
        - iface=self.interface         # Network interface
    
    4️⃣ Gọi Scapy's sniff() để bắt đầu packet capture
```

### Bước 2.2: Xử Lý Mỗi Packet - `process_packet(packet)`
**Được gọi cho MỖI packet được capture:**

#### Bước 2.2.1: Lưu Packet vào Packet-level CSV (Optional)
```
Nếu capture_packets=True:
    ✓ Gọi save_packet_to_csv(packet, packet.time)
    ✓ Generate Wireshark-style "Info" string:
        - ARP packets: "Who has X? Tell Y"
        - ICMP packets: "Echo Request", "Echo Reply"
        - TCP packets: "SYN, ACK", "FIN, ACK", Seq/Ack/Win
        - UDP packets: "DNS ...", "DHCP ...", "MDNS ..."
    ✓ Viết vào packet CSV file
```

#### Bước 2.2.2: Extract Features từ Packet
```python
def extract_features(packet):
    ✓ Kiểm tra xem là IPv4 packet không (version == 4)
    ✓ Extract L3 (IP layer):
        - Source IP, Destination IP
        - Protocol (TCP=6, UDP=17, ICMP=1)
        - IP Header Length
    
    ✓ Extract L4 (TCP/UDP/ICMP):
        TCP: src_port, dst_port, TCP flags (SYN, ACK, FIN, RST, PSH, URG, CWE, ECE)
        UDP: src_port, dst_port
        ICMP: type, code, id, seq
    
    ✓ Extract L5+ (Payload):
        - Payload content (hex format if hex_payload=True)
        - Payload length
    
    ✓ Trả về: packet_features dict
```

#### Bước 2.2.3: Tạo Flow ID từ Packet Features
```python
def generate_flow_id(src_ip, src_port, dst_ip, dst_port, protocol):
    ✓ Tạo forward ID: "192.168.1.1-10.0.0.1-1234-80-TCP"
    ✓ Tạo reverse ID: "10.0.0.1-192.168.1.1-80-1234-TCP"
    ✓ Return canonical ID (lexicographically smaller)
    
    Ví dụ: 
        Packet A: 192.168.1.1:1234 -> 10.0.0.1:80
        Packet B: 10.0.0.1:80 -> 192.168.1.1:1234
        Cả 2 cùng flow ID: "10.0.0.1-192.168.1.1-80-1234-TCP"
```

#### Bước 2.2.4: Xác Định Hướng Packet (Fwd hay Bwd)
```python
def get_flow_direction(flow_id, src_ip, src_port, dst_ip, dst_port, protocol):
    • Nếu packet đầu tiên của flow:
        → direction = 'fwd'
    
    • Nếu src_ip và src_port match với first packet:
        → direction = 'fwd' (forward)
    
    • Ngược lại:
        → direction = 'bwd' (backward)
```

#### Bước 2.2.5: Update Flow Statistics
```python
Với mỗi packet được xác định là 'fwd' hay 'bwd':

• Update packet count:
    self.flow_packets[flow_id]['fwd'] += 1  hoặc  ['bwd']

• Update bytes:
    self.flow_bytes[flow_id]['fwd'] += packet_length

• Update packet lengths:
    self.flow_packet_lengths[flow_id]['fwd'].append(length)

• Update TCP flags (nếu TCP):
    self.flow_flags[flow_id]['SYN'] += 1
    self.flow_flags[flow_id]['ACK'] += 1
    ...

• Update Inter-Arrival Time (IAT):
    Thời gian giữa 2 packets liên tiếp
    self.flow_iat[flow_id]['fwd'].append(current_time - last_time)

• Update Header lengths:
    self.flow_header_lengths[flow_id]['fwd'].append(ip_header_len)

• Update Window sizes (nếu TCP):
    self.flow_window_sizes[flow_id]['fwd'].append(tcp_window)

• Update Active/Idle times:
    Nếu gap > threshold: idle_times
    Ngược lại: active_times

• Lưu first packet info:
    self.flows[flow_id]['first_packet'] = {...}
    self.flows[flow_id]['last_timestamp'] = current_time

• Lưu Info string (Wireshark-style):
    self.flow_info[flow_id] = generate_packet_info(packet)

• Lưu Payload content (Hex):
    self.flow_content[flow_id] = hex_payload
```

### Bước 2.3: Periodic Save Thread
```python
def periodic_save(interval=120):
    • Mỗi 120 giây (2 phút):
        ✓ Duyệt qua tất cả flows
        ✓ Nếu flow timeout (không có packet trong 'timeout' giây):
            - Gọi save_individual_flow(flow_id)
            - Xóa flow khỏi tất cả data structures
        ✓ Log statistics: # flows saved, # packets captured
```

---

## 💾 GIAI ĐOẠN 3: SAVE & CLEANUP (Saving Phase)

### Bước 3.1: Save Individual Flow - `save_individual_flow(flow_id)`
**Được gọi khi:**
- Flow timeout (periodic save)
- Dừng collection (save_flows)

**Chi tiết:**
```python
def save_individual_flow(flow_id):
    1️⃣ Lấy flow metadata:
        - source_ip, dst_ip, src_port, dst_port, protocol
        - timestamp (khi packet đầu tiên)
        - flow duration = last_timestamp - first_timestamp
    
    2️⃣ Tính statistics từ collected data:
        
        📊 Packet Statistics:
            - Packet count (fwd, bwd, total)
            - Packet length (max, min, mean, std, variance)
        
        📊 Byte Statistics:
            - Total bytes (fwd, bwd)
            - Bytes/second rate
        
        📊 Inter-Arrival Time (IAT):
            - Mean, Std Dev, Max, Min
            - Cho cả forward/backward/all
        
        📊 TCP Flags (nếu TCP):
            - FIN := 0/1/2, SYN := 0/1/2, ...
            - Forward/Backward count để
        
        📊 Active/Idle Times:
            - Mean, Std Dev, Max, Min
        
        📊 Header Lengths:
            - Tổng header length fwd/bwd
        
        📊 Window Sizes (nếu TCP):
            - Initial window size
        
        📊 Packet Rates:
            - Packets/second
            - Bytes/second
    
    3️⃣ Xây dựng feature vector với 80+ features:
        [Flow ID, SrcIP, SrcPort, DstIP, DstPort, Protocol,
         Duration, FwdPkts, BwdPkts, FwdBytes, BwdBytes,
         Fwd_Length_Max, Fwd_Length_Min, Fwd_Length_Mean, Fwd_Length_Std,
         Bwd_Length_Max, Bwd_Length_Min, Bwd_Length_Mean, Bwd_Length_Std,
         Bytes_Per_Sec, Packets_Per_Sec, IAT_Mean, IAT_Std,
         ... (50+ more features)
         Info, Payload_Content, Class='BENIGN']
    
    4️⃣ Write feature vector vào CSV file:
        with open(output_file, 'a') as f:
            csv.writer(f).writerow(features)
```

### Bước 3.2: Final Cleanup - `save_flows()`
**Được gọi khi:**
- Ctrl+C (shutdown signal)
- Timeout đạt được
- Lỗi xảy ra

```python
def save_flows():
    1️⃣ Log thông tin:
        "Saving all remaining flows..."
    
    2️⃣ Duyệt qua TẤT CẢ flows còn lại:
        for flow_id in list(self.flows.keys()):
            ✓ Gọi save_individual_flow(flow_id)
            ✓ Xóa flow khỏi tất cả tracking dicts:
                - self.flows
                - self.flow_bytes
                - self.flow_flags
                - self.flow_iat
                - self.flow_packet_lengths
                - self.flow_iat
                - self.flow_header_lengths
                - self.flow_window_sizes
                - self.flow_active_times
                - self.flow_idle_times
                - self.flow_info
                - self.flow_content
                - ... (tất cả)
    
    3️⃣ Log final statistics:
        - Total saved: X flows
        - Total captured: Y packets
        - Output file: network_flows_*.csv
```

---

## 🔄 FLOW XỬ LÝ PACKET EXAMPLE

**Ví dụ thực tế với 3 packets:**

```
PACKET 1: 192.168.1.100:12345 → 8.8.8.8:53 (DNS Query, UDP)
├─ Flow ID: "8.8.8.8-192.168.1.100-53-12345-UDP"
├─ Direction: 'fwd' (first packet)
├─ Update:
│  ├─ packet_count[fwd] += 1  → 1
│  ├─ bytes[fwd] += 65
│  ├─ packet_lengths[fwd] = [65]
│  ├─ first_packet = {ip, port, timestamp=T1}
│  └─ Info = "DNS Standard query A google.com"
└─ Saved? NO (flow still active)

PACKET 2: 8.8.8.8:53 → 192.168.1.100:12345 (DNS Response)
├─ Flow ID: "8.8.8.8-192.168.1.100-53-12345-UDP"
├─ Direction: 'bwd' (reverse direction of first packet)
├─ Update:
│  ├─ packet_count[bwd] += 1  → 1
│  ├─ bytes[bwd] += 145
│  ├─ packet_lengths[bwd] = [145]
│  ├─ IAT[bwd] += (T2 - T1) = 0.035 seconds
│  └─ Info: "DNS Standard query response"
└─ Saved? NO

TIMEOUT HẬP LẠI (120 seconds, no more packets):
├─ Periodic check: flow timed out
├─ Calculate features:
│  ├─ duration = T2 - T1 = 0.035 sec
│  ├─ fwd_packets = 1, bwd_packets = 1
│  ├─ fwd_bytes = 65, bwd_bytes = 145
│  ├─ packet_length stats = [65, 145]
│  └─ ... (calculate other 70+ features)
├─ Build CSV row with 80+ fields
├─ Append to network_flows_*.csv
├─ Delete from all tracking dicts
└─ Saved? YES ✓
```

---

## 🎯 PROMISCUOUS MODE VS NORMAL MODE

### Normal Mode (promiscuous=False)
```
┌─ Local Machine ─┐
│  Eth0: 192.168.1.1
│  │
│  ├─ Packet to 8.8.8.8 ✓ CAPTURED
│  ├─ Packet from 8.8.8.8 ✓ CAPTURED
│  └─ Packet from 192.168.1.2 ✗ IGNORED
│
└─ Chỉ capture traffic từ/tới máy này
```

### Promiscuous Mode (promiscuous=True)
```
┌─ Network Segment ─────────────────┐
│  Eth0: 192.168.1.1  (Collector)
│  
│  192.168.1.2 → 8.8.8.8 ✓ CAPTURED
│  8.8.8.8 → 192.168.1.2 ✓ CAPTURED
│  192.168.1.3 → 1.1.1.1 ✓ CAPTURED
│  1.1.1.1 → 192.168.1.3 ✓ CAPTURED
│
└─ Capture TẤT CẢ traffic trên network segment
```

---

## 📊 OUTPUT CSV STRUCTURE

### File 1: `network_flows_TIMESTAMP.csv`
```csv
Flow ID,Source IP,Source Port,Destination IP,Destination Port,Protocol,Timestamp,Flow Duration,...
8.8.8.8-192.168.1.100-53-12345-UDP,192.168.1.100,12345,8.8.8.8,53,17,2026-03-24 10:15:30,35000,...
```

### File 2 (Optional): `network_flows_packets_TIMESTAMP.csv`
```csv
No.,Time,Source,Src Port,Destination,Dst Port,Protocol,Length,TTL,Info
1,2026-03-24 10:15:30.123,192.168.1.100,12345,8.8.8.8,53,DNS,65,64,Standard query A google.com
2,2026-03-24 10:15:30.158,8.8.8.8,53,192.168.1.100,12345,DNS,145,64,Standard query response
```

---

## 🔧 ERROR HANDLING

```python
try:
    sniff(**capture_params)  # Packet capture
except Exception as e:
    logger.error(f"Error: {e}")
    logger.error("Make sure Npcap is installed")
    logger.error("Run as Administrator")
finally:
    # Luôn luôn save flows trước khi exit
    save_flows()
```

---

## 🏁 SHUTDOWN SEQUENCE

```
1. User: Ctrl+C
   └─> signal_handler()
       └─> self.running = False
           └─> sniff() loop dừng
               └─> start_collection() exits
                   └─> print final statistics
                       └─> save_flows() (save all remaining)
                           └─> Print: "Output file: ..."
2. Exit program
```

---

## 📈 PERFORMANCE METRICS

```
Packet Capture Rate:
    - Windows Ethernet: ~10,000 packets/second
    - Windows Wi-Fi: ~5,000 packets/second (slower)

Flow Creation Rate:
    - New unique flows: ~100-500/second (depends on network)

Memory Usage:
    - Per flow: ~5KB (stored statistics)
    - For 1000 flows: ~5MB RAM
    - For 10,000 flows: ~50MB RAM
    - Periodic save every 120s clears memory

CSV File Size:
    - Per flow: ~100-150 bytes
    - 1000 flows: ~100-150KB
    - 10,000 flows: ~1-2MB
```

---

## 🔐 SECURITY INTEGRATION

```python
# Optional: Integrate with Security Management System
if SECURITY_INTEGRATION_AVAILABLE:
    agent_client = integrate_with_flow_collector(collector, "http://localhost:5000")
    # Flows sẽ tự động được gửi tới server để phân tích threat
```

---

## ✅ TỔNG KẾT Qbluepint

```
START
  ↓
1. INIT
  ├─ Check Npcap
  ├─ Create CSV files
  ├─ Setup logging
  └─ Init data structures
  ↓
2. CAPTURE LOOP (sniff)
  ├─ Receive packet
  ├─ Save to packet CSV (optional)
  ├─ Extract features
  ├─ Generate flow ID
  ├─ Determine direction (fwd/bwd)
  ├─ Update flow statistics
  └─ [Repeat for each packet]
  ↓
3. PERIODIC SAVE (every 120s)
  ├─ Check for timed-out flows
  ├─ Calculate all 80+ features
  ├─ Write to CSV
  └─ Clean up memory
  ↓
4. GRACEFUL SHUTDOWN (Ctrl+C)
  ├─ Stop sniff loop
  ├─ Save all remaining flows
  └─ Print statistics → EXIT
```
