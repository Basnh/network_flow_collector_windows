# PHÂN TÍCH CÔNG THỨC TÍNH TOÁN NETWORK FLOW FEATURES
# VÀ HƯỚNG DẪN TÌM KIẾM TRÊN WIRESHARK
# =====================================================

## 1. THÔNG TIN FLOW CƠ BẢN
### Flow ID
- Công thức: "{src_ip}-{dst_ip}-{src_port}-{dst_port}-{protocol}" (chọn lexicographically smaller)
- Wireshark: Filter "ip.src == X.X.X.X and ip.dst == Y.Y.Y.Y and tcp.srcport == P1 and tcp.dstport == P2"

### Flow Duration
- Công thức: (last_timestamp - first_timestamp) * 1,000,000 (microseconds)
- Wireshark: Statistics > Flow Graph > Time difference giữa first và last packet

### Protocol
- Công thức: 
  * TCP = 6
  * UDP = 17  
  * ICMP = 1
- Wireshark: Protocol column hoặc ip.proto == 6/17/1

## 2. PACKET COUNTS
### Total Forward/Backward Packets
- Công thức: Đếm packets theo hướng từ source đầu tiên
- Wireshark: 
  * Filter forward: "ip.src == X.X.X.X and ip.dst == Y.Y.Y.Y"
  * Filter backward: "ip.src == Y.Y.Y.Y and ip.dst == X.X.X.X"
  * Xem packet count ở status bar

## 3. PACKET LENGTH STATISTICS
### Packet Lengths (Forward/Backward)
- Công thức: len(packet) - lấy từ Scapy
- Wireshark: Frame > Frame Length (bytes)

### Forward Packet Length Max/Min/Mean/Std
- Công thức: 
  * Max: max(fwd_lengths)
  * Min: min(fwd_lengths)
  * Mean: np.mean(fwd_lengths)
  * Std: np.std(fwd_lengths)
- Wireshark: Statistics > Packet Lengths > Filter by direction

### Backward Packet Length Max/Min/Mean/Std
- Tương tự forward nhưng cho backward packets

### Total Length of Fwd/Bwd Packets
- Công thức: sum(packet_lengths) cho từng direction
- Wireshark: I/O Graph > Advanced > Sum(frame.len)

## 4. FLOW RATE CALCULATIONS
### Flow Bytes/s 
- Công thức: total_bytes / flow_duration_seconds (check 👍🏻)
- Wireshark: Statistics > I/O Graph > Y Axis: Bits/s hoặc Bytes/s

### Flow Packets/s 
- Công thức: total_packets / flow_duration_seconds (check 👍🏻)
- Wireshark: Statistics > I/O Graph > Y Axis: Packets/s

### Forward/Backward Packets/s
- Công thức: 
  * fwd_packets_per_sec = fwd_packets / duration  (check 👍🏻)
  * bwd_packets_per_sec = bwd_packets / duration  (check 👍🏻)

## 5. INTER-ARRIVAL TIME (IAT) STATISTICS
### IAT Calculation
- Công thức: current_timestamp - previous_timestamp (same direction)
- Wireshark: 
  * Statistics > Packet Details
  * Calculate manually: Time delta from previous displayed packet

### Flow IAT Mean/Std/Max/Min
- Công thức: 
  * all_iat = fwd_iat + bwd_iat
  * Mean: np.mean(all_iat)
  * Std: np.std(all_iat)
  * Max: max(all_iat)
  * Min: min(all_iat)

### Forward IAT Total/Mean/Std/Max/Min
- Công thức: Tính trên fwd_iat array
- Wireshark: Filter forward packets và tính time delta

### Backward IAT Total/Mean/Std/Max/Min
- Công thức: Tính trên bwd_iat array
- Wireshark: Filter backward packets và tính time delta

## 6. TCP FLAGS ANALYSIS
### Flag Counts (FIN, SYN, RST, PSH, ACK, URG, CWE, ECE)
- Công thức: 
  * FIN: int(tcp_layer.flags.F)
  * SYN: int(tcp_layer.flags.S)
  * RST: int(tcp_layer.flags.R)
  * PSH: int(tcp_layer.flags.P)
  * ACK: int(tcp_layer.flags.A)
  * URG: int(tcp_layer.flags.U)
  * ECE: int(tcp_layer.flags.E)
  * CWE: int(tcp_layer.flags.C)
- Wireshark: tcp.flags.fin == 1, tcp.flags.syn == 1, etc.

## 7. HEADER LENGTH CALCULATIONS
### IP Header Length
- Công thức: ip_layer.ihl * 4 (IPv4)
- Wireshark: Internet Protocol Version 4 > Header Length

### TCP Header Length
- Công thức: tcp_layer.dataofs * 4
- Wireshark: Transmission Control Protocol > Header Length

### UDP Header Length
- Công thức: 8 bytes (cố định)
- Wireshark: User Datagram Protocol > Length

### ICMP Header Length
- Công thức: 8 bytes (cố định)
- Wireshark: Internet Control Message Protocol > Header Length

### Forward/Backward Header Length
- Công thức: sum(header_lengths) cho mỗi direction

## 8. WINDOW SIZE ANALYSIS (TCP Only)
### TCP Window Size
- Công thức: tcp_layer.window
- Wireshark: tcp.window_size

### Initial Window Bytes Forward/Backward
- Công thức: first_packet_window_size cho mỗi direction
- Wireshark: Filter first packet của mỗi direction, xem tcp.window_size

## 9. PACKET SIZE STATISTICS
### Min/Max Packet Length
- Công thức: 
  * Min: min(all_packet_lengths)
  * Max: max(all_packet_lengths)
- Wireshark: Statistics > Packet Lengths

### Packet Length Mean/Std/Variance
- Công thức:
  * Mean: np.mean(all_lengths)
  * Std: np.std(all_lengths)
  * Variance: np.var(all_lengths)

### Average Packet Size
- Công thức: total_bytes / total_packets (check 👍🏻)
- Wireshark: Total bytes / Total packets

### Average Forward/Backward Segment Size
- Công thức: 
  * Avg Fwd: fwd_bytes / fwd_packets (check 👍🏻)
  * Avg Bwd: bwd_bytes / bwd_packets (check 👍🏻)

## 10. FLOW RATIOS
### Down/Up Ratio
- Công thức: bwd_packets / fwd_packets (if fwd_packets > 0 else 0)
- Mô tả: Tỉ lệ giữa traffic downstream và upstream

## 11. ACTIVITY/IDLE TIME ANALYSIS
### Active Time Calculation
- Công thức: Thời gian giữa các packet liên tiếp < 1.0 second
- Logic: if (timestamp - last_active_time) <= 1.0 → active_time

### Idle Time Calculation  
- Công thức: Thời gian giữa các packet liên tiếp > 1.0 second
- Logic: if (timestamp - last_active_time) > 1.0 → idle_time

### Active Mean/Std/Max/Min
- Công thức: Statistics trên active_times array

### Idle Mean/Std/Max/Min
- Công thức: Statistics trên idle_times array

## 12. SUBFLOW FEATURES
### Subflow Forward/Backward Packets
- Công thức: Số packets trong từng direction (giống Total Fwd/Bwd Packets)

### Subflow Forward/Backward Bytes
- Công thức: Tổng bytes trong từng direction (giống Total Length)

## 13. BULK FEATURES (CHƯA IMPLEMENT)
### Bulk-related features
- Fwd Avg Bytes/Bulk = 0 (not implemented)
- Fwd Avg Packets/Bulk = 0 (not implemented) 
- Fwd Avg Bulk Rate = 0 (not implemented)
- Tương tự cho backward

## 14. MINIMUM SEGMENT SIZE
### min_seg_size_forward
- Công thức: min(fwd_packet_lengths) if fwd_lengths else 0
- Wireshark: Filter forward packets, tìm smallest packet

## 15. ACTIVE DATA PACKETS FORWARD
### act_data_pkt_fwd
- Công thức: fwd_packets (tương đương total forward packets)

