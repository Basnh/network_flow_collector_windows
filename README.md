# Network Flow Data Collector - Windows Version

Tool thu thập dữ liệu network flow chạy trực tiếp trên Windows với tất cả 79 features để training machine learning models phát hiện intrusion.

## 🚀 **Tính năng chính**

- **Native Windows Support**: Chạy trực tiếp trên Windows 10/11
- **Npcap Integration**: Sử dụng Npcap để capture packets
- **79 Features**: Thu thập đầy đủ features theo chuẩn CIC-IDS
- **Real-time Analysis**: Phân tích và export CSV real-time
- **Windows Service Detection**: Tự động nhận diện RDP, SMB, DNS patterns
- **Administrator Privilege Support**: Optimize cho Windows privilege system

## 🛠️ **Yêu cầu hệ thống**

### Bắt buộc:
- Windows 10/11 (64-bit recommended)
- Python 3.7+ 
- **Npcap** - Download từ: https://nmap.org/npcap/
- Administrator privileges (khuyến nghị)

### Optional:
- Visual Studio C++ Build Tools (cho một số packages)

## 📦 **Cài đặt**

### Automatic Installation (PowerShell as Administrator):

```powershell
# Chạy PowerShell as Administrator
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
.\install.ps1
```

### Manual Installation:

1. **Cài đặt Npcap**:
   - Download từ: https://nmap.org/npcap/
   - Chọn "WinPcap API-compatible Mode" khi cài đặt

2. **Cài đặt Python packages**:
```cmd
pip install -r requirements.txt
```

3. **Verify cài đặt**:
```cmd
python network_flow_collector_windows.py --list-interfaces
```

## 🖥️ **Sử dụng**

### Liệt kê network interfaces
```cmd
python network_flow_collector_windows.py --list-interfaces
```

### Thu thập dữ liệu cơ bản
```cmd
python network_flow_collector_windows.py -o windows_training_data.csv -t 300
```

### Thu thập từ interface cụ thể
```cmd
python network_flow_collector_windows.py -i "Ethernet" -o flows.csv
```

### Chạy as Administrator (khuyến nghị)
```cmd
# Mở Command Prompt as Administrator
python network_flow_collector_windows.py -o admin_flows.csv
```

## 📊 **Phân tích dữ liệu**

### Analyze collected data
```cmd
python flow_analyzer_windows.py windows_training_data.csv --plot-dir windows_plots
```

### Windows-specific analysis
```cmd
python flow_analyzer_windows.py flows.csv --report windows_report.txt
```

## 🏷️ **Labeling Data**

### Auto-detect Windows attacks
```cmd
python flow_labeler_windows.py flows.csv --auto-windows --auto-rdp --auto-smb
```

### Interactive labeling với Windows-specific options
```cmd
python flow_labeler_windows.py flows.csv --interactive
```

### Sử dụng configuration file
```cmd
# Tạo config template
python flow_labeler_windows.py dummy.csv --create-config

# Apply config
python flow_labeler_windows.py flows.csv --config windows_labeling_config.json
```

## 🎯 **Windows-Specific Features**

### Supported Windows Services:
- **RDP (3389)** - Remote Desktop attacks
- **SMB (445)** - File sharing, lateral movement
- **NetBIOS (139)** - Network browsing
- **RPC (135)** - Remote procedure calls
- **WinRM (5985/5986)** - Remote management
- **DNS (53)** - Domain name resolution
- **MSSQL (1433/1434)** - Database access

### Attack Detection:
- **RDP Brute Force** - Multiple failed RDP connections
- **SMB Lateral Movement** - Unusual SMB access patterns
- **Large Data Transfers** - Potential data exfiltration
- **DNS Tunneling** - High volume DNS requests

## 💻 **Windows Interface Names**

Common Windows interface patterns:
```
- "Ethernet"                    # Wired connection
- "Wi-Fi"                       # Wireless connection  
- "Local Area Connection"       # Legacy naming
- "Ethernet 2", "Ethernet 3"   # Multiple adapters
- "VMware Network Adapter"      # Virtual adapters
```

## 🔧 **Troubleshooting**

### Npcap Issues:
```cmd
# Check Npcap installation
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst"

# Reinstall Npcap nếu cần
# Download mới từ: https://nmap.org/npcap/
```

### Permission Issues:
```cmd
# Chạy as Administrator
# Right-click Command Prompt -> "Run as administrator"
```

### Python Package Issues:
```cmd
# Reinstall packages
pip uninstall scapy pandas numpy matplotlib seaborn
pip install -r requirements.txt
```

### No Packets Captured:
1. Verify interface name: `--list-interfaces`
2. Check Windows Defender Firewall
3. Ensure Npcap service is running: `services.msc` -> Npcap Loopback Adapter
4. Try different interface hoặc run as Administrator

## 📁 **Output Files**

- `network_flows.csv` - Raw flow data với 79 features
- `windows_analysis_report.txt` - Analysis summary
- `windows_plots/` - Visualizations
- `windows_labeled.csv` - Labeled training data
- `network_collector.log` - Debug logs

## 🎯 **Use Cases trên Windows**

### Enterprise Network Monitoring:
```cmd
# Monitor corporate network
python network_flow_collector_windows.py -i "Ethernet" -o corporate_flows.csv -t 3600
```

### Malware Analysis:
```cmd
# Capture during malware execution
python network_flow_collector_windows.py -o malware_traffic.csv -t 600
```

### Security Training Data:
```cmd
# Normal operations
python network_flow_collector_windows.py -o normal_windows.csv -t 1800

# During penetration testing
python network_flow_collector_windows.py -o pentest_windows.csv -t 1800
```

## ⚡ **Performance Notes**

- **Memory Usage**: ~100-500MB tùy thuộc vào traffic volume
- **CPU Usage**: ~5-15% trên moderate traffic
- **Disk I/O**: CSV files được flush mỗi 30 giây
- **Network Impact**: Passive monitoring, không ảnh hưởng performance

## 🔒 **Security Considerations**

- Tool chỉ **capture và analyze** - không modify traffic
- Sensitive data có thể có trong packet payload - chú ý khi share CSV files
- Logs và CSV files nên được encrypted khi lưu trữ
- Tuân thủ company policy về network monitoring

## 🆚 **So sánh với Linux version**

| Feature | Windows | Linux |
|---------|---------|-------|
| Packet Capture | Npcap | Raw sockets |
| Privileges | Administrator | sudo/root |
| Performance | Good | Better |
| Ease of Setup | Easy | Moderate |
| Service Detection | Windows-specific | Generic |

## 📈 **Training Data Quality**

Tool tạo CSV files với:
- **79 features** theo chuẩn CIC-IDS dataset
- **Compatible** với scikit-learn, TensorFlow, PyTorch
- **Balanced** normal vs attack samples khi có proper labeling
- **Real-world** Windows network characteristics

Perfect để train các models detect:
- Network intrusions
- Malware communications
- Lateral movement
- Data exfiltration
- Insider threats

## 🤝 **Contributing**

Issues hoặc improvements, please create GitHub issues hoặc pull requests.

