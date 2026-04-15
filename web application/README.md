# Network Security Management System

Hệ thống quản lý bảo mật mạng tự động thu thập dữ liệu từ các agent, phân tích và phát hiện trojan/malware, đồng thời có khả năng cô lập các máy bị nhiễm độc.

## Tính năng chính

### 🛡️ Thu thập dữ liệu tự động
- Thu thập network flow data từ các agent (máy chạy network collector)
- Phân tích payload content ở định dạng hex dump
- Lưu trữ và quản lý dữ liệu tập trung

### 🔍 Phát hiện mối đe dọa (AI-powered)
- Phát hiện trojan và malware thông qua payload analysis
- Machine Learning với Isolation Forest để phát hiện anomaly
- Signature-based detection cho các mối đe dọa đã biết
- Scoring system để đánh giá mức độ nguy hiểm

### 🚨 Cảnh báo và thông báo
- Hệ thống cảnh báo real-time cho các mối đe dọa
- Phân loại mức độ: Low, Medium, High, Critical
- Dashboard hiển thị trực quan tình trạng bảo mật

### 🔒 Cô lập mạng tự động
- Tự động cô lập các agent có mối đe dọa cao
- Firewall rules để block network traffic
- Manual controls để isolate/restore agents

## Cấu trúc hệ thống

```
web application/
├── app.py                    # Flask web application chính
├── security_agent_client.py  # Agent client để gửi dữ liệu về server
├── setup_and_run.py         # Setup và run script
├── requirements.txt         # Python dependencies
├── templates/               # HTML templates
│   ├── base.html           
│   ├── dashboard.html       # Dashboard chính
│   ├── agents.html         # Danh sách agents
│   ├── agent_detail.html   # Chi tiết agent
│   └── alerts.html         # Danh sách cảnh báo
└── network_security.db     # SQLite database (tự động tạo)
```

## Cài đặt và chạy

### Bước 1: Cài đặt thư viện (Setup)
**Cách nhanh nhất:** Vào thư mục `web application` và click đúp vào file `install_modules.bat` để script tự động cài đặt toàn bộ thư viện cần thiết.

Hoặc bạ có thể setup thủ công qua lệnh:
```powershell
cd "web application"
python setup_and_run.py setup
```

### Bước 2: Chạy Management Server (Trang Dashboard)
Mở cửa sổ dòng lệnh tại thư mục `web application` và chạy:
```powershell
python setup_and_run.py server
```
Chương trình sẽ khởi động và cung cấp địa chỉ truy cập web (VD: `http://localhost:5000` hoặc IP LAN thực tế của máy).

### Bước 3: Tích hợp với Network Flow Collector (Chạy Agent)

#### Cách 1: Sử dụng Script tự động (Khuyến nghị)
Về lại thư mục cài đặt gốc `network_flow_collector_windows`, click chuột phải vào file `run_agent_admin.bat` và chọn **Run as administrator**. 
Khi được hỏi, hãy nhập địa chỉ IP của máy Server (hoặc nhấn Enter để dùng localhost). Chức năng đồng bộ tự động sẽ ghi đè IP này vào `config.ini` để làm mặc định cho các lần sau.

#### Cách 2: Chạy Agent bằng dòng lệnh (Thủ công)
```powershell
python setup_and_run.py integrate --collector-path "../network_flow_collector_windows/network_flow_collector_windows.py" --server-url "http://IP-MAY-SERVER:5000"
```

## Usage trong mã hiện có

### Tích hợp với WindowsNetworkFlowCollector

Thêm vào file `network_flow_collector_windows.py`:

```python
# Import agent client
from web_application.security_agent_client import integrate_with_flow_collector

# Trong main function
collector = WindowsNetworkFlowCollector(
    output_file="network_flows.csv",
    timeout=120,
    hex_payload=True  # Enable hex payload format
)

# Tích hợp với security system
agent_client = integrate_with_flow_collector(collector, "http://your-server-ip:5000")

# Start collection
collector.start_collection()
```

## Web Interface

### Dashboard (`http://localhost:5000`)
- Tổng quan hệ thống với thống kê real-time
- Danh sách agents có mối đe dọa cao
- Recent security alerts
- Malicious network traffic

### Agents Management (`/agents`)
- Danh sách tất cả agents
- Trạng thái: Active, Isolated, Offline  
- Threat level: Low, Medium, High, Critical
- Actions: View details, Isolate, Restore

### Agent Details (`/agent/<agent_id>`)
- Thông tin chi tiết agent
- Security alerts của agent
- Network traffic history với payload hex dump
- Isolate/Restore controls

### Security Alerts (`/alerts`)
- Tất cả security alerts trong hệ thống
- Filter theo severity và status
- Mark alerts as resolved

## API Endpoints

### Agent Registration
```http
POST /api/register_agent
Content-Type: application/json

{
    "agent_id": "unique-agent-id",
    "hostname": "DESKTOP-ABC123",
    "ip_address": "192.168.1.100",
    "os_info": "Windows 11 Pro..."
}
```

### Submit Network Flows
```http  
POST /api/submit_flow
Content-Type: application/json

{
    "agent_id": "unique-agent-id",
    "flows": [
        {
            "flow_id": "192.168.1.100-10.0.0.1-1234-80-TCP",
            "src_ip": "192.168.1.100",
            "dst_ip": "10.0.0.1", 
            "src_port": 1234,
            "dst_port": 80,
            "protocol": "TCP",
            "payload_content": "TCP: 1703 0300 26fc d776 5b4e afe8 ....&..v[N..",
            "timestamp": "2024-02-26T15:30:00"
        }
    ]
}
```

### Check Agent Status
```http
GET /api/agent_status/<agent_id>

Response:
{
    "agent_id": "unique-agent-id",
    "status": "active",
    "threat_level": "high",
    "instructions": ["INCREASE_MONITORING"],
    "recent_alerts": 5
}
```

## Threat Detection

### Signature-based Detection
Hệ thống có sẵn các signatures phát hiện:
- Backdoor patterns
- Trojan connect-back signatures  
- Remote shell attempts
- Suspicious executables
- Botnet communications

### Machine Learning Detection
- Isolation Forest algorithm để phát hiện anomaly
- Feature engineering từ network flows:
  - Port numbers, payload size, protocol
  - Time-based patterns (suspicious hours)
  - Payload entropy và patterns
  - Executable signatures

### Threat Scoring
- 0.0 - 0.3: Low risk
- 0.4 - 0.6: Medium risk  
- 0.7 - 0.8: High risk
- 0.9 - 1.0: Critical risk

## Network Isolation

### Automatic Isolation
Hệ thống tự động cô lập agent khi:
- Phát hiện > 5 threats trong 1 lần submit
- Threat level = Critical
- Threat score > 0.9

### Manual Isolation
Admin có thể manually isolate/restore agents qua web interface.

### Firewall Rules
Isolation sử dụng Windows Firewall:
```powershell
# Block incoming traffic
netsh advfirewall firewall add rule name="Isolate_<agent_id>" dir=in action=block remoteip=any

# Block outgoing traffic  
netsh advfirewall firewall add rule name="Isolate_<agent_id>_out" dir=out action=block remoteip=any
```

## Configuration

### Server Configuration (app.py)
```python
app.config['SECRET_KEY'] = 'your-secret-key-change-this'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///network_security.db'
```

### Agent Configuration
```python
agent = SecurityAgentClient(
    server_url='http://localhost:5000',
    batch_size=50,           # Số flows upload mỗi lần
    upload_interval=30       # Interval upload (seconds)
)
```

## Production Deployment

### Sử dụng PostgreSQL thay SQLite
```python
# Uncomment trong requirements.txt:
# psycopg2-binary==2.9.7

# Update config:
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://user:pass@localhost/security_db'
```

### Chạy với Gunicorn
```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

### Network Security
- Chạy server trên internal network
- Sử dụng HTTPS trong production
- Configure firewall cho port 5000

## Troubleshooting

### Agent không kết nối được
- Kiểm tra server URL và port
- Kiểm tra firewall settings
- Xem logs để debug

### Database issues
```powershell
# Reset database
rm network_security.db
python setup_and_run.py setup
```

### High memory usage
- Giảm batch_size của agents
- Tăng cleanup frequency
- Sử dụng PostgreSQL cho production

## Logs và Monitoring

### Server Logs
```python
# File: network_collector.log
# Level: INFO, WARNING, ERROR
```

### Agent Logs  
```python
# Format: %(asctime)s - %(levelname)s - %(message)s
```

### Database Monitoring
- Monitor số lượng flows
- Cleanup old data định kỳ
- Monitor alert frequency

## Security Considerations

⚠️ **Important Security Notes:**

1. **Authentication**: Current version không có authentication - chỉ sử dụng trong internal network
2. **Firewall**: Đảm bảo port 5000 chỉ accessible từ trusted networks  
3. **Database**: SQLite phù hợp cho testing, sử dụng PostgreSQL cho production
4. **Isolation**: Cần admin privileges để execute firewall commands
5. **API Security**: Consider rate limiting và input validation

## Support và Development

Để extend functionality:
1. Thêm threat signatures vào `ThreatDetector.load_trojan_signatures()`
2. Customize ML model trong `ThreatDetector.train_model()`  
3. Thêm notification channels (email, Slack, etc.)
4. Integrate với SIEM systems
5. Thêm network-based remediation actions