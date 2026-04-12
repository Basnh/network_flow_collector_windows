# Cơ chế hoạt động và Phương thức truyền tải dữ liệu giữa Agent và Server

Hệ thống Giám sát An ninh mạng được thiết kế theo kiến trúc **Client-Server (Máy khách - Máy chủ)**, trong đó các máy trạm (Agent) đóng vai trò thu thập dữ liệu tại chỗ (Endpoint) và Máy chủ quản lý trung tâm (Server/Dashboard) đóng vai trò tiếp nhận, phân tích và hiển thị thông tin. Quá trình giao tiếp và truyền tải dữ liệu giữa Agent và Server được thực hiện thông qua giao thức **HTTP/HTTPS** dựa trên kiến trúc **RESTful API**, với định dạng dữ liệu trao đổi chuẩn là **JSON (JavaScript Object Notation)**.

Cơ chế hoạt động này được chia thành các tiến trình cốt lõi sau:

### 1. Cơ chế Định danh và Duy trì kết nối (Heartbeat / Keep-alive)
* Khi khởi chạy trên máy trạm (thông qua quyền Administrator), Agent sẽ tự động thu thập các thông tin định danh cơ bản của máy bao gồm: Địa chỉ IP, Tên máy (Hostname), Hệ điều hành, và tạo ra một định danh duy nhất (`Agent ID`).
* Agent được thiết lập một luồng chạy ngầm (background thread) thực hiện gửi các tín hiệu **Heartbeat** định kỳ (ví dụ: mỗi 5-10 giây) lên Server thông qua API Endpoint (VD: `/api/agents/heartbeat`). 
* Tín hiệu này chứa trạng thái hoạt động hiện tại (Online), mức độ tiêu thụ tài nguyên hệ thống (CPU, RAM) và cập nhật thời gian liên lạc cuối cùng (`last_seen`). Dựa vào tín hiệu này, Server có thể xác định máy trạm nào đang hoạt động hoặc đã ngắt kết nối để hiển thị lên bảng điều khiển (Dashboard).

### 2. Cơ chế Thu thập và Gửi dữ liệu Lưu lượng mạng (Network Flows)
* Tại máy trạm, module `network_flow_collector` (sử dụng thư viện giám sát gói tin như thư viện Scapy hoặc Pyshark) sẽ liên tục lắng nghe (sniff) trên các giao diện mạng (Network Interfaces).
* Thay vì gửi trực tiếp từng gói tin thô (raw packets) lên Server gây quá tải băng thông, Agent tiến hành **gom cụm (batch) và trích xuất đặc trưng (feature extraction)** thành các luồng mạng (Network Flows) như: *IP nguồn, IP đích, Port, Giao thức (TCP/UDP), tổng số bytes, số lượng packets, thời lượng luồng...*
* Khi bộ đệm (buffer) đạt đến một số lượng bản ghi nhất định hoặc hết một khoảng thời gian (Timeout), Agent đóng gói dữ liệu này thành payload `JSON` và dùng lệnh `POST` gửi về API tiếp nhận lưu lượng của Server (thường là `/api/flows`).

### 3. Theo dõi Tiến trình và Kết nối cục bộ (Process & Connection Monitor)
* Nhằm phục vụ tính năng "Process Monitor", Agent sử dụng các thư viện điều lệnh hệ thống (như `psutil` hoặc các lệnh PowerShell/Netstat API) để ánh xạ các kết nối mạng `(IP:Port)` với các tiến trình (`PID - Process ID`) đang thực thi trên Windows.
* Dữ liệu tiến trình sau khi được thu thập sẽ được chuyển hóa thành dạng danh sách object và gửi về Server bảo mật qua kênh API tương ứng. Cơ chế này cho phép Người quản trị từ xa không chỉ biết *gói tin đi đâu* mà còn biết chính xác *phần mềm/mã độc nào* đang thực hiện kết nối đó.

### 4. Xử lý dữ liệu tại Máy chủ (Server-side Processing)
* Khi Server (Python Flask) tiếp nhận luồng `POST Request` từ Agent, hệ thống sẽ giải mã chuỗi JSON.
* Dữ liệu sẽ đi qua module **Security Analyzer (Phân tích an ninh)** hoặc Mô hình học máy phát hiện bất thường (AI/ML Module). Nếu phát hiện dấu hiệu của mã độc (Malware, Trojan, DDoS), hệ thống lập tức gắn cờ cảnh báo (Alert).
* Cuối cùng, dữ liệu sạch và các cảnh báo được ghi vào cơ sở dữ liệu quan hệ (PostgreSQL) và phát luồng (Stream/API Fetch) đến giao diện Web Dashboard của ban quản trị theo thời gian thực.

### Tóm tắt ưu điểm của mô hình
Việc sử dụng phương thức liên lạc HTTP RESTful API kết hợp `JSON` tạo ra sự độc lập giữa hai môi trường. Máy trạm (Windows Agent) không cần kết nối trực tiếp vào Database của Server, đảm bảo tính bảo mật (Ngăn chặn SQL Injection trực tiếp), hoạt động linh hoạt vượt qua phần lớn các quy tắc chặn của NAT/Firewall nội bộ, dung lượng truyền tải nhỏ, tối ưu hoá băng thông mạng của hệ thống.