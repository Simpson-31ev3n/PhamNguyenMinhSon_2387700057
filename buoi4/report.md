# 📑 BÁO CÁO THỰC HÀNH: BÀI 4 - BẢO MẬT WEB APP VÀ API

---

## 👤 Thông tin sinh viên
- **Họ và tên:** Phạm Nguyễn Minh Sơn
- **Mã số sinh viên (MSSV):** 2387700057
- **Lớp:** 23DATA1
- **Môn học:** Thực hành Lập trình An ninh thông tin
- **Bài thực hành:** Bài 4: Bảo mật Web App và API

---

## 🎯 I. Mục tiêu bài thực hành
1. **Nghiên cứu các lỗ hổng Web phổ biến:** Phân tích nguyên nhân gốc rễ, cơ chế khai thác và kỹ thuật phòng chống 4 loại lỗ hổng hàng đầu theo chuẩn OWASP:
   - **XSS (Cross-Site Scripting):** Reflected XSS, Stored XSS, DOM-based XSS.
   - **SQL Injection (SQLi):** Classic SQLi, Blind SQLi, Time-Based Blind SQLi, Union-Based SQLi, Second-Order SQLi.
   - **CSRF (Cross-Site Request Forgery):** Khai thác cookie phiên làm việc, cơ chế phòng vệ bằng Anti-CSRF token và SameSite cookie.
   - **SSRF (Server-Side Request Forgery):** Ép máy chủ truy xuất tài nguyên mạng nội bộ (`127.0.0.1`, mạng LAN) và Cloud Metadata service.
2. **Xây dựng công cụ Web Vulnerability Scanner:**
   - Thiết kế các module kiểm thử chuyên biệt: `CSRFDetector`, `SQLInjectionTester`, `SSRFTester`, `XSSScanner`.
   - Xây dựng module tạo báo cáo tổng hợp `ReportGenerator`.
   - Phát triển giao diện Web UI tương tác bằng Flask Framework (`index.html` và `result.html`).
3. **Làm chủ cơ chế xác thực JWT & OAuth 2.0:**
   - Khảo sát cấu trúc token (`Header.Payload.Signature`), rủi ro bảo mật (`alg=none`, brute-force secret yếu, key confusion, token replay, lộ dữ liệu trong payload).
   - Thiết kế mô hình quản lý vòng đời token phân tách giữa Access Token (ngắn hạn: 15 phút) và Refresh Token (dài hạn: 24 giờ).
4. **Phát triển bộ công cụ bảo mật JWT (JWT Security Tools):**
   - Triển khai `JWTValidator` kiểm tra tính hợp lệ và thời hạn token.
   - Triển khai `JWTCracker` thử nghiệm tấn công dò khóa bằng xử lý đa luồng (`ThreadPoolExecutor`).
   - Triển khai `OAuthClient` tuân thủ các luồng ủy quyền chuẩn.
   - Triển khai `TokenManager` quản lý vòng đời token (issue, refresh, revoke).
   - Triển khai `APIGateway` bảo vệ tài nguyên nhạy cảm bằng xác thực Bearer token.
5. **Kiểm thử tự động & Quản lý an toàn mã nguồn:**
   - Thực thi kiểm thử tự động với `unittest` và `pytest`.
   - Tuân thủ quy chuẩn bảo mật `GitSecure` (quản lý secret key an toàn bằng biến môi trường `os.getenv`).

---

## 📁 II. Kiến trúc thư mục dự án

```text
buoi4/
├── web-vuln-scanner/
│   ├── requirements.txt
│   ├── __init__.py
│   ├── main.py                        # Script demo quét mẫu CLI
│   ├── scanners/
│   │   ├── __init__.py
│   │   ├── csrf_detector.py           # Quét thiếu CSRF token trong HTML
│   │   ├── sql_injection_tester.py    # Phát hiện SQL Injection trong URL query
│   │   ├── ssrf_tester.py             # Phát hiện SSRF trỏ tới IP nội bộ
│   │   └── xss_scanner.py             # Gửi payload kiểm tra phản hồi XSS
│   ├── report/
│   │   ├── __init__.py
│   │   └── report_generator.py        # Gom nhóm và chuẩn hóa báo cáo
│   ├── tests/                         # Bộ Unit Test toàn diện (9 tests)
│   │   ├── __init__.py
│   │   ├── test_csrf.py
│   │   ├── test_sql_injection.py
│   │   ├── test_ssrf.py
│   │   ├── test_xss.py
│   │   └── test_report.py
│   └── ui/
│       ├── app.py                     # Máy chủ Web Flask
│       └── templates/
│           ├── index.html             # Form nhập URL và chọn scanner
│           └── result.html            # Bảng hiển thị kết quả phân loại rủi ro
│
├── jwt-security-tools/
│   ├── requirements.txt
│   ├── pytest.ini
│   ├── main.py                        # Cấp phát token & khởi chạy API Gateway
│   ├── api_gateway/
│   │   ├── __init__.py
│   │   └── gateway.py                 # Route /protected xác thực Bearer token
│   ├── jwt_cracker/
│   │   ├── __init__.py
│   │   └── cracker.py                 # Tấn công brute-force đa luồng
│   ├── jwt_validator/
│   │   ├── __init__.py
│   │   └── validator.py               # Kiểm tra tính toàn vẹn và hạn sử dụng
│   ├── oauth_client/
│   │   ├── __init__.py
│   │   └── client.py                  # Client OAuth 2.0 (tạo auth URL, lấy token)
│   ├── token_manager/
│   │   ├── __init__.py
│   │   └── manager.py                 # Quản lý vòng đời Access / Refresh Token
│   └── tests/                         # Bộ Pytest toàn diện (7 tests)
│       ├── __init__.py
│       ├── test_api_gateway.py
│       ├── test_cracker.py
│       ├── test_oauth_client.py
│       ├── test_token_manager.py
│       └── test_validator.py
│
├── images/                            # Các ảnh chụp minh chứng thực nghiệm
├── pic.docx                           # File tài liệu ảnh gốc
├── report.docx                        # Báo cáo định dạng Word hoàn chỉnh
└── report.md                          # Báo cáo Markdown
```

---

## 🧪 III. Các bước thực hiện & Kết quả kiểm thử thực tế

### Bước 1: Kiểm thử tự động Web Vulnerability Scanner bằng Unittest (9/9 tests passed)
- **Mục đích:** Kiểm thử tính đúng đắn của toàn bộ các thuật toán bóc tách tham số, nhận diện mã độc và lập báo cáo lỗ hổng tự động.
- **Lệnh thực hiện trên Command Prompt:**
  ```cmd
  cd /d "E:\web rác\PhamNguyenMinhSon_2387700057\buoi4\web-vuln-scanner"
  python -m unittest discover -v tests
  ```
- **Kết quả thực tế:** 9/9 tests đều đạt trạng thái `ok` trong 0.003 giây.
  ```text
  test_csrf_token_missing (test_csrf.TestCSRFDetector.test_csrf_token_missing) ... ok
  test_csrf_token_present (test_csrf.TestCSRFDetector.test_csrf_token_present) ... ok
  test_generate_report_with_dict (test_report.TestReportGenerator.test_generate_report_with_dict) ... ok
  test_generate_report_with_list (test_report.TestReportGenerator.test_generate_report_with_list) ... ok
  test_detect_sql_injection (test_sql_injection.TestSQLInjectionTester.test_detect_sql_injection) ... ok
  test_no_vulnerability (test_sql_injection.TestSQLInjectionTester.test_no_vulnerability) ... ok
  test_detect_ssrf (test_ssrf.TestSSRFTester.test_detect_ssrf) ... ok
  test_no_ssrf (test_ssrf.TestSSRFTester.test_no_ssrf) ... ok
  test_detect_xss (test_xss.TestXSSScanner.test_detect_xss) ... ok
  ----------------------------------------------------------------------
  Ran 9 tests in 0.003s

  OK
  ```

![Hình 1: Kết quả kiểm thử Unittest cho Web Vulnerability Scanner (9/9 passed)](images/image1.png)

*Hình 1: Kết quả kiểm thử Unittest cho Web Vulnerability Scanner đạt 9/9 tests passed.*

---

### Bước 2: Khởi chạy và kiểm thử Giao diện Web UI của Web Vulnerability Scanner
- **Mục đích:** Cung cấp trải nghiệm quét lỗ hổng trực quan trên nền tảng web, cho phép người dùng nhập URL mục tiêu và chọn các module quét tương ứng.
- **Lệnh thực hiện trên Windows PowerShell:**
  ```powershell
  cd "e:\web rác\PhamNguyenMinhSon_2387700057\buoi4\web-vuln-scanner"
  python .\ui\app.py
  ```
- **Kết quả thực tế:** Máy chủ Flask khởi động thành công ở chế độ Debug trên cổng 5000 (`http://127.0.0.1:5000`).

![Hình 2: Khởi chạy dịch vụ Web UI Scanner bằng Flask trên cổng 5000](images/image4.png)

*Hình 2: Khởi chạy dịch vụ Web UI Scanner bằng Flask trên cổng 5000.*

---

### Bước 3: Kiểm thử tự động bộ công cụ bảo mật JWT bằng Pytest (7/7 tests passed)
- **Mục đích:** Kiểm thử toàn diện các module của `jwt-security-tools` gồm bảo vệ API Gateway, dò secret key đa luồng, OAuth client, quản lý vòng đời token và bộ kiểm định validator.
- **Lệnh thực hiện trên Command Prompt:**
  ```cmd
  cd /d "E:\web rác\PhamNguyenMinhSon_2387700057\buoi4\jwt-security-tools"
  python -m pytest tests/
  ```
- **Kết quả thực tế:** Toàn bộ 7/7 ca kiểm thử đều đạt trạng thái `PASSED`.
  ```text
  tests\test_api_gateway.py ..                                             [ 28%]
  tests\test_cracker.py .                                                  [ 42%]
  tests\test_oauth_client.py .                                             [ 57%]
  tests\test_token_manager.py .                                            [ 71%]
  tests\test_validator.py ..                                               [100%]
  ======================= 7 passed, 19 warnings in 0.60s =======================
  ```

![Hình 3: Kết quả thực thi Pytest trên jwt-security-tools](images/image2.png)

*Hình 3: Kết quả thực thi Pytest trên jwt-security-tools (7/7 tests passed).*

---

### Bước 4: Kiểm thử cơ chế xác thực và bảo vệ API Gateway qua cURL
- **Mục đích:** Kiểm tra thực tế route `/protected` của API Gateway bằng công cụ `curl.exe` dưới hai trường hợp: truy cập trái phép và truy cập hợp lệ bằng JWT Access Token.
- **Lệnh thực hiện trên Command Prompt:**
  1. *Trường hợp 1 (Token không hợp lệ):* Gửi chuỗi giữ chỗ `<access_token>`:
     ```cmd
     curl.exe -H "Authorization: Bearer <access_token>" http://127.0.0.1:5000/protected
     ```
     $\rightarrow$ Server từ chối và trả về HTTP 401: `{"message":"Access denied"}`.
  2. *Trường hợp 2 (Token hợp lệ):* Gửi chuỗi Access Token thật do `TokenManager` cấp phát:
     ```cmd
     curl.exe -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." http://127.0.0.1:5000/protected
     ```
     $\rightarrow$ Server xác thực thành công và trả về HTTP 200: `{"message":"Access granted","user":"phuoc"}`.

![Hình 4: Kết quả kiểm thử cURL thực tế với cả 2 trường hợp Access Denied và Access Granted](images/image3.png)

*Hình 4: Kết quả kiểm thử cURL thực tế với cả 2 trường hợp Access Denied và Access Granted.*

---

## 📝 IV. Đánh giá và Kết luận

1. **Hiệu quả của Web Vulnerability Scanner:**
   - Xây dựng thành công công cụ quét lỗ hổng ứng dụng web đa năng, phát hiện chính xác các lỗ hổng OWASP Top 10 phổ biến (XSS, SQLi, CSRF, SSRF).
   - Kỹ thuật Mocking trong Unit Test giúp tách biệt hoàn toàn môi trường kiểm thử với môi trường mạng thực tế, nâng cao tốc độ và độ tin cậy.

2. **Cơ chế bảo mật JWT & API Gateway:**
   - Triển khai thành công mô hình xác thực phi trạng thái (**Stateless Authentication**) sử dụng cặp Access Token (hạn ngắn 15 phút) và Refresh Token (hạn dài 24 giờ).
   - Module `JWTCracker` chứng minh sự nguy hiểm của các secret key yếu và ngắn; từ đó khẳng định tầm quan trọng của việc sử dụng key HMAC SHA-256 có độ dài tối thiểu 32 bytes (256 bits) theo khuyến nghị RFC 7518.

3. **Quản lý an toàn mã nguồn (GitSecure Compliance):**
   - Không lưu trữ mật khẩu, secret key trực tiếp trong code (hardcode), thay vào đó nạp từ biến môi trường thông qua `os.getenv`.
   - Đáp ứng các tiêu chuẩn quét mã bảo mật tự động, sẵn sàng triển khai trong môi trường CI/CD và đẩy lên remote repository an toàn.
