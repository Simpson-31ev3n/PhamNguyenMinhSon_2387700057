# Lab 3: Xây dựng hệ thống Secure Logger bảo mật nhật ký ứng dụng

- Môn học: Lập trình an toàn / Bảo mật ứng dụng
- Sinh viên: Phạm Nguyễn Minh Sơn
- Thư mục: `buoi1/lab3/`

---

## 1. Cơ chế bảo mật (Security Mechanisms)

Module `securelogger/logger.py` được thiết kế để giải quyết 4 thách thức bảo mật cốt lõi trong ghi nhật ký ứng dụng theo khuyến nghị của OWASP và chuẩn tuân thủ dữ liệu (GDPR / ISO 27001):

| Cơ chế bảo mật | Triển khai trong mã nguồn | Mục đích & Ngăn chặn lỗ hổng |
|---|---|---|
| **Che giấu thông tin cá nhân (PII Masking)** | Hàm `mask_pii()` sử dụng biểu thức chính quy để nhận diện địa chỉ email và các biến credentials/token/password, thay thế bằng `<email_masked>`, `<token_masked>`. | Tránh vi phạm quyền riêng tư và quy định bảo vệ dữ liệu cá nhân (GDPR, Luật An ninh mạng); ngăn ngừa lộ lọt dữ liệu định danh khi chia sẻ log cho bên thứ 3 hoặc đội ngũ vận hành. |
| **Chống chèn mã giả mạo log (Log Injection / CRLF Defense)** | Lớp `JSONFormatter` chuyển toàn bộ bản ghi log thành chuỗi JSON một dòng duy nhất (`json.dumps(record_dict)`), chuẩn hóa thời gian UTC ISO-8601 (`YYYY-MM-DDTHH:MM:SSZ`). | Ngăn chặn tấn công ngắt dòng CRLF (`\r\n`) chèn thêm các bản ghi log giả mạo nhằm đánh lừa đội ngũ điều tra số (Forensics) hoặc làm sai lệch kết quả phân tích của SIEM. |
| **Phát hiện sửa đổi & Toàn vẹn log (Tamper Detection)** | Hàm `append_signature()` tự động tính mã băm SHA-256 (`hashlib.sha256`) cho từng dòng log và ghi tuần tự vào file chữ ký `secure.log.sig`. | Hỗ trợ đối soát và kiểm tra tính toàn vẹn (Integrity Verification). Nếu file `secure.log` bị chỉnh sửa hoặc xóa bớt dòng, mã hash đối soát sẽ không còn khớp. |
| **Quản lý luân chuyển & Nén log (Log Rotation & Compression)** | Kế thừa `SecureRotatingFileHandler` với giới hạn dung lượng `MAX_LOG_SIZE = 1MB`, `backupCount = 2`, tích hợp `GZipRotator` nén các file log cũ thành đuôi `.gz`. | Chống tấn công làm cạn kiệt tài nguyên lưu trữ (Disk Space Exhaustion DoS) do kẻ tấn công cố ý spam request để làm sập hệ thống máy chủ. |
| **Tích hợp API Flask an toàn** | Ứng dụng Flask trong [`app.py`](file:///e:/web%20r%C3%A1c/security-labs-main/buoi1/lab3/app.py) tiếp nhận POST JSON `/validate`, lọc dữ liệu với SecureValidator và ghi log chi tiết có che PII. | Giám sát và ghi nhận toàn bộ hoạt động kiểm tra dữ liệu đầu vào phục vụ kiểm toán bảo mật (Security Auditing). |

---

## 2. Bảng bộ Test Cases (Unit Tests & API Tests)

File kiểm thử [`tests/test_logger.py`](file:///e:/web%20r%C3%A1c/security-labs-main/buoi1/lab3/tests/test_logger.py) thực hiện xác minh toàn diện các thành phần bảo mật:

| STT | Tên Test Case | Đầu vào thử nghiệm (Input) | Kết quả kỳ vọng | Trạng thái |
|---|---|---|---|:---:|
| 1 | `test_mask_pii_email` | `"User email is test.user@example.com in system"` | Không còn email gốc, xuất hiện `<email_masked>` | ✅ PASS |
| 2 | `test_mask_pii_password` | `"credentials: password='secret12345' found"` | Không còn `secret12345`, xuất hiện `<token_masked>` | ✅ PASS |
| 3 | `test_hash_sha256` | `{"message": "test"}` | Sinh ra chuỗi băm hex đúng độ dài 64 ký tự | ✅ PASS |
| 4 | `test_api_validate` | POST JSON chứa email, url, filename traversal, sql injection | HTTP 200, trả về JSON sanitized, `secure.log` được ghi với email đã che, `secure.log.sig` được cập nhật hash | ✅ PASS |
| 5 | Xử lý JSON lỗi (Malformed) | POST dữ liệu chuỗi không đúng định dạng JSON | HTTP 400 `{"error": "Invalid JSON format"}`, logger ghi nhận warning | ✅ PASS |

---

## 3. Phân tích kịch bản & Kỹ thuật Bypass / Hạn chế

Dù đã triển khai các kỹ thuật bảo mật log hiện đại, hệ thống vẫn tồn tại các giới hạn có thể bị khai thác:

### 3.1. Điểm yếu của cơ chế băm SHA-256 đơn thuần (Tamper Detection Bypass)
- **Kịch bản tấn công**:
  - Cơ chế hiện tại dùng SHA-256 thông thường: `hashlib.sha256(line.encode("utf-8")).hexdigest()`.
  - Thuật toán băm này hoàn toàn **không sử dụng khóa bí mật (Secret Key)**.
  - Nếu kẻ tấn công chiếm được quyền ghi tệp (thông qua lỗ hổng RCE hoặc Local Privilege Escalation), chúng có thể mở `secure.log`, chỉnh sửa hoặc xóa dòng log ghi nhận hành vi phạm tội của mình.
  - Sau đó, kẻ tấn công chỉ cần viết một script Python ngắn để đọc lại từng dòng trong `secure.log`, tính toán lại mã SHA-256 tương ứng và **ghi đè toàn bộ nội dung file `secure.log.sig`**!
  - Khi đội ngũ quản trị viên kiểm tra, mọi mã hash vẫn khớp 100% với file log đã bị làm giả.
- **Khắc phục**:
  - Nâng cấp từ SHA-256 thường sang **HMAC-SHA256** với một Secret Key bí mật chỉ hệ thống log biết:
    ```python
    import hmac, hashlib
    HMAC_KEY = os.environ.get("LOG_HMAC_SECRET_KEY", "default_secret").encode()
    def hash_line_hmac(line: str) -> str:
        return hmac.new(HMAC_KEY, line.encode("utf-8"), hashlib.sha256).hexdigest()
    ```
  - Hoặc ký số bất đối xứng (Asymmetric Signing - RSA/ECDSA) lưu private key ở phân vùng bảo mật (KMS/Vault).

### 3.2. Bypass bộ lọc che giấu PII (`mask_pii`)
- **Kịch bản tấn công**:
  - **Đặt tên biến ngoài phạm vi regex**: Regex `PII_PATTERNS` chỉ lọc các từ khóa `(token|apikey|key|password)`. Nếu lập trình viên hoặc kẻ tấn công log các trường như:
    ```python
    extra={"authorization": "Bearer eyJhbGci...", "client_secret": "my_secret_999"}
    ```
    thì giá trị này hoàn toàn **không bị che giấu** và lộ nguyên văn trong file nhật ký.
  - **Kỹ thuật lừa regex email**: Viết email dạng phân tách: `admin [at] organization [dot] com` hoặc URL-encoded `admin%40corp.com`.
  - **Thiếu lọc các dữ liệu nhạy cảm khác**: Hệ thống chưa lọc số thẻ tín dụng (Credit Card 16 số kèm thuật toán Luhn), số Căn cước công dân (12 số), số điện thoại cá nhân.
- **Khắc phục**:
  - Xây dựng bộ lọc PII đa tầng sử dụng các thư viện DLP (Data Loss Prevention) như `Microsoft Presidio` hoặc quét theo schema dữ liệu (Field-level encryption/masking).

### 3.3. Log Injection qua các thuộc tính JSON mở rộng
- **Kịch bản tấn công**:
  - Dù đã dùng `json.dumps()` để chống ngắt dòng CRLF (`\n`), nếu các trường trong `extra` nhận chuỗi chứa ký tự phân tách đặc biệt của Unicode (như `\u2028` Line Separator hoặc `\u2029` Paragraph Separator), một số hệ thống giám sát log cũ hoặc terminal log viewer có thể hiểu nhầm đây là ký tự xuống dòng và tách thành 2 bản ghi riêng biệt.
- **Khắc phục**:
  - Sanitize loại bỏ các ký tự điều khiển Unicode không in được (non-printable control characters) trước khi đưa vào formatter.

---

## 4. Giải pháp nâng cấp chuẩn công nghiệp (Production Best Practices)

1. **Lưu trữ bất biến (Write-Once-Read-Many - WORM)**: Đẩy log trực tiếp lên AWS S3 với tính năng **S3 Object Lock** hoặc Azure Immutable Blob Storage để ngăn chặn bất kỳ ai (kể cả quản trị viên) chỉnh sửa hoặc xóa log trong thời hạn lưu trữ bắt buộc (ví dụ 1 năm).
2. **Hệ thống thu thập log tập trung (Centralized Log Management)**: Sử dụng các agent như Fluentbit, Logstash để vận chuyển log theo thời gian thực về cụm máy chủ SIEM (Elasticsearch, Splunk, Datadog) qua kênh mã hóa TLS mTLS.
3. **Mã hóa nhật ký tĩnh (Encryption at Rest)**: Sử dụng chuẩn mã hóa AES-256 để mã hóa toàn bộ tệp nhật ký trên ổ cứng để bảo vệ dữ liệu khi ổ cứng bị sao lưu hoặc trích xuất trái phép.

---

## 5. Hướng dẫn chạy thử và kiểm nghiệm

```bash
# Di chuyển vào thư mục lab3
cd buoi1/lab3

# Cài đặt thư viện cần thiết
pip install -r requirements.txt

# Chạy unit tests kiểm tra cơ chế che PII và tạo chữ ký
python -m unittest discover tests

# Khởi chạy server API Flask
python app.py
```

### Kiểm tra bằng cURL / Postman:
```bash
curl -X POST http://127.0.0.1:5000/validate \
     -H "Content-Type: application/json" \
     -d '{
       "email": "son.pham@example.com",
       "url": "https://secure.example.com",
       "filename": "document.pdf",
       "sql": "SELECT * FROM users WHERE 1=1",
       "html": "<img src=x onerror=alert(1)>"
     }'
```
Sau đó kiểm tra nội dung file `secure.log` (xem email đã bị che thành `<email_masked>`) và file `secure.log.sig` (chứa chuỗi băm đối soát SHA-256).
