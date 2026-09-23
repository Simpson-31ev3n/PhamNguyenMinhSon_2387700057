# Báo cáo thực hành Buổi 1: Cơ sở lập trình bảo mật

- Sinh viên: Phạm Nguyễn Minh Sơn
- Môn học: Lập trình an toàn / Bảo mật ứng dụng
- Kho lưu trữ: `security-labs`

---

## 1. Cấu trúc thư mục Buổi 1

```text
buoi1/
├── README.md               # Báo cáo tổng hợp toàn bộ Buổi 1
├── lab1/                   # Lab 1: Kiểm tra và làm sạch dữ liệu đầu vào
│   ├── README.md           # Chi tiết bảo mật, test case & bypass Lab 1
│   ├── app.py              # Ứng dụng Flask Web
│   ├── requirements.txt    # Danh sách thư viện (Flask, gunicorn)
│   ├── render.yaml         # Cấu hình tự động deploy Cloud Render
│   ├── securevalidator/    # Module xử lý kiểm tra đầu vào
│   │   ├── __init__.py
│   │   └── core.py
│   ├── templates/
│   │   └── index.html      # Giao diện web kiểm tra (PicoCSS)
│   └── tests/
│       └── test_validators.py # 10 Unit test cases
├── lab2/                   # Lab 2: Git Security Hook ("GitSecure")
│   ├── README.md           # Chi tiết bảo mật, test case & bypass Lab 2
│   ├── requirements.txt    # Thư viện quét Bandit
│   ├── .githooks/
│   │   └── pre-commit      # Script hook chặn rò rỉ secret, license & perms
│   └── pre-commit-hook-test/
│       └── bad.py          # File mẫu thử nghiệm vi phạm
└── lab3/                   # Lab 3: Hệ thống Secure Logger
    ├── README.md           # Chi tiết bảo mật, test case & bypass Lab 3
    ├── app.py              # API Flask /validate
    ├── requirements.txt    # Thư viện Flask
    ├── securevalidator/    # Tích hợp module validator từ Lab 1
    │   ├── __init__.py
    │   └── core.py
    ├── securelogger/       # Module ghi log an toàn
    │   ├── __init__.py
    │   └── logger.py
    └── tests/
        └── test_logger.py  # Unit test kiểm tra log PII, SHA-256 & API
```

---

## 2. Lab 1: Kiểm tra và làm sạch dữ liệu đầu vào (Input Validation & Sanitization)

*Tài liệu chi tiết riêng của Lab 1: [buoi1/lab1/README.md](file:///e:/web%20r%C3%A1c/security-labs-main/buoi1/lab1/README.md)*

### 2.1. Mục tiêu & Cơ chế bảo mật (`lab1/securevalidator/core.py`)
- **Kiểm tra Email (`validate_email`)**: Sử dụng regex `^[\w\.-]+@[\w\.-]+\.\w+$` và chặn chuỗi chứa `..`.
- **Kiểm tra URL (`validate_url`)**: Phân tách URL bằng `urllib.parse`, áp dụng Whitelist chỉ chấp nhận giao thức `http`, `https` và bắt buộc có `netloc` nhằm chặn SSRF cơ bản và Protocol Smuggling (`file://`, `gopher://`).
- **Kiểm tra tên file (`validate_filename`)**: Chặn ký tự điều hướng `..`, `/`, `\` và đối soát `os.path.basename(filename) == filename` chống Path Traversal.
- **Lọc ký tự SQL (`sanitize_sql_input`)**: Loại bỏ các ký tự đặc biệt (`'`, `"`, `;`, `--`, `#`) và các từ khóa truy vấn nguy hiểm (`SELECT`, `INSERT`, `UPDATE`, `DELETE`, `DROP`, `OR`, `AND`, `UNION`, `WHERE`) theo cơ chế Blacklist Regex.
- **Mã hóa HTML (`sanitize_html_input`)**: Sử dụng `html.escape` mã hóa các ký tự `<`, `>`, `&`, `"` thành HTML entities để vô hiệu hóa mã script (chống XSS).

### 2.2. Bảng bộ Test Cases kiểm thử (10/10 PASS)
| STT | Hàm | Input | Kỳ vọng | Kết quả | Đánh giá |
|---|---|---|---|:---:|---|
| 1 | `validate_email` | `user@example.com` | `True` | PASS | Email chuẩn RFC |
| 2 | `validate_email` | `user@@example..com` | `False` | PASS | Chặn ký tự lỗi và `..` |
| 3 | `validate_url` | `https://example.com` | `True` | PASS | Giao thức HTTPS an toàn |
| 4 | `validate_url` | `ftp://example.com` | `False` | PASS | Chặn giao thức ngoài whitelist |
| 5 | `validate_filename` | `report.pdf` | `True` | PASS | Tên file an toàn |
| 6 | `validate_filename` | `../../etc/passwd` | `False` | PASS | Chặn Directory Traversal |
| 7 | `sanitize_sql_input` | `' OR 1=1 --` | `1=1` | PASS | Lọc nháy đơn, comment và từ khóa OR |
| 8 | `sanitize_sql_input` | `hello world` | `hello world` | PASS | Giữ nguyên dữ liệu sạch |
| 9 | `sanitize_html_input` | `<script>alert("XSS")</script>` | `&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;` | PASS | Mã hóa thẻ tag và nháy kép |
| 10 | `sanitize_html_input` | `Hello World` | `Hello World` | PASS | Giữ nguyên văn bản an toàn |

### 2.3. Các kịch bản & Kỹ thuật Bypass
1. **Bypass Email**:
   - `admin@127.0.0.1`: Vượt qua regex vì `\w` cho phép chữ số; có thể gây SSRF nếu ứng dụng dùng email này để gửi webhook hoặc truy vấn mạng.
   - `_@_._`, `test@b.co`: Khớp regex nhưng domain không hề tồn tại trên Internet.
2. **Bypass URL (SSRF nâng cao)**:
   - `http://127.0.0.1:8080`, `http://localhost`: Đều có scheme `http` và `netloc` nên trả về `True`, cho phép truy cập service nội bộ.
   - `http://169.254.169.254/`: Truy vấn AWS Metadata service đánh cắp Cloud credentials.
   - Decimal IP: `http://2130706433/` (tương đương `127.0.0.1`).
3. **Bypass SQL Blacklist (Nguy cơ lớn nhất)**:
   - **Lồng từ khóa (Nested Keywords)**: Kẻ tấn công gửi `SELSELECTECT` hoặc `UNUNIONION`. Regex chỉ lọc 1 lần, khi từ `SELECT` ở giữa bị xóa, hai nửa ghép lại tạo thành `SELECT` nguyên vẹn!
   - **Inline Comments**: Dùng `UN/**/ION` hoặc `SE/**/LECT` để đánh lừa regex nhưng SQL Engine vẫn biên dịch.
   - **Boolean Blind**: Khai thác biểu thức điều kiện không cần từ khóa bị cấm: `admin' AND 1=1`.
4. **Bypass HTML Sanitize (Context-based XSS)**:
   - Nếu đưa vào thuộc tính liên kết `<a href="{{ data }}">`: Kẻ tấn công gửi `javascript:alert(1)`. Chuỗi này không có `<`, `>`, `"`, `&` nên không bị mã hóa nhưng vẫn kích hoạt XSS khi click chuột.

---

## 3. Lab 2: Cấu hình Git Security Hook ("GitSecure")

*Tài liệu chi tiết riêng của Lab 2: [buoi1/lab2/README.md](file:///e:/web%20r%C3%A1c/security-labs-main/buoi1/lab2/README.md)*

### 3.1. Mục tiêu & Cơ chế bảo mật (`lab2/.githooks/pre-commit`)
- **Quét thông tin nhạy cảm (Secret Scanning)**: Nhận diện API keys, mật khẩu, access token, và AWS keys (`AKIA/ASIA`) trong mã nguồn trước khi commit.
- **Kiểm tra tuân thủ giấy phép (License Compliance)**: Tự động cảnh báo và chặn commit nếu mã nguồn hoặc `requirements.txt` xuất hiện các giấy phép hạn chế / copyleft nguy hiểm (`GPL`, `AGPL`, `SSPL`).
- **Kiểm tra quyền tệp (File Permissions)**: Phát hiện và chặn tệp bị cấp quyền ghi công khai (`world-writable` - `stat.S_IWOTH` trên Linux), tự động bỏ qua an toàn trên Windows.
- **Tích hợp SAST (Bandit)**: Chạy phân tích tĩnh tự động để cảnh báo các lỗ hổng mã Python mức High severity.
- **Chặn commit & Ghi nhật ký**: Nếu vi phạm, trả về mã thoát `sys.exit(1)`, ghi nhận vào `gitsecure.log` và loại trừ file log trong `.gitignore`.

### 3.2. Bảng bộ Test Cases kiểm thử
| STT | Kịch bản thử nghiệm | Dữ liệu kiểm tra | Kết quả | Trạng thái |
|---|---|---|---|:---:|
| 1 | File chứa mật khẩu | `bad.py` (`password = "super_secret_password_12345"`) | Chặn commit (`pattern (password)...`) | ✅ PASS |
| 2 | File chứa API Key | `apikey = "abcdef1234567890"` | Chặn commit (`pattern (apikey)...`) | ✅ PASS |
| 3 | File chứa AWS Key | `AKIAIOSFODNN7EXAMPLE` | Chặn commit (`pattern (AKIA|ASIA)...`) | ✅ PASS |
| 4 | File chứa giấy phép copyleft | `license_test.py` (`# Licensed under GPL-3.0`) | Chặn commit (`License compliance issue...`) | ✅ PASS |
| 5 | Commit mã nguồn sạch | Toàn bộ mã nguồn hợp lệ của dự án | Cho phép commit (`GitSecure: All checks passed.`) | ✅ PASS |

### 3.3. Các kịch bản & Kỹ thuật Bypass Git Hook
1. **Bypass qua flag Git (`--no-verify`)**:
   - Sử dụng lệnh `git commit --no-verify -m "force bypass"` hoặc `git commit -n`. Cờ này bỏ qua toàn bộ Client-Side hook.
2. **Che giấu chuỗi Secret (String Obfuscation / Splitting)**:
   - Nối chuỗi: `p1 = "pass"; p2 = "word"; p1 + p2 = "secret123"`.
   - Mã hóa Base64: `base64.b64decode("c3VwZXJfc2VjcmV0...")`.
   - Đảo chuỗi: `"drowssap_terces"[::-1]`.
3. **Đổi tên định danh biến**:
   - Đặt tên biến ngoài bộ lọc regex, ví dụ `auth_val = "secret_123"`, `client_jwt = "..."`.
4. **Hạn chế của Client-Side**:
   - Lập trình viên mới clone repo chưa gõ lệnh `git config core.hooksPath buoi1/lab2/.githooks` thì hook sẽ không được kích hoạt.
- **Biện pháp khắc phục**: Bắt buộc triển khai thêm **Server-Side Pre-receive Hook** và quét tự động trên CI/CD Pipeline bằng **TruffleHog / GitLeaks**.

---

## 4. Lab 3: Xây dựng hệ thống Secure Logger

*Tài liệu chi tiết riêng của Lab 3: [buoi1/lab3/README.md](file:///e:/web%20r%C3%A1c/security-labs-main/buoi1/lab3/README.md)*

### 4.1. Mục tiêu & Cơ chế bảo mật (`lab3/securelogger/logger.py`)
- **Che giấu PII (`mask_pii`)**: Thay thế email thành `<email_masked>`, token/password thành `<token_masked>` trước khi ghi nhật ký.
- **Định dạng JSON một dòng (`JSONFormatter`)**: Chuẩn hóa log thành chuỗi JSON duy nhất kèm timestamp UTC ISO-8601 (`YYYY-MM-DDTHH:MM:SSZ`), ngăn chặn tấn công ngắt dòng CRLF (Log Injection).
- **Chống giả mạo nhật ký (`append_signature`)**: Băm SHA-256 từng dòng log vào `secure.log.sig` để đối soát tính toàn vẹn (Tamper Detection).
- **Luân phiên và nén log (`SecureRotatingFileHandler` & `GZipRotator`)**: Giới hạn kích thước 1MB, lưu 2 bản sao dự phòng và tự động nén `.gz` chống DoS dung lượng ổ cứng.

### 4.2. Bảng bộ Test Cases kiểm thử
| STT | Kịch bản kiểm thử | Dữ liệu đầu vào | Kỳ vọng | Trạng thái |
|---|---|---|---|:---:|
| 1 | Che giấu email PII | `"User email is test.user@example.com in system"` | Email được thay bằng `<email_masked>` | ✅ PASS |
| 2 | Che giấu token / password | `"credentials: password='secret12345' found"` | Mật khẩu được thay bằng `<token_masked>` | ✅ PASS |
| 3 | Tính mã băm toàn vẹn | Băm dòng JSON mẫu bằng SHA-256 | Độ dài chuỗi băm hex đúng 64 ký tự | ✅ PASS |
| 4 | API POST `/validate` hợp lệ | JSON chứa email, url, filename, sql, html | HTTP 200, log ghi email đã che, file `.sig` có mã băm | ✅ PASS |
| 5 | API POST `/validate` lỗi | Dữ liệu không phải định dạng JSON hợp lệ | HTTP 400, logger ghi nhận warning | ✅ PASS |

### 4.3. Các kịch bản & Kỹ thuật Bypass / Hạn chế
1. **Làm giả toàn bộ Signature (Bypass SHA-256 đơn thuần)**:
   - Do `hash_line` chỉ dùng SHA-256 không có Secret Key, kẻ tấn công chiếm quyền ghi tệp có thể sửa file `secure.log`, sau đó chạy script tự tính lại SHA-256 cho từng dòng và **ghi đè `secure.log.sig`**. Quản trị viên đối soát vẫn thấy khớp!
   - *Khắc phục*: Phải sử dụng **HMAC-SHA256** với Secret Key được bảo vệ trong biến môi trường / Vault hoặc ký số bất đối xứng (ECDSA/RSA).
2. **Bypass che giấu PII**:
   - Biến mang tên lạ: `authorization: Bearer ey...`, `access_secret = ...` không nằm trong regex `PII_PATTERNS`.
   - Viết phân tách: `admin [at] company [dot] com`.
   - Chưa hỗ trợ che số thẻ tín dụng (PAN 16 số) và số Căn cước công dân (12 số).
3. **Log Injection qua Unicode Separators**:
   - Kẻ tấn công gửi ký tự phân cách Unicode `\u2028` (Line Separator) hoặc `\u2029` (Paragraph Separator). Chuỗi JSON vẫn hợp lệ nhưng một số parser log có thể bị tách dòng giả mạo.

---

## 5. Tổng kết bài học và Khuyến nghị bảo mật (Summary & Best Practices)

1. **Input Validation**: Luôn ưu tiên phương pháp **Whitelist** thay vì Blacklist. Chống SQL Injection bắt buộc dùng **Prepared Statements**, không dựa vào regex lọc từ khóa.
2. **Git Security**: Triển khai kiến trúc bảo mật nhiều lớp (**Defense-in-depth**) kết hợp Client-Side Hook, Server-Side Pre-receive Hook và CI/CD Secret Scanning.
3. **Secure Logging**: Nâng cấp cơ chế đối soát log sang **HMAC-SHA256** hoặc ký số bất đối xứng, định kỳ đẩy log về kho lưu trữ bất biến (WORM Storage / AWS S3 Object Lock) và SIEM tập trung.
