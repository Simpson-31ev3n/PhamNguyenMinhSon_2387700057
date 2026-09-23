# Lab 1: Kiểm tra và làm sạch dữ liệu đầu vào (Input Validation & Sanitization)

- Môn học: Lập trình an toàn / Bảo mật ứng dụng
- Sinh viên: Phạm Nguyễn Minh Sơn
- Thư mục: `buoi1/lab1/`

---

## 1. Cơ chế bảo mật (Security Mechanisms)

Module `securevalidator/core.py` áp dụng các nguyên tắc phòng thủ theo chiều sâu (Defense-in-Depth) nhằm ngăn chặn các lỗ hổng OWASP Top 10 phổ biến:

| Hàm xử lý | Cơ chế bảo mật | Ngăn chặn lỗ hổng |
|---|---|---|
| `validate_email(email)` | Kiểm tra cấu trúc email theo regex `^[\w\.-]+@[\w\.-]+\.\w+$` và chặn chuỗi chứa hai dấu chấm liên tiếp (`..`). | Input Manipulation, Malformed Data |
| `validate_url(url)` | Sử dụng `urllib.parse.urlparse` kiểm tra protocol chỉ thuộc whitelist (`http`, `https`) và bắt buộc phải có `netloc` (domain/host). | Server-Side Request Forgery (SSRF cơ bản), Protocol Smuggling (`file://`, `gopher://`) |
| `validate_filename(filename)` | Kiểm tra từ chối chứa `..`, `/`, `\` và đối soát `os.path.basename(filename) == filename`. | Directory Traversal / Path Traversal (Arbitrary File Read/Write) |
| `sanitize_sql_input(input_str)` | Loại bỏ các ký tự đặc biệt (`'`, `"`, `;`, `--`, `#`) và dùng regex `\b(KEYWORD)\b` loại bỏ các từ khóa truy vấn SQL nguy hiểm (`SELECT`, `INSERT`, `UPDATE`, `DELETE`, `DROP`, `OR`, `AND`, `UNION`, `WHERE`). | SQL Injection (SQLi) |
| `sanitize_html_input(html_str)` | Sử dụng hàm chuẩn `html.escape` chuyển các ký tự `<`, `>`, `&`, `"` thành HTML entities tương ứng (`&lt;`, `&gt;`, `&amp;`, `&quot;`). | Stored & Reflected Cross-Site Scripting (XSS) |

---

## 2. Bảng bộ Test Cases (Unit Tests & Functional Tests)

File kiểm thử [`tests/test_validators.py`](file:///e:/web%20r%C3%A1c/security-labs-main/buoi1/lab1/tests/test_validators.py) chứa 10 unit test cases bao quát cả kịch bản bình thường lẫn tấn công:

| STT | Hàm kiểm tra | Dữ liệu đầu vào (Input) | Kết quả kỳ vọng | Ý nghĩa kiểm thử |
|---|---|---|---|---|
| 1 | `validate_email` | `user@example.com` | `True` | Email chuẩn RFC hợp lệ |
| 2 | `validate_email` | `user@@example..com` | `False` | Chặn email chứa ký tự lỗi và `..` |
| 3 | `validate_url` | `https://example.com` | `True` | URL giao thức HTTPS hợp lệ |
| 4 | `validate_url` | `ftp://example.com` | `False` | Chặn giao thức không nằm trong whitelist (`http`/`https`) |
| 5 | `validate_filename` | `report.pdf` | `True` | Tên file an toàn không có đường dẫn |
| 6 | `validate_filename` | `../../etc/passwd` | `False` | Chặn tấn công Path Traversal đọc file hệ thống |
| 7 | `sanitize_sql_input` | `' OR 1=1 --` | `1=1` | Lọc bỏ dấu nháy đơn, từ khóa `OR`, và dấu comment `--` |
| 8 | `sanitize_sql_input` | `hello world` | `hello world` | Giữ nguyên dữ liệu văn bản bình thường |
| 9 | `sanitize_html_input` | `<script>alert("XSS")</script>` | `&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;` | Mã hóa các thẻ tag và nháy kép chống XSS |
| 10 | `sanitize_html_input` | `Hello World` | `Hello World` | Giữ nguyên văn bản an toàn |

---

## 3. Phân tích kịch bản & Kỹ thuật Bypass

Mặc dù các hàm đã giải quyết được các vector tấn công cơ bản, việc dựa trên **Blacklist** và **Regex đơn giản** bộc lộ nhiều điểm yếu có thể bị kẻ tấn công vượt qua:

### 3.1. Bypass `validate_email`
- **Tấn công**:
  - `admin@127.0.0.1`: Vẫn trả về `True` vì `\w` bao gồm cả số. Nếu hệ thống dùng email này để gửi webhook hoặc request nội bộ, có thể kích hoạt **SSRF**.
  - `test@b.co`, `_@_._`: Cấu trúc vô nghĩa hoặc domain không hề tồn tại nhưng vẫn pass regex.
- **Khắc phục**: Sử dụng thư viện `email-validator` kiểm tra cú pháp chuẩn RFC 5322 kết hợp tra cứu bản ghi DNS MX record.

### 3.2. Bypass `validate_url` (SSRF nâng cao)
- **Tấn công**:
  - `http://127.0.0.1:8080` hoặc `http://localhost`: `parsed.scheme == 'http'` và có `netloc` nên hàm trả về `True`! Ứng dụng gọi URL này sẽ bị tấn công vào các service nội bộ.
  - `http://169.254.169.254/latest/meta-data/`: Khai thác AWS Instance Metadata Service đánh cắp IAM credentials.
  - Sử dụng địa chỉ dạng số nguyên (Decimal IP): `http://2130706433` (tương đương `127.0.0.1`).
  - DNS Rebinding: Domain công khai trỏ về IP Private `192.168.x.x` hoặc `10.x.x.x`.
- **Khắc phục**: Phải phân giải IP của domain (DNS resolution) và kiểm tra IP đó không thuộc dải Private/Loopback (`ipaddress.ip_address(ip).is_private`).

### 3.3. Bypass `validate_filename` (Path Traversal nâng cao)
- **Tấn công**:
  - Trên Windows: Đường dẫn tuyệt đối như `C:\Windows\System32\drivers\etc\hosts` không chứa `/` hay `\..`, nhưng `os.path.basename` trên Linux runner có thể xử lý khác Windows.
  - Windows Alternate Data Streams (ADS): `file.txt::$DATA` có thể làm rối loạn việc kiểm tra đuôi mở rộng.
  - URL Encoding / Double Encoding: `%2e%2e%2f` nếu ứng dụng giải mã URL sau khi validate.
- **Khắc phục**: Dùng `werkzeug.utils.secure_filename` kết hợp chuẩn hóa đường dẫn với `os.path.abspath()` và kiểm tra đường dẫn nằm trọn trong thư mục cho phép (Safe Base Directory).

### 3.4. Bypass `sanitize_sql_input` (Lỗ hổng nghiêm trọng của Blacklist Regex)
- **Tấn công**:
  - **Kỹ thuật lồng từ khóa (Nested Keywords)**: Kẻ tấn công gửi `SELSELECTECT` hoặc `UNUNIONION`. Khi regex xóa từ `SELECT` ở giữa, các ký tự còn lại gộp thành `SELECT` hợp lệ!
  - **Inline Comments**: Dùng `UN/**/ION` hoặc `SE/**/LECT` để chia tách từ khóa mà SQL engine vẫn hiểu.
  - **Tấn công không dùng từ khóa bị cấm**: Khai thác Boolean Blind: `admin' AND 1=1` (nếu không dùng khoảng trắng chuẩn hoặc dùng hàm như `CHAR(65)`).
- **Khắc phục chuẩn công nghiệp**: **TUYỆT ĐỐI KHÔNG** dùng Regex Blacklist để chống SQL Injection. Bắt buộc phải sử dụng **Prepared Statements / Parameterized Queries** (như trong `sqlite3`, `psycopg2`, hoặc ORM như SQLAlchemy).

### 3.5. Bypass `sanitize_html_input` (Context-Based XSS)
- **Tấn công**:
  - `html.escape` chỉ an toàn khi đưa dữ liệu vào giữa cặp thẻ HTML (HTML Body Context: `<div>{{ data }}</div>`).
  - **Attribute Context**: Nếu dữ liệu được đưa vào thuộc tính href: `<a href="{{ data }}">Click</a>`, kẻ tấn công nhập `javascript:alert(1)` — chuỗi này **hoàn toàn không chứa ký tự `<`, `>`, `"` hay `&`** nên không bị escape, nhưng trình duyệt vẫn thực thi mã độc khi người dùng click!
- **Khắc phục**: Sử dụng các thư viện lọc HTML chuyên dụng theo Whitelist như `bleach` hoặc validate cấu trúc URL trước khi nhúng vào thuộc tính.

---

## 4. Hướng dẫn chạy thử và kiểm chứng

```bash
# Di chuyển vào thư mục lab1
cd buoi1/lab1

# Chạy unit tests
python -m unittest discover tests

# Cài đặt thư viện và chạy ứng dụng web Flask
pip install -r requirements.txt
python app.py
```
Truy cập giao diện tại: `http://127.0.0.1:5000/` để thử nghiệm trực tiếp các payload.
