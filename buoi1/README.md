# Báo cáo thực hành Buổi 1: Cơ sở lập trình bảo mật

- Sinh viên: Phạm Nguyễn Minh Sơn
- Môn học: Lập trình an toàn / Bảo mật ứng dụng

---

## 1. Cấu trúc thư mục buổi 1

```text
buoi1/
├── README.md               # Báo cáo tổng hợp buổi 1
├── lab1/                   # Lab 1: Kiểm tra và làm sạch dữ liệu đầu vào
│   ├── app.py              # Ứng dụng Flask
│   ├── requirements.txt    # Danh sách thư viện
│   ├── render.yaml         # Cấu hình deploy Render
│   ├── securevalidator/    # Module xử lý kiểm tra đầu vào
│   │   ├── __init__.py
│   │   └── core.py
│   ├── templates/
│   │   └── index.html      # Giao diện web kiểm tra
│   └── tests/
│       └── test_validators.py
├── lab2/                   # Lab 2: Git Security Hook
│   ├── requirements.txt
│   ├── .githooks/
│   │   └── pre-commit      # Script hook chặn rò rỉ secret
│   └── pre-commit-hook-test/
│       └── bad.py          # File test vi phạm
└── lab3/                   # Lab 3: Hệ thống Secure Logger
    ├── app.py              # API Flask /validate
    ├── requirements.txt
    ├── securevalidator/    # Kế thừa module validator từ Lab 1
    │   ├── __init__.py
    │   └── core.py
    ├── securelogger/       # Module ghi log an toàn
    │   ├── __init__.py
    │   └── logger.py
    └── tests/
        └── test_logger.py
```

---

## 2. Lab 1: Kiểm tra và làm sạch dữ liệu đầu vào (Input Validation & Sanitization)

### 2.1. Mục tiêu
Áp dụng nguyên tắc kiểm tra chặt chẽ dữ liệu đầu vào của người dùng trước khi xử lý, ngăn chặn các lỗi bảo mật phổ biến như SQL Injection, Cross-Site Scripting (XSS), Directory Traversal và SSRF.

### 2.2. Chi tiết thực hiện (`lab1/securevalidator/core.py`)
- **Kiểm tra email (`validate_email`)**: Dùng biểu thức chính quy để kiểm tra đúng cấu trúc email, đồng thời chặn các trường hợp chứa hai dấu chấm liên tiếp (`..`).
- **Kiểm tra URL (`validate_url`)**: Sử dụng thư viện `urllib.parse` để bóc tách URL, chỉ cho phép các giao thức an toàn (`http`, `https`) và bắt buộc phải có tên miền hợp lệ để hạn chế tấn công SSRF cơ bản.
- **Kiểm tra tên file (`validate_filename`)**: Kiểm tra và chặn các ký tự điều hướng thư mục như `..`, `/`, `\` nhằm ngăn chặn tấn công đọc file tùy ý (Path Traversal).
- **Lọc chuỗi SQL (`sanitize_sql_input`)**: Sử dụng Regex để loại bỏ các ký tự bẻ gãy cú pháp SQL (`'`, `"`, `;`, `--`, `#`) và các từ khóa truy vấn nguy hiểm (`SELECT`, `INSERT`, `UPDATE`, `DELETE`, `DROP`, `OR`, `AND`, `UNION`, `WHERE`).
- **Mã hóa HTML (`sanitize_html_input`)**: Dùng `html.escape` để chuyển đổi các ký tự `<`, `>`, `&`, `"` thành mã HTML entities, tránh bị thực thi mã JavaScript độc hại trên trình duyệt (XSS).

### 2.3. Kết quả kiểm thử
- **Unit test**: Chạy lệnh `python -m unittest discover tests`, toàn bộ 10/10 test case đều pass (kiểm tra cả trường hợp dữ liệu đúng và dữ liệu cố ý tấn công).
- **Kiểm tra trên web (`app.py`)**:
  - Email đúng: báo hợp lệ (xanh).
  - URL hợp lệ: báo hợp lệ (xanh).
  - Tên file chứa `../../etc/passwd`: bị từ chối (báo đỏ).
  - Dữ liệu SQL `' OR 1=1 --`: được lọc còn `1=1`.
  - Dữ liệu HTML `<script>alert(1)</script>`: được mã hóa thành `&lt;script&gt;alert(1)&lt;/script&gt;`.

### 2.4. Hạn chế và ví dụ bypass

Hàm `validate_email` chỉ kiểm tra đúng **cấu trúc ký tự** bằng regex (`^[\w\.-]+@[\w\.-]+\.\w+$`), không xác thực domain có tồn tại hay TLD có hợp lệ hay không, nên vẫn có thể bị "vượt qua" bằng các chuỗi không phải email thật:

| Input | Kết quả `validate_email()` | Vấn đề |
|---|---|---|
| `a@b.co` | `True` | Domain 1 ký tự, không tồn tại nhưng vẫn khớp regex |
| `test@127.0.0.1` | `True` | `\w` bao gồm cả chữ số nên địa chỉ IP bị nhận nhầm là domain hợp lệ — nếu giá trị này được dùng tiếp ở chỗ khác (gửi mail, gọi API...) có thể tiềm ẩn rủi ro SSRF |
| `_@_._` | `True` | Underscore và dấu chấm đều nằm trong lớp ký tự cho phép, chuỗi vô nghĩa vẫn "hợp lệ" |
| `admin@localhost.local` | `True` | `.local` không phải TLD thật nhưng regex không phân biệt được |

**Nguyên nhân**: regex chỉ đảm bảo đúng *hình dạng* `local-part@domain.tld`, không kiểm tra domain có đăng ký, có MX record hay TLD có nằm trong danh sách hợp lệ (IANA) hay không.

**Đề xuất khắc phục**: dùng thư viện chuyên dụng như `email-validator` (hỗ trợ kiểm tra cú pháp theo RFC và tuỳ chọn tra cứu DNS/MX record) thay vì chỉ dựa vào regex tự viết.

---

## 3. Lab 2: Cấu hình Git Security Hook

### 3.1. Mục tiêu
Sử dụng tính năng Pre-commit Hook của Git để quét mã nguồn trên máy lập trình viên trước mỗi lần commit, ngăn chặn việc vô tình đẩy mật khẩu, API key hoặc token dịch vụ đám mây lên kho lưu trữ.

### 3.2. Chi tiết thực hiện (`lab2/.githooks/pre-commit`)
- Script được viết bằng Python và cấu hình hook thông qua lệnh:
  ```bash
  git config core.hooksPath buoi1/lab2/.githooks
  ```
- Hook tự động lấy danh sách file đang được `git add` (`git diff --cached --name-only`) và kiểm tra nội dung dựa trên:
  - **Quét thông tin nhạy cảm**:
    - Mẫu API Key: `(apikey)\s*[:=]\s*['"][A-Za-z0-9_-]{16,}['"]`
    - Mẫu Password: `(password)\s*[:=]\s*['"][^'"\s]{4,}['"]`
    - Mẫu Secret: `(secret)\s*[:=]\s*['"][A-Za-z0-9_\-]{8,}['"]`
    - Mẫu Token: `(token)\s*[:=]\s*['"][A-Za-z0-9_\-]{10,}['"]`
    - Mẫu AWS Access Key: `(AKIA|ASIA)[A-Z0-9]{16}`
  - **Kiểm tra tuân thủ giấy phép (License Compliance)**: Tự động phát hiện mã nguồn hoặc dependency chứa các loại giấy phép hạn chế / copyleft (GPL, AGPL, SSPL) có thể vi phạm chính sách bản quyền dự án.
  - **Kiểm tra phân quyền tệp**: Phát hiện tệp bị phân quyền `world-writable` (trên hệ điều hành Unix/Linux), đồng thời tương thích tốt trên môi trường Windows.
  - **Tích hợp Bandit SAST**: Quét phát hiện các lỗi bảo mật mã nguồn mức High.
- Nếu phát hiện vi phạm, hook in thông báo lỗi, ghi log vào `gitsecure.log` và trả về mã thoát `sys.exit(1)` để dừng lệnh commit. Tệp nhật ký `gitsecure.log` và `secure.log` được cấu hình trong `.gitignore` để tránh rò rỉ lên repo.

### 3.3. Kết quả thử nghiệm
- Tạo file `pre-commit-hook-test/bad.py` chứa nội dung:
  ```python
  password = "super_secret_password_12345"
  ```
- Khi chạy lệnh commit:
  ```bash
  git add buoi1/lab2/pre-commit-hook-test/bad.py
  git commit -m "test commit"
  ```
- Kết quả: Git tự động chặn commit và hiển thị thông báo:
  ```text
  COMMIT BLOCKED by GitSecure:
   - Sensitive info found in bad.py: pattern (password)...
  ```

---

## 4. Lab 3: Xây dựng hệ thống Secure Logger

### 4.1. Mục tiêu
Xây dựng module ghi log an toàn cho ứng dụng Flask, giải quyết các vấn đề thường gặp: lộ thông tin cá nhân trong log, tấn công chèn mã giả mạo log (Log Injection) và kiểm tra tính toàn vẹn của tệp nhật ký.

### 4.2. Chi tiết thực hiện (`lab3/securelogger/logger.py`)
- **Che giấu thông tin cá nhân (`mask_pii`)**: Tự động nhận diện địa chỉ email, mật khẩu hoặc token có trong log và thay thế bằng nhãn `<email_masked>`, `<token_masked>`.
- **Định dạng JSON (`JSONFormatter`)**: Ghi log theo định dạng JSON một dòng kèm dấu thời gian chuẩn UTC ISO 8601, giúp chống lỗi ngắt dòng và dễ tích hợp với các hệ thống phân tích log.
- **Xác thực toàn vẹn bằng SHA-256 (`append_signature`)**: Mỗi dòng log khi ghi vào `secure.log` sẽ đồng thời được băm SHA-256 và lưu vào file `secure.log.sig`. Nếu tệp log bị chỉnh sửa thủ công, chuỗi băm sẽ không khớp.
- **Quản lý dung lượng (`GZipRotator`)**: Cấu hình luân phiên log khi đạt kích thước 1MB và tự động nén các file cũ thành dạng `.gz`.

### 4.3. Kết quả kiểm thử
- **Unit test**: Chạy `python -m unittest discover tests` trong thư mục `lab3`, vượt qua 4/4 bài kiểm tra.
- **Kiểm tra API (`POST /validate`)**:
  - Gửi dữ liệu JSON chứa email và payload test.
  - Phản hồi trả về kết quả đã được làm sạch.
  - Tệp `secure.log` ghi lại log với trường email đã được che thành `<email_masked>`.
  - Tệp `secure.log.sig` sinh mã băm SHA-256 đối soát tương ứng.
