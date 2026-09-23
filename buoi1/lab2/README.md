# Lab 2: Cấu hình Git Security Pre-commit Hook (GitSecure)

- Môn học: Lập trình an toàn / Bảo mật ứng dụng
- Sinh viên: Phạm Nguyễn Minh Sơn
- Thư mục: `buoi1/lab2/`

---

## 1. Cơ chế bảo mật (Security Mechanisms)

Hệ thống **GitSecure** hoạt động dưới dạng **Client-Side Pre-commit Hook** của Git, thực thi tự động ngay khi lập trình viên gõ lệnh `git commit` nhằm ngăn chặn các vi phạm an toàn mã nguồn từ giai đoạn sớm nhất (Shift-Left Security):

| Thành phần kiểm tra | Cơ chế thực hiện | Mục đích & Phòng chống lỗ hổng |
|---|---|---|
| **Quét Secret / Credentials** | Kiểm tra danh sách staged files (`git diff --cached --name-only`) với bộ Regex `SENSITIVE_PATTERNS`. | Ngăn chặn đẩy lộ API Keys, Passwords, Tokens, AWS Access Keys (`AKIA/ASIA`) lên GitHub/GitLab. |
| **Kiểm tra tuân thủ bản quyền (License Compliance)** | Hàm `check_license` quét mã nguồn và `requirements.txt` tìm các mẫu giấy phép hạn chế (`GPL`, `AGPL`, `SSPL`). | Tránh vi phạm quyền tác giả hoặc rủi ro pháp lý buộc mở toàn bộ mã nguồn do giấy phép Copyleft lây lan. |
| **Kiểm tra phân quyền tệp (File Permissions)** | Sử dụng `os.stat` kiểm tra cờ bit `stat.S_IWOTH` (chỉ trên Unix/Linux, tự động bỏ qua an toàn trên Windows). | Chặn việc cấp quyền ghi cho toàn bộ người dùng (`world-writable` / `chmod 777`) gây nguy cơ Leo thang đặc quyền (Privilege Escalation). |
| **Phân tích tĩnh SAST (Bandit)** | Chạy công cụ `bandit -r .` quét lỗ hổng mã Python mức High severity. | Phát hiện sớm các lỗi nghiêm trọng như `eval()`, `exec()`, hardcoded bind all interfaces `0.0.0.0`, v.v. |
| **Ghi nhận sự cố & Chặn commit** | Nếu phát hiện bất kỳ vi phạm nào, in cảnh báo, ghi log vào `gitsecure.log` và gọi `sys.exit(1)`. | Dừng quy trình commit ngay lập tức, bắt buộc lập trình viên phải xử lý trước khi lưu vào Git history. |
| **Bộ lọc thông minh (Smart Filtering)** | Tự động bỏ qua tài liệu `.md` và thư mục `/tests/` để loại trừ các chuỗi giả lập kiểm thử. | Giảm thiểu tối đa tình trạng báo động giả (False Positives) làm gián đoạn luồng làm việc. |

---

## 2. Bảng bộ Test Cases (Verification & Test Scenarios)

| STT | Kịch bản kiểm thử | File / Dữ liệu thử nghiệm | Kết quả mong đợi | Trạng thái thực tế |
|---|---|---|---|:---:|
| 1 | File chứa mật khẩu cài cứng | `buoi1/lab2/pre-commit-hook-test/bad.py` (`password = "super_secret_password_12345"`) | Bị chặn (`COMMIT BLOCKED: pattern (password)...`) | ✅ PASS |
| 2 | File chứa API Key lộ | `apikey = "abcdef1234567890"` | Bị chặn (`pattern (apikey)...`) | ✅ PASS |
| 3 | File chứa AWS Access Key | `AKIAIOSFODNN7EXAMPLE` | Bị chặn (`pattern (AKIA|ASIA)...`) | ✅ PASS |
| 4 | File chứa giấy phép hạn chế | `license_test.py` (`# Licensed under GPL-3.0`) | Bị chặn (`License compliance issue: Found restricted license pattern...`) | ✅ PASS |
| 5 | File phân quyền quá rộng (Linux) | `chmod 777 exploit.py` | Bị chặn (`File exploit.py is world-writable!`) | ✅ PASS |
| 6 | File mã nguồn chuẩn an toàn | Code trong `lab1/` và `lab3/` không chứa secret | Cho phép commit (`GitSecure: All checks passed.`) | ✅ PASS |
| 7 | Tệp nhật ký phát sinh | Kiểm tra `gitsecure.log` sau khi bị chặn | Log được ghi nhận và bị `.gitignore` ẩn khỏi Git | ✅ PASS |

---

## 3. Phân tích kịch bản & Kỹ thuật Bypass Git Hook

Mặc dù Pre-commit Hook là rào chắn đầu tiên rất hữu ích, kẻ tấn công hoặc lập trình viên bất cẩn vẫn có thể dễ dàng vượt qua theo các kỹ thuật sau:

### 3.1. Bypass hoàn toàn hook bằng cờ Git (`--no-verify`)
- **Kỹ thuật**: Git hỗ trợ tham số bỏ qua hook:
  ```bash
  git commit --no-verify -m "force bypass"
  # Hoặc viết tắt:
  git commit -n -m "bypass hook"
  ```
- **Hậu quả**: Toàn bộ script `.githooks/pre-commit` hoàn toàn không được thực thi; secret vẫn bị commit vào Git.

### 3.2. Che giấu chuỗi Secret (String Obfuscation / Splitting)
- **Kỹ thuật**: Hook sử dụng Regex cố định để bắt tên biến và giá trị. Kẻ tấn công hoặc lập trình viên có thể biến tấu:
  ```python
  # Chia nhỏ chuỗi nối lại
  p1 = "pass"
  p2 = "word"
  secret_map = {p1 + p2: "super_secret_12345"}

  # Mã hóa Base64
  import base64
  api_token = base64.b64decode("c3VwZXJfc2VjcmV0X3Rva2VuXzEyMzQ1").decode()

  # Đảo chuỗi
  db_pass = "54321_terces_repus"[::-1]
  ```
- **Hậu quả**: Regex tĩnh không thể phát hiện chuỗi động trong thời gian chạy.

### 3.3. Thay đổi tên định danh biến (Alternative Variable Naming)
- **Kỹ thuật**: Danh sách từ khóa chỉ bắt `password`, `secret`, `apikey`, `token`. Nếu lập trình viên đặt tên biến khác:
  ```python
  auth_cred = "super_secret_credential_12345"
  jwt_signature_str = "eyJhbGciOiJIUzI1NiIsInR5cCI6..."
  connection_uri = "postgres://root:pass12345@db.internal:5432/main"
  ```
- **Hậu quả**: Vượt qua bộ lọc `SENSITIVE_PATTERNS` mà không bị cảnh báo.

### 3.4. Vô hiệu hóa cấu hình hook cục bộ (Client-Side Limitation)
- **Kỹ thuật**: `core.hooksPath` được lưu trữ ở cấu hình máy cục bộ (`.git/config`). Khi người khác clone repository hoặc clone sang môi trường máy mới, nếu không chủ động gõ lệnh:
  ```bash
  git config core.hooksPath buoi1/lab2/.githooks
  ```
  thì Git sẽ không tự kích hoạt hook trong thư mục `.githooks/`.

---

## 4. Giải pháp khắc phục & Phòng thủ theo chiều sâu (Defense-in-Depth)

Để đảm bảo an toàn tuyệt đối cho tổ chức, không được chỉ dựa duy nhất vào Client-Side Hook:

1. **Triển khai Server-Side Hook**: Cấu hình `pre-receive` hook trên GitLab / GitHub Enterprise Server. Khi lập trình viên push code, Server sẽ kiểm tra; nếu phát hiện secret hoặc flag `--no-verify`, server sẽ từ chối nhận code (Remote Rejection).
2. **Tích hợp Secret Scanner trên CI/CD Pipeline**: Chạy các công cụ chuyên dụng như **TruffleHog**, **GitLeaks**, hoặc **GitHub Secret Scanning** tự động quét toàn bộ lịch sử commit và entropy (độ ngẫu nhiên của chuỗi) để phát hiện cả secret bị mã hóa.
3. **Quản trị bí mật tập trung (Secret Management)**: Tuyệt đối không lưu secret trong source code. Sử dụng biến môi trường kết hợp dịch vụ bảo mật: HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, hoặc Doppler.

---

## 5. Hướng dẫn thiết lập và thử nghiệm

```bash
# 1. Kích hoạt hook cho repository
git config core.hooksPath buoi1/lab2/.githooks

# 2. Cài đặt công cụ Bandit (nếu chưa cài)
pip install -r buoi1/lab2/requirements.txt

# 3. Thử nghiệm chặn commit với file bad.py
git add buoi1/lab2/pre-commit-hook-test/bad.py
git commit -m "Test GitSecure Block"
# -> Kết quả: COMMIT BLOCKED by GitSecure

# 4. Kiểm tra file nhật ký ghi nhận vi phạm
cat gitsecure.log
```
