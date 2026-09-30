# Báo cáo thực hành Buổi 2: Mã hoá dữ liệu và triển khai PKI

- **Sinh viên:** Phạm Nguyễn Minh Sơn
- **MSSV:** 2387700057
- **Lớp:** 23DATA1
- **Môn học:** Thực hành Lập trình An ninh thông tin

---

## 📁 1. Cấu trúc thư mục Buổi 2

```text
buoi2/
├── README.md               # Báo cáo tổng hợp toàn bộ Buổi 2
├── pics/                   # Ảnh tài liệu giáo trình thực hành
├── lab1/                   # Lab 1: Bộ công cụ mã hoá dữ liệu (Crypto Toolkit)
│   ├── README.md           # Hướng dẫn chi tiết & tài liệu kỹ thuật Lab 1
│   ├── report lab1.md      # Báo cáo kết quả kiểm thử thực tế Lab 1
│   ├── setup.py            # Cấu hình cài đặt package 'securecrypto'
│   ├── requirements.txt    # Danh sách thư viện (cryptography, argon2-cffi, flask, pytest)
│   ├── files/              # Dữ liệu thử nghiệm (data.txt)
│   ├── securecrypto/       # Mã nguồn chính của thư viện
│   │   ├── __init__.py
│   │   ├── aes_utils.py    # Mã hóa/giải mã đối xứng AES-256-GCM + PBKDF2
│   │   ├── hash_utils.py   # Băm mật khẩu an toàn với Argon2id
│   │   ├── rsa_utils.py    # Sinh khóa RSA-2048 & Ký số/Xác thực PKCS1v15
│   │   ├── cli.py          # Giao diện dòng lệnh CLI (securecrypto-cli)
│   │   ├── api.py          # RESTful API Backend với Flask
│   │   └── app_gui.py      # Giao diện đồ họa Tkinter GUI
│   └── tests/              # Bộ Unit Test tự động (Pytest)
│       ├── test_aes_utils.py
│       ├── test_hash_utils.py
│       └── test_rsa_utils.py
└── lab2/                   # Lab 2: Hệ thống chứng thực số (Mini CA / PKI)
    ├── README.md           # Hướng dẫn chi tiết & tài liệu kỹ thuật Lab 2
    ├── report lab2.md      # Báo cáo kết quả kiểm thử thực tế Lab 2
    ├── requirements.txt    # Thư viện cryptography
    ├── .gitignore          # Chặn commit certs và khóa riêng (*.pem)
    ├── ca_utils.py         # Root CA, Intermediate CA, phát hành cert, verify chain
    ├── revoke_utils.py     # Thu hồi chứng chỉ, phát hành CRL, kiểm tra OCSP
    ├── demo.py             # Script demo CLI chạy toàn bộ vòng đời PKI
    └── demo_ui.py          # Giao diện đồ họa Tkinter 5 nút chức năng
```

---

## 🔐 2. Tóm tắt nội dung Lab 1: Bộ công cụ mã hoá dữ liệu (`lab1`)

*Chi tiết báo cáo và testcase: [buoi2/lab1/report lab1.md](./lab1/report%20lab1.md)*

### 2.1. Các kỹ thuật mật mã áp dụng:
1. **Mã hóa đối xứng AES-256-GCM (`aes_utils.py`):**
   - Kết hợp hàm dẫn xuất khóa **PBKDF2HMAC** (SHA-256, 100.000 vòng lặp, 16 bytes salt ngẫu nhiên) để sinh khóa AES 256-bit từ mật khẩu người dùng.
   - Sử dụng chế độ **GCM (Galois/Counter Mode)** đảm bảo vừa bảo mật (Confidentiality) vừa toàn vẹn dữ liệu (Integrity / Authenticity).
   - Tối ưu hàm giải mã hỗ trợ cả **Mật khẩu thuần** lẫn **Key Base64** theo ghi chú debug giáo trình.
2. **Băm mật khẩu an toàn với Argon2id (`hash_utils.py`):**
   - Sử dụng thuật toán **Argon2id** (thuật toán đoạt giải Password Hashing Competition), cấu hình bộ nhớ và độ phức tạp cao, chống tấn công brute-force bằng GPU/ASIC.
3. **Mã hóa bất đối xứng & Chữ ký số RSA-2048 (`rsa_utils.py`):**
   - Sinh cặp khóa RSA 2048-bit (`e=65537`).
   - Ký số và xác thực chữ ký số bằng thuật toán **PKCS1v15 + SHA-256**, chống giả mạo và chống chối bỏ.
4. **Đa dạng giao diện sử dụng:**
   - **CLI Tool:** Cung cấp lệnh mã hóa/giải mã file qua dòng lệnh.
   - **Tkinter GUI:** Giao diện đồ họa đơn giản, thân thiện, có hộp thoại thông báo.
   - **REST API Flask:** Endpoint `/encrypt` và `/decrypt` hỗ trợ tải lên file qua `multipart/form-data`.

### 2.2. Kết quả kiểm thử tự động (Unit Tests):
- Chạy `pytest tests/ -v` đạt **6/6 test cases PASSED** (100%).

---

## 🏛️ 3. Tóm tắt nội dung Lab 2: Hệ thống Mini CA / PKI (`lab2`)

*Chi tiết báo cáo và testcase: [buoi2/lab2/report lab2.md](./lab2/report%20lab2.md)*

### 3.1. Các thành phần trong hạ tầng PKI:
1. **Root CA (`create_root_ca`):**
   - Tự ký (Self-signed), khóa RSA 2048-bit, thời hạn 10 năm.
   - Extension: `BasicConstraints(ca=True, path_length=1)`.
2. **Intermediate CA (`create_intermediate_ca`):**
   - Được ký bởi Root CA, thời hạn 5 năm.
   - Extension: `BasicConstraints(ca=True, path_length=0)` (không thể cấp quyền CA tiếp theo).
3. **End-Entity Certificate (`issue_certificate`):**
   - Được cấp cho sinh viên `Simpson` (Simpson Company), thời hạn 1 năm.
   - Extension: `BasicConstraints(ca=False)`.
4. **Xác thực chuỗi chứng chỉ (`verify_certificate_chain`):**
   - Kiểm tra chữ ký số lần lượt: `Simpson -> Intermediate CA -> Root CA`.
5. **Cơ chế thu hồi chứng chỉ (`revoke_certificate` & `check_revocation_status`):**
   - Phát hành danh sách thu hồi **CRL (Certificate Revocation List)** có chữ ký của Intermediate CA với lý do `key_compromise`.
   - Kiểm tra trạng thái thu hồi qua CRL/OCSP check.
6. **Giao diện người dùng:**
   - Script tự động `demo.py` xử lý toàn bộ luồng.
   - Giao diện `demo_ui.py` gồm 5 nút bấm tuần tự trực quan.
7. **Bảo mật GitSecure:**
   - Cấu hình `.gitignore` chặn lưu trữ khóa riêng và chứng chỉ (`certs/`, `*.pem`), đảm bảo không lộ lọt bí mật lên Git.
