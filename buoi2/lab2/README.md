# 🔒 Mini CA - Certificate Authority

> **Bài 2.4: Thực hành Certificate Authority** — Xây dựng hệ thống CA đơn giản

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## 📋 Mô tả

**Mini CA** là hệ thống Certificate Authority đơn giản được xây dựng bằng Python, mô phỏng quy trình PKI thực tế:

| Chức năng | Mô tả |
|-----------|--------|
| `create_root_ca()` | Tạo chứng chỉ Root CA (tự ký, hiệu lực 10 năm) |
| `create_intermediate_ca(root_key, root_cert)` | Tạo CA trung gian (hiệu lực 5 năm) |
| `issue_certificate(ca_key, ca_cert, subject_info)` | Phát hành chứng chỉ end-entity (hiệu lực 1 năm) |
| `verify_certificate_chain(cert, ca_chain)` | Xác thực chuỗi chứng chỉ |
| `revoke_certificate(cert_file, issuer_cert, issuer_key, reason)` | Thu hồi chứng chỉ |
| `check_revocation_status(cert_file)` | Kiểm tra trạng thái OCSP/CRL |

---

## 📁 Cấu trúc thư mục

```
lab2/
├── ca_utils.py          # Tạo Root CA, Intermediate CA, phát hành cert, verify chain
├── revoke_utils.py      # Thu hồi chứng chỉ, tạo CRL, kiểm tra trạng thái
├── demo.py              # Demo CLI - chạy toàn bộ flow PKI
├── demo_ui.py           # Giao diện Tkinter GUI
├── requirements.txt     # Dependencies
├── .gitignore
├── README.md
└── report lab2.md       # Báo cáo thực hành chi tiết
```

**Sau khi chạy**, folder `certs/` sẽ được tạo tự động chứa:

```
certs/
├── root_ca_key.pem           # Khóa riêng Root CA
├── root_ca_cert.pem          # Chứng chỉ Root CA
├── intermediate_key.pem      # Khóa riêng Intermediate CA
├── intermediate_cert.pem     # Chứng chỉ Intermediate CA
├── Simpson_key.pem           # Khóa riêng User (Simpson)
├── Simpson_cert.pem          # Chứng chỉ User (Simpson)
└── ca_crl.pem                # Danh sách thu hồi (CRL)
```

---

## 🚀 Cài đặt dependencies

```bash
pip install -r requirements.txt
```

---

## 🧪 Chạy Demo CLI

```bash
python demo.py
```

**Kết quả mong đợi:**

```
Tạo Root CA...
Root CA: <RSAPrivateKey...>, <Certificate(subject=<Name(CN=Mini Root CA Root...)>)>
Tạo Intermediate CA...
Intermediate CA: <RSAPrivateKey...>, <Certificate(subject=<Name(CN=Mini Intermediate CA...)>)>
Phát hành chứng chỉ người dùng cuối...
Đã phát hành: certs\Simpson_cert.pem, certs\Simpson_key.pem
Kiểm tra chuỗi chứng chỉ...
Chuỗi hợp lệ: True
Thu hồi chứng chỉ Simpson...
Đã thu hồi
Kiểm tra trạng thái OCSP của Simpson_cert.pem...
Trạng thái: Revoked
```

---

## 🖥️ Chạy GUI (Tkinter)

```bash
python demo_ui.py
```

Giao diện gồm 5 nút thao tác tuần tự:

| Nút | Chức năng |
|-----|-----------|
| **1. Tạo Root & Intermediate CA** | Sinh cặp khóa RSA và chứng chỉ cho Root CA + Intermediate CA |
| **2. Phát hành User Cert** | Phát hành chứng chỉ cho người dùng cuối (Simpson) |
| **3. Kiểm tra Chuỗi Cert** | Xác thực chuỗi: User → Intermediate → Root |
| **4. Thu hồi User Cert** | Thu hồi chứng chỉ user và cập nhật CRL |
| **5. Kiểm tra Trạng thái OCSP** | Kiểm tra chứng chỉ có bị thu hồi hay không |

---

## 🔑 Giải thích các hàm

### ca_utils.py

| Hàm | Mô tả |
|-----|--------|
| `generate_key()` | Sinh cặp khóa RSA 2048 bit |
| `save_key(key, filename)` | Lưu khóa riêng dạng PEM (không mã hóa) |
| `save_cert(cert, filename)` | Lưu chứng chỉ X.509 dạng PEM |
| `load_key(filename)` | Đọc khóa riêng từ file PEM |
| `load_cert(filepath)` | Đọc chứng chỉ X.509 từ file PEM |
| `create_root_ca()` | Tạo Root CA tự ký, `BasicConstraints(ca=True, path_length=1)`, hiệu lực 10 năm |
| `create_intermediate_ca()` | Tạo Intermediate CA, `BasicConstraints(ca=True, path_length=0)`, hiệu lực 5 năm |
| `issue_certificate()` | Phát hành end-entity cert, `BasicConstraints(ca=False)`, hiệu lực 1 năm |
| `verify_certificate_chain()` | Xác thực chuỗi chứng chỉ bằng chữ ký số PKCS1v15 |

### revoke_utils.py

| Hàm | Mô tả |
|-----|--------|
| `create_empty_crl()` | Tạo CRL rỗng, hiệu lực 7 ngày |
| `revoke_certificate()` | Thu hồi chứng chỉ, thêm vào CRL và ký lại bằng khóa CA |
| `check_revocation_status()` | Kiểm tra serial number trong CRL, trả về `True` nếu đã thu hồi |

---

## 🛠️ Công nghệ sử dụng

- **Python 3.10+**
- **cryptography** — X.509, RSA, CRL, PKCS1v15
- **Tkinter** — GUI