import logging, logging.handlers, gzip, json, os, re, hashlib
from datetime import datetime

LOG_FILE = "secure.log"
SIGNATURE_FILE = "secure.log.sig"
MAX_LOG_SIZE = 1024 * 1024
BACKUP_COUNT = 2

PII_PATTERNS = {
    "email": r'[\w\.-]+@[\w\.-]+\.\w+',
    "token": r'(?i)(token|apikey|key|password)\s*[:=]\s*[\"\']?[\w\-]{8,}[\"\']?'
}

def mask_pii(text: str) -> str:
    """Tự động phát hiện và che giấu thông tin định danh PII."""
    for label, pattern in PII_PATTERNS.items():
        text = re.sub(pattern, f"<{label}_masked>", text, flags=re.IGNORECASE)
    return text

def hash_line(line: str) -> str:
    """Tính mã băm SHA-256 cho dòng nhật ký."""
    return hashlib.sha256(line.encode("utf-8")).hexdigest()

def append_signature(line: str):
    """Ghi mã băm SHA-256 vào file signature để chống giả mạo (Tamper Detection)."""
    with open(SIGNATURE_FILE, "a", encoding="utf-8") as f:
        f.write(hash_line(line) + "\n")

class JSONFormatter(logging.Formatter):
    """Formatter chuyển đổi log sang định dạng JSON có che giấu PII."""
    def format(self, record):
        message = mask_pii(record.getMessage())
        record_dict = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "message": message,
        }
        if hasattr(record, "data"):
            record_dict["data"] = mask_pii(str(record.data))
        if hasattr(record, "results"):
            record_dict["results"] = mask_pii(str(record.results))
        json_line = json.dumps(record_dict, ensure_ascii=False)
        return json_line

class GZipRotator:
    """Bộ nén gzip khi luân phiên file nhật ký (Log Rotation)."""
    def __call__(self, source, dest):
        with open(source, 'rb') as f_in, gzip.open(dest + ".gz", 'wb') as f_out:
            f_out.writelines(f_in)
        os.remove(source)

class SecureRotatingFileHandler(logging.handlers.RotatingFileHandler):
    """File Handler hỗ trợ luân phiên log kèm chữ ký SHA-256."""
    def emit(self, record):
        try:
            msg = self.format(record)
            super().emit(record)
            append_signature(msg)
        except Exception:
            self.handleError(record)

def get_secure_logger():
    """Khởi tạo và trả về Secure Logger cấu hình chuẩn."""
    logger = logging.getLogger("secure_logger")
    logger.setLevel(logging.DEBUG)
    if not logger.handlers:
        handler = SecureRotatingFileHandler(
            LOG_FILE, maxBytes=MAX_LOG_SIZE, backupCount=BACKUP_COUNT, encoding="utf-8"
        )
        handler.setFormatter(JSONFormatter())
        handler.rotator = GZipRotator()
        logger.addHandler(handler)
        logger.propagate = False
    return logger

secure_logger = get_secure_logger()
