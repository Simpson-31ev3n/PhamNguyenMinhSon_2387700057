import unittest
import os
import json
from securelogger.logger import mask_pii, hash_line, append_signature, SIGNATURE_FILE, LOG_FILE
from app import app

class TestSecureLogger(unittest.TestCase):
    def test_mask_pii_email(self):
        sample = "User email is test.user@example.com in system"
        masked = mask_pii(sample)
        self.assertNotIn("test.user@example.com", masked)
        self.assertIn("<email_masked>", masked)

    def test_mask_pii_password(self):
        sample = "credentials: password='secret12345' found"
        masked = mask_pii(sample)
        self.assertNotIn("secret12345", masked)
        self.assertIn("<token_masked>", masked)

    def test_hash_sha256(self):
        line = '{"message": "test"}'
        h1 = hash_line(line)
        self.assertEqual(len(h1), 64) # SHA256 hex length is 64

    def test_api_validate(self):
        client = app.test_client()
        payload = {
            "email": "nhatlam@example.com",
            "url": "https://secure.com",
            "filename": "report.pdf",
            "sql": "' OR 1=1 --",
            "html": "<script>alert(1)</script>"
        }
        response = client.post("/validate", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data["email"])
        self.assertTrue(data["url"])
        self.assertTrue(data["filename"])
        self.assertEqual(data["sql"], "1=1")
        self.assertEqual(data["html"], "&lt;script&gt;alert(1)&lt;/script&gt;")

        # Verify secure.log has been written with masked data
        self.assertTrue(os.path.exists(LOG_FILE))
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
            last_line = lines[-1]
            log_data = json.loads(last_line)
            self.assertIn("<email_masked>", str(log_data.get("data", "")))

if __name__ == "__main__":
    unittest.main()
