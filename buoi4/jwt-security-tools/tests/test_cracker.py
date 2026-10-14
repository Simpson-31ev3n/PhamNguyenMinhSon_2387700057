import os
import jwt
import tempfile
from jwt_cracker.cracker import JWTCracker

def test_crack_token():
    secret = os.getenv("SECRET_KEY", "supersecret")
    token = jwt.encode({"sub": "test"}, secret, algorithm="HS256")

    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as f:
        f.write("wrongpass\n123456\nsupersecret\n")
        f.seek(0)
        cracker = JWTCracker(token, f.name)
        found = cracker.crack()

    assert found == "supersecret"
