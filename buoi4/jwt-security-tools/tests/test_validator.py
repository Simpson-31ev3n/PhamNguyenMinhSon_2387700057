import os
import jwt
import datetime
from jwt_validator.validator import JWTValidator

def generate_token(secret):
    payload = {
        "sub": "test",
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
    }
    return jwt.encode(payload, secret, algorithm="HS256")

def test_valid_token():
    secret = os.getenv("SECRET_KEY", "secret123")
    token = generate_token(secret)
    validator = JWTValidator(secret)
    result = validator.validate(token)
    assert result["valid"] is True
    assert result["payload"]["sub"] == "test"

def test_invalid_signature():
    token = generate_token("wrongsecret")
    validator = JWTValidator("correctsecret")
    result = validator.validate(token)
    assert result["valid"] is False
