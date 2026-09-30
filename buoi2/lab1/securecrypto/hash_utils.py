from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

ph = PasswordHasher()


def hash_password_secure(password):
    return ph.hash(password)


def verify_password_secure(hash_val, password):
    try:
        ph.verify(hash_val, password)
        return True
    except VerifyMismatchError:
        return False
    except Exception:
        return False
