
import pyotp, secrets, base64, hashlib
from cryptography.fernet import Fernet
from ..config import settings
import os

def generate_secret():
    # REQ-12 160 bits = 20 bytes
    return secrets.token_bytes(20)

def encrypt_secret(secret_bytes: bytes) -> str:
    key = base64.urlsafe_b64encode(hashlib.sha256(settings.TOTP_ENCRYPTION_KEY.encode()).digest())
    f = Fernet(key)
    return f.encrypt(secret_bytes).decode()

def decrypt_secret(enc: str) -> bytes:
    key = base64.urlsafe_b64encode(hashlib.sha256(settings.TOTP_ENCRYPTION_KEY.encode()).digest())
    f = Fernet(key)
    return f.decrypt(enc.encode())

def get_totp_uri(secret_bytes, email):
    b32 = base64.b32encode(secret_bytes).decode()
    totp = pyotp.TOTP(b32)
    return totp.provisioning_uri(name=email, issuer_name=settings.RP_NAME)

def verify_totp(secret_bytes, code):
    b32 = base64.b32encode(secret_bytes).decode()
    totp = pyotp.TOTP(b32)
    # REQ-11 janela 30s tolerancia +-1
    return totp.verify(code, valid_window=1)

def hash_backup_code(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()
