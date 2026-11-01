
import os
from dotenv import load_dotenv
load_dotenv()

REQUIRED_VARS = [
    "DATABASE_URL",
    "JWT_PRIVATE_KEY_PATH",
    "JWT_PUBLIC_KEY_PATH",
    "JWT_ISSUER",
    "MASTER_KEY",
    "TOTP_ENCRYPTION_KEY",
    "CORS_ALLOWED_ORIGINS",
    "RP_ID",
    "RP_NAME",
]

class Settings:
    def __init__(self):
        missing = [v for v in REQUIRED_VARS if not os.getenv(v)]
        if missing:
            raise RuntimeError(f"RNF-08: Variáveis ausentes: {', '.join(missing)}. App recusa subir.")
        self.DATABASE_URL = os.getenv("DATABASE_URL")
        self.JWT_PRIVATE_KEY_PATH = os.getenv("JWT_PRIVATE_KEY_PATH")
        self.JWT_PUBLIC_KEY_PATH = os.getenv("JWT_PUBLIC_KEY_PATH")
        self.JWT_ISSUER = os.getenv("JWT_ISSUER")
        self.MASTER_KEY = os.getenv("MASTER_KEY")
        self.TOTP_ENCRYPTION_KEY = os.getenv("TOTP_ENCRYPTION_KEY")
        self.CORS_ALLOWED_ORIGINS = [o.strip() for o in os.getenv("CORS_ALLOWED_ORIGINS").split(",")]
        self.RP_ID = os.getenv("RP_ID")
        self.RP_NAME = os.getenv("RP_NAME", "Assinatura PDF")
        self.ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
        self.REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))
        self.MAX_LOGIN_ATTEMPTS = int(os.getenv("MAX_LOGIN_ATTEMPTS", "5"))
        self.LOCKOUT_MINUTES = int(os.getenv("LOCKOUT_MINUTES", "15"))
        self.RATE_LIMIT_LOGIN_PER_MIN = int(os.getenv("RATE_LIMIT_LOGIN_PER_MIN", "10"))
        self.RATE_LIMIT_VERIFY_PER_MIN = int(os.getenv("RATE_LIMIT_VERIFY_PER_MIN", "20"))

settings = Settings()
