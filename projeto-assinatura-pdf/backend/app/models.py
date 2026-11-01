
from sqlalchemy import Column, String, Integer, DateTime, Boolean, Text, LargeBinary, ForeignKey, Index
from sqlalchemy.dialects.postgresql import UUID
from datetime import datetime, timezone
import uuid
from .database import Base

class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String, unique=True, nullable=False)
    name = Column(String, nullable=False)
    password_hash = Column(String, nullable=False)
    failed_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)
    password_changed_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    private_key_encrypted = Column(Text, nullable=False)  # REQ-45
    public_key = Column(Text, nullable=False)
    totp_secret_encrypted = Column(Text, nullable=True)  # REQ-12 criptografado
    totp_enabled = Column(Boolean, default=False)

class PasskeyDevice(Base):
    __tablename__ = "passkey_devices"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    credential_id = Column(Text, nullable=False)  # REQ-07
    public_key = Column(Text, nullable=False)
    counter = Column(Integer, default=0)
    aaguid = Column(String, nullable=True)
    name = Column(String, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"))
    token_hash = Column(String, nullable=False, unique=True)
    family_id = Column(String, nullable=False)  # para detectar reuso REQ-30
    used = Column(Boolean, default=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

class Denylist(Base):
    __tablename__ = "denylist"
    jti = Column(String, primary_key=True)
    expires_at = Column(DateTime, nullable=False)

class Session(Base):
    __tablename__ = "sessions"
    id = Column(String, primary_key=True)  # session_id REQ-28
    user_id = Column(String, ForeignKey("users.id"))
    ip_hash = Column(String)
    ua_hash = Column(String)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    revoked = Column(Boolean, default=False)

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, nullable=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)  # UTC REQ-56
    ip = Column(String)
    user_agent = Column(String)
    action = Column(String, nullable=False)  # login, logout, falha, emissao token, assinatura, verificacao, troca senha
    result = Column(String)  # sucesso/falha
    # append-only REQ-55

class Signature(Base):
    __tablename__ = "signatures"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"))
    original_hash = Column(String, nullable=False)  # REQ-48 SHA256 original
    signed_hash = Column(String, nullable=False)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    ip = Column(String)  # REQ-48 geolocalização IP
    page_number = Column(Integer)
    x = Column(Integer)
    y = Column(Integer)

class BackupCode(Base):
    __tablename__ = "backup_codes"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"))
    code_hash = Column(String, nullable=False)
    used = Column(Boolean, default=False)

class TOTPFailedAttempt(Base):
    __tablename__ = "totp_failed"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"))
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
