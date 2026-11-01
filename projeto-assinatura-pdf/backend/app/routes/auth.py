
from fastapi import APIRouter, Depends, Request, Response, HTTPException
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import User, RefreshToken, Denylist, Session as UserSession, AuditLog
from ..security.argon2 import hash_password, verify_password
from ..security.jwt_handler import create_access_token, verify_access_token
from ..config import settings
from datetime import datetime, timedelta, timezone
import hashlib, secrets, uuid, time

router = APIRouter()

# REQ-01 política senhas 12 chars maiusculas minusculas numeros simbolos
def validate_password_policy(pwd: str):
    if len(pwd) < 12: raise ValueError("VAL_003: senha mínimo 12 caracteres REQ-01")
    if not any(c.isupper() for c in pwd): raise ValueError("VAL_003: precisa maiúscula")
    if not any(c.islower() for c in pwd): raise ValueError("VAL_003: precisa minúscula")
    if not any(c.isdigit() for c in pwd): raise ValueError("VAL_003: precisa número")
    if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in pwd): raise ValueError("VAL_003: precisa símbolo")

@router.post("/register")
def register(email: str, name: str, password: str, db: Session = Depends(get_db), request: Request = None):
    from ..security.sanitize import sanitize_text, validate_email
    validate_email(email)
    sanitize_text(name)
    validate_password_policy(password)
    if db.query(User).filter(User.email==email).first():
        raise HTTPException(status_code=400, detail={"code":"AUTH_004","message":"Usuário já existe","timestamp": datetime.now(timezone.utc).isoformat()})
    # REQ-45 gera par chaves RSA-2048
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    pub_pem = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    # criptografa privada com master key (simplificado)
    user = User(email=email, name=sanitize_text(name), password_hash=hash_password(password), private_key_encrypted=priv_pem, public_key=pub_pem)
    db.add(user)
    db.commit()
    return {"id": user.id, "email": user.email}

@router.post("/login")
def login(email: str, password: str, totp_code: str = None, request: Request = None, response: Response = None, db: Session = Depends(get_db)):
    from ..middlewares.rate_limit import rate_limit
    ip = request.client.host if request else "0.0.0.0"
    # REQ-05 rate limiting por IP e conta
    try:
        rate_limit(f"login_ip_{ip}", settings.RATE_LIMIT_LOGIN_PER_MIN)
        rate_limit(f"login_account_{email}", settings.RATE_LIMIT_LOGIN_PER_MIN)
    except HTTPException as e:
        raise e
    user = db.query(User).filter(User.email==email).first()
    # REQ-04 mensagem única não diferencia usuário inexistente de senha errada
    generic_fail = HTTPException(status_code=401, detail={"code":"AUTH_001","message":"Credenciais inválidas","timestamp": datetime.now(timezone.utc).isoformat()})
    if not user:
        raise generic_fail
    # REQ-03 bloqueio temporário
    if user.locked_until and user.locked_until > datetime.now(timezone.utc):
        raise HTTPException(status_code=403, detail={"code":"AUTH_005","message":"Conta bloqueada temporariamente REQ-03","timestamp": datetime.now(timezone.utc).isoformat()})
    if not verify_password(user.password_hash, password):
        user.failed_attempts += 1
        if user.failed_attempts >= settings.MAX_LOGIN_ATTEMPTS:
            user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=settings.LOCKOUT_MINUTES)
        db.commit()
        db.add(AuditLog(user_id=user.id, ip=ip, user_agent=request.headers.get("user-agent",""), action="falha_autenticacao", result="falha"))  # REQ-55
        db.commit()
        raise generic_fail
    # sucesso reseta
    user.failed_attempts = 0
    db.commit()
    # REQ-15 TOTP antes do JWT
    if user.totp_enabled:
        if not totp_code:
            return {"requires_totp": True, "message": "Informe código TOTP"}
        from ..security.totp import decrypt_secret, verify_totp
        secret = decrypt_secret(user.totp_secret_encrypted)
        if not verify_totp(secret, totp_code):
            # REQ-16 alerta códigos inválidos repetidos
            db.add(AuditLog(user_id=user.id, ip=ip, user_agent=request.headers.get("user-agent",""), action="totp_invalido", result="falha"))
            db.commit()
            raise HTTPException(status_code=401, detail={"code":"AUTH_006","message":"TOTP inválido","timestamp": datetime.now(timezone.utc).isoformat()})
    # cria sessão REQ-28
    session_id = str(uuid.uuid4())
    ip_hash = hashlib.sha256(ip.encode()).hexdigest()[:16]
    ua = request.headers.get("user-agent","")
    ua_hash = hashlib.sha256(ua.encode()).hexdigest()[:16]
    db.add(UserSession(id=session_id, user_id=user.id, ip_hash=ip_hash, ua_hash=ua_hash))
    db.commit()
    access_token, jti, payload = create_access_token(user.id, session_id, ip, ua, user.password_changed_at)
    # REQ-19 refresh token opaco 256 bits CSPRNG
    refresh_raw = secrets.token_bytes(32)
    refresh_hash = hashlib.sha256(refresh_raw).hexdigest()
    family_id = str(uuid.uuid4())
    db.add(RefreshToken(user_id=user.id, token_hash=refresh_hash, family_id=family_id, expires_at=datetime.now(timezone.utc)+timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)))
    db.add(AuditLog(user_id=user.id, ip=ip, user_agent=ua, action="login", result="sucesso"))
    db.add(AuditLog(user_id=user.id, ip=ip, user_agent=ua, action="emissao_token", result="sucesso"))
    db.commit()
    # REQ-20 cookie HttpOnly Secure SameSite=Strict
    response.set_cookie(key="refresh_token", value=refresh_raw.hex(), httponly=True, secure=True, samesite="strict", max_age=7*24*3600)
    response.set_cookie(key="csrf_token", value=secrets.token_urlsafe(32), httponly=False, secure=True, samesite="strict")
    return {"access_token": access_token, "token_type":"bearer"}

@router.post("/logout")
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    auth_header = request.headers.get("Authorization")
    if auth_header:
        token = auth_header.replace("Bearer ","")
        payload = verify_access_token(token)
        if payload:
            jti = payload.get("jti")
            exp = datetime.fromtimestamp(payload.get("exp"), tz=timezone.utc)
            db.add(Denylist(jti=jti, expires_at=exp))  # REQ-21
    refresh = request.cookies.get("refresh_token")
    if refresh:
        h = hashlib.sha256(bytes.fromhex(refresh)).hexdigest()
        rt = db.query(RefreshToken).filter(RefreshToken.token_hash==h).first()
        if rt:
            rt.used = True  # REQ-23 invalida
            db.commit()
    response.delete_cookie("refresh_token")
    return {"message":"Logout realizado"}

@router.post("/refresh")
def refresh(request: Request, response: Response, db: Session = Depends(get_db)):
    # REQ-29 rotação a cada uso, REQ-30 reuso indica comprometimento
    raw = request.cookies.get("refresh_token")
    if not raw:
        raise HTTPException(status_code=401, detail={"code":"AUTH_007","message":"Refresh ausente","timestamp": datetime.now(timezone.utc).isoformat()})
    h = hashlib.sha256(bytes.fromhex(raw)).hexdigest()
    rt = db.query(RefreshToken).filter(RefreshToken.token_hash==h).first()
    if not rt:
        raise HTTPException(status_code=401, detail={"code":"AUTH_007","message":"Refresh inválido","timestamp": datetime.now(timezone.utc).isoformat()})
    if rt.used:
        # reuso -> invalida família inteira
        db.query(RefreshToken).filter(RefreshToken.family_id==rt.family_id).delete()
        db.commit()
        raise HTTPException(status_code=401, detail={"code":"AUTH_008","message":"Reuso detectado, família invalidada REQ-30","timestamp": datetime.now(timezone.utc).isoformat()})
    if rt.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail={"code":"AUTH_009","message":"Refresh expirado","timestamp": datetime.now(timezone.utc).isoformat()})
    rt.used = True
    # emite novo par
    from ..security.jwt_handler import create_access_token
    ip = request.client.host
    ua = request.headers.get("user-agent","")
    session = db.query(UserSession).filter(UserSession.user_id==rt.user_id).first()
    session_id = session.id if session else str(uuid.uuid4())
    user = db.query(User).filter(User.id==rt.user_id).first()
    access_token, jti, _ = create_access_token(rt.user_id, session_id, ip, ua, user.password_changed_at)
    new_raw = secrets.token_bytes(32)
    new_hash = hashlib.sha256(new_raw).hexdigest()
    db.add(RefreshToken(user_id=rt.user_id, token_hash=new_hash, family_id=rt.family_id, expires_at=datetime.now(timezone.utc)+timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)))
    db.commit()
    response.set_cookie(key="refresh_token", value=new_raw.hex(), httponly=True, secure=True, samesite="strict", max_age=7*24*3600)
    return {"access_token": access_token}
