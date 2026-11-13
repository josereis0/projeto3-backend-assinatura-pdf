
from fastapi import APIRouter, Depends, Request, HTTPException
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import User, BackupCode
from ..security.jwt_handler import verify_access_token
from ..security.totp import generate_secret, encrypt_secret, get_totp_uri, hash_backup_code
from datetime import datetime, timezone
import secrets, qrcode, io, base64

router = APIRouter()

@router.post("/setup/begin")
def setup_begin(request: Request, db: Session = Depends(get_db)):
    auth = request.headers.get("Authorization")
    payload = verify_access_token(auth.replace("Bearer ","")) if auth else None
    user = db.query(User).filter(User.id==payload["sub"]).first()
    secret_bytes = generate_secret()  # REQ-12 160 bits
    enc = encrypt_secret(secret_bytes)
    user.totp_secret_encrypted = enc
    db.commit()
    uri = get_totp_uri(secret_bytes, user.email)
    # REQ-13 QR Code
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode()
    # REQ-14 backup codes
    db.query(BackupCode).filter(BackupCode.user_id==user.id).delete()
    codes = [secrets.token_hex(4).upper() for _ in range(8)]
    for c in codes:
        db.add(BackupCode(user_id=user.id, code_hash=hash_backup_code(c)))
    db.commit()
    b32_secret = base64.b32encode(secret_bytes).decode()
    return {"qr_base64": b64, "uri": uri, "secret": b32_secret, "backup_codes": codes, "message":"Guarde os códigos REQ-14"}

@router.post("/setup/confirm")
def setup_confirm(code: str, request: Request, db: Session = Depends(get_db)):
    auth = request.headers.get("Authorization")
    payload = verify_access_token(auth.replace("Bearer ","")) if auth else None
    user = db.query(User).filter(User.id==payload["sub"]).first()
    from ..security.totp import decrypt_secret, verify_totp
    secret = decrypt_secret(user.totp_secret_encrypted)
    if verify_totp(secret, code):
        user.totp_enabled = True
        db.commit()
        return {"message":"2FA ativado REQ-11"}
    raise HTTPException(status_code=400, detail={"code":"AUTH_017","message":"Código inválido","timestamp": datetime.now(timezone.utc).isoformat()})

@router.post("/disable")
def disable_totp(request: Request, db: Session = Depends(get_db)):
    auth = request.headers.get("Authorization")
    payload = verify_access_token(auth.replace("Bearer ","")) if auth else None
    if not payload:
        raise HTTPException(status_code=401, detail={"code":"AUTH_003","message":"Token inválido","timestamp": datetime.now(timezone.utc).isoformat()})
    user = db.query(User).filter(User.id==payload["sub"]).first()
    if user:
        user.totp_enabled = False
        user.totp_secret_encrypted = None
        db.query(BackupCode).filter(BackupCode.user_id==user.id).delete()
        db.commit()
    return {"message":"2FA desativado"}
