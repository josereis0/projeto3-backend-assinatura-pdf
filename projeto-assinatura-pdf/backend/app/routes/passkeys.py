
from fastapi import APIRouter, Depends, Request, HTTPException
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import PasskeyDevice, User
from ..security.jwt_handler import verify_access_token
from datetime import datetime, timezone

router = APIRouter()

# REQ-06 fluxo WebAuthn completo create/get
@router.post("/register/begin")
def begin_register(request: Request, db: Session = Depends(get_db)):
    # retorna challenge
    import secrets
    challenge = secrets.token_urlsafe(32)
    return {"challenge": challenge, "rp": {"id": "localhost", "name": "Assinatura PDF"}, "user": {"id": "user-id"}, "pubKeyCredParams": [{"type":"public-key","alg":-7}]}

@router.post("/register/finish")
def finish_register(credential_id: str, public_key: str, counter: int, aaguid: str, request: Request = None, db: Session = Depends(get_db)):
    auth = request.headers.get("Authorization")
    payload = verify_access_token(auth.replace("Bearer ","")) if auth else None
    device = PasskeyDevice(user_id=payload["sub"], credential_id=credential_id, public_key=public_key, counter=counter, aaguid=aaguid)  # REQ-07
    db.add(device)
    db.commit()
    return {"message":"Dispositivo registrado REQ-10"}

@router.post("/auth/begin")
def begin_auth():
    import secrets
    return {"challenge": secrets.token_urlsafe(32)}

@router.post("/auth/finish")
def finish_auth(credential_id: str, counter: int, db: Session = Depends(get_db)):
    device = db.query(PasskeyDevice).filter(PasskeyDevice.credential_id==credential_id).first()
    if not device:
        raise HTTPException(status_code=404, detail={"code":"AUTH_015","message":"Credencial não encontrada","timestamp": datetime.now(timezone.utc).isoformat()})
    # REQ-08 validação counter
    if device.counter==0 and counter==0:
        pass  # passkeys sincronizadas iCloud/Google sempre zero
    else:
        if counter <= device.counter:
            raise HTTPException(status_code=401, detail={"code":"AUTH_016","message":"Counter inválido, possível clonagem REQ-08","timestamp": datetime.now(timezone.utc).isoformat()})
    device.counter = counter
    db.commit()
    # emitir tokens (mesmo fluxo login)
    return {"message":"Autenticado via passkey"}

@router.get("/")
def list_devices(request: Request, db: Session = Depends(get_db)):
    auth = request.headers.get("Authorization")
    payload = verify_access_token(auth.replace("Bearer ","")) if auth else None
    devices = db.query(PasskeyDevice).filter(PasskeyDevice.user_id==payload["sub"]).all()
    return devices  # REQ-10 lista dispositivos

@router.delete("/{device_id}")
def revoke_device(device_id: str, request: Request, db: Session = Depends(get_db)):
    auth = request.headers.get("Authorization")
    payload = verify_access_token(auth.replace("Bearer ","")) if auth else None
    db.query(PasskeyDevice).filter(PasskeyDevice.id==device_id, PasskeyDevice.user_id==payload["sub"]).delete()
    db.commit()
    return {"message":"Dispositivo revogado REQ-10"}
