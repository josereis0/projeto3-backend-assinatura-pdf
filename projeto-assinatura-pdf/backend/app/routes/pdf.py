
from fastapi import APIRouter, UploadFile, File, Depends, Request, HTTPException
from sqlalchemy.orm import Session
from ..database import get_db
from ..services.pdf_service import sign_pdf
from ..models import Signature, AuditLog, User
from ..security.jwt_handler import verify_access_token
from datetime import datetime, timezone

router = APIRouter()

def get_current_user(request: Request, db: Session):
    auth = request.headers.get("Authorization")
    if not auth:
        raise HTTPException(status_code=401, detail={"code":"AUTH_001","message":"Não autenticado","timestamp": datetime.now(timezone.utc).isoformat()})
    token = auth.replace("Bearer ","")
    payload = verify_access_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail={"code":"AUTH_010","message":"Token inválido","timestamp": datetime.now(timezone.utc).isoformat()})
    # REQ-22 denylist check (simplificado)
    from ..models import Denylist
    if db.query(Denylist).filter(Denylist.jti==payload.get("jti")).first():
        raise HTTPException(status_code=401, detail={"code":"AUTH_011","message":"Token revogado","timestamp": datetime.now(timezone.utc).isoformat()})
    # REQ-25 iat vs troca senha
    user = db.query(User).filter(User.id==payload.get("sub")).first()
    if not user:
        raise HTTPException(status_code=404, detail={"code":"AUTH_012","message":"Usuário não encontrado","timestamp": datetime.now(timezone.utc).isoformat()})
    iat = datetime.fromtimestamp(payload.get("iat"), tz=timezone.utc)
    if user.password_changed_at and iat < user.password_changed_at:
        raise HTTPException(status_code=401, detail={"code":"AUTH_013","message":"Token emitido antes da troca de senha REQ-25","timestamp": datetime.now(timezone.utc).isoformat()})
    # REQ-27 ua_hash
    import hashlib
    current_ua_hash = hashlib.sha256(request.headers.get("user-agent","").encode()).hexdigest()[:16]
    if current_ua_hash != payload.get("ua_hash"):
        raise HTTPException(status_code=401, detail={"code":"AUTH_014","message":"User-Agent divergente REQ-27","timestamp": datetime.now(timezone.utc).isoformat()})
    # REQ-26 ip hash alerta (não rejeita)
    current_ip_hash = hashlib.sha256(request.client.host.encode()).hexdigest()[:16]
    if current_ip_hash != payload.get("ip"):
        # gera alerta mas não bloqueia
        pass
    return user, payload

@router.post("/sign")
async def sign_document(page: int, x: int, y: int, file: UploadFile = File(...), request: Request = None, db: Session = Depends(get_db)):
    user, payload = get_current_user(request, db)
    data = await file.read()
    signed_bytes, orig_hash, signed_hash = sign_pdf(data, user.name, str(user.id), page, x, y)
    sig = Signature(user_id=user.id, original_hash=orig_hash, signed_hash=signed_hash, ip=request.client.host, page_number=page, x=x, y=y)
    db.add(sig)
    db.add(AuditLog(user_id=user.id, ip=request.client.host, user_agent=request.headers.get("user-agent",""), action="assinatura_documento", result="sucesso"))
    db.commit()
    # RNF não armazena PDF, só devolve e descarta REQ-54 / 9.2
    from fastapi.responses import Response
    return Response(content=signed_bytes, media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename=assinado_{file.filename}", "X-Signature-ID": sig.id})
