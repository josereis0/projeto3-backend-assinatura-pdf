
from fastapi import APIRouter, Depends, Request, HTTPException
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import AuditLog
from ..security.jwt_handler import verify_access_token
from datetime import datetime, timezone

router = APIRouter()

@router.get("/")
def get_audit(request: Request, db: Session = Depends(get_db)):
    auth = request.headers.get("Authorization")
    payload = verify_access_token(auth.replace("Bearer ","")) if auth else None
    if not payload:
        raise HTTPException(status_code=401, detail={"code":"AUTH_001","message":"Não autenticado","timestamp": datetime.now(timezone.utc).isoformat()})
    logs = db.query(AuditLog).filter(AuditLog.user_id==payload["sub"]).order_by(AuditLog.timestamp.desc()).limit(100).all()
    return [{"action": l.action, "timestamp": l.timestamp, "ip": l.ip, "result": l.result, "user_agent": l.user_agent} for l in logs]

@router.get("/security-events")
def security_events(request: Request, db: Session = Depends(get_db)):
    # REQ-58 atividade de segurança: novo IP, ativação/desativação 2FA, troca senha
    auth = request.headers.get("Authorization")
    payload = verify_access_token(auth.replace("Bearer ","")) if auth else None
    logs = db.query(AuditLog).filter(AuditLog.user_id==payload["sub"], AuditLog.action.in_(["novo_ip","ativacao_2fa","desativacao_2fa","troca_senha"])).all()
    return logs
