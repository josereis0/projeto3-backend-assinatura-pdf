
from fastapi import APIRouter, Depends, Request, HTTPException
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import Session as UserSession, User
from ..security.jwt_handler import verify_access_token
from datetime import datetime, timezone

router = APIRouter()

@router.get("/")
def list_sessions(request: Request, db: Session = Depends(get_db)):
    auth = request.headers.get("Authorization")
    token = auth.replace("Bearer ","") if auth else ""
    payload = verify_access_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail={"code":"AUTH_001","message":"Não autenticado","timestamp": datetime.now(timezone.utc).isoformat()})
    sessions = db.query(UserSession).filter(UserSession.user_id==payload["sub"], UserSession.revoked==False).all()
    return [{"id": s.id, "ip_hash": s.ip_hash, "created_at": s.created_at} for s in sessions]  # REQ-57

@router.delete("/{session_id}")
def revoke_session(session_id: str, request: Request, db: Session = Depends(get_db)):
    auth = request.headers.get("Authorization")
    payload = verify_access_token(auth.replace("Bearer ","")) if auth else None
    if not payload:
        raise HTTPException(status_code=401, detail={"code":"AUTH_001","message":"Não autenticado","timestamp": datetime.now(timezone.utc).isoformat()})
    s = db.query(UserSession).filter(UserSession.id==session_id, UserSession.user_id==payload["sub"]).first()
    if s:
        s.revoked=True
        db.commit()
    return {"message":"Sessão encerrada REQ-57"}

@router.post("/revoke-all")
def revoke_all(request: Request, db: Session = Depends(get_db)):
    auth = request.headers.get("Authorization")
    payload = verify_access_token(auth.replace("Bearer ","")) if auth else None
    db.query(UserSession).filter(UserSession.user_id==payload["sub"]).update({"revoked": True})
    db.commit()
    return {"message":"Todas as sessões encerradas - sair de todos dispositivos REQ-57"}
