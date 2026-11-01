
from fastapi import APIRouter, UploadFile, File, Depends, Request, HTTPException
from sqlalchemy.orm import Session
from ..database import get_db
from ..services.pdf_service import verify_pdf
from ..models import Signature, AuditLog
from ..middlewares.rate_limit import rate_limit
from datetime import datetime, timezone

router = APIRouter()

@router.post("/")
async def verify_document(file: UploadFile = File(...), request: Request = None, db: Session = Depends(get_db)):
    # REQ-53 rate limiting verificação pública
    ip = request.client.host
    try:
        from ..middlewares.rate_limit import rate_limit
        rate_limit(f"verify_{ip}", 20)
    except HTTPException as e:
        raise e
    data = await file.read()
    # REQ-54 descartado após processamento - não salva
    signatures = db.query(Signature).all()
    result = verify_pdf(data, signatures)
    db.add(AuditLog(user_id=None, ip=ip, user_agent=request.headers.get("user-agent",""), action="verificacao_documento", result=result.get("status")))
    db.commit()
    # REQ-52 resultado claro
    if result["status"] == "integro":
        return {"resultado":"documento_íntegro", "assinatura": str(result.get("signature").id) if result.get("signature") else None}
    elif result["status"] == "adulterado":
        return {"resultado":"documento_adulterado", "detalhe": result}
    else:
        return {"resultado":"assinatura_nao_encontrada"}
