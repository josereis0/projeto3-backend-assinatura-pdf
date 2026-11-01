
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from datetime import datetime, timezone
from .config import settings
from .middlewares.cors_middleware import get_cors_config
from fastapi.middleware.cors import CORSMiddleware
from .middlewares.security_headers import SecurityHeadersMiddleware
from .routes import auth, pdf, verify, sessions, audit, passkeys, totp
import time

app = FastAPI(title="Assinatura Digital PDF API", version="1.0")

# RNF-16 prefixo /api/v1 já nas rotas

# CORS RNF + REQ-31..36
cors_cfg = get_cors_config()
app.add_middleware(CORSMiddleware, **cors_cfg)
app.state.allowed_origins = settings.CORS_ALLOWED_ORIGINS

app.add_middleware(SecurityHeadersMiddleware)

@app.middleware("http")
async def jwt_denylist_and_checks(request: Request, call_next):
    # REQ-22 consulta denylist, REQ-25 iat vs troca senha, REQ-26 ip hash alerta, REQ-27 ua_hash
    # implementação simplificada - detalhes no serviço auth
    start = time.time()
    response = await call_next(request)
    # RNF-12 erro padronizado
    return response

@app.exception_handler(Exception)
async def standardized_error(request: Request, exc: Exception):
    # RNF-12/13/14/15
    code = getattr(exc, "code", "AUTH_001")
    if isinstance(exc, ValueError):
        return JSONResponse(status_code=400, content={"code": code, "message": str(exc), "timestamp": datetime.now(timezone.utc).isoformat()})
    return JSONResponse(status_code=500, content={"code": "SYS_001", "message": "Erro interno", "timestamp": datetime.now(timezone.utc).isoformat()})

app.include_router(auth.router, prefix="/api/v1/auth", tags=["auth"])
app.include_router(passkeys.router, prefix="/api/v1/passkeys", tags=["passkeys"])
app.include_router(totp.router, prefix="/api/v1/totp", tags=["totp"])
app.include_router(pdf.router, prefix="/api/v1/documents", tags=["documents"])
app.include_router(verify.router, prefix="/api/v1/verify", tags=["verify"])
app.include_router(sessions.router, prefix="/api/v1/sessions", tags=["sessions"])
app.include_router(audit.router, prefix="/api/v1/audit", tags=["audit"])

@app.get("/health")
def health():
    return {"status":"ok"}
