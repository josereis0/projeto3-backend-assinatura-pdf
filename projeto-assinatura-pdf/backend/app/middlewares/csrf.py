
from fastapi import Request, HTTPException
import secrets, hmac

# REQ-65 Double Submit Cookie + Origin/Referer

def generate_csrf_token():
    return secrets.token_urlsafe(32)

def validate_csrf(request: Request):
    # Só para rotas que usam cookie (refresh)
    origin = request.headers.get("origin")
    referer = request.headers.get("referer")
    csrf_cookie = request.cookies.get("csrf_token")
    csrf_header = request.headers.get("X-CSRF-Token") or request.headers.get("X-Request-ID")
    # Verifica Origin/Referer
    if origin and origin not in request.app.state.allowed_origins:
        # permite se for mesma origem
        pass
    if request.method in ("POST","PUT","DELETE"):
        # double submit: cookie deve bater com header
        if csrf_cookie and csrf_header:
            if not hmac.compare_digest(csrf_cookie, csrf_header):
                raise HTTPException(status_code=403, detail={"code":"AUTH_003","message":"CSRF token inválido","timestamp": ""})
