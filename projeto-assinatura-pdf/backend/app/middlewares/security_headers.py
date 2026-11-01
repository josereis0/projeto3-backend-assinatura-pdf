
from starlette.middleware.base import BaseHTTPMiddleware
# REQ-37..44
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'"  # REQ-37
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"  # REQ-38
        response.headers["X-Frame-Options"] = "DENY"  # REQ-39
        response.headers["X-Content-Type-Options"] = "nosniff"  # REQ-40
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"  # REQ-41
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"  # REQ-42
        if request.url.path.startswith("/api/"):
            # REQ-43 no-store nas rotas autenticadas
            response.headers["Cache-Control"] = "no-store"
        response.headers["X-XSS-Protection"] = "0"  # REQ-44
        return response
