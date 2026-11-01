
from fastapi.middleware.cors import CORSMiddleware
from ..config import settings

def get_cors_config():
    return {
        "allow_origins": settings.CORS_ALLOWED_ORIGINS,  # REQ-31 explicito nunca *
        "allow_methods": ["GET","POST","PUT","DELETE","OPTIONS"],  # REQ-32
        "allow_headers": ["Authorization","Content-Type","X-Request-ID"],  # REQ-33
        "allow_credentials": True,  # REQ-34 só para confiáveis
        "max_age": 600,  # REQ-36 cache preflight
    }
