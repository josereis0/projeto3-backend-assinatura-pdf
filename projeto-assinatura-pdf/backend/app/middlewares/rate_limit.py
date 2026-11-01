
from collections import defaultdict
import time
from fastapi import Request, HTTPException

# simples in-memory para demo; em produção usar Redis
buckets = defaultdict(list)

def rate_limit(key: str, limit: int, window: int = 60):
    now = time.time()
    lst = buckets[key]
    # limpa antigos
    buckets[key] = [t for t in lst if now - t < window]
    if len(buckets[key]) >= limit:
        raise HTTPException(status_code=429, detail={"code":"AUTH_002","message":"Rate limit excedido","timestamp": now})
    buckets[key].append(now)

async def rate_limit_login(request: Request):
    from ..config import settings
    ip = request.client.host
    # REQ-05 por IP e por conta (conta checada no serviço)
    rate_limit(f"login_ip_{ip}", settings.RATE_LIMIT_LOGIN_PER_MIN)

async def rate_limit_verify(request: Request):
    from ..config import settings
    ip = request.client.host
    rate_limit(f"verify_{ip}", settings.RATE_LIMIT_VERIFY_PER_MIN)  # REQ-53
