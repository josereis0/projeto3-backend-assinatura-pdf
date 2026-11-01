
import jwt, uuid, hashlib
from datetime import datetime, timedelta, timezone
from ..config import settings

def load_keys():
    with open(settings.JWT_PRIVATE_KEY_PATH, "r") as f:
        priv = f.read()
    with open(settings.JWT_PUBLIC_KEY_PATH, "r") as f:
        pub = f.read()
    return priv, pub

def create_access_token(user_id, session_id, ip, user_agent, password_changed_at):
    priv, _ = load_keys()
    now = datetime.now(timezone.utc)
    jti = str(uuid.uuid4())
    payload = {
        "sub": user_id,
        "jti": jti,  # REQ-24
        "iat": int(now.timestamp()),  # REQ-25
        "exp": int((now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)).timestamp()),
        "iss": settings.JWT_ISSUER,
        "ip": hashlib.sha256(ip.encode()).hexdigest()[:16],  # REQ-26 hash
        "ua_hash": hashlib.sha256(user_agent.encode()).hexdigest()[:16],  # REQ-27
        "session_id": session_id,  # REQ-28
    }
    token = jwt.encode(payload, priv, algorithm="RS256")  # REQ-17
    return token, jti, payload

def verify_access_token(token):
    _, pub = load_keys()
    try:
        payload = jwt.decode(token, pub, algorithms=["RS256","ES256"], issuer=settings.JWT_ISSUER)
        return payload
    except Exception as e:
        return None
