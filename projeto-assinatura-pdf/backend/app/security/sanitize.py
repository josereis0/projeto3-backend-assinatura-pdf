
import re, html
# REQ-64 sanitização XSS e SQL injection
def sanitize_text(s: str) -> str:
    if not s: return s
    # remove <script> e tags
    s = html.escape(s)
    # bloqueia padrões SQL injection simples
    if re.search(r"(\bSELECT\b|\bDROP\b|--|;|\bUNION\b)", s, re.I):
        raise ValueError("VAL_001: entrada contém padrão suspeito")
    return s.strip()

def validate_email(email: str):
    if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
        raise ValueError("VAL_002: e-mail inválido")
