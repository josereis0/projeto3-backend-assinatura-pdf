
from argon2 import PasswordHasher
# REQ-02 RFC 9106 memory=64MB, iterations=3, parallelism=4
ph = PasswordHasher(memory_cost=65536, time_cost=3, parallelism=4)

def hash_password(pwd: str) -> str:
    return ph.hash(pwd)

def verify_password(hash_: str, pwd: str) -> bool:
    try:
        return ph.verify(hash_, pwd)
    except:
        return False
