
# Backend - API de Assinatura Digital de PDFs

## Arquitetura (REQ/RNF-12)
Entrada -> Middlewares (CORS, security headers, rate limit, CSRF, JWT) -> Rotas /api/v1 (validação, erros padronizados RNF-12) -> Serviços (auth, sessões, assinatura, verificação, auditoria) -> Infraestrutura (Criptografia Argon2id/JWT/TOTP/chaves, Processamento PDF isolado, Persistência PostgreSQL + Alembic)

Toda requisição atravessa a cadeia de middlewares uma única vez. Regras de domínio nunca ficam nas rotas.

## Como executar
cp .env.example .env
# gere chaves RSA: openssl genrsa -out private.pem 2048; openssl rsa -in private.pem -pubout -out public.pem
docker-compose up --build
alembic upgrade head
uvicorn app.main:app --reload

## Env Vars (RNF-05/06/07/08)
Ver .env.example. Validação na inicialização - recusa subir se ausente.

## Segurança implementada
- REQ-01..05: Argon2id RFC9106, bloqueio, mensagem única, rate limit IP/conta
- REQ-06..10: WebAuthn, counter, rpId, gerenciamento dispositivos
- REQ-11..16: TOTP RFC6238 160bits criptografado, QR, backup codes hash, TOTP antes JWT
- REQ-17..30: JWT RS256 jti/iat/ip hash/ua_hash/session_id, denylist, refresh opaco 256bits em cookie HttpOnly Secure SameSite=Strict, rotação e detecção de reuso
- REQ-31..44: CORS explícito, headers CSP/HSTS/X-Frame etc
- REQ-45..54: RSA-2048 por usuário, assinatura ISO32000 embutida + selo visual, hashes, rate limit verificação, descarte PDFs
- REQ-55..58: log append-only, sessões individuais + sair de todos
- REQ-60..66: %PDF- magic, 20MB, sandbox, rejeita /JS, sanitização XSS/SQL, CSRF Double Submit, npm audit
- RNF-09..11: Alembic timestamp upgrade/downgrade
- RNF-12..15: erros {code,message,timestamp} por domínio AUTH_/DOC_/VAL_
- RNF-16/17: /api/v1/
