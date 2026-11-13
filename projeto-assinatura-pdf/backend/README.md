# SignPDF Secure — Backend API & Banco de Dados (Projeto 3 · Segurança da Informação)

API REST em **FastAPI (Python 3.11)** com banco de dados **PostgreSQL 15** e containerização **Docker**, responsável pela autenticação multifator (Argon2id, 2FA TOTP RFC 6238 e Passkeys WebAuthn), gestão de sessões JWT RS256 (com denylist e rotação de refresh token), trilha de auditoria imutável e processamento seguro de documentos PDF.

---

## 1. Arquitetura do Backend

Toda requisição atravessa primeiro a cadeia de middlewares antes de chegar às rotas versionadas em `/api/v1`:

```text
Entrada HTTP
 └── Cadeia de Middlewares
      ├── 1. CORS (origens explícitas: http://localhost:5173 e http://localhost:3000 — sem wildcard *)
      ├── 2. Security Headers (CSP, HSTS preload, X-Frame-Options: DENY, nosniff, Referrer-Policy, Permissions-Policy, Cache-Control: no-store, X-XSS-Protection: 0)
      ├── 3. Rate Limiting (por IP e por conta no login; 20 req/min por IP na verificação pública)
      ├── 4. Proteção CSRF (Double Submit Cookie + verificação de Origin/Referer)
      └── 5. Verificação JWT RS256 (assinatura, consulta à denylist por jti, checagem de iat contra troca de senha, ua_hash e alerta de ip_hash)
           │
           ▼
Rotas REST (/api/v1/*)
 ├── /api/v1/auth      → Cadastro (Argon2id + par RSA-2048 criptografado com MASTER_KEY), Login, Logout, Refresh rotativo e Troca de Senha
 ├── /api/v1/totp      → Ativação 2FA (segredo 160 bits criptografado com Fernet, QR Code PNG, 8 Backup Codes com hash SHA-256) e Desativação
 ├── /api/v1/passkeys  → Registro e autenticação WebAuthn/FIDO2 (challenge, credentialId, publicKey, validação de counter e revogação)
 ├── /api/v1/documents → Validação (%PDF-, máx. 20 MB, bloqueio de /JS e /JavaScript) e assinatura digital em memória (sem persistir o PDF)
 ├── /api/v1/verify    → Verificação pública de autenticidade e integridade (recomputação de SHA-256 + validação de assinatura)
 ├── /api/v1/sessions  → Listagem de sessões ativas, revogação individual e encerramento global ("sair de todos os dispositivos")
 └── /api/v1/audit     → Log de auditoria append-only e eventos de segurança da conta
```

---

## 2. Como Subir o Sistema Completo (Backend + Frontend)

### Pré-requisitos
- **Docker Desktop** instalado e aberto.
- **Python 3** instalado (para servir o frontend estático na porta `5173`).

---

### Passo 1 — Configurar e Subir o Backend (Docker + PostgreSQL)

1. Abra um terminal e entre na pasta do backend:
   ```powershell
   cd "projeto3-backend-assinatura-pdf/projeto-assinatura-pdf/backend"
   ```

2. Crie o arquivo `.env` a partir do `.env.example` (caso ainda não exista na máquina):
   ```powershell
   copy .env.example .env
   ```
   *(Certifique-se de que `MASTER_KEY` e `TOTP_ENCRYPTION_KEY` no `.env` contenham chaves Fernet válidas de 32 bytes em Base64).*

3. Verifique se os arquivos de chave RSA do JWT (`private.pem` e `public.pem`) existem na pasta `backend/`. Caso esteja rodando em um computador novo onde eles ainda não foram gerados, gere-os com:
   ```powershell
   python -c "from cryptography.hazmat.primitives.asymmetric import rsa; from cryptography.hazmat.primitives import serialization; k = rsa.generate_private_key(65537, 2048); open('private.pem','wb').write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())); open('public.pem','wb').write(k.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))"
   ```

4. Suba os containers do **PostgreSQL 15**, da **API FastAPI** e do **Sandbox de PDF**:
   ```powershell
   docker compose up -d --build
   ```

5. Verifique se a API está online:
   - Healthcheck: `http://localhost:8000/health`
   - Documentação interativa (Swagger): `http://localhost:8000/docs`

> **Dica:** Como a pasta `backend/` está mapeada via volume no `docker-compose.yml` com `--reload`, alterações nos arquivos `.py` recarregam automaticamente. Para parar os containers, use `docker compose down`.

---

### Passo 2 — Subir o Frontend Web

1. Abra **outro terminal** na pasta do repositório do frontend (`projeto3-frontend-assinatura-pdf`):
   ```powershell
   cd "projeto3-frontend-assinatura-pdf"
   ```

2. Inicie o servidor HTTP na porta `5173` (porta liberada na lista explícita de CORS do backend):
   ```powershell
   python -m http.server 5173
   ```

3. Abra o navegador em:
   ```text
   http://localhost:5173
   ```

---

## 3. Variáveis de Ambiente e Migrações
- Todas as variáveis obrigatórias estão documentadas em `.env.example` (RNF-05, RNF-06).
- O arquivo `.env` e as chaves privadas `*.pem` são ignorados pelo `.gitignore` (RNF-07).
- Na inicialização (`app/config.py`), a aplicação valida a presença de todas as variáveis obrigatórias e recusa subir caso alguma esteja ausente (RNF-08).
- As migrações versionadas do PostgreSQL ficam em `migrations/versions/001_initial.py` com operações de `upgrade()` e `downgrade()` gerenciadas pelo Alembic (RNF-09 a RNF-11).
