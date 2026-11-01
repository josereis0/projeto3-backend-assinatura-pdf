# Projeto 3 - Sistema Web de Assinatura Digital de PDFs
Entrega completa - Segurança da Informação UAB00084 - Prof Ygor

## Estrutura
- backend/ : API FastAPI com todos REQs 01-66 e RNFs
- frontend/index.html : Artefato interativo completo com Tailwind

## Como rodar backend
cd backend
cp .env.example .env
# gere chaves:
openssl genrsa -out keys/private.pem 2048
openssl rsa -in keys/private.pem -pubout -out keys/public.pem
docker-compose up --build
alembic upgrade head
uvicorn app.main:app --reload --port 8000

## Como rodar frontend
Abra frontend/index.html ou use o preview do artefato.

## Requisitos atendidos
Ver backend/README.md para mapa completo REQ->codigo
