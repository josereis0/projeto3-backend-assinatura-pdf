
import hashlib, io, uuid
from datetime import datetime, timezone
from PyPDF2 import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
# REQ-62 processamento isolado - em prod rodar em container sem rede
# REQ-60 magic %PDF-, REQ-61 20MB, REQ-63 rejeita /JS

MAX_SIZE = 20 * 1024 * 1024

def validate_pdf_bytes(data: bytes):
    if len(data) > MAX_SIZE:
        raise ValueError("DOC_001: PDF excede 20MB")
    if not data.startswith(b"%PDF-"):
        raise ValueError("DOC_002: Magic number inválido, não é PDF")
    # parsing simples para checar /JS
    if b"/JS" in data or b"/JavaScript" in data:
        raise ValueError("DOC_003: PDF contém JavaScript, rejeitado REQ-63")

def sign_pdf(original_bytes: bytes, signer_name: str, signature_id: str, page_num: int, x: int, y: int):
    validate_pdf_bytes(original_bytes)
    orig_hash = hashlib.sha256(original_bytes).hexdigest()

    reader = PdfReader(io.BytesIO(original_bytes))
    writer = PdfWriter()
    for p in reader.pages:
        writer.add_page(p)

    # cria selo visual REQ-47
    packet = io.BytesIO()
    can = canvas.Canvas(packet, pagesize=letter)
    can.setFillColorRGB(0.9,0.9,1)
    can.rect(x, y, 200, 80, fill=1, stroke=1)
    can.setFillColorRGB(0,0,0)
    can.setFont("Helvetica", 8)
    can.drawString(x+5, y+65, f"Assinado por: {signer_name}")
    can.drawString(x+5, y+50, f"Data UTC: {datetime.now(timezone.utc).isoformat()}")
    can.drawString(x+5, y+35, f"Hash: {orig_hash[:16]}...")
    can.drawString(x+5, y+20, f"ID: {signature_id}")
    can.save()
    packet.seek(0)
    # merge - simplificado: adiciona como nova página de selo? Para demo, adiciona annotation na página escolhida
    # Aqui para simplificar, adicionamos o selo como overlay na página alvo usando PyPDF2
    from PyPDF2 import PdfReader as PR2
    overlay_reader = PR2(packet)
    if page_num < len(writer.pages):
        writer.pages[page_num].merge_page(overlay_reader.pages[0])

    # assinatura embutida padrão ISO 32000 - simplificado como metadata
    writer.add_metadata({
        "/Signature": signature_id,
        "/Signer": signer_name,
        "/SignedHash": orig_hash,
    })

    out = io.BytesIO()
    writer.write(out)
    signed_bytes = out.getvalue()
    signed_hash = hashlib.sha256(signed_bytes).hexdigest()
    return signed_bytes, orig_hash, signed_hash

def verify_pdf(pdf_bytes: bytes, db_signatures):
    validate_pdf_bytes(pdf_bytes)
    current_hash = hashlib.sha256(pdf_bytes).hexdigest()
    reader = PdfReader(io.BytesIO(pdf_bytes))
    meta = reader.metadata
    sig_id = meta.get("/Signature") if meta else None
    if not sig_id:
        return {"status":"assinatura_nao_encontrada", "code":"DOC_004"}  # REQ-52
    # REQ-50 verificação criptográfica (aqui checa metadata) + REQ-51 comparação hashes
    # busca no banco o hash original
    record = next((s for s in db_signatures if s.id == sig_id), None)
    if not record:
        return {"status":"adulterado","reason":"hash não registrado"}
    # se o hash atual bate com signed_hash registrado e original ainda bate?
    # Simplificação: compara se current_hash == signed_hash -> integro, senão adulterado
    if current_hash == record.signed_hash:
        return {"status":"integro","signature": record}
    else:
        return {"status":"adulterado","expected": record.signed_hash, "got": current_hash}
