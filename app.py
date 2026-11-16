"""
ImageGuard v2 - Experimental Image Forensics and Signature Workbench
FastAPI Application Entry Point
"""

import os
import io
import uuid
import json
import hashlib
import asyncio
import shutil
import logging
import warnings
from pathlib import Path
from PIL import Image, UnidentifiedImageError
from starlette.concurrency import run_in_threadpool
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.exceptions import InvalidTag
from datetime import datetime
from contextlib import asynccontextmanager
from typing import Dict, Optional

from fastapi import (
    FastAPI, File, UploadFile, Form, HTTPException, Request,
    WebSocket, WebSocketDisconnect, Query
)
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from config import Config
from models.database import init_db, ImageRecord, KeyPair, MerkleCheckpoint, AuditEvent
from services.forgery_detection import ForgeryDetector
from services.digital_signature import DigitalSignatureService, EnvelopeKeyVault
from services.metadata_analyzer import MetadataAnalyzer
from services.certificate_gen import CertificateGenerator
from services.c2pa_provenance import C2PAProvenanceService
from services.watermark_engine import SoftBindingService
from services.merkle_ledger import MerkleAuditTree, LedgerIntegrityError
from services.access_control import AccessControlMiddleware


# ─── Globals ───────────────────────────────────────────────
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = Config.DB_PATH
Config.init_app()

Session = None
forgery_detector = None
signature_service = DigitalSignatureService(key_size=Config.RSA_KEY_SIZE)
metadata_analyzer = MetadataAnalyzer()
certificate_generator = CertificateGenerator(Config.CERTIFICATES_FOLDER)
c2pa_service = C2PAProvenanceService()
soft_binding_service = SoftBindingService()


# ─── WebSocket Live Progress Connection Manager ────────────
class ConnectionManager:
    """Manages real-time forensic progress WebSocket streaming."""
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}

    async def connect(self, client_id: str, websocket: WebSocket):
        await websocket.accept()
        self.active_connections[client_id] = websocket

    def disconnect(self, client_id: str):
        if client_id in self.active_connections:
            del self.active_connections[client_id]

    async def send_progress(self, client_id: str, stage: str, percent: int, detail: str):
        if client_id and client_id in self.active_connections:
            try:
                await self.active_connections[client_id].send_json({
                    "type": "progress",
                    "stage": stage,
                    "percent": percent,
                    "detail": detail
                })
            except Exception:
                pass

ws_manager = ConnectionManager()


# ─── Lifespan ──────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize resources and database on startup."""
    global Session, forgery_detector
    Config.init_app()
    session_factory = init_db(DB_PATH)
    Session = session_factory
    forgery_detector = await run_in_threadpool(ForgeryDetector, ela_quality=Config.ELA_QUALITY, ela_scale=Config.ELA_SCALE)
    print("[OK] ImageGuard v2 initialized with signed local audit checkpoints and unverified metadata.")
    yield
    session_factory.kw["bind"].dispose()
    print("[STOP] ImageGuard shutting down.")


# ─── App ───────────────────────────────────────────────────
app = FastAPI(
    title="ImageGuard v2",
    description="Experimental image signals, exact-byte signatures, unverified metadata, and signed local audit checkpoints",
    version="2.0.0",
    lifespan=lifespan,
)

# Mount static files
app.add_middleware(AccessControlMiddleware)
for name, directory in [('css', os.path.join(BASE_DIR, 'static', 'css')), ('js', os.path.join(BASE_DIR, 'static', 'js')),
                        ('uploads', Config.UPLOAD_FOLDER), ('results', Config.RESULTS_FOLDER), ('certificates', Config.CERTIFICATES_FOLDER)]:
    app.mount('/static/' + name, StaticFiles(directory=directory), name=name)

write_lock = asyncio.Lock()

@app.middleware('http')
async def serialize_mutations(request, call_next):
    # Single-process workbench: bounded work admission avoids unbounded inference
    # queues and serializes filesystem/database audit updates.
    if request.method in ('POST', 'DELETE', 'PUT', 'PATCH') or request.url.path.startswith('/api/certificate/'):
        if write_lock.locked():
            return JSONResponse({'detail': 'Workbench is busy; retry shortly'}, status_code=429, headers={'Retry-After': '2'})
        async with write_lock:
            return await call_next(request)
    return await call_next(request)

@app.exception_handler(LedgerIntegrityError)
async def ledger_error(request, exc):
    return JSONResponse({'detail': str(exc)}, status_code=409)

@app.get('/api/health')
async def health():
    analyzer = getattr(forgery_detector, 'deep_analyzer', None)
    return {'status': 'ready' if forgery_detector else 'starting',
            'access_mode': 'authenticated_operator' if Config.ADMIN_PASSWORD else 'loopback_only',
            'forensic_scores_calibrated': False,
            'neural_available': bool(analyzer and analyzer.onnx_available)}
app.mount("/uploads", StaticFiles(directory=Config.UPLOAD_FOLDER), name="uploads")

# Templates
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))


# ─── Helper ────────────────────────────────────────────────
def allowed_file(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS


# ═══════════════════════════════════════════════════════════
#  WEBSOCKET: LIVE FORENSIC PIPELINE STEPPER
# ═══════════════════════════════════════════════════════════
async def read_validated_image(file):
    if not file.filename or len(file.filename) > 255 or not allowed_file(file.filename):
        raise HTTPException(400, 'Unsupported image extension')
    raw = await file.read(Config.MAX_CONTENT_LENGTH + 1)
    if len(raw) > Config.MAX_CONTENT_LENGTH:
        raise HTTPException(413, 'Image exceeds 16 MB upload limit')
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('error', Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(raw)) as image:
                expected = {'jpg': 'JPEG', 'jpeg': 'JPEG', 'png': 'PNG', 'webp': 'WEBP', 'bmp': 'BMP', 'tiff': 'TIFF'}
                if image.format != expected[file.filename.rsplit('.', 1)[1].lower()]:
                    raise ValueError('File extension does not match image format')
                if image.width * image.height > Config.MAX_IMAGE_PIXELS:
                    raise HTTPException(413, 'Decoded image exceeds pixel limit')
                if min(image.size) < 64 or getattr(image, 'n_frames', 1) != 1:
                    raise ValueError('Use a single-frame image at least 64 by 64 pixels')
                image.verify()
    except HTTPException:
        raise
    except (OSError, ValueError, UnidentifiedImageError, Image.DecompressionBombError, Image.DecompressionBombWarning) as exc:
        raise HTTPException(400, 'Invalid or unsupported image') from exc
    return raw


def normalize_public_key(pem):
    try:
        key = serialization.load_pem_public_key(pem.encode())
        if not isinstance(key, rsa.RSAPublicKey) or not 2048 <= key.key_size <= 4096:
            raise ValueError('Unsupported key')
        return key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    except (ValueError, TypeError) as exc:
        raise HTTPException(400, 'Provide a valid RSA public key (2048?4096 bits)') from exc


def ensure_file_integrity(record):
    path = Path(Config.UPLOAD_FOLDER) / record.filename
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != record.file_hash:
        raise HTTPException(409, 'Stored image bytes differ from the recorded hash')
    return raw


@app.websocket("/ws/analyze/{client_id}")
async def websocket_analyze(websocket: WebSocket, client_id: str):
    """6-stage live progress stream for deep neural & spectral forensics."""
    await ws_manager.connect(client_id, websocket)
    try:
        while True:
            # Keep connection open for client messages or heartbeats
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(client_id)
    except Exception:
        ws_manager.disconnect(client_id)


# ═══════════════════════════════════════════════════════════
#  PAGES
# ═══════════════════════════════════════════════════════════
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Serve the main SPA page."""
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"}
    )


# ═══════════════════════════════════════════════════════════
#  API: IMAGE UPLOAD & MULTI-BRANCH FORGERY DETECTION
# ═══════════════════════════════════════════════════════════
@app.post("/api/analyze")
async def analyze_image(
    file: UploadFile = File(...),
    client_id: Optional[str] = Form(None)
):
    """
    Upload an image for comprehensive v2 multi-branch forgery analysis:
    ELA, 30-filter SRM steganalysis, 2D FFT radial spectrum, ONNX synthetic classification,
    perceptual dHash, and C2PA Content Credentials extraction.
    """
    if not file.filename or not allowed_file(file.filename):
        raise HTTPException(status_code=400, detail="Invalid file type. Allowed: PNG, JPG, JPEG, BMP, TIFF, WEBP")

    image_bytes = await read_validated_image(file)
    file_size = len(image_bytes)

    if file_size > Config.MAX_CONTENT_LENGTH:
        raise HTTPException(status_code=400, detail="File too large. Maximum: 16 MB")

    ext = file.filename.rsplit('.', 1)[1].lower()
    unique_name = f"{uuid.uuid4().hex}.{ext}"
    upload_path = os.path.join(Config.UPLOAD_FOLDER, unique_name)

    with open(upload_path, 'wb') as f:
        f.write(image_bytes)

    try:
        # Progress callback hook for WebSocket stepper
        loop = asyncio.get_event_loop()
        def sync_progress(stage, percent, detail):
            if client_id:
                asyncio.run_coroutine_threadsafe(
                    ws_manager.send_progress(client_id, stage, percent, detail),
                    loop
                )

        # 1. Metadata & C2PA analysis
        metadata_report = await run_in_threadpool(metadata_analyzer.get_full_report, image_bytes, file_path=upload_path)
        has_camera = metadata_report.get('analysis', {}).get('has_camera_info', False)

        # 2. Multi-Branch Forgery detection
        forgery_results = await run_in_threadpool(forgery_detector.full_analysis,
            image_bytes, Config.UPLOAD_FOLDER, Config.RESULTS_FOLDER,
            unique_name.rsplit('.', 1)[0],
            progress_callback=sync_progress,
            has_camera=has_camera,
            file_size_kb=file_size / 1024.0
        )

        # 3. Compute 64-bit Perceptual dHash
        perceptual_dhash = soft_binding_service.compute_dhash(image_bytes)

        # 4. Save to database
        session = Session()
        try:
            shutil.copyfile(upload_path, os.path.join(Config.ORIGINALS_FOLDER, unique_name))
            from sqlalchemy import func
            # SQLite can reuse a deleted maximum row ID in legacy schemas.
            # Include retained events so image identities are never recycled.
            next_id = max(session.query(func.max(ImageRecord.id)).scalar() or 0,
                          session.query(func.max(AuditEvent.image_id)).scalar() or 0) + 1
            record = ImageRecord(
                id=next_id,
                filename=unique_name,
                original_storage_name=unique_name,
                original_file_hash=forgery_results['file_hash'],
                original_filename=file.filename,
                file_hash=forgery_results['file_hash'],
                file_size=file_size,
                width=forgery_results['width'],
                height=forgery_results['height'],
                authenticity_score=forgery_results['authenticity_score'],
                ela_score=forgery_results['ela_score'],
                noise_score=forgery_results['noise_score'],
                cnn_score=forgery_results['cnn_score'],
                fft_score=forgery_results.get('fft_score', 0.0),
                ai_generation_prob=forgery_results.get('ai_generation_prob', 0.0),
                perceptual_dhash=perceptual_dhash,
                is_authentic=forgery_results['is_authentic'],
                forgery_details=forgery_results['forgery_details'],
                heatmap_path=forgery_results['heatmap_path'],
                ela_image_path=forgery_results['ela_image_path'],
                saliency_map_path=forgery_results.get('saliency_map_path', ''),
                metadata_json=metadata_report['metadata_json'],
                metadata_score=metadata_report['metadata_score'],
                c2pa_manifest_json=json.dumps(metadata_report.get('c2pa', {}))
            )
            session.add(record)
            session.flush()

            merkle_info = MerkleAuditTree.append_event(session, record, 'analysis')
            session.commit()

            result = record.to_dict()
            result['verdict'] = forgery_results.get('verdict', 'Authentic Media' if record.is_authentic else 'Manipulated / Spliced Forgery')
            result['metadata_report'] = metadata_report
            result['spectral_slope'] = forgery_results.get('spectral_slope', 2.0)
            result['frequencies'] = forgery_results.get('frequencies', [])
            result['radial_bins'] = forgery_results.get('radial_bins', [])
            result['merkle_info'] = merkle_info
        finally:
            session.close()

        return JSONResponse(content={"status": "success", "data": result})

    except Exception as e:
        if os.path.exists(upload_path):
            os.remove(upload_path)
        logging.exception('Image analysis failed')
        original_path = Path(Config.ORIGINALS_FOLDER) / unique_name
        original_path.unlink(missing_ok=True)
        raise HTTPException(status_code=500, detail='Analysis failed; see server logs') from e


# ═══════════════════════════════════════════════════════════
#  API: DIGITAL SIGNATURES & ZERO-TRUST KEY CUSTODY
# ═══════════════════════════════════════════════════════════
@app.post('/api/keys/generate')
def generate_keys(owner_name: str = Form(...), owner_email: str = Form(''),
                  custody_mode: str = Form('SERVER_AES_GCM'), passphrase: str = Form(''),
                  public_key_pem: str = Form('')):
    if not owner_name.strip() or len(owner_name) > 120 or len(owner_email) > 254:
        raise HTTPException(400, 'Provide a name (1?120 characters) and valid-length email')
    if custody_mode not in ('SERVER_AES_GCM', 'CLIENT_WEBCRYPTO'):
        raise HTTPException(400, 'Unsupported key custody mode')
    if custody_mode == 'CLIENT_WEBCRYPTO':
        public = normalize_public_key(public_key_pem)
        key_data = dict(key_id=uuid.uuid4().hex, public_key_pem=public,
                        private_key_pem='CLIENT_WEBCRYPTO_NON_CUSTODIAL', is_envelope_encrypted=False)
    else:
        if len(passphrase) < 12:
            raise HTTPException(400, 'Use a passphrase of at least 12 characters')
        key_data = signature_service.generate_key_pair(owner_name.strip(), owner_email.strip(), custody_mode, passphrase)
    with Session() as session:
        record = KeyPair(key_id=key_data['key_id'], owner_name=owner_name.strip(), owner_email=owner_email.strip(),
                         public_key_pem=key_data['public_key_pem'], private_key_pem=key_data['private_key_pem'],
                         is_envelope_encrypted=key_data['is_envelope_encrypted'], custody_mode=custody_mode)
        session.add(record)
        session.commit()
        return {'status': 'success', 'data': record.to_dict()}


@app.get("/api/keys")
def list_keys():
    """List all available key pairs without leaking private keys."""
    session = Session()
    try:
        keys = session.query(KeyPair).filter(KeyPair.is_active == True).all()
        return JSONResponse(content={
            "status": "success",
            "data": [k.to_dict() for k in keys]
        })
    finally:
        session.close()


@app.get("/api/keys/{key_id}/export")
def export_key(key_id: str):
    """Export public key certificate for a registered key."""
    session = Session()
    try:
        key = session.query(KeyPair).filter(KeyPair.key_id == key_id).first()
        if not key:
            raise HTTPException(status_code=404, detail="Key pair not found")
        return JSONResponse(content={
            "status": "success",
            "data": {
                "key_id": key.key_id,
                "owner_name": key.owner_name,
                "owner_email": key.owner_email,
                "custody_mode": key.custody_mode,
                "public_key_pem": key.public_key_pem
            }
        })
    finally:
        session.close()


@app.post('/api/sign/{image_id}')
def sign_image(image_id: int, key_id: str = Form(...), passphrase: str = Form('')):
    staged = None
    with Session() as session:
        try:
            record = session.get(ImageRecord, image_id)
            key = session.query(KeyPair).filter_by(key_id=key_id, is_active=True).first()
            if not record or not key:
                raise HTTPException(404, 'Image or active signing key not found')
            if key.custody_mode != 'SERVER_AES_GCM':
                raise HTTPException(400, 'Use client signing for this key')
            if not key.is_envelope_encrypted or key.private_key_pem.lstrip().startswith('-----BEGIN'):
                raise HTTPException(409, 'Legacy plaintext keys cannot sign; create a new passphrase-protected key')
            if record.is_signed:
                raise HTTPException(409, 'Image is already signed; analyze a new copy to create a new version')
            MerkleAuditTree.require_valid_record(session, record)
            # Authenticate before any filesystem mutation.
            try:
                private = EnvelopeKeyVault.decrypt_private_key(key.private_key_pem, key.key_id, passphrase)
            except (InvalidTag, ValueError, KeyError):
                raise HTTPException(403, 'Signing credentials are invalid')
            original = ensure_file_integrity(record)
            packaged = soft_binding_service.embed_watermark(original, record.id)
            new_name = uuid.uuid4().hex + Path(record.filename).suffix
            staged = Path(Config.UPLOAD_FOLDER) / new_name
            staged.write_bytes(packaged)
            manifest = c2pa_service.build_c2pa_manifest(record.to_dict(), key.owner_name, key.key_id, json.loads(record.forgery_details))
            c2pa_service.embed_manifest_in_file(str(staged), manifest)
            final = staged.read_bytes()
            signature = signature_service.sign_image(final, private)
            if not signature_service.verify_signature(final, signature['signature'], key.public_key_pem)['is_valid']:
                raise RuntimeError('Signature self-check failed')
            timestamp = c2pa_service.request_rfc3161_timestamp(signature['signature_bytes'])
            watermark = soft_binding_service.extract_watermark(final)
            record.filename = new_name
            record.file_hash = signature['image_hash']
            record.file_size = len(final)
            record.perceptual_dhash = soft_binding_service.compute_dhash(final)
            record.watermark_embedded = watermark.get('recovered_id') == record.id
            record.provenance_status = 'unverified_metadata'
            record.c2pa_manifest_json = json.dumps(manifest)
            record.timestamp_info = json.dumps(timestamp)
            record.rfc3161_tst_b64 = timestamp['rfc3161_tst_b64']
            record.is_signed = True
            record.signature = signature['signature']
            record.public_key_id = key.key_id
            record.signer_name = key.owner_name
            record.signed_date = datetime.utcnow()
            checkpoint = MerkleAuditTree.append_event(session, record, 'server_signing')
            session.commit()
            staged = None
            return {'status': 'success', 'data': {'image_id': record.id, 'signer': key.owner_name,
                    'signed_date': record.signed_date.isoformat(), 'watermark_embedded': record.watermark_embedded,
                    'has_rfc3161': timestamp['is_authoritative'], 'timestamp_status': timestamp['status'],
                    'provenance_status': record.provenance_status, 'merkle_root': checkpoint['root_hash'],
                    'message': 'Final derivative signed; original retained. Analysis metadata is unverified.'}}
        except Exception:
            session.rollback()
            if staged is not None:
                staged.unlink(missing_ok=True)
            raise


@app.post('/api/sign-client/{image_id}')
def sign_image_client(image_id: int, signature_b64: str = Form(...), public_key_pem: str = Form(...),
                      signer_name: str = Form(...), key_id: str = Form(...)):
    with Session() as session:
        record = session.get(ImageRecord, image_id)
        key = session.query(KeyPair).filter_by(key_id=key_id, is_active=True).first()
        if not record or not key:
            raise HTTPException(404, 'Image or registered key not found')
        if record.is_signed:
            raise HTTPException(409, 'Image is already signed')
        if key.custody_mode != 'CLIENT_WEBCRYPTO' or normalize_public_key(public_key_pem) != key.public_key_pem or signer_name != key.owner_name:
            raise HTTPException(403, 'Signature identity does not match the registered browser key')
        MerkleAuditTree.require_valid_record(session, record)
        raw = ensure_file_integrity(record)
        verification = signature_service.verify_signature(raw, signature_b64, key.public_key_pem)
        if not verification['is_valid']:
            raise HTTPException(400, 'Client signature does not verify against these image bytes')
        # Detached client signing NEVER changes the bytes that were signed.
        import base64
        timestamp = c2pa_service.request_rfc3161_timestamp(base64.b64decode(signature_b64, validate=True))
        record.signature, record.is_signed = signature_b64, True
        record.public_key_id, record.signer_name = key.key_id, key.owner_name
        record.signed_date = datetime.utcnow()
        record.timestamp_info = json.dumps(timestamp)
        record.rfc3161_tst_b64 = timestamp['rfc3161_tst_b64']
        checkpoint = MerkleAuditTree.append_event(session, record, 'client_signing')
        session.commit()
        return {'status': 'success', 'data': {'image_id': record.id, 'signer': key.owner_name,
                'pss_mode': verification['pss_mode'], 'merkle_root': checkpoint['root_hash'],
                'message': 'Detached browser signature verified; image bytes preserved.'}}


@app.post('/api/images/{image_id}/import-legacy')
def import_legacy(image_id: int):
    """Explicitly anchor current legacy state; makes no claim about past integrity."""
    with Session() as session:
        record = session.get(ImageRecord, image_id)
        if not record:
            raise HTTPException(404, 'Image not found')
        if MerkleAuditTree.verify_record(session, record)['ledger_status'] != 'legacy_unanchored':
            raise HTTPException(409, 'Only unanchored legacy records can be imported')
        ensure_file_integrity(record)
        checkpoint = MerkleAuditTree.append_event(session, record, 'legacy_import')
        session.commit()
        return {'status': 'success', 'data': checkpoint, 'message': 'Current state anchored; prior history remains unverified.'}


@app.get('/api/images/{image_id}/original')
def original_image(image_id: int):
    with Session() as session:
        record = session.get(ImageRecord, image_id)
        if not record or not record.original_storage_name:
            raise HTTPException(404, 'No preserved original is available for this record')
        return FileResponse(Path(Config.ORIGINALS_FOLDER) / record.original_storage_name,
                            filename=record.original_filename)


@app.post("/api/verify-signature/{image_id}")
def verify_image_signature(image_id: int):
    """
    Verify the digital signature of a signed image.
    Uses Dual-Mode RSA-PSS to verify both backend and WebCrypto signatures.
    """
    session = Session()
    try:
        record = session.query(ImageRecord).filter(ImageRecord.id == image_id).first()
        if not record:
            raise HTTPException(status_code=404, detail="Image not found")

        if not record.is_signed:
            raise HTTPException(status_code=400, detail="Image has not been signed")

        key_pair = session.query(KeyPair).filter(KeyPair.key_id == record.public_key_id).first()
        if not key_pair:
            raise HTTPException(status_code=404, detail="Signing key not found")

        image_path = os.path.join(Config.UPLOAD_FOLDER, record.filename)
        with open(image_path, 'rb') as f:
            image_bytes = f.read()

        verification = signature_service.verify_signature(
            image_bytes, record.signature, key_pair.public_key_pem
        )

        return JSONResponse(content={
            "status": "success",
            "data": {
                "image_id": image_id,
                "signer": record.signer_name,
                **verification
            }
        })
    finally:
        session.close()


@app.post("/api/verify")
async def verify_uploaded_file(file: UploadFile = File(...)):
    """
    Verify an uploaded image against existing signed records in the ledger.
    """
    if not file.filename or not allowed_file(file.filename):
        raise HTTPException(status_code=400, detail="Invalid image format")

    image_bytes = await read_validated_image(file)
    file_hash = hashlib.sha256(image_bytes).hexdigest()

    session = Session()
    try:
        record = session.query(ImageRecord).filter(ImageRecord.file_hash == file_hash).first()
        if not record:
            query_dhash = await run_in_threadpool(soft_binding_service.compute_dhash, image_bytes)
            wm_result = await run_in_threadpool(soft_binding_service.extract_watermark, image_bytes)
            if wm_result.get('is_valid') and wm_result.get('recovered_id'):
                record = session.query(ImageRecord).filter(ImageRecord.id == wm_result['recovered_id']).first()

        if not record:
            return JSONResponse(status_code=404, content={
                "status": "not_found",
                "message": "No matching record found in the transparency ledger.",
                "file_hash": file_hash
            })

        if not record.is_signed:
            return JSONResponse(content={
                "status": "success",
                "data": {
                    "image_id": record.id,
                    "is_signed": False,
                    "is_valid": False,
                    "message": "Image is recorded in the ledger but has not been digitally signed.",
                    "file_hash": file_hash,
                    "authenticity_score": record.authenticity_score
                }
            })

        key_pair = session.query(KeyPair).filter(KeyPair.key_id == record.public_key_id).first()
        pub_key = key_pair.public_key_pem if key_pair else ""

        verification = signature_service.verify_signature(image_bytes, record.signature, pub_key)
        return JSONResponse(content={
            "status": "success",
            "data": {
                "image_id": record.id,
                "is_signed": True,
                "signer": record.signer_name,
                "file_hash": file_hash,
                "authenticity_score": record.authenticity_score,
                **verification
            }
        })
    finally:
        session.close()


# ═══════════════════════════════════════════════════════════
#  API: SOFT-BINDING PROVENANCE RECOVERY & ATTACK SIMULATOR
# ═══════════════════════════════════════════════════════════
@app.post("/api/recover-provenance")
async def recover_provenance(file: UploadFile = File(...)):
    """
    Accept any stripped or re-compressed derivative image.
    Extracts 64-bit frequency watermark and perceptual dHash to locate original
    canonical master record, and returns tamper-diff localization overlay.
    """
    if not file.filename or not allowed_file(file.filename):
        raise HTTPException(status_code=400, detail="Invalid image file format")

    image_bytes = await read_validated_image(file)
    query_dhash = await run_in_threadpool(soft_binding_service.compute_dhash, image_bytes)
    wm_result = await run_in_threadpool(soft_binding_service.extract_watermark, image_bytes)

    session = Session()
    try:
        master_record = None

        # Strategy 1: Exact watermark match
        if wm_result.get('is_valid') and wm_result.get('recovered_id'):
            rec_id = wm_result['recovered_id']
            master_record = session.query(ImageRecord).filter(ImageRecord.id == rec_id).first()

        # Strategy 2: Perceptual dHash minimum Hamming distance <= 10
        if not master_record:
            signed_records = session.query(ImageRecord).filter(ImageRecord.is_signed == True).all()
            best_dist = 64
            best_candidate = None

            for r in signed_records:
                if r.perceptual_dhash:
                    dist = soft_binding_service.hamming_distance(query_dhash, r.perceptual_dhash)
                    if dist < best_dist:
                        best_dist = dist
                        best_candidate = r

            if best_candidate and best_dist <= 10:
                master_record = best_candidate

        if not master_record:
            raise HTTPException(
                status_code=404,
                detail="No matching master record found. The image has no valid ImageGuard watermark and exceeds dHash threshold (dH > 10)."
            )

        # Localize tampering against master image
        master_path = os.path.join(Config.UPLOAD_FOLDER, master_record.filename)
        with open(master_path, 'rb') as f:
            master_bytes = f.read()

        diff_filename = f"diff_recover_{uuid.uuid4().hex[:8]}.png"
        diff_path = os.path.join(Config.RESULTS_FOLDER, diff_filename)

        tamper_info = await run_in_threadpool(soft_binding_service.localize_tampering,
            master_image_bytes=master_bytes,
            derivative_image_bytes=image_bytes,
            save_diff_path=diff_path
        )

        hamming_dist = soft_binding_service.hamming_distance(query_dhash, master_record.perceptual_dhash or "")

        return JSONResponse(content={
            "status": "success",
            "data": {
                "recovered_master_id": master_record.id,
                "match_status": "candidate_only",
                "provenance_verified": False,
                "original_filename": master_record.original_filename,
                "signer_name": master_record.signer_name,
                "signed_date": master_record.signed_date.isoformat() if master_record.signed_date else None,
                "authenticity_score": master_record.authenticity_score,
                "hamming_distance": hamming_dist,
                "watermark_recovered": wm_result.get('is_valid', False),
                "tamper_detected": tamper_info['is_tampered'],
                "pixel_change_percentage": tamper_info['pixel_change_percentage'],
                "diff_overlay_url": f"/static/results/{diff_filename}"
            }
        })
    finally:
        session.close()


@app.post("/api/simulate-attack/{image_id}")
def simulate_attack(image_id: int):
    """
    Execute 3 controlled adversarial perturbations on a signed image:
    1. whatsapp_compress: EXIF/JUMBF strip + heavy JPEG QF 70 re-encode
    2. color_shift: Contrast & luminance shift
    3. pixel_splice: Localized synthetic patch injection
    Demonstrates that Hard Binding (SHA-256) breaks across all 3,
    while Soft Binding (watermark + dHash) survives and isolates tamper.
    """
    session = Session()
    try:
        record = session.query(ImageRecord).filter(ImageRecord.id == image_id).first()
        if not record:
            raise HTTPException(status_code=404, detail="Image not found")

        image_path = os.path.join(Config.UPLOAD_FOLDER, record.filename)
        with open(image_path, 'rb') as f:
            master_bytes = f.read()

        base_name = record.filename.rsplit('.', 1)[0]
        results = {}

        # 1. WhatsApp Compression
        wa_bytes = soft_binding_service.apply_attack(master_bytes, 'whatsapp_compress')
        wa_hash = hashlib.sha256(wa_bytes).hexdigest()
        wa_dhash = soft_binding_service.compute_dhash(wa_bytes)
        wa_dh_dist = soft_binding_service.hamming_distance(wa_dhash, record.perceptual_dhash)
        wa_wm = soft_binding_service.extract_watermark(wa_bytes)

        wa_filename = f"attack_wa_{base_name}.jpg"
        with open(os.path.join(Config.RESULTS_FOLDER, wa_filename), 'wb') as f:
            f.write(wa_bytes)

        results['whatsapp_compress'] = {
            "attack_name": "WhatsApp Re-Compression & Strip",
            "description": "Strips all EXIF/JUMBF C2PA metadata and recompresses to JPEG Quality Factor 70",
            "hard_binding_valid": (wa_hash == record.file_hash),
            "soft_binding_recovered": (wa_dh_dist <= 10 or (wa_wm.get('is_valid') and wa_wm.get('recovered_id') == image_id)),
            "hamming_distance": wa_dh_dist,
            "watermark_intact": wa_wm.get('is_valid', False),
            "attacked_image_url": f"/static/results/{wa_filename}"
        }

        # 2. Color Shift
        color_bytes = soft_binding_service.apply_attack(master_bytes, 'color_shift')
        color_hash = hashlib.sha256(color_bytes).hexdigest()
        color_dhash = soft_binding_service.compute_dhash(color_bytes)
        color_dh_dist = soft_binding_service.hamming_distance(color_dhash, record.perceptual_dhash)
        color_wm = soft_binding_service.extract_watermark(color_bytes)

        color_filename = f"attack_color_{base_name}.jpg"
        with open(os.path.join(Config.RESULTS_FOLDER, color_filename), 'wb') as f:
            f.write(color_bytes)

        results['color_shift'] = {
            "attack_name": "Luminance & Contrast Shift",
            "description": "Performs gamma and color profile adjustments",
            "hard_binding_valid": (color_hash == record.file_hash),
            "soft_binding_recovered": (color_dh_dist <= 10 or (color_wm.get('is_valid') and color_wm.get('recovered_id') == image_id)),
            "hamming_distance": color_dh_dist,
            "watermark_intact": color_wm.get('is_valid', False),
            "attacked_image_url": f"/static/results/{color_filename}"
        }

        # 3. Pixel Splice
        splice_bytes = soft_binding_service.apply_attack(master_bytes, 'pixel_splice')
        splice_hash = hashlib.sha256(splice_bytes).hexdigest()
        splice_dhash = soft_binding_service.compute_dhash(splice_bytes)
        splice_dh_dist = soft_binding_service.hamming_distance(splice_dhash, record.perceptual_dhash)
        splice_wm = soft_binding_service.extract_watermark(splice_bytes)

        splice_filename = f"attack_splice_{base_name}.jpg"
        splice_diff_filename = f"attack_splice_diff_{base_name}.png"
        with open(os.path.join(Config.RESULTS_FOLDER, splice_filename), 'wb') as f:
            f.write(splice_bytes)

        tamper_info = soft_binding_service.localize_tampering(
            master_image_bytes=master_bytes,
            derivative_image_bytes=splice_bytes,
            save_diff_path=os.path.join(Config.RESULTS_FOLDER, splice_diff_filename)
        )

        results['pixel_splice'] = {
            "attack_name": "Localized Synthetic Patch Splice",
            "description": "Injects an artificial synthetic patch into image pixels",
            "hard_binding_valid": (splice_hash == record.file_hash),
            "soft_binding_recovered": (splice_dh_dist <= 10 or (splice_wm.get('is_valid') and splice_wm.get('recovered_id') == image_id)),
            "hamming_distance": splice_dh_dist,
            "watermark_intact": splice_wm.get('is_valid', False),
            "tamper_detected": tamper_info['is_tampered'],
            "pixel_change_percentage": tamper_info['pixel_change_percentage'],
            "attacked_image_url": f"/static/results/{splice_filename}",
            "diff_overlay_url": f"/static/results/{splice_diff_filename}"
        }

        return JSONResponse(content={
            "status": "success",
            "data": {
                "image_id": image_id,
                "original_filename": record.original_filename,
                "canonical_file_hash": record.file_hash,
                "attacks": results
            }
        })
    finally:
        session.close()


# ═══════════════════════════════════════════════════════════
#  API: CERTIFICATES & MERKLE INCLUSION PROOFS
# ═══════════════════════════════════════════════════════════
@app.api_route("/api/certificate/{image_id}", methods=["GET", "POST"])
def generate_certificate(image_id: int):
    """Generate or retrieve a PDF ownership certificate for an image with Merkle proofs."""
    session = Session()
    try:
        record = session.query(ImageRecord).filter(ImageRecord.id == image_id).first()
        if not record:
            raise HTTPException(status_code=404, detail="Image not found")

        MerkleAuditTree.require_valid_record(session, record)
        ensure_file_integrity(record)
        # Get latest Merkle checkpoint info
        latest_cp = session.query(MerkleCheckpoint).order_by(MerkleCheckpoint.id.desc()).first()
        merkle_info = {
            "root_hash": latest_cp.root_hash if latest_cp else record.merkle_leaf_hash,
            "tree_size": latest_cp.tree_size if latest_cp else 1
        }

        image_path = os.path.join(Config.UPLOAD_FOLDER, record.filename)
        report_data = record.to_dict()
        report_data['signature_valid'] = False
        if record.is_signed:
            key = session.query(KeyPair).filter_by(key_id=record.public_key_id).first()
            report_data['signature_valid'] = bool(key and signature_service.verify_signature(
                Path(image_path).read_bytes(), record.signature, key.public_key_pem)['is_valid'])
        cert_path = certificate_generator.generate_certificate(
            report_data, image_path, base_url=Config.PUBLIC_BASE_URL, merkle_info=merkle_info
        )

        record.certificate_path = os.path.basename(cert_path)
        session.commit()

        return FileResponse(
            path=cert_path,
            filename=os.path.basename(cert_path),
            media_type='application/pdf'
        )
    finally:
        session.close()


# ═══════════════════════════════════════════════════════════
#  API: DASHBOARD & HISTORY
# ═══════════════════════════════════════════════════════════
@app.get("/api/images")
@app.get("/api/records")
def list_images():
    """Get all analyzed images for the dashboard."""
    session = Session()
    try:
        records = session.query(ImageRecord).order_by(ImageRecord.upload_date.desc()).all()
        return JSONResponse(content={
            "status": "success",
            "data": [r.to_dict() for r in records]
        })
    finally:
        session.close()


@app.get("/api/images/{image_id}")
@app.get("/api/records/{image_id}")
def get_image(image_id: int):
    """Get a specific image record with full details and Merkle inclusion proof."""
    session = Session()
    try:
        record = session.query(ImageRecord).filter(ImageRecord.id == image_id).first()
        if not record:
            raise HTTPException(status_code=404, detail="Image not found")

        data = record.to_dict()

        try:
            data['forgery_details_parsed'] = json.loads(data['forgery_details'])
        except Exception:
            data['forgery_details_parsed'] = {}

        try:
            data['metadata_parsed'] = json.loads(data['metadata_json'])
        except Exception:
            data['metadata_parsed'] = {}

        try:
            data['c2pa_parsed'] = json.loads(data['c2pa_manifest_json'])
        except Exception:
            data['c2pa_parsed'] = {}

        data.update(MerkleAuditTree.verify_record(session, record))

        return JSONResponse(content={"status": "success", "data": data})
    finally:
        session.close()


@app.delete("/api/images/{image_id}")
@app.delete("/api/records/{image_id}")
def delete_image(image_id: int):
    """Delete an image record and its associated files."""
    session = Session()
    try:
        record = session.query(ImageRecord).filter(ImageRecord.id == image_id).first()
        if not record:
            raise HTTPException(status_code=404, detail="Image not found")

        MerkleAuditTree.require_valid_record(session, record)
        MerkleAuditTree.append_event(session, record, 'deletion')
        paths = [Path(Config.UPLOAD_FOLDER) / record.filename]
        if record.original_storage_name:
            paths += [Path(Config.ORIGINALS_FOLDER) / record.original_storage_name,
                      Path(Config.UPLOAD_FOLDER) / record.original_storage_name]
        for artifact in [record.ela_image_path, record.heatmap_path, record.saliency_map_path]:
            if artifact:
                paths.append(Path(Config.RESULTS_FOLDER) / Path(artifact).name)
        if record.certificate_path:
            paths.append(Path(Config.CERTIFICATES_FOLDER) / record.certificate_path)
        session.delete(record)
        session.commit()
        for path in paths:
            path.unlink(missing_ok=True)

        return JSONResponse(content={"status": "success", "message": "Image deleted and Merkle ledger updated"})
    finally:
        session.close()


@app.get("/api/stats")
def get_stats():
    """Get dashboard statistics including Merkle and AI metrics."""
    session = Session()
    try:
        from sqlalchemy import func
        total = session.query(ImageRecord).count()
        authentic = session.query(ImageRecord).filter(ImageRecord.is_authentic == True).count()
        forged = session.query(ImageRecord).filter(ImageRecord.is_authentic == False).count()
        signed = session.query(ImageRecord).filter(ImageRecord.is_signed == True).count()

        avg_auth = session.query(func.avg(ImageRecord.authenticity_score)).scalar() or 0
        avg_ela = session.query(func.avg(ImageRecord.ela_score)).scalar() or 0
        avg_noise = session.query(func.avg(ImageRecord.noise_score)).scalar() or 0
        avg_cnn = session.query(func.avg(ImageRecord.cnn_score)).scalar() or 0
        avg_fft = session.query(func.avg(ImageRecord.fft_score)).scalar() or 0

        latest_cp = session.query(MerkleCheckpoint).order_by(MerkleCheckpoint.id.desc()).first()

        return JSONResponse(content={
            "status": "success",
            "data": {
                "total_images": total,
                "authentic_count": authentic,
                "forged_count": forged,
                "signed_count": signed,
                "avg_authenticity": round(avg_auth, 1),
                "avg_ela": round(avg_ela, 1),
                "avg_noise": round(avg_noise, 1),
                "avg_cnn": round(avg_cnn, 1),
                "avg_fft": round(avg_fft, 1),
                "merkle_root": latest_cp.root_hash if latest_cp else "GENESIS",
                "merkle_tree_size": latest_cp.tree_size if latest_cp else total,
            }
        })
    finally:
        session.close()


# ═══════════════════════════════════════════════════════════
#  API: VERIFICATION PAGE
# ═══════════════════════════════════════════════════════════
@app.get("/verify/{image_id}")
async def verify_page(
    image_id: int,
    request: Request,
    format: Optional[str] = Query(None)
):
    """Public verification page for an image with Merkle transparency proofs."""
    session = Session()
    try:
        record = session.query(ImageRecord).filter(ImageRecord.id == image_id).first()
        if not record:
            raise HTTPException(status_code=404, detail="Image record not found in ledger")
        data = record.to_dict()

        if format == 'json' or request.headers.get('accept') == 'application/json':
            audit = MerkleAuditTree.verify_record(session, record)
            return JSONResponse({'status': 'success', 'data': {**data, **audit,
                                 'proof_length': len(audit['merkle_proof'])}})
    finally:
        session.close()

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"verify_id": image_id},
        headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"}
    )


# ─── Run ───────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)
