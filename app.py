"""
ImageGuard - Digital Image Authenticity & Ownership Verification System
FastAPI Application Entry Point
"""

import os
import uuid
import json
from datetime import datetime
from contextlib import asynccontextmanager

from fastapi import FastAPI, File, UploadFile, Form, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from config import Config
from models.database import init_db, ImageRecord, KeyPair
from services.forgery_detection import ForgeryDetector
from services.digital_signature import DigitalSignatureService
from services.metadata_analyzer import MetadataAnalyzer
from services.certificate_gen import CertificateGenerator


# ─── Globals ───────────────────────────────────────────────
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, 'instance', 'imageguard.db')

Session = None
forgery_detector = ForgeryDetector(ela_quality=Config.ELA_QUALITY, ela_scale=Config.ELA_SCALE)
signature_service = DigitalSignatureService(key_size=Config.RSA_KEY_SIZE)
metadata_analyzer = MetadataAnalyzer()
certificate_generator = CertificateGenerator(Config.CERTIFICATES_FOLDER)


# ─── Lifespan ──────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize resources on startup."""
    global Session
    # Create directories
    for folder in [Config.UPLOAD_FOLDER, Config.RESULTS_FOLDER,
                   Config.CERTIFICATES_FOLDER, Config.KEYS_FOLDER,
                   os.path.join(BASE_DIR, 'instance')]:
        os.makedirs(folder, exist_ok=True)
    # Init database
    Session = init_db(DB_PATH)
    print("[OK] ImageGuard initialized successfully!")
    yield
    print("[STOP] ImageGuard shutting down.")


# ─── App ───────────────────────────────────────────────────
app = FastAPI(
    title="ImageGuard",
    description="Digital Image Authenticity & Ownership Verification System",
    version="1.0.0",
    lifespan=lifespan,
)

# Mount static files
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")

# Templates
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))


# ─── Helper ────────────────────────────────────────────────
def allowed_file(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS


# ═══════════════════════════════════════════════════════════
#  PAGES
# ═══════════════════════════════════════════════════════════

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Serve the main SPA page."""
    return templates.TemplateResponse("index.html", {"request": request})


# ═══════════════════════════════════════════════════════════
#  API: IMAGE UPLOAD & FORGERY DETECTION
# ═══════════════════════════════════════════════════════════

@app.post("/api/analyze")
async def analyze_image(file: UploadFile = File(...)):
    """
    Upload an image for comprehensive forgery analysis.
    Performs ELA, noise analysis, CNN classification, and metadata extraction.
    """
    if not file.filename or not allowed_file(file.filename):
        raise HTTPException(status_code=400, detail="Invalid file type. Allowed: PNG, JPG, JPEG, BMP, TIFF, WEBP")

    # Read file
    image_bytes = await file.read()
    file_size = len(image_bytes)

    if file_size > Config.MAX_CONTENT_LENGTH:
        raise HTTPException(status_code=400, detail="File too large. Maximum: 16 MB")

    # Generate unique filename
    ext = file.filename.rsplit('.', 1)[1].lower()
    unique_name = f"{uuid.uuid4().hex[:12]}.{ext}"
    upload_path = os.path.join(Config.UPLOAD_FOLDER, unique_name)

    # Save uploaded file
    with open(upload_path, 'wb') as f:
        f.write(image_bytes)

    try:
        # 1. Forgery detection
        forgery_results = forgery_detector.full_analysis(
            image_bytes, Config.UPLOAD_FOLDER, Config.RESULTS_FOLDER,
            unique_name.rsplit('.', 1)[0]
        )

        # 2. Metadata analysis
        metadata_report = metadata_analyzer.get_full_report(image_bytes)

        # 3. Save to database
        session = Session()
        try:
            record = ImageRecord(
                filename=unique_name,
                original_filename=file.filename,
                file_hash=forgery_results['file_hash'],
                file_size=file_size,
                width=forgery_results['width'],
                height=forgery_results['height'],
                authenticity_score=forgery_results['authenticity_score'],
                ela_score=forgery_results['ela_score'],
                noise_score=forgery_results['noise_score'],
                cnn_score=forgery_results['cnn_score'],
                is_authentic=forgery_results['is_authentic'],
                forgery_details=forgery_results['forgery_details'],
                heatmap_path=forgery_results['heatmap_path'],
                ela_image_path=forgery_results['ela_image_path'],
                metadata_json=metadata_report['metadata_json'],
                metadata_score=metadata_report['metadata_score'],
            )
            session.add(record)
            session.commit()

            result = record.to_dict()
            result['metadata_report'] = metadata_report
        finally:
            session.close()

        return JSONResponse(content={"status": "success", "data": result})

    except Exception as e:
        # Clean up on error
        if os.path.exists(upload_path):
            os.remove(upload_path)
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


# ═══════════════════════════════════════════════════════════
#  API: DIGITAL SIGNATURES
# ═══════════════════════════════════════════════════════════

@app.post("/api/keys/generate")
async def generate_keys(owner_name: str = Form(...), owner_email: str = Form('')):
    """Generate a new RSA key pair for a user."""
    if not owner_name.strip():
        raise HTTPException(status_code=400, detail="Owner name is required")

    key_data = signature_service.generate_key_pair(owner_name.strip(), owner_email.strip())

    session = Session()
    try:
        key_record = KeyPair(
            key_id=key_data['key_id'],
            owner_name=key_data['owner_name'],
            owner_email=key_data['owner_email'],
            public_key_pem=key_data['public_key_pem'],
            private_key_pem=key_data['private_key_pem'],
        )
        session.add(key_record)
        session.commit()

        result = key_record.to_dict()
        result['private_key_pem'] = key_data['private_key_pem']  # Include for download
    finally:
        session.close()

    return JSONResponse(content={"status": "success", "data": result})


@app.get("/api/keys")
async def list_keys():
    """List all available key pairs."""
    session = Session()
    try:
        keys = session.query(KeyPair).filter(KeyPair.is_active == True).all()
        return JSONResponse(content={
            "status": "success",
            "data": [k.to_dict() for k in keys]
        })
    finally:
        session.close()


@app.post("/api/sign/{image_id}")
async def sign_image(image_id: int, key_id: str = Form(...)):
    """Sign an image with a user's private key to claim ownership."""
    session = Session()
    try:
        record = session.query(ImageRecord).filter(ImageRecord.id == image_id).first()
        if not record:
            raise HTTPException(status_code=404, detail="Image not found")

        key_pair = session.query(KeyPair).filter(KeyPair.key_id == key_id).first()
        if not key_pair:
            raise HTTPException(status_code=404, detail="Key pair not found")

        # Read the image file
        image_path = os.path.join(Config.UPLOAD_FOLDER, record.filename)
        with open(image_path, 'rb') as f:
            image_bytes = f.read()

        # Sign
        sig_result = signature_service.sign_image(image_bytes, key_pair.private_key_pem)

        # Update record
        record.is_signed = True
        record.signature = sig_result['signature']
        record.public_key_id = key_pair.key_id
        record.signer_name = key_pair.owner_name
        record.signed_date = datetime.utcnow()
        session.commit()

        return JSONResponse(content={
            "status": "success",
            "data": {
                "image_id": image_id,
                "signature": sig_result['signature'][:50] + '...',
                "signer": key_pair.owner_name,
                "signed_date": sig_result['signed_date'],
                "message": "Image signed successfully!"
            }
        })
    finally:
        session.close()


@app.post("/api/verify-signature/{image_id}")
async def verify_image_signature(image_id: int):
    """Verify the digital signature of a signed image."""
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

        # Read current image
        image_path = os.path.join(Config.UPLOAD_FOLDER, record.filename)
        with open(image_path, 'rb') as f:
            image_bytes = f.read()

        # Verify
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


# ═══════════════════════════════════════════════════════════
#  API: CERTIFICATES
# ═══════════════════════════════════════════════════════════

@app.post("/api/certificate/{image_id}")
async def generate_certificate(image_id: int):
    """Generate a PDF ownership certificate for an image."""
    session = Session()
    try:
        record = session.query(ImageRecord).filter(ImageRecord.id == image_id).first()
        if not record:
            raise HTTPException(status_code=404, detail="Image not found")

        image_path = os.path.join(Config.UPLOAD_FOLDER, record.filename)
        cert_path = certificate_generator.generate_certificate(
            record.to_dict(), image_path
        )

        # Update record with certificate path
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
async def list_images():
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
async def get_image(image_id: int):
    """Get a specific image record with full details."""
    session = Session()
    try:
        record = session.query(ImageRecord).filter(ImageRecord.id == image_id).first()
        if not record:
            raise HTTPException(status_code=404, detail="Image not found")

        data = record.to_dict()

        # Parse JSON fields for response
        try:
            data['forgery_details_parsed'] = json.loads(data['forgery_details'])
        except:
            data['forgery_details_parsed'] = {}
        try:
            data['metadata_parsed'] = json.loads(data['metadata_json'])
        except:
            data['metadata_parsed'] = {}

        return JSONResponse(content={"status": "success", "data": data})
    finally:
        session.close()


@app.delete("/api/images/{image_id}")
async def delete_image(image_id: int):
    """Delete an image record and its associated files."""
    session = Session()
    try:
        record = session.query(ImageRecord).filter(ImageRecord.id == image_id).first()
        if not record:
            raise HTTPException(status_code=404, detail="Image not found")

        # Delete files
        for path in [
            os.path.join(Config.UPLOAD_FOLDER, record.filename),
            os.path.join(Config.RESULTS_FOLDER, f'{record.filename.rsplit(".", 1)[0]}_ela.png'),
            os.path.join(Config.RESULTS_FOLDER, f'{record.filename.rsplit(".", 1)[0]}_heatmap.png'),
        ]:
            if os.path.exists(path):
                os.remove(path)

        if record.certificate_path:
            cert_path = os.path.join(Config.CERTIFICATES_FOLDER, record.certificate_path)
            if os.path.exists(cert_path):
                os.remove(cert_path)

        session.delete(record)
        session.commit()

        return JSONResponse(content={"status": "success", "message": "Image deleted"})
    finally:
        session.close()


@app.get("/api/stats")
async def get_stats():
    """Get dashboard statistics."""
    session = Session()
    try:
        total = session.query(ImageRecord).count()
        authentic = session.query(ImageRecord).filter(ImageRecord.is_authentic == True).count()
        forged = session.query(ImageRecord).filter(ImageRecord.is_authentic == False).count()
        signed = session.query(ImageRecord).filter(ImageRecord.is_signed == True).count()

        # Average scores
        from sqlalchemy import func
        avg_auth = session.query(func.avg(ImageRecord.authenticity_score)).scalar() or 0
        avg_ela = session.query(func.avg(ImageRecord.ela_score)).scalar() or 0
        avg_noise = session.query(func.avg(ImageRecord.noise_score)).scalar() or 0
        avg_cnn = session.query(func.avg(ImageRecord.cnn_score)).scalar() or 0

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
            }
        })
    finally:
        session.close()


# ═══════════════════════════════════════════════════════════
#  API: VERIFICATION PAGE
# ═══════════════════════════════════════════════════════════

@app.get("/verify/{image_id}")
async def verify_page(image_id: int, request: Request):
    """Public verification page for an image."""
    session = Session()
    try:
        record = session.query(ImageRecord).filter(ImageRecord.id == image_id).first()
        if not record:
            raise HTTPException(status_code=404, detail="Image not found")
        data = record.to_dict()
    finally:
        session.close()

    return templates.TemplateResponse("index.html", {
        "request": request,
        "verify_id": image_id
    })


# ─── Run ───────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)
