"""
Database models for ImageGuard v2.
Uses SQLAlchemy ORM with SQLite backend and automatic schema migration.
"""

from sqlalchemy import create_engine, Column, Integer, String, Float, Text, DateTime, Boolean, text
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime
import os

Base = declarative_base()


class ImageRecord(Base):
    """Stores information about each analyzed image."""
    __tablename__ = 'image_records'

    id = Column(Integer, primary_key=True, autoincrement=True)
    filename = Column(String(255), nullable=False)
    original_storage_name = Column(String(255), default='')
    original_file_hash = Column(String(64), default='')
    provenance_status = Column(String(64), default='unverified_metadata')
    timestamp_info = Column(Text, default='{}')
    original_filename = Column(String(255), nullable=False)
    file_hash = Column(String(64), nullable=False)  # SHA-256 hash
    file_size = Column(Integer)
    width = Column(Integer)
    height = Column(Integer)
    upload_date = Column(DateTime, default=datetime.utcnow)

    # Forgery detection results
    authenticity_score = Column(Float, default=0.0)  # 0-100
    ela_score = Column(Float, default=0.0)
    noise_score = Column(Float, default=0.0)
    cnn_score = Column(Float, default=0.0)
    is_authentic = Column(Boolean, default=True)
    forgery_details = Column(Text, default='{}')  # JSON string

    # Visual artifact paths
    heatmap_path = Column(String(500), default='')
    ela_image_path = Column(String(500), default='')
    saliency_map_path = Column(String(500), default='')  # v2 Saliency/Confidence overlay

    # Advanced v2 Spectral & Neural Metrics
    fft_score = Column(Float, default=0.0)
    ai_generation_prob = Column(Float, default=0.0)
    perceptual_dhash = Column(String(64), default='')  # 64-bit dHash hex

    # Digital signature & RFC 3161
    is_signed = Column(Boolean, default=False)
    signature = Column(Text, default='')
    public_key_id = Column(String(64), default='')
    signer_name = Column(String(255), default='')
    signed_date = Column(DateTime, nullable=True)
    rfc3161_tst_b64 = Column(Text, default='')  # RFC 3161 Timestamp token

    # Soft Binding & C2PA
    watermark_embedded = Column(Boolean, default=False)
    parent_master_id = Column(Integer, nullable=True)  # Links derivative to signed master
    c2pa_manifest_json = Column(Text, default='{}')

    # Merkle Tree Audit Ledger
    merkle_leaf_hash = Column(String(64), default='')

    # Certificate
    certificate_path = Column(String(500), default='')

    # Metadata
    metadata_json = Column(Text, default='{}')  # JSON string
    metadata_score = Column(Float, default=0.0)

    def to_dict(self):
        """Convert record to dictionary for API responses."""
        return {
            'id': self.id,
            'filename': self.filename,
            'original_file_hash': self.original_file_hash,
            'provenance_status': self.provenance_status,
            'timestamp_info': self.timestamp_info,
            'original_filename': self.original_filename,
            'file_hash': self.file_hash,
            'file_size': self.file_size,
            'width': self.width,
            'height': self.height,
            'upload_date': self.upload_date.isoformat() if self.upload_date else None,
            'authenticity_score': self.authenticity_score,
            'ela_score': self.ela_score,
            'noise_score': self.noise_score,
            'cnn_score': self.cnn_score,
            'fft_score': self.fft_score,
            'ai_generation_prob': self.ai_generation_prob,
            'perceptual_dhash': self.perceptual_dhash,
            'is_authentic': self.is_authentic,
            'forgery_details': self.forgery_details,
            'heatmap_path': self.heatmap_path,
            'ela_image_path': self.ela_image_path,
            'saliency_map_path': self.saliency_map_path,
            'is_signed': self.is_signed,
            'signature': self.signature,
            'public_key_id': self.public_key_id,
            'signer_name': self.signer_name,
            'signed_date': self.signed_date.isoformat() if self.signed_date else None,
            'rfc3161_tst_b64': self.rfc3161_tst_b64,
            'watermark_embedded': self.watermark_embedded,
            'parent_master_id': self.parent_master_id,
            'c2pa_manifest_json': self.c2pa_manifest_json,
            'merkle_leaf_hash': self.merkle_leaf_hash,
            'certificate_path': self.certificate_path,
            'metadata_json': self.metadata_json,
            'metadata_score': self.metadata_score,
        }


class KeyPair(Base):
    """Stores RSA key pairs for users with zero-trust envelope encryption."""
    __tablename__ = 'key_pairs'

    id = Column(Integer, primary_key=True, autoincrement=True)
    key_id = Column(String(64), unique=True, nullable=False)
    owner_name = Column(String(255), nullable=False)
    owner_email = Column(String(255), default='')
    public_key_pem = Column(Text, nullable=False)
    private_key_pem = Column(Text, nullable=False)  # Envelope encrypted (AES-256-GCM) or placeholder in CLIENT_WEBCRYPTO
    is_envelope_encrypted = Column(Boolean, default=True)
    custody_mode = Column(String(64), default='SERVER_AES_GCM')  # 'SERVER_AES_GCM' vs 'CLIENT_WEBCRYPTO'
    created_date = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)

    def to_dict(self):
        return {
            'id': self.id,
            'key_id': self.key_id,
            'owner_name': self.owner_name,
            'owner_email': self.owner_email,
            'public_key_pem': self.public_key_pem,
            'is_envelope_encrypted': self.is_envelope_encrypted,
            'custody_mode': self.custody_mode,
            'created_date': self.created_date.isoformat() if self.created_date else None,
            'is_active': self.is_active,
        }


class MerkleCheckpoint(Base):
    """Stores append-only Merkle transparency ledger roots."""
    __tablename__ = 'merkle_checkpoints'

    id = Column(Integer, primary_key=True, autoincrement=True)
    root_hash = Column(String(64), nullable=False)
    tree_size = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    version = Column(Integer, default=2)
    signature = Column(Text, default='')
    public_key = Column(Text, default='')

    def to_dict(self):
        return {
            'id': self.id,
            'root_hash': self.root_hash,
            'tree_size': self.tree_size,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'version': self.version,
            'signature': self.signature,
            'public_key': self.public_key,
        }


class AuditEvent(Base):
    """Historical snapshots retained even after an image is deleted."""
    __tablename__ = 'audit_events'
    id = Column(Integer, primary_key=True, autoincrement=True)
    image_id = Column(Integer, nullable=False, index=True)
    event_type = Column(String(32), nullable=False)
    payload = Column(Text, nullable=False)
    leaf_hash = Column(String(64), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


def init_db(db_path: str):
    """
    Initialize database and return session factory.
    Inspects PRAGMA table_info on startup and automatically executes
    ALTER TABLE ... ADD COLUMN ... for all new v2 columns.
    """
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    engine = create_engine(f'sqlite:///{db_path}', echo=False)

    # First, create tables if they do not exist
    Base.metadata.create_all(engine)

    # Now inspect existing tables and migrate columns if needed
    with engine.connect() as conn:
        # Check image_records columns
        existing_cols_image = set()
        try:
            result = conn.execute(text("PRAGMA table_info(image_records)"))
            for row in result:
                existing_cols_image.add(row[1])
        except Exception:
            pass

        new_image_cols = [
            ('original_storage_name', "VARCHAR(255) DEFAULT ''"),
            ('original_file_hash', "VARCHAR(64) DEFAULT ''"),
            ('provenance_status', "VARCHAR(64) DEFAULT 'unverified_metadata'"),
            ('timestamp_info', "TEXT DEFAULT '{}'"),
            ("perceptual_dhash", "VARCHAR(64) DEFAULT ''"),
            ("fft_score", "FLOAT DEFAULT 0.0"),
            ("ai_generation_prob", "FLOAT DEFAULT 0.0"),
            ("saliency_map_path", "VARCHAR(500) DEFAULT ''"),
            ("c2pa_manifest_json", "TEXT DEFAULT '{}'"),
            ("rfc3161_tst_b64", "TEXT DEFAULT ''"),
            ("watermark_embedded", "BOOLEAN DEFAULT 0"),
            ("parent_master_id", "INTEGER"),
            ("merkle_leaf_hash", "VARCHAR(64) DEFAULT ''"),
        ]

        for col_name, col_type in new_image_cols:
            if col_name not in existing_cols_image and len(existing_cols_image) > 0:
                try:
                    conn.execute(text(f"ALTER TABLE image_records ADD COLUMN {col_name} {col_type}"))
                    conn.commit()
                except Exception as e:
                    raise RuntimeError(f'Cannot migrate image_records.{col_name}') from e

        # Check key_pairs columns
        existing_cols_keys = set()
        try:
            result = conn.execute(text("PRAGMA table_info(key_pairs)"))
            for row in result:
                existing_cols_keys.add(row[1])
        except Exception:
            pass

        new_key_cols = [
            ("is_envelope_encrypted", "BOOLEAN DEFAULT 1"),
            ("custody_mode", "VARCHAR(64) DEFAULT 'SERVER_AES_GCM'"),
        ]

        for col_name, col_type in new_key_cols:
            if col_name not in existing_cols_keys and len(existing_cols_keys) > 0:
                try:
                    conn.execute(text(f"ALTER TABLE key_pairs ADD COLUMN {col_name} {col_type}"))
                    conn.commit()
                except Exception as e:
                    raise RuntimeError(f'Cannot migrate key_pairs.{col_name}') from e

        checkpoint_cols = {r[1] for r in conn.execute(text('PRAGMA table_info(merkle_checkpoints)'))}
        for name, kind in [('version', 'INTEGER DEFAULT 1'), ('signature', "TEXT DEFAULT ''"), ('public_key', "TEXT DEFAULT ''")]:
            if name not in checkpoint_cols:
                conn.execute(text(f'ALTER TABLE merkle_checkpoints ADD COLUMN {name} {kind}'))
        conn.commit()

    Session = sessionmaker(bind=engine)
    return Session
