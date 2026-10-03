"""
Database models for ImageGuard.
Uses SQLAlchemy ORM with SQLite backend.
"""

from sqlalchemy import create_engine, Column, Integer, String, Float, Text, DateTime, Boolean, LargeBinary
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import os

Base = declarative_base()


class ImageRecord(Base):
    """Stores information about each analyzed image."""
    __tablename__ = 'image_records'

    id = Column(Integer, primary_key=True, autoincrement=True)
    filename = Column(String(255), nullable=False)
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

    # Heatmap path
    heatmap_path = Column(String(500), default='')
    ela_image_path = Column(String(500), default='')

    # Digital signature
    is_signed = Column(Boolean, default=False)
    signature = Column(Text, default='')
    public_key_id = Column(String(64), default='')
    signer_name = Column(String(255), default='')
    signed_date = Column(DateTime, nullable=True)

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
            'is_authentic': self.is_authentic,
            'forgery_details': self.forgery_details,
            'heatmap_path': self.heatmap_path,
            'ela_image_path': self.ela_image_path,
            'is_signed': self.is_signed,
            'signature': self.signature,
            'public_key_id': self.public_key_id,
            'signer_name': self.signer_name,
            'signed_date': self.signed_date.isoformat() if self.signed_date else None,
            'certificate_path': self.certificate_path,
            'metadata_json': self.metadata_json,
            'metadata_score': self.metadata_score,
        }


class KeyPair(Base):
    """Stores RSA key pairs for users."""
    __tablename__ = 'key_pairs'

    id = Column(Integer, primary_key=True, autoincrement=True)
    key_id = Column(String(64), unique=True, nullable=False)
    owner_name = Column(String(255), nullable=False)
    owner_email = Column(String(255), default='')
    public_key_pem = Column(Text, nullable=False)
    private_key_pem = Column(Text, nullable=False)  # In production, encrypt this!
    created_date = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)

    def to_dict(self):
        return {
            'id': self.id,
            'key_id': self.key_id,
            'owner_name': self.owner_name,
            'owner_email': self.owner_email,
            'public_key_pem': self.public_key_pem,
            'created_date': self.created_date.isoformat() if self.created_date else None,
            'is_active': self.is_active,
        }


def init_db(db_path):
    """Initialize database and return session factory."""
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    engine = create_engine(f'sqlite:///{db_path}', echo=False)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    return Session
