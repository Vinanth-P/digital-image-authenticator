"""
Digital Signature Service for ImageGuard.
Implements RSA-based digital signatures with SHA-256 hashing
for image ownership verification.
"""

import hashlib
import os
import uuid
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import base64


class DigitalSignatureService:
    """RSA digital signature management for image ownership."""

    def __init__(self, key_size=2048):
        self.key_size = key_size

    def generate_key_pair(self, owner_name: str, owner_email: str = '') -> dict:
        """
        Generate an RSA key pair for a user.

        Returns dict with key_id, public_key_pem, private_key_pem.
        """
        # Generate RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        # Serialize to PEM format
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        # Generate unique key ID
        key_id = hashlib.sha256(
            f"{owner_name}{owner_email}{datetime.utcnow().isoformat()}{uuid.uuid4()}".encode()
        ).hexdigest()[:16]

        return {
            'key_id': key_id,
            'owner_name': owner_name,
            'owner_email': owner_email,
            'public_key_pem': public_pem,
            'private_key_pem': private_pem,
        }

    def compute_image_hash(self, image_bytes: bytes) -> str:
        """Compute SHA-256 hash of image binary data."""
        return hashlib.sha256(image_bytes).hexdigest()

    def sign_image(self, image_bytes: bytes, private_key_pem: str) -> dict:
        """
        Sign an image using the owner's private key.

        Process:
        1. Compute SHA-256 hash of the image
        2. Sign the hash with RSA private key using PSS padding
        3. Return the signature and hash

        Returns dict with image_hash, signature (base64), signed_date.
        """
        # Compute hash
        image_hash = self.compute_image_hash(image_bytes)

        # Load private key
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None,
            backend=default_backend()
        )

        # Sign the hash
        signature_bytes = private_key.sign(
            image_hash.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # Encode signature as base64
        signature_b64 = base64.b64encode(signature_bytes).decode('utf-8')

        return {
            'image_hash': image_hash,
            'signature': signature_b64,
            'signed_date': datetime.utcnow().isoformat(),
        }

    def verify_signature(self, image_bytes: bytes, signature_b64: str,
                         public_key_pem: str) -> dict:
        """
        Verify an image's digital signature.

        Process:
        1. Compute SHA-256 hash of the current image
        2. Decode the stored signature
        3. Verify using the public key

        Returns dict with is_valid, current_hash, message.
        """
        # Compute current hash
        current_hash = self.compute_image_hash(image_bytes)

        try:
            # Load public key
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode('utf-8'),
                backend=default_backend()
            )

            # Decode signature
            signature_bytes = base64.b64decode(signature_b64)

            # Verify
            public_key.verify(
                signature_bytes,
                current_hash.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            return {
                'is_valid': True,
                'current_hash': current_hash,
                'message': 'Signature is VALID. The image is authentic and unmodified.',
                'integrity': 'intact'
            }

        except Exception as e:
            return {
                'is_valid': False,
                'current_hash': current_hash,
                'message': f'Signature INVALID. The image may have been tampered with. Details: {str(e)}',
                'integrity': 'compromised'
            }

    def get_key_info(self, public_key_pem: str) -> dict:
        """Extract information from a public key."""
        try:
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode('utf-8'),
                backend=default_backend()
            )
            return {
                'key_size': public_key.key_size,
                'algorithm': 'RSA',
                'valid': True
            }
        except Exception as e:
            return {
                'valid': False,
                'error': str(e)
            }
