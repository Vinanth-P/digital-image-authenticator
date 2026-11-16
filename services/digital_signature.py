"""
Digital Signature Service for ImageGuard v2.
Zero-Trust Envelope Key Vault with AES-256-GCM AEAD encryption,
Scrypt Key Derivation (n=2^14, r=8, p=1), and Dual-Mode RSA-PSS
Signature Verification (Backend MAX_LENGTH & W3C WebCrypto saltLength=32).
"""

import hashlib
import os
import uuid
import json
import base64
from datetime import datetime

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature, InvalidTag

from config import Config


class EnvelopeKeyVault:
    """
    Zero-Trust Envelope Key Encryption Vault.
    Guarantees private keys are never stored in plaintext at rest.
    Uses Scrypt(n=2^14, r=8, p=1) + MASTER_PEPPER to derive a 256-bit KEK,
    and AES-256-GCM AEAD encryption binding key_id as associated data.
    """

    @staticmethod
    def derive_kek(salt: bytes, passphrase: str = "") -> bytes:
        """Derive 256-bit KEK using Scrypt combined with Config.MASTER_PEPPER."""
        if not Config.MASTER_PEPPER:
            Config.init_app()
        pepper = Config.MASTER_PEPPER
        if isinstance(pepper, str):
            pepper = pepper.encode('utf-8')
        combined_secret = passphrase.encode('utf-8') + pepper

        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2**14,
            r=8,
            p=1,
            backend=default_backend()
        )
        return kdf.derive(combined_secret)

    @classmethod
    def encrypt_private_key(cls, private_key_pem: str, key_id: str, passphrase: str = "") -> str:
        """
        Encrypts PKCS#8 PEM string using AES-256-GCM envelope encryption.
        Binds key_id as AEAD associated_data.
        Returns serialized JSON string with base64 components.
        """
        salt = os.urandom(16)
        nonce = os.urandom(12)  # 96-bit nonce for AES-GCM
        kek = cls.derive_kek(salt, passphrase)

        aesgcm = AESGCM(kek)
        associated_data = key_id.encode('utf-8')
        ciphertext = aesgcm.encrypt(nonce, private_key_pem.encode('utf-8'), associated_data)

        payload = {
            "version": "v3_envelope_aes_gcm",
            "key_id": key_id,
            "salt": base64.b64encode(salt).decode('utf-8'),
            "nonce": base64.b64encode(nonce).decode('utf-8'),
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
        }
        return json.dumps(payload)

    @classmethod
    def decrypt_private_key(cls, encrypted_payload: str, key_id: str, passphrase: str = "") -> str:
        """
        Decrypts an envelope-encrypted PKCS#8 private key.
        Verifies AEAD associated_data matches key_id.
        Raises InvalidTag or ValueError on tampered ciphertext, bad key_id, or wrong passphrase.
        """
        # If already raw PEM string (e.g. legacy v1 data), return as is
        trimmed = encrypted_payload.strip()
        if trimmed.startswith("-----BEGIN") and "PRIVATE KEY-----" in trimmed:
            return trimmed

        try:
            data = json.loads(encrypted_payload)
        except Exception as e:
            raise ValueError(f"Invalid envelope key payload format: {str(e)}")

        salt = base64.b64decode(data['salt'])
        nonce = base64.b64decode(data['nonce'])
        ciphertext = base64.b64decode(data['ciphertext'])

        kek = cls.derive_kek(salt, passphrase)
        aesgcm = AESGCM(kek)
        associated_data = key_id.encode('utf-8')

        # AESGCM.decrypt raises InvalidTag if ciphertext, key, or associated_data is invalid
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
        except InvalidTag:
            # Read-only compatibility for existing v2 keys using the published
            # default pepper. New keys never use this value.
            if data.get('version') != 'v2_envelope_aes_gcm':
                raise
            legacy_kek = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(
                passphrase.encode('utf-8') + b'imageguard-v2-super-master-pepper-key-9988')
            plaintext = AESGCM(legacy_kek).decrypt(nonce, ciphertext, associated_data)
        return plaintext.decode('utf-8')


class DigitalSignatureService:
    """RSA digital signature management for image ownership with zero-trust key custody."""

    def __init__(self, key_size=2048):
        self.key_size = key_size

    def generate_key_pair(self, owner_name: str, owner_email: str = '',
                          custody_mode: str = 'SERVER_AES_GCM',
                          passphrase: str = '') -> dict:
        """
        Generate an RSA key pair for a user with envelope encryption.
        Never returns unencrypted private key for server storage.
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        # Serialize to PKCS#8 PEM format
        raw_private_pem = private_key.private_bytes(
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

        if custody_mode == 'CLIENT_WEBCRYPTO':
            # Non-custodial mode: server never stores private key
            encrypted_private_pem = "CLIENT_WEBCRYPTO_NON_CUSTODIAL"
            is_encrypted = False
        else:
            # Envelope encrypt with AES-256-GCM
            encrypted_private_pem = EnvelopeKeyVault.encrypt_private_key(
                raw_private_pem, key_id=key_id, passphrase=passphrase
            )
            is_encrypted = True

        return {
            'key_id': key_id,
            'owner_name': owner_name,
            'owner_email': owner_email,
            'public_key_pem': public_pem,
            'private_key_pem': encrypted_private_pem,  # Envelope encrypted for DB storage
            'raw_private_key_pem': raw_private_pem,    # Exposed only once at generation for user download
            'is_envelope_encrypted': is_encrypted,
            'custody_mode': custody_mode,
        }

    def compute_image_hash(self, image_bytes: bytes) -> str:
        """Compute SHA-256 hash of image binary data."""
        return hashlib.sha256(image_bytes).hexdigest()

    def sign_image(self, image_bytes: bytes, private_key_pem_or_envelope: str,
                   key_id: str = '', passphrase: str = '') -> dict:
        """
        Sign an image using the owner's private key.
        Automatically decrypts envelope if encrypted.
        """
        image_hash = self.compute_image_hash(image_bytes)

        # Decrypt if payload is envelope-encrypted
        raw_pem = EnvelopeKeyVault.decrypt_private_key(
            private_key_pem_or_envelope, key_id=key_id, passphrase=passphrase
        )

        private_key = serialization.load_pem_private_key(
            raw_pem.encode('utf-8'),
            password=None,
            backend=default_backend()
        )

        # Sign the hash using RSA-PSS
        signature_bytes = private_key.sign(
            image_hash.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        signature_b64 = base64.b64encode(signature_bytes).decode('utf-8')

        return {
            'image_hash': image_hash,
            'signature': signature_b64,
            'signature_bytes': signature_bytes,
            'signed_date': datetime.utcnow().isoformat(),
        }

    def verify_signature(self, image_bytes: bytes, signature_b64: str,
                         public_key_pem: str) -> dict:
        """
        Verify an image's digital signature with Dual-Mode RSA-PSS:
        1. Backend standard (salt_length = padding.PSS.MAX_LENGTH)
        2. W3C WebCrypto standard (salt_length = 32 matching SHA-256 digest length)
        """
        current_hash = self.compute_image_hash(image_bytes)

        try:
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode('utf-8'),
                backend=default_backend()
            )
            signature_bytes = base64.b64decode(signature_b64)
            hash_bytes = current_hash.encode('utf-8')

            # Attempt 1: W3C WebCrypto 32-byte salt (window.crypto.subtle.sign)
            try:
                public_key.verify(
                    signature_bytes,
                    hash_bytes,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=32
                    ),
                    hashes.SHA256()
                )
                return {
                    'is_valid': True,
                    'current_hash': current_hash,
                    'message': 'Signature is VALID. Verified with W3C WebCrypto RSA-PSS (32-byte salt).',
                    'integrity': 'intact',
                    'pss_mode': 'w3c_webcrypto'
                }
            except InvalidSignature:
                pass

            # Attempt 2: Backend standard MAX_LENGTH salt
            try:
                public_key.verify(
                    signature_bytes,
                    hash_bytes,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                return {
                    'is_valid': True,
                    'current_hash': current_hash,
                    'message': 'Signature is VALID. Verified with RSA-PSS (Max Salt).',
                    'integrity': 'intact',
                    'pss_mode': 'standard_backend'
                }
            except InvalidSignature:
                pass

            return {
                'is_valid': False,
                'current_hash': current_hash,
                'message': 'Signature INVALID. The image has been tampered with or modified.',
                'integrity': 'compromised',
                'pss_mode': 'failed'
            }

        except Exception as e:
            return {
                'is_valid': False,
                'current_hash': current_hash,
                'message': f'Signature verification error: {str(e)}',
                'integrity': 'compromised',
                'pss_mode': 'error'
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
