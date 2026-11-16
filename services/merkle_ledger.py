"""Event-based Merkle integrity log with signed local checkpoints.

Uses RFC 6962 tree hashing, but is not a Certificate Transparency service.
Export checkpoints/public keys to detect rollback; a compromised host holding
both the database and signing key can rewrite local history.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
from datetime import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from config import Config


class LedgerIntegrityError(ValueError):
    pass


class MerkleAuditTree:
    @staticmethod
    def canonical(value):
        return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)

    @staticmethod
    def hash_leaf(payload):
        return hashlib.sha256(b'\x00' + payload.encode('utf-8')).hexdigest()

    @classmethod
    def compute_leaf_hash(cls, image_id, file_hash, authenticity_score, signature=None):
        return cls.hash_leaf(cls.canonical([image_id, file_hash, authenticity_score, signature or 'UNSIGNED']))

    @staticmethod
    def hash_pair(left, right):
        return hashlib.sha256(b'\x01' + bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()

    @classmethod
    def build_tree_and_proof(cls, leaf_hashes, target_index=0):
        if not leaf_hashes:
            return {'root': hashlib.sha256(b'').hexdigest(), 'tree_size': 0, 'proof': []}
        if not 0 <= target_index < len(leaf_hashes):
            raise ValueError('Invalid Merkle leaf index')
        def build(leaves, index):
            if len(leaves) == 1:
                return leaves[0], []
            split = 1 << ((len(leaves) - 1).bit_length() - 1)
            left, lp = build(leaves[:split], index if index < split else 0)
            right, rp = build(leaves[split:], index - split if index >= split else 0)
            proof = lp + [{'sibling': right, 'direction': 'R'}] if index < split else rp + [{'sibling': left, 'direction': 'L'}]
            return cls.hash_pair(left, right), proof
        root, proof = build(list(leaf_hashes), target_index)
        return {'root': root, 'tree_size': len(leaf_hashes), 'proof': proof}

    @classmethod
    def verify_inclusion_proof(cls, leaf_hash, proof, expected_root):
        try:
            current = leaf_hash
            for step in proof:
                if step['direction'] not in ('L', 'R'):
                    return False
                current = cls.hash_pair(current, step['sibling']) if step['direction'] == 'R' else cls.hash_pair(step['sibling'], current)
            return current == expected_root
        except (KeyError, ValueError, TypeError):
            return False

    @staticmethod
    def _key(create=False):
        path = Path(Config.LEDGER_KEY_PATH)
        if not path.exists() and create:
            path.parent.mkdir(parents=True, exist_ok=True)
            raw = Ed25519PrivateKey.generate().private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(Config.MASTER_PEPPER))
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(raw)
            except FileExistsError:
                pass
        return serialization.load_pem_private_key(path.read_bytes(), password=Config.MASTER_PEPPER)

    @classmethod
    def checkpoint_message(cls, cp):
        return cls.canonical({'version': cp.version, 'root_hash': cp.root_hash,
                              'tree_size': cp.tree_size, 'created_at': cp.created_at.isoformat()}).encode()

    @classmethod
    def snapshot(cls, record):
        data = record.to_dict()
        # UI artifact caches are mutable and are deliberately not evidence.
        for name in ['merkle_leaf_hash', 'certificate_path', 'heatmap_path', 'ela_image_path', 'saliency_map_path']:
            data.pop(name, None)
        return data

    @classmethod
    def _validated_history(cls, session):
        from models.database import AuditEvent, MerkleCheckpoint
        events = session.query(AuditEvent).order_by(AuditEvent.id).all()
        cp = session.query(MerkleCheckpoint).filter_by(version=2).order_by(MerkleCheckpoint.id.desc()).first()
        if not events and not cp:
            return events, cp
        if not cp or cp.tree_size != len(events):
            raise LedgerIntegrityError('Audit log size does not match its checkpoint')
        leaves = [cls.hash_leaf(event.payload) for event in events]
        if any(leaf != event.leaf_hash for leaf, event in zip(leaves, events)):
            raise LedgerIntegrityError('Audit event content was modified')
        if cls.build_tree_and_proof(leaves)['root'] != cp.root_hash:
            raise LedgerIntegrityError('Audit root does not match checkpoint')
        try:
            key = cls._key().public_key()
            public = key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
            if cp.public_key != public:
                raise ValueError('Checkpoint key mismatch')
            key.verify(base64.b64decode(cp.signature, validate=True), cls.checkpoint_message(cp))
        except Exception as exc:
            raise LedgerIntegrityError('Checkpoint signature is invalid or local trust key is missing') from exc
        return events, cp

    @classmethod
    def append_event(cls, session, record, event_type):
        from models.database import AuditEvent, MerkleCheckpoint
        events, cp = cls._validated_history(session)
        previous = next((e for e in reversed(events) if e.image_id == record.id), None)
        if event_type in ('analysis', 'legacy_import') and previous:
            raise LedgerIntegrityError('Record already has an audit history')
        if event_type not in ('analysis', 'legacy_import') and not previous:
            raise LedgerIntegrityError('Import legacy record before updating it')
        payload = cls.canonical({'event_type': event_type, 'previous_leaf': previous.leaf_hash if previous else None,
                                 'record': cls.snapshot(record)})
        leaf = cls.hash_leaf(payload)
        event = AuditEvent(image_id=record.id, event_type=event_type, payload=payload, leaf_hash=leaf)
        session.add(event)
        record.merkle_leaf_hash = leaf
        leaves = [e.leaf_hash for e in events] + [leaf]
        root = cls.build_tree_and_proof(leaves)['root']
        key = cls._key(create=not events and cp is None)
        checkpoint = MerkleCheckpoint(root_hash=root, tree_size=len(leaves), created_at=datetime.utcnow(), version=2,
            public_key=key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode())
        checkpoint.signature = base64.b64encode(key.sign(cls.checkpoint_message(checkpoint))).decode()
        session.add(checkpoint)
        session.flush()
        return checkpoint.to_dict()

    @classmethod
    def verify_record(cls, session, record):
        result = {'merkle_verified': False, 'merkle_root': '', 'merkle_proof': [], 'checkpoint': None}
        try:
            events, cp = cls._validated_history(session)
            indexes = [i for i, e in enumerate(events) if e.image_id == record.id]
            if not indexes:
                return {**result, 'ledger_status': 'legacy_unanchored'}
            index = indexes[-1]
            event = events[index]
            payload = json.loads(event.payload)
            if event.event_type == 'deletion' or payload['record'] != cls.snapshot(record) or record.merkle_leaf_hash != event.leaf_hash:
                raise LedgerIntegrityError('Current record differs from its retained audit snapshot')
            tree = cls.build_tree_and_proof([e.leaf_hash for e in events], index)
            return {**result, 'merkle_verified': cls.verify_inclusion_proof(event.leaf_hash, tree['proof'], cp.root_hash),
                    'merkle_root': cp.root_hash, 'merkle_proof': tree['proof'], 'checkpoint': cp.to_dict(), 'ledger_status': 'verified_local_checkpoint'}
        except (LedgerIntegrityError, ValueError, KeyError) as exc:
            return {**result, 'ledger_status': 'integrity_failure', 'ledger_error': str(exc)}

    @classmethod
    def require_valid_record(cls, session, record):
        result = cls.verify_record(session, record)
        if not result['merkle_verified']:
            raise LedgerIntegrityError(result.get('ledger_error', 'Legacy record requires explicit import before mutation'))
        return result

    @classmethod
    def sync_ledger(cls, session):
        """Compatibility helper for new demo records; never re-anchor changed rows."""
        from models.database import ImageRecord
        for record in session.query(ImageRecord).order_by(ImageRecord.id).all():
            result = cls.verify_record(session, record)
            if result['ledger_status'] == 'legacy_unanchored':
                cls.append_event(session, record, 'legacy_import')
            elif not result['merkle_verified']:
                raise LedgerIntegrityError(result.get('ledger_error', 'Integrity failure'))
        session.commit()
        _, cp = cls._validated_history(session)
        return cp.to_dict() if cp else {'root_hash': hashlib.sha256(b'').hexdigest(), 'tree_size': 0}
