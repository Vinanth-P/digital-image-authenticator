"""Unverified analysis metadata, optional credential parsing, and explicit timestamp states.

This module does not issue or establish trust in C2PA credentials.
"""

import os
import io
import json
import uuid
import base64
import hashlib
from datetime import datetime


from config import Config

# Optional c2pa and rfc3161ng wrapped for 100% offline resilience
try:
    import c2pa
except ImportError:
    c2pa = None

try:
    import rfc3161ng
except ImportError:
    rfc3161ng = None


class C2PAProvenanceService:
    """Metadata inspection and receipt generation with explicit trust status."""

    def __init__(self, tsa_url: str = None):
        self.tsa_url = Config.RFC3161_TSA_URL if tsa_url is None else tsa_url

    def build_c2pa_manifest(self, image_record_dict: dict,
                            signer_name: str,
                            key_id: str,
                            forensic_scores: dict = None) -> dict:
        """
        Build an unverified analysis note using legacy manifest-shaped fields.
        This JSON is not a signed C2PA credential or a validated assertion.
        """
        forensic_scores = forensic_scores or {}
        now_iso = datetime.utcnow().isoformat() + "Z"
        manifest_id = f"urn:uuid:{uuid.uuid4()}"

        # Resolve forensic scores with robust fallbacks
        ela = forensic_scores.get('ela_score')
        if ela is None:
            if isinstance(forensic_scores.get('ela'), dict):
                ela = forensic_scores['ela'].get('score', 0.0)
            else:
                ela = image_record_dict.get('ela_score', 0.0)
        ela = float(ela or 0.0)

        noise = forensic_scores.get('noise_score')
        if noise is None:
            if isinstance(forensic_scores.get('noise'), dict):
                noise = forensic_scores['noise'].get('score', 0.0)
            else:
                noise = image_record_dict.get('noise_score', 0.0)
        noise = float(noise or 0.0)

        fft = forensic_scores.get('fft_score')
        if fft is None:
            if isinstance(forensic_scores.get('fft'), dict):
                fft = forensic_scores['fft'].get('score', 0.0)
            else:
                fft = image_record_dict.get('fft_score', 0.0)
        fft = float(fft or 0.0)

        ai_raw = forensic_scores.get('ai_generation_prob')
        if ai_raw is None:
            if isinstance(forensic_scores.get('ai_neural'), dict):
                ai_raw = forensic_scores['ai_neural'].get('p_ai', 0.0)
            else:
                ai_raw = image_record_dict.get('ai_generation_prob', 0.0)
        ai_raw = float(ai_raw or 0.0)
        ai_prob_pct = ai_raw * 100.0 if ai_raw <= 1.0 else ai_raw

        gates = forensic_scores.get('gates') if isinstance(forensic_scores.get('gates'), dict) else {}
        tamper_integrity = gates.get('tamper_integrity_score')
        if tamper_integrity is None:
            tamper_integrity = round(0.55 * ela + 0.45 * noise, 2)
        else:
            tamper_integrity = float(tamper_integrity)

        origin_integrity = gates.get('origin_integrity_score')
        if origin_integrity is None:
            origin_integrity = round(0.70 * (100.0 - ai_prob_pct) + 0.30 * fft, 2)
        else:
            origin_integrity = float(origin_integrity)

        # Synchronize Two-Gate Veto IPTC digitalSourceType and verdict
        if ai_prob_pct >= 55.0:
            digital_source_type = "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"
            verdict = "AI-Generated / Synthetic Media"
        elif tamper_integrity < 60.0:
            digital_source_type = "http://cv.iptc.org/newscodes/digitalsourcetype/compositeCapture"
            verdict = "Manipulated / Spliced Forgery"
        else:
            digital_source_type = "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture"
            verdict = "Authentic Media"

        manifest = {
            "claim_generator": "ImageGuard/2.1 analysis note",
            "trust_status": "unverified_metadata",
            "claim_generator_info": [
                {
                    "name": "ImageGuard",
                    "version": "2.0.0"
                }
            ],
            "title": image_record_dict.get('original_filename', 'Untitled Image'),
            "format": "image/jpeg" if str(image_record_dict.get('filename', '')).lower().endswith(('.jpg', '.jpeg')) else "image/png",
            "instance_id": manifest_id,
            "registered_signer": {
                "issuer": signer_name,
                "key_id": key_id,
                "time": now_iso
            },
            "assertions": [
                # 1. Standard c2pa.actions with IPTC digitalSourceType
                {
                    "label": "c2pa.actions",
                    "data": {
                        "actions": [
                            {
                                "action": "c2pa.published",
                                "when": now_iso,
                                "softwareAgent": "ImageGuard Forensic Provenance Engine v2.0",
                                "predicted_source_type": digital_source_type
                            }
                        ]
                    }
                },
                # 2. ImageGuard Forensic Attestation (locks branch scores & two-gate veto)
                {
                    "label": "org.imageguard.forensic_attestation",
                    "data": {
                        "ela_score": ela,
                        "srm_noise_score": noise,
                        "fft_score": fft,
                        "ai_generation_prob": ai_raw,
                        "gate1_tamper_integrity": tamper_integrity,
                        "gate2_origin_integrity": origin_integrity,
                        "verdict": verdict,
                        "predicted_source_type": digital_source_type,
                        "calibrated_probability": False,
                        "authenticity_score": forensic_scores.get('authenticity_score', image_record_dict.get('authenticity_score', 0.0)),
                        "is_authentic": (verdict == "Authentic Media"),
                        "file_hash_sha256": image_record_dict.get('file_hash', ''),
                        "locked_at": now_iso
                    }
                },
                # 3. C2PA Training & Mining AI Opt-Out
                {
                    "label": "c2pa.training-mining",
                    "data": {
                        "entries": {
                            "c2pa.ai_generative_training": {"use": "notAllowed"},
                            "c2pa.ai_training": {"use": "notAllowed"},
                            "c2pa.ai_inference": {"use": "notAllowed"},
                            "c2pa.data_mining": {"use": "notAllowed"}
                        }
                    }
                },
                # 4. Data Hash Assertion
                {
                    "label": "org.imageguard.original_bytes",
                    "data": {
                        "name": "Original bytes at analysis; not a C2PA binding",
                        "alg": "sha256",
                        "hash": image_record_dict.get('file_hash', '')
                    }
                }
            ]
        }
        return manifest

    def embed_manifest_in_file(self, file_path: str, manifest: dict, output_path: str = None) -> str:
        """Embed an explicitly unverified analysis note in PNG; no C2PA claim.

        Other formats retain their bytes. The analysis note remains available
        in the database/API. Genuine C2PA signing requires a configured signer
        and an independently validated credential chain, not a JSON fallback.
        """
        from PIL import Image, PngImagePlugin
        import shutil
        out_path = output_path or file_path
        with Image.open(file_path) as source:
            if source.format == 'PNG':
                image = source.copy()
                meta = PngImagePlugin.PngInfo()
                meta.add_text('IMAGEGUARD_ANALYSIS', json.dumps(manifest))
                image.save(out_path, 'PNG', pnginfo=meta)
            elif out_path != file_path:
                shutil.copyfile(file_path, out_path)
        return out_path

    def inspect_c2pa_manifest(self, file_path: str) -> dict:
        """Presence is not validation. Never infer camera origin from markers."""
        result = {'has_c2pa': False, 'status': 'unavailable', 'claim_generator': 'None',
                  'is_ai_generated': False, 'actions': [], 'assertions': {}, 'raw_manifest': None}
        if not os.path.exists(file_path):
            return result
        if c2pa is not None:
            try:
                with c2pa.Reader(file_path) as reader:
                    data = json.loads(reader.json())
                if data.get('active_manifest'):
                    result.update(has_c2pa=True, status='unverified_credential', raw_manifest=data)
                    active = data.get('manifests', {}).get(data['active_manifest'], {})
                    result['claim_generator'] = active.get('claim_generator', 'Unknown signer')
                    # SDK parsing is exposed separately from trust validation.
                    result['validation_status'] = data.get('validation_status', [])
                    return result
            except Exception:
                pass
        try:
            from PIL import Image
            with Image.open(file_path) as image:
                note = image.info.get('IMAGEGUARD_ANALYSIS') or image.info.get('C2PA_MANIFEST')
                if note:
                    result.update(status='unverified_metadata', raw_manifest=json.loads(note),
                                  claim_generator='ImageGuard analysis note')
        except (OSError, ValueError):
            pass
        return result

    def request_rfc3161_timestamp(self, signature_bytes: bytes) -> dict:
        """Return explicit receipt status; a local clock is not a trusted TSA."""
        now = datetime.utcnow().isoformat() + 'Z'
        digest = hashlib.sha256(signature_bytes).hexdigest()
        if rfc3161ng is not None and self.tsa_url:
            try:
                token = rfc3161ng.RemoteTimestamper(self.tsa_url, hashname='sha256', timeout=2.0)(data=signature_bytes)
                if token:
                    return {'status': 'received_unverified', 'rfc3161_tst_b64': base64.b64encode(token).decode(),
                            'tsa_source': self.tsa_url, 'is_authoritative': False,
                            'timestamp': now, 'sig_hash': digest}
            except Exception:
                pass
        return {'status': 'local_receipt', 'rfc3161_tst_b64': '', 'is_authoritative': False,
                'tsa_source': 'Local application clock', 'timestamp': now, 'sig_hash': digest}
