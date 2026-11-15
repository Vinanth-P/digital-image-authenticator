"""
Automated Test Suite for ImageGuard v2.
Verifies:
1. Multi-Branch Forensic Completeness (ELA, SRM noise, 2D FFT, ONNX/Heuristic, Saliency, Merkle leaf)
2. Zero-Trust AES-256-GCM Envelope Encryption Integrity & Tamper Rejection
3. Hard-Binding vs. Soft-Binding Adversarial Attack Regimes & Tamper Localization
4. Merkle Audit Transparency Ledger Inclusion & Micro-Tamper Detection
"""

import os
import io
import json
import numpy as np
import pytest
from PIL import Image
from fastapi.testclient import TestClient

from app import app
from config import Config
from services.digital_signature import DigitalSignatureService, EnvelopeKeyVault
from services.watermark_engine import SoftBindingService
from services.merkle_ledger import MerkleAuditTree


def create_test_image_bytes(width=200, height=200, pattern='textured', seed=42):
    """Generate deterministic test image bytes."""
    if pattern == 'textured':
        rng = np.random.RandomState(seed)
        arr = (rng.rand(height, width, 3) * 220 + 20).astype(np.uint8)
    else:
        arr = np.full((height, width, 3), 128, dtype=np.uint8)
    img = Image.fromarray(arr)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    return buf.getvalue()


# ═══════════════════════════════════════════════════════════
#  TEST A: Multi-Branch Forensic Completeness
# ═══════════════════════════════════════════════════════════
def test_multi_branch_forensic_completeness(client):
    """
    POST /api/analyze populates bounded [0, 100] scores for ELA, SRM noise,
    2D FFT spectrum, and ONNX/heuristic inference, saves saliency overlay,
    and commits a valid merkle_leaf_hash.
    """
    img_bytes = create_test_image_bytes(200, 200, 'textured')
    files = {"file": ("test_forensic.png", img_bytes, "image/png")}

    response = client.post("/api/analyze", files=files)
    assert response.status_code == 200, f"Analysis failed: {response.text}"
    body = response.json()
    assert body["status"] == "success"
    data = body["data"]

    # 1. Bounded [0, 100] scores
    assert 0.0 <= data["authenticity_score"] <= 100.0
    assert 0.0 <= data["ela_score"] <= 100.0
    assert 0.0 <= data["noise_score"] <= 100.0
    assert 0.0 <= data["fft_score"] <= 100.0
    assert 0.0 <= data["cnn_score"] <= 100.0

    # 2. Bounded AI probability
    assert 0.0 <= data["ai_generation_prob"] <= 1.0

    # 3. Perceptual dHash format
    assert len(data["perceptual_dhash"]) == 16

    # 4. Saliency map path generated and exists
    assert "saliency_map_path" in data
    assert "saliency" in data["saliency_map_path"]
    saliency_full_path = os.path.join(Config.RESULTS_FOLDER, os.path.basename(data["saliency_map_path"]))
    assert os.path.exists(saliency_full_path), f"Saliency file missing: {saliency_full_path}"

    # 5. Merkle leaf hash committed
    assert "merkle_leaf_hash" in data
    assert len(data["merkle_leaf_hash"]) == 64

    # 6. Forgery details contains all branches
    details = json.loads(data["forgery_details"])
    assert "ela" in details
    assert "noise" in details
    assert "fft" in details
    assert "ai_neural" in details


# ═══════════════════════════════════════════════════════════
#  TEST B: Zero-Trust AES-256-GCM Envelope Key Vault Integrity
# ═══════════════════════════════════════════════════════════
def test_zero_trust_aes_256_gcm_envelope_integrity():
    """
    EnvelopeKeyVault.decrypt_private_key recovers exact PKCS#8 key under
    valid passphrase and key_id, and raises authentication error if passphrase,
    ciphertext, or AEAD associated_data (key_id) is mutated.
    """
    sig_service = DigitalSignatureService()
    key_data = sig_service.generate_key_pair(
        owner_name="Alice Security",
        owner_email="alice@zerotrust.local",
        custody_mode="SERVER_AES_GCM",
        passphrase="vault-passphrase-2026"
    )

    raw_pem = key_data["raw_private_key_pem"]
    enc_payload = key_data["private_key_pem"]
    key_id = key_data["key_id"]

    # 1. Successful decryption under valid credentials
    recovered_pem = EnvelopeKeyVault.decrypt_private_key(
        encrypted_payload=enc_payload,
        key_id=key_id,
        passphrase="vault-passphrase-2026"
    )
    assert recovered_pem.strip() == raw_pem.strip()

    # 2. Tampered passphrase -> Authentication failure (InvalidTag)
    with pytest.raises(Exception):
        EnvelopeKeyVault.decrypt_private_key(
            encrypted_payload=enc_payload,
            key_id=key_id,
            passphrase="wrong-passphrase"
        )

    # 3. Tampered AEAD associated_data (key_id) -> Authentication failure
    with pytest.raises(Exception):
        EnvelopeKeyVault.decrypt_private_key(
            encrypted_payload=enc_payload,
            key_id="tampered_key_id_9999",
            passphrase="vault-passphrase-2026"
        )

    # 4. Tampered ciphertext payload -> Authentication failure
    parsed = json.loads(enc_payload)
    ct_bytes = bytearray(parsed["ciphertext"].encode('utf-8'))
    ct_bytes[5] = (ct_bytes[5] + 1) % 128
    parsed["ciphertext"] = ct_bytes.decode('utf-8', errors='ignore')
    tampered_json = json.dumps(parsed)

    with pytest.raises(Exception):
        EnvelopeKeyVault.decrypt_private_key(
            encrypted_payload=tampered_json,
            key_id=key_id,
            passphrase="vault-passphrase-2026"
        )


# ═══════════════════════════════════════════════════════════
#  TEST C: Hard-Binding vs. Soft-Binding Adversarial Regimes
# ═══════════════════════════════════════════════════════════
def test_hard_binding_vs_soft_binding_adversarial_regimes(client):
    """
    Signing an image and executing POST /api/simulate-attack/{image_id} across
    whatsapp_compress and pixel_splice proves that byte-level SHA-256 verification
    fails (hard_binding_valid == False) while soft-binding recovery (watermark or d_H <= 10)
    recovers the exact master image_id and flags localized tampering on pixel_splice.
    """
    # 1. Generate key
    key_res = client.post("/api/keys/generate", data={
        "owner_name": "Test Signer",
        "owner_email": "signer@provenance.test",
        "custody_mode": "SERVER_AES_GCM",
        "passphrase": "test-passphrase"
    })
    assert key_res.status_code == 200
    key_id = key_res.json()["data"]["key_id"]

    # 2. Upload image
    img_bytes = create_test_image_bytes(240, 240, 'textured')
    upload_res = client.post("/api/analyze", files={"file": ("master.png", img_bytes, "image/png")})
    assert upload_res.status_code == 200
    image_id = upload_res.json()["data"]["id"]

    # 3. Sign image
    sign_res = client.post(f"/api/sign/{image_id}", data={"key_id": key_id, "passphrase": "test-passphrase"})
    assert sign_res.status_code == 200
    assert sign_res.json()["data"]["watermark_embedded"] is True

    # 4. Execute Adversarial Attack Simulation
    sim_res = client.post(f"/api/simulate-attack/{image_id}")
    assert sim_res.status_code == 200
    attacks = sim_res.json()["data"]["attacks"]

    # Assert WhatsApp Re-Compression Regime
    wa = attacks["whatsapp_compress"]
    assert wa["hard_binding_valid"] is False, "Hard binding SHA-256 must fail under WhatsApp compression!"
    assert wa["soft_binding_recovered"] is True, "Soft binding must survive WhatsApp compression!"
    assert wa["hamming_distance"] <= 10, f"Hamming distance {wa['hamming_distance']} exceeded threshold <= 10"

    # Assert Pixel Splice Regime
    splice = attacks["pixel_splice"]
    assert splice["hard_binding_valid"] is False, "Hard binding SHA-256 must fail under pixel splicing!"
    assert splice["soft_binding_recovered"] is True, "Soft binding must recover master identity!"
    assert splice["tamper_detected"] is True, "Pixel splice must be flagged as tampered!"
    assert splice["pixel_change_percentage"] > 0.5, "Localized tamper percentage must be isolated!"


# ═══════════════════════════════════════════════════════════
#  TEST D: Merkle Audit Tamper Detection
# ═══════════════════════════════════════════════════════════
def test_merkle_audit_tamper_detection():
    """
    MerkleAuditTree.verify_inclusion_proof returns True for an unmodified record
    and immediately returns False if authenticity_score or file_hash is altered
    by even 0.01 without updating the Merkle root.
    """
    # 1. Build Merkle tree from 4 records
    leaf1 = MerkleAuditTree.compute_leaf_hash(1, "hash_alpha_1234", 95.50, "SIG1")
    leaf2 = MerkleAuditTree.compute_leaf_hash(2, "hash_beta_5678", 72.30, "SIG2")
    leaf3 = MerkleAuditTree.compute_leaf_hash(3, "hash_gamma_9012", 40.00, None)
    leaf4 = MerkleAuditTree.compute_leaf_hash(4, "hash_delta_3456", 88.80, "SIG4")
    leaves = [leaf1, leaf2, leaf3, leaf4]

    # Generate proof for record 2 (index 1)
    tree_data = MerkleAuditTree.build_tree_and_proof(leaves, target_index=1)
    root = tree_data["root"]
    proof = tree_data["proof"]

    # 2. Unmodified leaf must verify True
    assert MerkleAuditTree.verify_inclusion_proof(leaf2, proof, root) is True

    # 3. Micro-tamper authenticity_score by 0.01 (72.30 -> 72.31) -> Must fail False
    tampered_score_leaf = MerkleAuditTree.compute_leaf_hash(2, "hash_beta_5678", 72.31, "SIG2")
    assert MerkleAuditTree.verify_inclusion_proof(tampered_score_leaf, proof, root) is False

    # 4. Tamper file_hash by 1 character -> Must fail False
    tampered_hash_leaf = MerkleAuditTree.compute_leaf_hash(2, "hash_beta_5679", 72.30, "SIG2")
    assert MerkleAuditTree.verify_inclusion_proof(tampered_hash_leaf, proof, root) is False

    # 5. Tamper signature state (signed -> unsigned) -> Must fail False
    tampered_sig_leaf = MerkleAuditTree.compute_leaf_hash(2, "hash_beta_5678", 72.30, None)
    assert MerkleAuditTree.verify_inclusion_proof(tampered_sig_leaf, proof, root) is False


# ═══════════════════════════════════════════════════════════
#  TEST E: Full Endpoint & Public HTML Contract Verification
# ═══════════════════════════════════════════════════════════
def test_all_endpoints_and_verify_html_contract(client):
    """
    Verifies that all 16 API endpoints (plus aliases and public HTML verification view)
    return HTTP 200 OK with valid schema contracts.
    """
    # 1. GET / (SPA index)
    r_home = client.get("/")
    assert r_home.status_code == 200
    assert "ImageGuard" in r_home.text

    # 2. POST /api/keys/generate (Generate Server Key)
    r_key = client.post("/api/keys/generate", data={
        "owner_name": "Contract Test Authority",
        "owner_email": "contract@auth.test",
        "custody_mode": "SERVER_AES_GCM",
        "passphrase": "test-passphrase-2026"
    })
    assert r_key.status_code == 200
    key_id = r_key.json()["data"]["key_id"]
    pub_pem = r_key.json()["data"]["public_key_pem"]
    assert r_key.json()["data"]["is_envelope_encrypted"] is True

    # 3. GET /api/keys (List Keys)
    r_keys = client.get("/api/keys")
    assert r_keys.status_code == 200
    assert len(r_keys.json()["data"]) >= 1

    # 4. GET /api/keys/{key_id}/export (Export Public Key)
    r_kexport = client.get(f"/api/keys/{key_id}/export")
    assert r_kexport.status_code == 200
    assert r_kexport.json()["data"]["public_key_pem"] == pub_pem

    # 5. POST /api/analyze (Upload & Multi-Branch Forensic Ingestion)
    img_bytes = create_test_image_bytes(240, 240, 'textured', seed=9999)
    r_ana = client.post("/api/analyze", files={"file": ("contract_test.png", img_bytes, "image/png")})
    assert r_ana.status_code == 200
    image_id = r_ana.json()["data"]["id"]

    # 6. POST /api/sign/{image_id} (Server Envelope Signing)
    r_sign = client.post(f"/api/sign/{image_id}", data={
        "key_id": key_id,
        "passphrase": "test-passphrase-2026"
    })
    assert r_sign.status_code == 200
    assert r_sign.json()["data"]["watermark_embedded"] is True

    # 7. POST /api/verify-signature/{image_id} (Dual-Mode Signature Verification)
    r_vsig = client.post(f"/api/verify-signature/{image_id}")
    assert r_vsig.status_code == 200
    assert r_vsig.json()["data"]["is_valid"] is True

    # 8. POST /api/verify (Upload File Hard Verification)
    r_vfile = client.post("/api/verify", files={"file": ("verify_query.png", img_bytes, "image/png")})
    assert r_vfile.status_code in [200, 404]

    # 9. POST /api/recover-provenance (Soft-Binding Recovery on compressed derivative)
    r_detail = client.get(f"/api/images/{image_id}").json()["data"]
    signed_img_path = os.path.join(Config.UPLOAD_FOLDER, r_detail["filename"])
    with open(signed_img_path, "rb") as f:
        signed_bytes = f.read()
    wa_pert = SoftBindingService().apply_attack(signed_bytes, "whatsapp_compress")
    r_recov = client.post("/api/recover-provenance", files={"file": ("recover_query.jpg", wa_pert, "image/jpeg")})
    assert r_recov.status_code == 200
    assert r_recov.json()["data"]["recovered_master_id"] == image_id

    # 10. POST /api/simulate-attack/{image_id} (Adversarial Regimes)
    r_sim = client.post(f"/api/simulate-attack/{image_id}")
    assert r_sim.status_code == 200
    assert "whatsapp_compress" in r_sim.json()["data"]["attacks"]

    # 11. POST /api/certificate/{image_id} & GET /api/certificate/{image_id}
    r_cert_post = client.post(f"/api/certificate/{image_id}")
    assert r_cert_post.status_code == 200
    assert r_cert_post.headers["content-type"] == "application/pdf"

    r_cert_get = client.get(f"/api/certificate/{image_id}")
    assert r_cert_get.status_code == 200
    assert r_cert_get.headers["content-type"] == "application/pdf"

    # 12. GET /api/images & GET /api/records (List Images / Records)
    r_imgs = client.get("/api/images")
    assert r_imgs.status_code == 200
    r_recs = client.get("/api/records")
    assert r_recs.status_code == 200

    # 13. GET /api/images/{image_id} & GET /api/records/{image_id} (Record Details)
    r_img_detail = client.get(f"/api/images/{image_id}")
    assert r_img_detail.status_code == 200
    assert r_img_detail.json()["data"]["merkle_verified"] is True

    r_rec_detail = client.get(f"/api/records/{image_id}")
    assert r_rec_detail.status_code == 200

    # 14. GET /api/stats (Dashboard Statistics)
    r_stats = client.get("/api/stats")
    assert r_stats.status_code == 200
    assert "merkle_root" in r_stats.json()["data"]

    # 15. GET /verify/{image_id} (Public Verification HTML & JSON views)
    r_vhtml = client.get(f"/verify/{image_id}")
    assert r_vhtml.status_code == 200
    assert "text/html" in r_vhtml.headers["content-type"]

    r_vjson = client.get(f"/verify/{image_id}?format=json")
    assert r_vjson.status_code == 200
    assert r_vjson.json()["data"]["merkle_verified"] is True

    # 16. DELETE /api/images/{image_id}
    r_del = client.delete(f"/api/images/{image_id}")
    assert r_del.status_code == 200


# ═══════════════════════════════════════════════════════════
#  TEST F: DOM-to-API Contract Alignment
# ═══════════════════════════════════════════════════════════
def test_dom_contract_static_alignment():
    """
    Parses templates/index.html and confirms that key v2 DOM element IDs
    referenced by static/js/app.js exist in the HTML markup.
    """
    import re
    with open("templates/index.html", "r", encoding="utf-8") as f:
        html = f.read()

    html_ids = set(re.findall(r'id=["\']([^"\']+)["\']', html))

    essential_ids = [
        "page-home", "page-analyze", "page-sign", "page-dashboard", "page-keys", "page-detail",
        "uploadZone", "fileInput", "uploadPreview", "previewImage", "fileInfo", "resultsContainer",
        "stepperContainer", "stepperStageTitle", "stepperStagePercent", "stepperBarFill", "stepperDetail",
        "signImageSelect", "signModeSelect", "serverKeyGroup", "signKeySelect", "passphraseGroup",
        "signPassphrase", "signActionBtn", "verifyImageSelect", "verificationResult",
        "recoverUploadZone", "recoverFileInput", "recoverResult",
        "statsGrid", "dashboardMerkleRoot", "dashboardTreeSize", "galleryGrid",
        "keyOwnerName", "keyOwnerEmail", "keyCustodyMode", "keyGenPassphraseGroup",
        "keyPassphrase", "keysList", "detailContent"
    ]

    missing = [eid for eid in essential_ids if eid not in html_ids]
    assert len(missing) == 0, f"Missing essential IDs in templates/index.html: {missing}"

    # Verify that 100% of getElementById calls in static/js/app.js exist in templates/index.html
    with open("static/js/app.js", "r", encoding="utf-8") as f:
        js = f.read()
    js_ids = set(re.findall(r"getElementById\(\s*['\"]([^'\"]+)['\"]\s*\)", js))
    missing_js_ids = [jid for jid in js_ids if jid not in html_ids]
    assert len(missing_js_ids) == 0, f"Missing IDs from static/js/app.js in templates/index.html: {missing_js_ids}"


# ═══════════════════════════════════════════════════════════
#  TEST G: Empirical Benchmark Metrics Verification
# ═══════════════════════════════════════════════════════════
def test_benchmark_metrics_validity():
    """
    Validates that results/benchmark_metrics.json exists, contains genuinely computed metrics,
    achieves 100% soft-binding recovery under WhatsApp compression, and maintains 100%
    Merkle micro-tamper detection across all tree sizes.
    """
    metrics_path = os.path.join("results", "benchmark_metrics.json")
    if not os.path.exists(metrics_path):
        import subprocess
        subprocess.run(["python", "scripts/run_benchmark.py"], check=True)

    assert os.path.exists(metrics_path), "benchmark_metrics.json was not generated!"

    with open(metrics_path, "r", encoding="utf-8") as f:
        metrics = json.load(f)

    # 1. Forensic metrics populated
    assert "regime_1_forensics" in metrics
    r1 = metrics["regime_1_forensics"]
    assert r1["mean_latency_ms"] > 0.0
    assert r1["class_summary"]["natural"]["fused_mean"] > r1["class_summary"]["spliced"]["fused_mean"]

    # 2. Survivability metrics populated
    assert "regime_2_survivability" in metrics
    r2 = metrics["regime_2_survivability"]
    wa_key = "3c. WhatsApp / JPEG (QF=50)"
    assert wa_key in r2
    assert r2[wa_key]["soft_recovery_rate_pct"] == 100.0, "Soft binding must achieve 100% recovery on WhatsApp compression!"
    assert r2[wa_key]["mean_hamming_distance"] <= 10.0

    # 3. Merkle scalability metrics populated
    assert "regime_3_crypto_merkle" in metrics
    r3 = metrics["regime_3_crypto_merkle"]
    merkle_trees = r3["merkle_scalability"]
    for size_str in ["10", "100", "1000", "5000"]:
        assert size_str in merkle_trees
        m = merkle_trees[size_str]
        assert m["tamper_detection_rate_pct"] == 100.0
        assert m["proof_path_length"] == m["expected_ceil_log2_n"]


# ═══════════════════════════════════════════════════════════
#  TEST H: Position-Invariant Forensics & Zero Spatial Blind Spots
# ═══════════════════════════════════════════════════════════
@pytest.mark.neural
def test_position_invariant_forensics_no_blind_spots(client):
    """
    Verifies position-invariant vision forensics across 100% of the canvas:
    (a) Natural photo with text overlay in middle/top AND natural photo without watermark both score >= 70% Authentic.
    (b) Splice injected into bottom 10% (y >= 0.85 * H) is detected and drops authenticity significantly (delta > 25 pts, marked Not Authentic).
    (c) Synthetic grid / diffusion images score low (< 55% or high AI prob >= 0.70).
    """
    from PIL import ImageDraw

    def make_natural_scene(w=400, h=400, seed=42):
        rng = np.random.RandomState(seed)
        white = rng.randn(h, w)
        fft_w = np.fft.fft2(white)
        ky = np.fft.fftfreq(h)[:, None]
        kx = np.fft.fftfreq(w)[None, :]
        k = np.sqrt(ky**2 + kx**2)
        k[0, 0] = 1.0
        pink = np.real(np.fft.ifft2(fft_w / (k**1.0)))
        pink = (pink - pink.min()) / (pink.max() - pink.min())
        arr = np.zeros((h, w, 3), dtype=np.float32)
        y, x = np.ogrid[:h, :w]
        grad = y / float(h)
        arr[:, :, 0] = (140 - grad * 60 + pink * 80)
        arr[:, :, 1] = (170 - grad * 40 + pink * 60)
        arr[:, :, 2] = (220 - grad * 120 + pink * 40)
        sensor_noise = rng.normal(0, 3.0, (h, w, 3))
        return np.clip(arr + sensor_noise, 0, 255).astype(np.uint8)

    arr_nat = make_natural_scene()

    # 1. Natural photo without watermark
    buf_clean = io.BytesIO()
    Image.fromarray(arr_nat).save(buf_clean, 'JPEG', quality=92)
    resp_clean = client.post('/api/analyze', files={'file': ('clean_nat.jpg', buf_clean.getvalue(), 'image/jpeg')})
    assert resp_clean.status_code == 200
    data_clean = resp_clean.json()['data']
    assert data_clean['is_authentic'] is True
    assert data_clean['authenticity_score'] >= 70.0

    # 2. Natural photo with text overlay in middle (zero false penalty on text)
    img_text = Image.fromarray(arr_nat.copy())
    draw = ImageDraw.Draw(img_text)
    draw.text((40, 180), 'BREAKING NEWS: LIVE VERIFICATION REPORT', fill=(255, 255, 255))
    buf_text = io.BytesIO()
    img_text.save(buf_text, 'JPEG', quality=92)
    resp_text = client.post('/api/analyze', files={'file': ('text_nat.jpg', buf_text.getvalue(), 'image/jpeg')})
    assert resp_text.status_code == 200
    data_text = resp_text.json()['data']
    assert data_text['is_authentic'] is True
    assert data_text['authenticity_score'] >= 70.0

    # 3. Splice injected into bottom 10% (y >= 0.85 * H)
    rng = np.random.RandomState(42)
    foreign = (rng.rand(60, 160, 3) * 180 + 30).astype(np.uint8)
    buf_p = io.BytesIO()
    Image.fromarray(foreign).save(buf_p, 'JPEG', quality=65)
    buf_p.seek(0)
    f_patch = np.array(Image.open(buf_p))
    arr_splice = arr_nat.copy()
    # Bottom 10%: y in [335, 395] is >= 0.84 * 400
    arr_splice[335:395, 80:240] = f_patch
    buf_splice = io.BytesIO()
    Image.fromarray(arr_splice).save(buf_splice, 'JPEG', quality=92)
    resp_splice = client.post('/api/analyze', files={'file': ('bottom_splice.jpg', buf_splice.getvalue(), 'image/jpeg')})
    assert resp_splice.status_code == 200
    data_splice = resp_splice.json()['data']
    assert data_splice['is_authentic'] is False
    assert data_splice['authenticity_score'] < 55.0
    assert (data_clean['authenticity_score'] - data_splice['authenticity_score']) > 25.0

    # 4. Synthetic grid / diffusion image
    synth = np.zeros((400, 400, 3), dtype=np.uint8)
    synth[::16, :, :] = 255
    synth[:, ::16, :] = 255
    buf_synth = io.BytesIO()
    Image.fromarray(synth).save(buf_synth, 'PNG')
    resp_synth = client.post('/api/analyze', files={'file': ('synth_grid.png', buf_synth.getvalue(), 'image/png')})
    assert resp_synth.status_code == 200
    data_synth = resp_synth.json()['data']
    assert (data_synth['is_authentic'] is False) or (data_synth['ai_generation_prob'] >= 0.70)


# ═══════════════════════════════════════════════════════════
#  TEST I: AI Slop vs Real Camera Discrimination
# ═══════════════════════════════════════════════════════════
@pytest.mark.neural
def test_ai_slop_vs_real_camera_discrimination(client):
    """
    Verifies Two-Gate Veto scoring & generative slop discrimination:
    (a) High-res indoor camera photo (simulating 720x1600 Samsung Galaxy S23 room photo
        with smooth walls, textured wallpaper, illumination falloff, and camera EXIF)
        -> MUST score authenticity_score >= 80.0% and ai_prob <= 25.0%.
    (b) 52 KB, 600x330 web-compressed hyper-textured "AI slop" image
        (stripped EXIF, dense multi-scale synthetic micro-contrast clutter across canvas, smooth VAE chroma)
        -> MUST score ai_prob >= 70.0% and authenticity_score <= 40.0% (flagged as Synthetic, NEVER Authentic).
    (c) Localized copy-move/spliced image
        -> MUST score authenticity_score <= 48.0%.
    """
    import piexif

    # ─────────────────────────────────────────────────────────────
    # Case a: High-resolution indoor smartphone camera photo (720x1600 Samsung Galaxy S23)
    # ─────────────────────────────────────────────────────────────
    h, w = 1600, 720
    rng = np.random.RandomState(42)
    room = np.full((h, w, 3), 195, dtype=np.float32)
    y, x = np.ogrid[:h, :w]
    illum = 1.0 - 0.20 * (y / float(h)) - 0.10 * (x / float(w))
    room = room * illum[:, :, None]

    # Wallpaper with multi-frequency optical pattern
    y_wp, x_wp = np.ogrid[:h, :280]
    pat = np.sin(y_wp / 12.0) * np.cos(x_wp / 12.0) * 30.0 + np.sin(y_wp / 30.0) * 20.0
    room[:, 440:, 0] += pat
    room[:, 440:, 1] += pat * 0.8
    room[:, 440:, 2] += pat * 0.5

    # Natural wall paint optical texture (1/f pink spectrum)
    white = rng.randn(h, w)
    fft_w = np.fft.fft2(white)
    ky = np.fft.fftfreq(h)[:, None]
    kx = np.fft.fftfreq(w)[None, :]
    k = np.sqrt(ky**2 + kx**2)
    k[0, 0] = 1.0
    pink = np.real(np.fft.ifft2(fft_w / (k**1.0)))
    pink = (pink - pink.min()) / (pink.max() - pink.min())
    room += (pink[:, :, None] * 12.0 - 6.0)
    room += rng.normal(0, 2.0, (h, w, 3))
    arr_s23 = np.clip(room, 0, 255).astype(np.uint8)

    zeroth_ifd = {
        piexif.ImageIFD.Make: 'Samsung',
        piexif.ImageIFD.Model: 'SM-S911B',
    }
    exif_ifd = {
        piexif.ExifIFD.ExposureTime: (1, 50),
        piexif.ExifIFD.FNumber: (18, 10),
        piexif.ExifIFD.ISOSpeedRatings: 200,
        piexif.ExifIFD.FocalLength: (54, 10),
        piexif.ExifIFD.DateTimeOriginal: '2024:03:15 14:22:10',
    }
    exif_dict = {'0th': zeroth_ifd, 'Exif': exif_ifd}
    exif_bytes = piexif.dump(exif_dict)

    buf_s23 = io.BytesIO()
    Image.fromarray(arr_s23).save(buf_s23, 'JPEG', quality=95, exif=exif_bytes)
    resp_a = client.post('/api/analyze', files={'file': ('galaxy_s23_indoor.jpg', buf_s23.getvalue(), 'image/jpeg')})
    assert resp_a.status_code == 200
    data_a = resp_a.json()['data']
    assert data_a['is_authentic'] is True
    assert data_a['authenticity_score'] >= 80.0
    assert data_a['ai_generation_prob'] <= 0.25
    assert data_a['verdict'] == 'Authentic Media'

    # ─────────────────────────────────────────────────────────────
    # Case b: 52 KB 600x330 web-compressed hyper-textured AI slop
    # ─────────────────────────────────────────────────────────────
    w_slop, h_slop = 600, 330
    y_s, x_s = np.mgrid[:h_slop, :w_slop]
    # Dense multi-scale synthetic micro-contrast clutter across the canvas
    clutter = (np.sin(x_s / 4.0) * np.cos(y_s / 4.0) * 80 +
               np.sin(x_s / 11.0 + y_s / 7.0) * 60 +
               np.cos(x_s / 2.0 - y_s / 3.0) * 40 + 128)
    clutter = np.clip(clutter, 0, 255).astype(np.uint8)

    arr_slop = np.zeros((h_slop, w_slop, 3), dtype=np.uint8)
    arr_slop[:, :, 0] = np.clip(clutter * 0.95 + 10, 0, 255)
    arr_slop[:, :, 1] = np.clip(clutter * 0.90 + 20, 0, 255)
    arr_slop[:, :, 2] = np.clip(clutter * 1.05 - 10, 0, 255)

    buf_slop = io.BytesIO()
    Image.fromarray(arr_slop).save(buf_slop, 'JPEG', quality=85)
    resp_b = client.post('/api/analyze', files={'file': ('ai_slop_thumbnail.jpg', buf_slop.getvalue(), 'image/jpeg')})
    assert resp_b.status_code == 200
    data_b = resp_b.json()['data']
    assert data_b['is_authentic'] is False
    assert data_b['ai_generation_prob'] >= 0.70
    assert data_b['authenticity_score'] <= 40.0
    assert data_b['verdict'] == 'AI-Generated / Synthetic Media'

    # ─────────────────────────────────────────────────────────────
    # Case c: Localized copy-move / splice manipulation
    # ─────────────────────────────────────────────────────────────
    def make_base_scene(w=400, h=400, seed=42):
        rng_c = np.random.RandomState(seed)
        white_c = rng_c.randn(h, w)
        fft_wc = np.fft.fft2(white_c)
        ky_c = np.fft.fftfreq(h)[:, None]
        kx_c = np.fft.fftfreq(w)[None, :]
        k_c = np.sqrt(ky_c**2 + kx_c**2)
        k_c[0, 0] = 1.0
        pink_c = np.real(np.fft.ifft2(fft_wc / (k_c**1.0)))
        pink_c = (pink_c - pink_c.min()) / (pink_c.max() - pink_c.min())
        arr_c = np.zeros((h, w, 3), dtype=np.float32)
        y_c, x_c = np.ogrid[:h, :w]
        grad_c = y_c / float(h)
        arr_c[:, :, 0] = (140 - grad_c * 60 + pink_c * 80)
        arr_c[:, :, 1] = (170 - grad_c * 40 + pink_c * 60)
        arr_c[:, :, 2] = (220 - grad_c * 120 + pink_c * 40)
        sensor_noise_c = rng_c.normal(0, 3.0, (h, w, 3))
        return np.clip(arr_c + sensor_noise_c, 0, 255).astype(np.uint8)

    arr_base = make_base_scene()
    foreign_c = (rng.rand(60, 160, 3) * 180 + 30).astype(np.uint8)
    buf_foreign = io.BytesIO()
    Image.fromarray(foreign_c).save(buf_foreign, 'JPEG', quality=65)
    buf_foreign.seek(0)
    foreign_patch = np.array(Image.open(buf_foreign))
    arr_spliced = arr_base.copy()
    arr_spliced[335:395, 80:240] = foreign_patch

    buf_splice_c = io.BytesIO()
    Image.fromarray(arr_spliced).save(buf_splice_c, 'JPEG', quality=92)
    resp_c = client.post('/api/analyze', files={'file': ('localized_splice.jpg', buf_splice_c.getvalue(), 'image/jpeg')})
    assert resp_c.status_code == 200
    data_c = resp_c.json()['data']
    assert data_c['is_authentic'] is False
    assert data_c['authenticity_score'] <= 48.0
    assert data_c['verdict'] == 'Manipulated / Spliced Forgery'


# ═══════════════════════════════════════════════════════════
#  TEST J: Two-Gate Veto UI, C2PA IPTC & PDF Synchronization
# ═══════════════════════════════════════════════════════════
@pytest.mark.neural
def test_two_gate_ui_c2pa_and_pdf_verdict_synchronization(client):
    """
    Verifies Phase 3 two-gate verdict synchronization across C2PA manifest assertions,
    ReportLab PDF certificates, and static design contract:
    1) Synthetic image returns verdict == 'AI-Generated / Synthetic Media',
       populates tamper_integrity_score and origin_integrity_score in forgery_details,
       and binds C2PA digitalSourceType = 'trainedAlgorithmicMedia'.
    2) Real camera image returns verdict == 'Authentic Media' and binds C2PA
       digitalSourceType = 'digitalCapture'.
    3) PDF certificates are generated cleanly with 200 OK for both classes.
    4) DESIGN.md exists and DOM-to-API contract checks pass.
    """
    import piexif

    # 0. Ensure a test signing key exists
    r_key = client.post("/api/keys/generate", data={
        "owner_name": "Synchronized Provenance Authority",
        "owner_email": "authority@imageguard.io",
        "custody_mode": "SERVER_AES_GCM",
        "passphrase": "authority-passphrase-2026"
    })
    assert r_key.status_code == 200
    key_id = r_key.json()["data"]["key_id"]

    # 1. Synthetic / AI Slop Image Ingestion & C2PA Assertion
    w_slop, h_slop = 600, 330
    y_s, x_s = np.mgrid[:h_slop, :w_slop]
    clutter = (np.sin(x_s / 4.0) * np.cos(y_s / 4.0) * 80 +
               np.sin(x_s / 11.0 + y_s / 7.0) * 60 +
               np.cos(x_s / 2.0 - y_s / 3.0) * 40 + 128)
    clutter = np.clip(clutter, 0, 255).astype(np.uint8)
    arr_slop = np.zeros((h_slop, w_slop, 3), dtype=np.uint8)
    arr_slop[:, :, 0] = np.clip(clutter * 0.95 + 10, 0, 255)
    arr_slop[:, :, 1] = np.clip(clutter * 0.90 + 20, 0, 255)
    arr_slop[:, :, 2] = np.clip(clutter * 1.05 - 10, 0, 255)

    buf_slop = io.BytesIO()
    Image.fromarray(arr_slop).save(buf_slop, 'JPEG', quality=85)
    resp_synth = client.post('/api/analyze', files={'file': ('synth_test_c2pa.jpg', buf_slop.getvalue(), 'image/jpeg')})
    assert resp_synth.status_code == 200
    synth_data = resp_synth.json()['data']
    synth_id = synth_data['id']

    assert synth_data['verdict'] == 'AI-Generated / Synthetic Media'
    synth_details = json.loads(synth_data['forgery_details'])
    assert 'gates' in synth_details
    assert 'tamper_integrity_score' in synth_details['gates']
    assert 'origin_integrity_score' in synth_details['gates']

    # Sign synthetic image and verify C2PA manifest assertions
    r_sign_synth = client.post(f"/api/sign/{synth_id}", data={
        "key_id": key_id,
        "passphrase": "authority-passphrase-2026"
    })
    assert r_sign_synth.status_code == 200

    r_synth_detail = client.get(f"/api/images/{synth_id}")
    assert r_synth_detail.status_code == 200
    synth_c2pa = r_synth_detail.json()["data"]["c2pa_parsed"]
    actions_synth = next(a["data"]["actions"] for a in synth_c2pa["assertions"] if a["label"] == "c2pa.actions")
    assert actions_synth[0]["predicted_source_type"] == "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"

    attest_synth = next(a["data"] for a in synth_c2pa["assertions"] if a["label"] == "org.imageguard.forensic_attestation")
    assert attest_synth["verdict"] == "AI-Generated / Synthetic Media"
    assert "gate1_tamper_integrity" in attest_synth
    assert "gate2_origin_integrity" in attest_synth

    # Generate PDF certificate for synthetic image
    r_synth_cert = client.post(f"/api/certificate/{synth_id}")
    assert r_synth_cert.status_code == 200
    assert "application/pdf" in r_synth_cert.headers["content-type"]

    # 2. Real Camera Photo Ingestion & C2PA Assertion
    h, w = 1600, 720
    rng = np.random.RandomState(42)
    room = np.full((h, w, 3), 195, dtype=np.float32)
    y, x = np.ogrid[:h, :w]
    illum = 1.0 - 0.20 * (y / float(h)) - 0.10 * (x / float(w))
    room = room * illum[:, :, None]

    y_wp, x_wp = np.ogrid[:h, :280]
    pat = np.sin(y_wp / 12.0) * np.cos(x_wp / 12.0) * 30.0 + np.sin(y_wp / 30.0) * 20.0
    room[:, 440:, 0] += pat
    room[:, 440:, 1] += pat * 0.8
    room[:, 440:, 2] += pat * 0.5

    white = rng.randn(h, w)
    fft_w = np.fft.fft2(white)
    ky = np.fft.fftfreq(h)[:, None]
    kx = np.fft.fftfreq(w)[None, :]
    k = np.sqrt(ky**2 + kx**2)
    k[0, 0] = 1.0
    pink = np.real(np.fft.ifft2(fft_w / (k**1.0)))
    pink = (pink - pink.min()) / (pink.max() - pink.min())
    room += (pink[:, :, None] * 12.0 - 6.0)
    room += rng.normal(0, 2.0, (h, w, 3))
    arr_camera = np.clip(room, 0, 255).astype(np.uint8)

    zeroth_ifd = {
        piexif.ImageIFD.Make: 'Samsung',
        piexif.ImageIFD.Model: 'SM-S911B',
    }
    exif_ifd = {
        piexif.ExifIFD.ExposureTime: (1, 50),
        piexif.ExifIFD.FNumber: (18, 10),
        piexif.ExifIFD.ISOSpeedRatings: 200,
        piexif.ExifIFD.FocalLength: (54, 10),
        piexif.ExifIFD.DateTimeOriginal: '2024:03:15 14:22:10',
    }
    exif_bytes = piexif.dump({'0th': zeroth_ifd, 'Exif': exif_ifd})

    buf_cam = io.BytesIO()
    Image.fromarray(arr_camera).save(buf_cam, 'JPEG', quality=95, exif=exif_bytes)
    resp_cam = client.post('/api/analyze', files={'file': ('real_camera_c2pa.jpg', buf_cam.getvalue(), 'image/jpeg')})
    assert resp_cam.status_code == 200
    cam_data = resp_cam.json()['data']
    cam_id = cam_data['id']

    assert cam_data['verdict'] == 'Authentic Media'

    # Sign real camera image and verify C2PA manifest assertions
    r_sign_cam = client.post(f"/api/sign/{cam_id}", data={
        "key_id": key_id,
        "passphrase": "authority-passphrase-2026"
    })
    assert r_sign_cam.status_code == 200

    r_cam_detail = client.get(f"/api/images/{cam_id}")
    assert r_cam_detail.status_code == 200
    cam_c2pa = r_cam_detail.json()["data"]["c2pa_parsed"]
    actions_cam = next(a["data"]["actions"] for a in cam_c2pa["assertions"] if a["label"] == "c2pa.actions")
    assert actions_cam[0]["predicted_source_type"] == "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture"

    attest_cam = next(a["data"] for a in cam_c2pa["assertions"] if a["label"] == "org.imageguard.forensic_attestation")
    assert attest_cam["verdict"] == "Authentic Media"

    # Generate PDF certificate for real camera image
    r_cam_cert = client.post(f"/api/certificate/{cam_id}")
    assert r_cam_cert.status_code == 200
    assert "application/pdf" in r_cam_cert.headers["content-type"]

    # 3. Design System & DOM Alignment Assertions
    assert os.path.exists("DESIGN.md"), "DESIGN.md design system must exist in project root"
    with open("DESIGN.md", "r", encoding="utf-8") as f:
        design_text = f.read()
    assert "DESIGN_VARIANCE" in design_text
    assert "VISUAL_DENSITY" in design_text

    with open("templates/index.html", "r", encoding="utf-8") as f:
        html_markup = f.read()
    assert "system-status-badge" in html_markup
    assert "Two-Gate Forensic Workbench" in html_markup


# ═══════════════════════════════════════════════════════════
#  TEST K: Low-Res Web Nature vs AI Slop Discrimination
# ═══════════════════════════════════════════════════════════
@pytest.mark.neural
def test_low_res_web_nature_vs_ai_slop_discrimination(client):
    """
    Verifies that low-resolution (480x640) natural outdoor photos with smooth sky,
    rainbow arc, and green grass/trees (with stripped EXIF and QF=75 compression)
    are NOT falsely penalized by AI slop detectors, while true AI slop and
    localized splices remain strictly detected:
    1. Low-Res Web Nature photo -> authenticity_score >= 65.0%, is_authentic is True,
       verdict == 'Authentic Media', ai_generation_prob < 0.30.
    2. 52 KB AI Slop thumbnail -> authenticity_score <= 40.0%, is_authentic is False,
       verdict == 'AI-Generated / Synthetic Media', ai_generation_prob >= 0.70.
    3. Localized Splice -> authenticity_score <= 48.0%, is_authentic is False,
       verdict == 'Manipulated / Spliced Forgery'.
    """
    # 1. 480x640 Low-res web nature photo (smooth rainbow sky + green foliage lawn)
    h_p, w_p = 480, 640
    park = np.zeros((h_p, w_p, 3), dtype=np.float32)
    y_p, x_p = np.mgrid[:h_p, :w_p]
    sky_y = y_p / float(h_p * 0.5)
    park[:, :, 0] = 135.0 + sky_y * 40.0
    park[:, :, 1] = 180.0 + sky_y * 30.0
    park[:, :, 2] = 235.0 - sky_y * 20.0

    cx, cy = w_p * 0.5, h_p * 0.6
    dist = np.sqrt((x_p - cx)**2 + (y_p - cy)**2)
    rainbow_mask = (dist > 180) & (dist < 230) & (y_p < h_p * 0.45)
    r_norm = (dist - 180) / 50.0
    park[rainbow_mask, 0] += np.sin(r_norm[rainbow_mask] * np.pi) * 45.0
    park[rainbow_mask, 1] += np.sin(r_norm[rainbow_mask] * np.pi + 1.0) * 35.0
    park[rainbow_mask, 2] += np.sin(r_norm[rainbow_mask] * np.pi + 2.0) * 40.0

    rng = np.random.RandomState(42)
    grass_mask = y_p >= int(h_p * 0.5)
    grass_y = (y_p - h_p * 0.5) / float(h_p * 0.5)
    base_green = np.array([45.0, 130.0, 35.0])
    park[grass_mask, :] = base_green + grass_y[grass_mask, None] * 25.0
    grass_noise = rng.normal(0, 18.0, (h_p, w_p, 3))
    park[grass_mask, :] += grass_noise[grass_mask, :]

    tree_band = (y_p >= int(h_p * 0.42)) & (y_p < int(h_p * 0.52))
    park[tree_band, 0] = 30 + rng.normal(0, 12.0, park[tree_band, 0].shape)
    park[tree_band, 1] = 75 + rng.normal(0, 15.0, park[tree_band, 1].shape)
    park[tree_band, 2] = 25 + rng.normal(0, 10.0, park[tree_band, 2].shape)

    park_arr = np.clip(park, 0, 255).astype(np.uint8)
    buf_park = io.BytesIO()
    Image.fromarray(park_arr).save(buf_park, 'JPEG', quality=75)
    resp_park = client.post('/api/analyze', files={'file': ('park_rainbow.jpg', buf_park.getvalue(), 'image/jpeg')})
    assert resp_park.status_code == 200
    d_park = resp_park.json()['data']
    assert d_park['is_authentic'] is True
    assert d_park['authenticity_score'] >= 65.0
    assert d_park['verdict'] == 'Authentic Media'
    assert d_park['ai_generation_prob'] < 0.30

    # 2. 52 KB AI Slop thumbnail (stripped EXIF, synthetic high-freq micro-contrast clutter)
    w_slop, h_slop = 600, 330
    y_s, x_s = np.mgrid[:h_slop, :w_slop]
    clutter = (np.sin(x_s / 4.0) * np.cos(y_s / 4.0) * 80 +
               np.sin(x_s / 11.0 + y_s / 7.0) * 60 +
               np.cos(x_s / 2.0 - y_s / 3.0) * 40 + 128)
    clutter = np.clip(clutter, 0, 255).astype(np.uint8)
    arr_slop = np.zeros((h_slop, w_slop, 3), dtype=np.uint8)
    arr_slop[:, :, 0] = np.clip(clutter * 0.95 + 10, 0, 255)
    arr_slop[:, :, 1] = np.clip(clutter * 0.90 + 20, 0, 255)
    arr_slop[:, :, 2] = np.clip(clutter * 1.05 - 10, 0, 255)
    buf_slop = io.BytesIO()
    Image.fromarray(arr_slop).save(buf_slop, 'JPEG', quality=85)
    resp_slop = client.post('/api/analyze', files={'file': ('ai_slop_nature.jpg', buf_slop.getvalue(), 'image/jpeg')})
    assert resp_slop.status_code == 200
    d_slop = resp_slop.json()['data']
    assert d_slop['is_authentic'] is False
    assert d_slop['authenticity_score'] <= 40.0
    assert d_slop['verdict'] == 'AI-Generated / Synthetic Media'
    assert d_slop['ai_generation_prob'] >= 0.70

    # 3. Localized copy-move / splice manipulation
    def make_base_scene(w=400, h=400, seed=42):
        rng_c = np.random.RandomState(seed)
        white_c = rng_c.randn(h, w)
        fft_wc = np.fft.fft2(white_c)
        ky_c = np.fft.fftfreq(h)[:, None]
        kx_c = np.fft.fftfreq(w)[None, :]
        k_c = np.sqrt(ky_c**2 + kx_c**2)
        k_c[0, 0] = 1.0
        pink_c = np.real(np.fft.ifft2(fft_wc / (k_c**1.0)))
        pink_c = (pink_c - pink_c.min()) / (pink_c.max() - pink_c.min())
        arr_c = np.zeros((h, w, 3), dtype=np.float32)
        y_c, x_c = np.ogrid[:h, :w]
        grad_c = y_c / float(h)
        arr_c[:, :, 0] = (140 - grad_c * 60 + pink_c * 80)
        arr_c[:, :, 1] = (170 - grad_c * 40 + pink_c * 60)
        arr_c[:, :, 2] = (220 - grad_c * 120 + pink_c * 40)
        sensor_noise_c = rng_c.normal(0, 3.0, (h, w, 3))
        return np.clip(arr_c + sensor_noise_c, 0, 255).astype(np.uint8)

    arr_base = make_base_scene()
    foreign_c = (rng.rand(60, 160, 3) * 180 + 30).astype(np.uint8)
    buf_foreign = io.BytesIO()
    Image.fromarray(foreign_c).save(buf_foreign, 'JPEG', quality=65)
    buf_foreign.seek(0)
    foreign_patch = np.array(Image.open(buf_foreign))
    arr_spliced = arr_base.copy()
    arr_spliced[335:395, 80:240] = foreign_patch
    buf_splice = io.BytesIO()
    Image.fromarray(arr_spliced).save(buf_splice, 'JPEG', quality=92)
    resp_splice = client.post('/api/analyze', files={'file': ('splice_nature.jpg', buf_splice.getvalue(), 'image/jpeg')})
    assert resp_splice.status_code == 200
    d_splice = resp_splice.json()['data']
    assert d_splice['is_authentic'] is False
    assert d_splice['authenticity_score'] <= 48.0
    assert d_splice['verdict'] == 'Manipulated / Spliced Forgery'






