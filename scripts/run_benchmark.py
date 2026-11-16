#!/usr/bin/env python3
"""
ImageGuard v2 - Reproducible Empirical Benchmark Suite
Evaluates:
  REGIME 1: Quad-Branch Forensic Discrimination & Ablation (N=30 images, 3 classes)
  REGIME 2: Hard-Binding vs. Soft-Binding Adversarial Survivability Matrix (5 perturbation levels)
  REGIME 3: Zero-Trust Cryptography & Merkle Audit Scalability (N in {10, 100, 1000, 5000})

Outputs:
  - results/benchmark_metrics.json (structured JSON)
  - results/BENCHMARK_REPORT.md   (publication-grade markdown report)
"""

import os
import sys
import io
import time
import json
import math
import hashlib
import numpy as np
from PIL import Image

# Ensure project root is in sys.path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

os.environ.setdefault('IMAGEGUARD_DATA_DIR', os.path.join(BASE_DIR, 'results', 'bench_tmp', 'runtime'))
from config import Config
from services.forgery_detection import ForgeryDetector
from services.watermark_engine import SoftBindingService
from services.digital_signature import DigitalSignatureService, EnvelopeKeyVault
from services.merkle_ledger import MerkleAuditTree
from services.certificate_gen import CertificateGenerator

RESULTS_DIR = os.path.join(BASE_DIR, "results")
TEMP_DIR = os.path.join(RESULTS_DIR, "bench_tmp")
os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs(TEMP_DIR, exist_ok=True)


# ═════════════════════════════════════════════════════════════
#  SYNTHETIC IMAGE GENERATOR (REGIME 1)
# ═════════════════════════════════════════════════════════════
def generate_regime1_dataset(n_per_class: int = 10, size: int = 256, seed: int = 42):
    """
    Generate N=30 deterministic test images across 3 forensic classes:
    1. Natural: 1/f^2 optical gradients + camera sensor noise (authentic)
    2. Spliced: Base natural image with high-contrast copy-move / splice patch
    3. Synthetic: Periodic upsampling grid & diffusion-like checkerboard artifacts
    """
    rng = np.random.RandomState(seed)
    dataset = []

    X, Y = np.meshgrid(np.linspace(0, 1, size), np.linspace(0, 1, size))

    # Class 1: Natural Optical Images (10 images)
    for i in range(n_per_class):
        f1, f2 = 1.0 + 0.3 * (i % 3), 1.5 + 0.2 * (i % 4)
        smooth = 128.0 + 55.0 * np.sin(2 * np.pi * X * f1) * np.cos(2 * np.pi * Y * f2)
        sensor_noise = rng.normal(0, 3.5, (size, size))
        img_gray = np.clip(smooth + sensor_noise, 15, 240).astype(np.uint8)
        # Create 3-channel RGB with slight chromatic variation
        ch_r = np.clip(img_gray.astype(float) + rng.normal(0, 1.5, (size, size)), 0, 255).astype(np.uint8)
        ch_g = np.clip(img_gray.astype(float) + rng.normal(0, 1.5, (size, size)), 0, 255).astype(np.uint8)
        ch_b = np.clip(img_gray.astype(float) + rng.normal(0, 1.5, (size, size)), 0, 255).astype(np.uint8)
        rgb = np.stack([ch_r, ch_g, ch_b], axis=-1)

        pil_img = Image.fromarray(rgb)
        buf = io.BytesIO()
        pil_img.save(buf, format="JPEG", quality=95)
        dataset.append({
            "class": "natural",
            "index": i,
            "bytes": buf.getvalue(),
            "expected_authentic": True
        })

    # Class 2: Localized Copy-Move / Spliced Forgery (10 images)
    for i in range(n_per_class):
        f1, f2 = 1.2 + 0.2 * (i % 3), 1.4 + 0.2 * (i % 4)
        smooth = 128.0 + 50.0 * np.sin(2 * np.pi * X * f1) * np.cos(2 * np.pi * Y * f2)
        sensor_noise = rng.normal(0, 3.0, (size, size))
        img_gray = np.clip(smooth + sensor_noise, 15, 240).astype(np.uint8)
        rgb = np.stack([img_gray, img_gray, img_gray], axis=-1).copy()

        # Inject high-contrast spliced patch (15-20% area)
        patch_w, patch_h = 75, 75
        x0 = 30 + (i * 17) % (size - patch_w - 60)
        y0 = 30 + (i * 23) % (size - patch_h - 60)
        # Spliced texture from different distribution with sharp edges
        spliced_texture = (rng.rand(patch_h, patch_w, 3) * 200 + 30).astype(np.uint8)
        rgb[y0:y0 + patch_h, x0:x0 + patch_w] = spliced_texture

        pil_img = Image.fromarray(rgb)
        buf = io.BytesIO()
        # Save at different quality to simulate ELA discrepancy
        pil_img.save(buf, format="JPEG", quality=80)
        dataset.append({
            "class": "spliced",
            "index": i,
            "bytes": buf.getvalue(),
            "expected_authentic": False
        })

    # Class 3: Synthetic / Diffusion Grid Artifacts (10 images)
    for i in range(n_per_class):
        # High-frequency periodic grid ripples characteristic of deconvolution/diffusion
        grid_freq = 14 + (i % 5) * 2
        grid = 35.0 * np.sin(grid_freq * np.pi * X) * np.sin(grid_freq * np.pi * Y)
        smooth_base = 120.0 + 30.0 * (X + Y)
        synth_arr = np.clip(smooth_base + grid + rng.normal(0, 2.0, (size, size)), 10, 245).astype(np.uint8)
        rgb = np.stack([synth_arr, synth_arr, synth_arr], axis=-1)

        pil_img = Image.fromarray(rgb)
        buf = io.BytesIO()
        pil_img.save(buf, format="PNG")
        dataset.append({
            "class": "synthetic",
            "index": i,
            "bytes": buf.getvalue(),
            "expected_authentic": False
        })

    return dataset


# ═════════════════════════════════════════════════════════════
#  EXECUTE REGIME 1: FORENSIC DISCRIMINATION & ABLATION
# ═════════════════════════════════════════════════════════════
def run_regime_1(detector: ForgeryDetector):
    print("\n" + "=" * 65)
    print(" [REGIME 1] Quad-Branch Forensic Discrimination & Ablation")
    print("=" * 65)

    dataset = generate_regime1_dataset(n_per_class=10, size=256, seed=42)
    results_by_class = {"natural": [], "spliced": [], "synthetic": []}
    latencies = []

    for idx, item in enumerate(dataset):
        cls = item["class"]
        img_bytes = item["bytes"]
        name_base = f"bench_r1_{cls}_{item['index']}"

        t0 = time.perf_counter()
        res = detector.full_analysis(
            image_bytes=img_bytes,
            upload_dir=TEMP_DIR,
            results_dir=TEMP_DIR,
            filename_base=name_base
        )
        lat_ms = (time.perf_counter() - t0) * 1000.0
        latencies.append(lat_ms)

        ela_score = res["ela_score"]
        noise_score = res["noise_score"]
        fft_score = res.get("fft_score", 0.0)
        ai_prob = res.get("ai_generation_prob", 0.0)
        onnx_score = (1.0 - ai_prob) * 100.0
        fused_score = res["authenticity_score"]

        results_by_class[cls].append({
            "ela": ela_score,
            "srm": noise_score,
            "fft": fft_score,
            "onnx": onnx_score,
            "fused": fused_score,
            "ai_prob": ai_prob,
            "is_authentic": res["is_authentic"]
        })
        print(f"  [{cls.upper():9s} #{item['index']:02d}] Fused={fused_score:5.1f}% | ELA={ela_score:5.1f}% | SRM={noise_score:5.1f}% | FFT={fft_score:5.1f}% | Latency={lat_ms:5.1f}ms")

    # Aggregate Statistics
    summary = {}
    for cls in ["natural", "spliced", "synthetic"]:
        arr = results_by_class[cls]
        summary[cls] = {
            "n": len(arr),
            "ela_mean": float(np.mean([x["ela"] for x in arr])),
            "ela_std": float(np.std([x["ela"] for x in arr])),
            "srm_mean": float(np.mean([x["srm"] for x in arr])),
            "srm_std": float(np.std([x["srm"] for x in arr])),
            "fft_mean": float(np.mean([x["fft"] for x in arr])),
            "fft_std": float(np.std([x["fft"] for x in arr])),
            "onnx_mean": float(np.mean([x["onnx"] for x in arr])),
            "onnx_std": float(np.std([x["onnx"] for x in arr])),
            "fused_mean": float(np.mean([x["fused"] for x in arr])),
            "fused_std": float(np.std([x["fused"] for x in arr])),
            "accuracy": float(np.mean([1.0 if (x["is_authentic"] if cls == "natural" else not x["is_authentic"]) else 0.0 for x in arr])) * 100.0
        }

    # Separation deltas: Natural vs Spliced, Natural vs Synthetic
    mu_nat = summary["natural"]["fused_mean"]
    mu_spl = summary["spliced"]["fused_mean"]
    mu_syn = summary["synthetic"]["fused_mean"]

    single_branch_deltas = {
        "ela_delta_spliced": float(summary["natural"]["ela_mean"] - summary["spliced"]["ela_mean"]),
        "srm_delta_spliced": float(summary["natural"]["srm_mean"] - summary["spliced"]["srm_mean"]),
        "fft_delta_synthetic": float(summary["natural"]["fft_mean"] - summary["synthetic"]["fft_mean"]),
        "onnx_delta_synthetic": float(summary["natural"]["onnx_mean"] - summary["synthetic"]["onnx_mean"]),
        "quad_branch_delta_spliced": float(mu_nat - mu_spl),
        "quad_branch_delta_synthetic": float(mu_nat - mu_syn)
    }

    regime_1_metrics = {
        "class_summary": summary,
        "separation_deltas": single_branch_deltas,
        "mean_latency_ms": float(np.mean(latencies)),
        "p95_latency_ms": float(np.percentile(latencies, 95))
    }

    print("\n--- REGIME 1 SUMMARY ---")
    print(f"  Natural Class Mean Fused Score:   {summary['natural']['fused_mean']:.2f}% (std {summary['natural']['fused_std']:.2f})")
    print(f"  Spliced Class Mean Fused Score:   {summary['spliced']['fused_mean']:.2f}% (std {summary['spliced']['fused_std']:.2f})")
    print(f"  Synthetic Class Mean Fused Score: {summary['synthetic']['fused_mean']:.2f}% (std {summary['synthetic']['fused_std']:.2f})")
    print(f"  Quad-Branch Separation Delta (Natural - Spliced):   {single_branch_deltas['quad_branch_delta_spliced']:.2f} pts")
    print(f"  Quad-Branch Separation Delta (Natural - Synthetic): {single_branch_deltas['quad_branch_delta_synthetic']:.2f} pts")
    print(f"  Mean Per-Image Pipeline Latency:  {regime_1_metrics['mean_latency_ms']:.2f} ms")

    return regime_1_metrics


# ═════════════════════════════════════════════════════════════
#  EXECUTE REGIME 2: ADVERSARIAL SURVIVABILITY MATRIX
# ═════════════════════════════════════════════════════════════
def run_regime_2(soft_service: SoftBindingService, n_masters: int = 10):
    print("\n" + "=" * 65)
    print(" [REGIME 2] Hard-Binding vs. Soft-Binding Adversarial Matrix")
    print("=" * 65)

    rng = np.random.RandomState(42)
    masters = []

    # Generate N=10 textured signed master images with embedded frequency watermarks
    for i in range(n_masters):
        arr = (rng.rand(240, 240, 3) * 210 + 25).astype(np.uint8)
        img = Image.fromarray(arr)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        raw_bytes = buf.getvalue()

        master_id = 300 + i
        # Embed 64-bit blind frequency watermark
        wm_bytes = soft_service.embed_watermark(raw_bytes, image_id=master_id)
        master_hash = hashlib.sha256(wm_bytes).hexdigest()
        master_dhash = soft_service.compute_dhash(wm_bytes)

        masters.append({
            "id": master_id,
            "bytes": wm_bytes,
            "sha256": master_hash,
            "dhash": master_dhash
        })

    # Define 5 perturbation levels
    perturbations = [
        {"name": "1. Direct Transfer", "type": "identity"},
        {"name": "2. Metadata Strip (Lossless)", "type": "meta_strip"},
        {"name": "3a. JPEG Re-encode (QF=90)", "type": "jpeg", "qf": 90},
        {"name": "3b. JPEG Re-encode (QF=75)", "type": "jpeg", "qf": 75},
        {"name": "3c. WhatsApp / JPEG (QF=50)", "type": "jpeg", "qf": 50},
        {"name": "4. Luminance Shift (+10%)", "type": "color_shift"},
        {"name": "5. Localized 15% Splice", "type": "pixel_splice"}
    ]

    matrix_results = {}

    for pert in perturbations:
        p_name = pert["name"]
        hard_passes = 0
        wm_recovered = 0
        soft_recovered = 0
        hamming_distances = []
        change_percentages = []

        for m in masters:
            m_bytes = m["bytes"]
            expected_id = m["id"]
            p_type = pert["type"]

            if p_type == "identity":
                att_bytes = m_bytes
            elif p_type == "meta_strip":
                # Re-save through PIL PNG to strip all metadata/ancillary chunks
                img = Image.open(io.BytesIO(m_bytes))
                buf = io.BytesIO()
                img.save(buf, format="PNG", optimize=True)
                att_bytes = buf.getvalue()
            elif p_type == "jpeg":
                qf = pert["qf"]
                img = Image.open(io.BytesIO(m_bytes)).convert("RGB")
                buf = io.BytesIO()
                img.save(buf, format="JPEG", quality=qf)
                att_bytes = buf.getvalue()
            elif p_type == "color_shift":
                att_bytes = soft_service.apply_attack(m_bytes, "color_shift")
            elif p_type == "pixel_splice":
                att_bytes = soft_service.apply_attack(m_bytes, "pixel_splice")

            # Evaluate Hard Binding
            att_hash = hashlib.sha256(att_bytes).hexdigest()
            hard_valid = (att_hash == m["sha256"])
            if hard_valid:
                hard_passes += 1

            # Evaluate Watermark Extraction
            wm_res = soft_service.extract_watermark(att_bytes)
            wm_ok = (wm_res.get("is_valid") and wm_res.get("recovered_id") == expected_id)
            if wm_ok:
                wm_recovered += 1

            # Evaluate Perceptual dHash
            att_dhash = soft_service.compute_dhash(att_bytes)
            dh_dist = soft_service.hamming_distance(att_dhash, m["dhash"])
            hamming_distances.append(dh_dist)

            # Soft-Binding Recovery Criterion: Watermark decoded OR dH <= 10
            is_soft_recovered = (wm_ok or dh_dist <= 10)
            if is_soft_recovered:
                soft_recovered += 1

            # Tamper Localization Diff
            diff_save = os.path.join(TEMP_DIR, f"diff_{expected_id}.png")
            tamper_info = soft_service.localize_tampering(m_bytes, att_bytes, save_diff_path=diff_save)
            change_percentages.append(tamper_info["pixel_change_percentage"])

        n = len(masters)
        matrix_results[p_name] = {
            "hard_pass_rate_pct": float(hard_passes / n * 100.0),
            "watermark_recovery_rate_pct": float(wm_recovered / n * 100.0),
            "mean_hamming_distance": float(np.mean(hamming_distances)),
            "soft_recovery_rate_pct": float(soft_recovered / n * 100.0),
            "mean_pixel_change_pct": float(np.mean(change_percentages))
        }

        print(f"  {p_name:<28s} | Hard: {matrix_results[p_name]['hard_pass_rate_pct']:5.1f}% | "
              f"WM: {matrix_results[p_name]['watermark_recovery_rate_pct']:5.1f}% | "
              f"dH: {matrix_results[p_name]['mean_hamming_distance']:4.1f} | "
              f"Soft: {matrix_results[p_name]['soft_recovery_rate_pct']:5.1f}% | "
              f"ChangedPixels: {matrix_results[p_name]['mean_pixel_change_pct']:4.1f}%")

    return matrix_results


# ═════════════════════════════════════════════════════════════
#  EXECUTE REGIME 3: ZERO-TRUST CRYPTO & MERKLE SCALABILITY
# ═════════════════════════════════════════════════════════════
def run_regime_3():
    print("\n" + "=" * 65)
    print(" [REGIME 3] Zero-Trust Cryptography & Merkle Audit Scalability")
    print("=" * 65)

    sig_service = DigitalSignatureService(key_size=2048)
    cert_gen = CertificateGenerator(certificates_dir=TEMP_DIR)
    results = {}

    # 1. Scrypt + AES-256-GCM Envelope Encryption & Decryption
    envelope_enc_times = []
    envelope_dec_times = []
    test_pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----"
    key_id = "bench-key-id-9901"
    passphrase = "benchmark-secure-passphrase-2026"

    for _ in range(50):
        t0 = time.perf_counter()
        enc_payload = EnvelopeKeyVault.encrypt_private_key(test_pem, key_id, passphrase)
        envelope_enc_times.append((time.perf_counter() - t0) * 1000.0)

        t0 = time.perf_counter()
        dec_pem = EnvelopeKeyVault.decrypt_private_key(enc_payload, key_id, passphrase)
        envelope_dec_times.append((time.perf_counter() - t0) * 1000.0)
        assert dec_pem == test_pem

    results["aes_gcm_envelope"] = {
        "encryption_mean_ms": float(np.mean(envelope_enc_times)),
        "decryption_mean_ms": float(np.mean(envelope_dec_times)),
        "accuracy_pct": 100.0
    }
    print(f"  AES-256-GCM Envelope Encryption (Scrypt KEK): {results['aes_gcm_envelope']['encryption_mean_ms']:5.2f} ms")
    print(f"  AES-256-GCM Envelope Decryption + AEAD Check:  {results['aes_gcm_envelope']['decryption_mean_ms']:5.2f} ms")

    # 2. 2048-bit RSA-PSS Signing and Dual Verification
    key_pair_data = sig_service.generate_key_pair("Bench Authority", "bench@auth.local", "CLIENT_WEBCRYPTO")
    raw_priv = key_pair_data["raw_private_key_pem"]
    pub_pem = key_pair_data["public_key_pem"]
    payload_bytes = b"ImageGuard v2 Forensic Attestation Payload for Merkle Audit Ledger Benchmark"

    sign_times = []
    verify_backend_times = []
    verify_webcrypto_times = []

    for _ in range(50):
        # Backend RSA-PSS (Max Salt)
        t0 = time.perf_counter()
        sig_res = sig_service.sign_image(payload_bytes, raw_priv)
        sign_times.append((time.perf_counter() - t0) * 1000.0)
        sig_b64 = sig_res["signature"]

        # Verification with MAX_LENGTH salt
        t0 = time.perf_counter()
        v_res = sig_service.verify_signature(payload_bytes, sig_b64, pub_pem)
        verify_backend_times.append((time.perf_counter() - t0) * 1000.0)
        assert v_res["is_valid"] is True

        # WebCrypto 32-byte salt verification
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes, serialization
        import base64
        key_obj = serialization.load_pem_private_key(raw_priv.encode(), password=None)
        hash_bytes = sig_service.compute_image_hash(payload_bytes).encode('utf-8')
        wc_sig = key_obj.sign(hash_bytes, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
        wc_sig_b64 = base64.b64encode(wc_sig).decode()

        t0 = time.perf_counter()
        v_wc = sig_service.verify_signature(payload_bytes, wc_sig_b64, pub_pem)
        verify_webcrypto_times.append((time.perf_counter() - t0) * 1000.0)
        assert v_wc["is_valid"] is True

    results["rsa_pss_2048"] = {
        "signing_mean_ms": float(np.mean(sign_times)),
        "verify_backend_max_salt_ms": float(np.mean(verify_backend_times)),
        "verify_webcrypto_32_salt_ms": float(np.mean(verify_webcrypto_times)),
        "accuracy_pct": 100.0
    }
    print(f"  RSA-PSS 2048-bit Signing:                      {results['rsa_pss_2048']['signing_mean_ms']:5.2f} ms")
    print(f"  RSA-PSS Verify (Backend MAX_LENGTH salt):     {results['rsa_pss_2048']['verify_backend_max_salt_ms']:5.2f} ms")
    print(f"  RSA-PSS Verify (W3C WebCrypto 32-byte salt):   {results['rsa_pss_2048']['verify_webcrypto_32_salt_ms']:5.2f} ms")

    # 3. ReportLab PDF Certificate Generation Latency
    pdf_times = []
    dummy_record = {
        "id": 999,
        "original_filename": "benchmark_audit_master.png",
        "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "perceptual_dhash": "a1b2c3d4e5f60718",
        "file_size": 1024 * 128,
        "width": 1024,
        "height": 1024,
        "authenticity_score": 97.4,
        "ela_score": 98.1,
        "noise_score": 95.6,
        "fft_score": 97.0,
        "ai_generation_prob": 0.02,
        "is_authentic": True,
        "is_signed": True,
        "signer_name": "ImageGuard Benchmark Authority",
        "public_key_id": "key-benchmark-root",
        "signed_date": "2026-11-10T00:00:00",
        "upload_date": "2026-11-10T00:00:00",
        "signature": "MEYCIQD...",
        "merkle_leaf_hash": "8f4e2b...",
        "rfc3161_tst_b64": "MIIB...",
        "watermark_embedded": True
    }
    dummy_img_path = os.path.join(TEMP_DIR, "dummy_pdf_src.png")
    Image.new("RGB", (200, 200), (100, 150, 200)).save(dummy_img_path)

    for _ in range(10):
        t0 = time.perf_counter()
        cert_gen.generate_certificate(
            dummy_record, dummy_img_path,
            merkle_info={"root_hash": "a" * 64, "tree_size": 5000}
        )
        pdf_times.append((time.perf_counter() - t0) * 1000.0)

    results["pdf_certificate"] = {
        "generation_mean_ms": float(np.mean(pdf_times)),
        "p95_ms": float(np.percentile(pdf_times, 95))
    }
    print(f"  ReportLab PDF Certificate Generation:          {results['pdf_certificate']['generation_mean_ms']:5.2f} ms")

    # 4. Merkle Audit Scalability across Tree Sizes N in {10, 100, 1000, 5000}
    tree_sizes = [10, 100, 1000, 5000]
    merkle_bench = {}

    for n in tree_sizes:
        # Generate N deterministic leaf hashes
        leaves = [
            MerkleAuditTree.compute_leaf_hash(i + 1, f"hash_{i:06d}_{n}", 90.0 + (i % 10), "SIG")
            for i in range(n)
        ]
        target_idx = n // 2

        # Measure Tree Build & O(log N) Proof Generation Latency
        build_times = []
        for _ in range(10):
            t0 = time.perf_counter()
            tree_data = MerkleAuditTree.build_tree_and_proof(leaves, target_index=target_idx)
            build_times.append((time.perf_counter() - t0) * 1000.0)

        root = tree_data["root"]
        proof = tree_data["proof"]
        path_length = len(proof)
        expected_log_n = math.ceil(math.log2(n))

        # Measure Verification Latency
        verify_times = []
        for _ in range(50):
            t0 = time.perf_counter()
            is_valid = MerkleAuditTree.verify_inclusion_proof(leaves[target_idx], proof, root)
            verify_times.append((time.perf_counter() - t0) * 1000.0)
            assert is_valid is True

        # Tamper Detection Test (Micro-tamper 1 bit)
        tampered_leaf = leaves[target_idx][:-1] + ("0" if leaves[target_idx][-1] != "0" else "1")
        tamper_detected = not MerkleAuditTree.verify_inclusion_proof(tampered_leaf, proof, root)
        assert tamper_detected is True

        merkle_bench[str(n)] = {
            "tree_size": n,
            "proof_path_length": path_length,
            "expected_ceil_log2_n": expected_log_n,
            "build_proof_mean_ms": float(np.mean(build_times)),
            "verify_mean_ms": float(np.mean(verify_times)),
            "tamper_detection_rate_pct": 100.0
        }

        print(f"  Merkle Tree (N={n:4d}) | Proof Path: {path_length:2d} nodes (O(log N)) | "
              f"Build+Proof: {merkle_bench[str(n)]['build_proof_mean_ms']:5.2f} ms | "
              f"Verify: {merkle_bench[str(n)]['verify_mean_ms']:5.3f} ms | Tamper Detect: 100%")

    results["merkle_scalability"] = merkle_bench
    return results


# ═════════════════════════════════════════════════════════════
#  MARKDOWN REPORT GENERATOR
# ═════════════════════════════════════════════════════════════
def generate_markdown_report(metrics: dict, output_path: str):
    r1, r2, r3 = (metrics[k] for k in ['regime_1_forensics', 'regime_2_survivability', 'regime_3_crypto_merkle'])
    lines = ['# ImageGuard procedural regression benchmark', '',
             'These generated patterns exercise code paths. They are not captured photographs or generator outputs, and establish no real-world detection accuracy or platform-wide watermark survivability.', '',
             '| Fixture class | N | Mean score | Fixture classification accuracy (%) |', '|---|---:|---:|---:|']
    for name, values in r1['class_summary'].items():
        lines.append(f"| {name} | {values['n']} | {values['fused_mean']:.2f} | {values['accuracy']:.1f} |")
    lines += ['', f"Mean pipeline latency: {r1['mean_latency_ms']:.2f} ms; p95: {r1['p95_latency_ms']:.2f} ms.", '',
              '| Transform | Exact bytes preserved (%) | Exact watermark recovery (%) | Candidate dHash recovery (%) |', '|---|---:|---:|---:|']
    for name, values in r2.items():
        lines.append(f"| {name} | {values['hard_pass_rate_pct']} | {values['watermark_recovery_rate_pct']} | {values['soft_recovery_rate_pct']} |")
    lines += ['', 'Candidate matching does not authenticate a derivative. JPEG quality settings simulate a transformation, not a measurement of a live social platform.', '',
              '| Tree leaves | Proof nodes for selected leaf | Build and proof (ms) | Verify (ms) |', '|---|---:|---:|---:|']
    for values in r3['merkle_scalability'].values():
        lines.append(f"| {values['tree_size']} | {values['proof_path_length']} | {values['build_proof_mean_ms']:.3f} | {values['verify_mean_ms']:.3f} |")
    lines += ['', 'This measures Merkle primitives, not concurrent server throughput or protection against a compromised signing host. Full metrics are in benchmark_metrics.json.', '']
    with open(output_path, 'w', encoding='utf-8') as stream:
        stream.write('\n'.join(lines))


def main():
    print("=" * 65)
    print(" ImageGuard v2 - Autonomous Benchmark Runner")
    print(" Reproducible Empirical Forensic & Scalability Evaluation")
    print("=" * 65)

    Config.init_app()
    detector = ForgeryDetector(ela_quality=Config.ELA_QUALITY, ela_scale=Config.ELA_SCALE)
    soft_service = SoftBindingService()

    regime_1 = run_regime_1(detector)
    regime_2 = run_regime_2(soft_service, n_masters=10)
    regime_3 = run_regime_3()

    all_metrics = {
        "benchmark_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "regime_1_forensics": regime_1,
        "regime_2_survivability": regime_2,
        "regime_3_crypto_merkle": regime_3
    }

    # Save JSON metrics
    json_path = os.path.join(RESULTS_DIR, "benchmark_metrics.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(all_metrics, f, indent=2)
    print(f"[OK] Structured JSON metrics saved to: {json_path}")

    # Generate Markdown Report
    md_path = os.path.join(RESULTS_DIR, "BENCHMARK_REPORT.md")
    generate_markdown_report(all_metrics, md_path)

    print("\n" + "=" * 65)
    print(" [COMPLETE] ImageGuard v2 Benchmark Executed Successfully!")
    print("=" * 65)


if __name__ == "__main__":
    main()
