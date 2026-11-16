#!/usr/bin/env python3
"""
ImageGuard v2 - External & Stress Dataset Evaluation Suite
Evaluates empirical forensic classification performance across:
  - Mode A: External Datasets (CASIA v1/v2 'Au'/'Tp', or binary 'real'/'fake' directories)
  - Mode B: Built-in Empirical Stress Cohorts (High-Res Camera, Procedural landscape pattern, Spliced, AI Slop)

Metrics Computed:
  - Confusion Matrix (TP, TN, FP, FN)
  - Accuracy, Precision, Recall (Sensitivity), Specificity, False Positive Rate (FPR), F1-Score
  - ROC-AUC (Area Under the Receiver Operating Characteristic Curve)
  - Multi-Gate Forensic Dissection (Tamper Integrity Gate vs. Origin Integrity Gate)

Outputs:
  - Formatted CLI summary table
  - results/dataset_evaluation_metrics.json (structured JSON)
  - results/DATASET_ACCURACY_REPORT.md (publication-ready markdown report)
"""

import os
import sys
import io
import time
import json
import math
import argparse
import hashlib
import platform
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple, Any, Optional

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

import numpy as np
from PIL import Image
import piexif

# Ensure project root is in sys.path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from services.forgery_detection import ForgeryDetector
from services.metadata_analyzer import MetadataAnalyzer

RESULTS_DIR = os.path.join(BASE_DIR, "results")
TEMP_DIR = os.path.join(RESULTS_DIR, "eval_tmp")
os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs(TEMP_DIR, exist_ok=True)

IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp", ".tif", ".tiff", ".bmp"}


# ═════════════════════════════════════════════════════════════
#  MODE B: BUILT-IN EMPIRICAL STRESS COHORTS GENERATOR
# ═════════════════════════════════════════════════════════════
def generate_stress_cohorts(samples_per_cohort: int = 10, seed: int = 42) -> List[Dict[str, Any]]:
    """
    Generates deterministic evaluation cohorts:
    1. High-Res Camera (Authentic): Optical gradients, wallpaper texture, pink noise, camera EXIF
    2. Procedural landscape pattern (Authentic): 480x640 park/sky/rainbow/grass, stripped EXIF, QF=75
    3. Localized Splice (Tampered): Natural base with foreign compression patch inserted
    4. AI Slop Thumbnail (Synthetic): 600x330 dense multi-scale micro-contrast clutter
    """
    rng = np.random.RandomState(seed)
    samples = []

    # ─────────────────────────────────────────────────────────
    # Cohort 1: Procedural camera-like pattern (Authentic)
    # ─────────────────────────────────────────────────────────
    h_cam, w_cam = 800, 600
    for i in range(samples_per_cohort):
        room = np.full((h_cam, w_cam, 3), 195.0, dtype=np.float32)
        y, x = np.ogrid[:h_cam, :w_cam]
        illum = 1.0 - 0.20 * (y / float(h_cam)) - 0.10 * (x / float(w_cam))
        room = room * illum[:, :, None]

        # Multi-frequency optical pattern
        y_wp, x_wp = np.ogrid[:h_cam, :250]
        pat = np.sin(y_wp / (12.0 + i)) * np.cos(x_wp / (12.0 + i)) * 25.0
        room[:, 350:, 0] += pat
        room[:, 350:, 1] += pat * 0.8
        room[:, 350:, 2] += pat * 0.5

        # 1/f pink optical texture
        white = rng.randn(h_cam, w_cam)
        fft_w = np.fft.fft2(white)
        ky = np.fft.fftfreq(h_cam)[:, None]
        kx = np.fft.fftfreq(w_cam)[None, :]
        k = np.sqrt(ky**2 + kx**2)
        k[0, 0] = 1.0
        pink = np.real(np.fft.ifft2(fft_w / (k**1.0)))
        pink = (pink - pink.min()) / (pink.max() - pink.min())
        room += (pink[:, :, None] * 12.0 - 6.0)
        room += rng.normal(0, 2.5, (h_cam, w_cam, 3))
        arr_cam = np.clip(room, 0, 255).astype(np.uint8)

        # Realistic camera EXIF
        zeroth_ifd = {
            piexif.ImageIFD.Make: 'Samsung' if i % 2 == 0 else 'Apple',
            piexif.ImageIFD.Model: 'SM-S911B' if i % 2 == 0 else 'iPhone 15 Pro',
        }
        exif_ifd = {
            piexif.ExifIFD.ExposureTime: (1, 60 + i * 10),
            piexif.ExifIFD.FNumber: (18, 10),
            piexif.ExifIFD.ISOSpeedRatings: 100 + i * 50,
            piexif.ExifIFD.FocalLength: (24 + i * 4, 10),
            piexif.ExifIFD.DateTimeOriginal: f'2026:0{1 + (i % 9)}:15 14:22:10',
        }
        exif_bytes = piexif.dump({'0th': zeroth_ifd, 'Exif': exif_ifd})

        buf = io.BytesIO()
        Image.fromarray(arr_cam).save(buf, 'JPEG', quality=94, exif=exif_bytes)
        samples.append({
            "id": f"camera_{i:02d}",
            "cohort": "Procedural camera-like pattern",
            "ground_truth": "authentic",
            "is_authentic_gt": True,
            "bytes": buf.getvalue(),
            "has_camera": True,
            "file_name": f"camera_{i:02d}.jpg"
        })

    # ─────────────────────────────────────────────────────────
    # Cohort 2: Procedural landscape pattern & Foliage (Authentic)
    # ─────────────────────────────────────────────────────────
    h_p, w_p = 480, 640
    for i in range(samples_per_cohort):
        park = np.zeros((h_p, w_p, 3), dtype=np.float32)
        y_p, x_p = np.mgrid[:h_p, :w_p]
        sky_y = y_p / float(h_p * 0.5)
        park[:, :, 0] = 130.0 + sky_y * 45.0 + (i % 3) * 5.0
        park[:, :, 1] = 175.0 + sky_y * 35.0
        park[:, :, 2] = 230.0 - sky_y * 25.0

        # Rainbow arc
        cx, cy = w_p * (0.45 + 0.02 * (i % 5)), h_p * 0.60
        dist = np.sqrt((x_p - cx)**2 + (y_p - cy)**2)
        rainbow_mask = (dist > 180) & (dist < 230) & (y_p < h_p * 0.45)
        r_norm = (dist - 180) / 50.0
        park[rainbow_mask, 0] += np.sin(r_norm[rainbow_mask] * np.pi) * 45.0
        park[rainbow_mask, 1] += np.sin(r_norm[rainbow_mask] * np.pi + 1.0) * 35.0
        park[rainbow_mask, 2] += np.sin(r_norm[rainbow_mask] * np.pi + 2.0) * 40.0

        # Green grass lawn
        grass_mask = y_p >= int(h_p * 0.5)
        grass_y = (y_p - h_p * 0.5) / float(h_p * 0.5)
        base_green = np.array([40.0 + i, 125.0 + i * 2, 35.0])
        park[grass_mask, :] = base_green + grass_y[grass_mask, None] * 25.0

        # Stochastic natural texture
        grass_noise = rng.normal(0, 16.0 + (i % 4), (h_p, w_p, 3))
        park[grass_mask, :] += grass_noise[grass_mask, :]

        # Tree line
        tree_band = (y_p >= int(h_p * 0.42)) & (y_p < int(h_p * 0.52))
        park[tree_band, 0] = 30 + rng.normal(0, 12.0, park[tree_band, 0].shape)
        park[tree_band, 1] = 75 + rng.normal(0, 15.0, park[tree_band, 1].shape)
        park[tree_band, 2] = 25 + rng.normal(0, 10.0, park[tree_band, 2].shape)

        arr_park = np.clip(park, 0, 255).astype(np.uint8)
        buf = io.BytesIO()
        Image.fromarray(arr_park).save(buf, 'JPEG', quality=75)
        samples.append({
            "id": f"web_nature_{i:02d}",
            "cohort": "Procedural landscape pattern",
            "ground_truth": "authentic",
            "is_authentic_gt": True,
            "bytes": buf.getvalue(),
            "has_camera": False,
            "file_name": f"web_nature_{i:02d}.jpg"
        })

    # ─────────────────────────────────────────────────────────
    # Cohort 3: Localized Copy-Move & Splices (Tampered)
    # ─────────────────────────────────────────────────────────
    h_s, w_s = 400, 400
    for i in range(samples_per_cohort):
        white_s = rng.randn(h_s, w_s)
        fft_ws = np.fft.fft2(white_s)
        ky_s = np.fft.fftfreq(h_s)[:, None]
        kx_s = np.fft.fftfreq(w_s)[None, :]
        k_s = np.sqrt(ky_s**2 + kx_s**2)
        k_s[0, 0] = 1.0
        pink_s = np.real(np.fft.ifft2(fft_ws / (k_s**1.0)))
        pink_s = (pink_s - pink_s.min()) / (pink_s.max() - pink_s.min())
        arr_base = np.zeros((h_s, w_s, 3), dtype=np.float32)
        y_s, x_s = np.ogrid[:h_s, :w_s]
        grad_s = y_s / float(h_s)
        arr_base[:, :, 0] = (140 - grad_s * 60 + pink_s * 80)
        arr_base[:, :, 1] = (170 - grad_s * 40 + pink_s * 60)
        arr_base[:, :, 2] = (220 - grad_s * 120 + pink_s * 40)
        arr_base += rng.normal(0, 3.0, (h_s, w_s, 3))
        arr_base = np.clip(arr_base, 0, 255).astype(np.uint8)

        # Foreign patch
        pw, ph = 140 + (i % 3) * 20, 60 + (i % 2) * 15
        py0 = 40 + (i * 31) % (h_s - ph - 60)
        px0 = 40 + (i * 27) % (w_s - pw - 60)

        foreign = (rng.rand(ph, pw, 3) * 180 + 30).astype(np.uint8)
        buf_f = io.BytesIO()
        Image.fromarray(foreign).save(buf_f, 'JPEG', quality=60 + (i % 3) * 5)
        buf_f.seek(0)
        f_patch = np.array(Image.open(buf_f))

        arr_spliced = arr_base.copy()
        arr_spliced[py0:py0 + ph, px0:px0 + pw] = f_patch

        buf = io.BytesIO()
        Image.fromarray(arr_spliced).save(buf, 'JPEG', quality=92)
        samples.append({
            "id": f"spliced_{i:02d}",
            "cohort": "Localized Splices",
            "ground_truth": "tampered",
            "is_authentic_gt": False,
            "bytes": buf.getvalue(),
            "has_camera": False,
            "file_name": f"spliced_{i:02d}.jpg"
        })

    # ─────────────────────────────────────────────────────────
    # Cohort 4: Modern AI-Generated / Diffusion Slop (Synthetic)
    # ─────────────────────────────────────────────────────────
    w_slop, h_slop = 600, 330
    for i in range(samples_per_cohort):
        y_sl, x_sl = np.mgrid[:h_slop, :w_slop]
        f_shift = 0.1 * i
        clutter = (np.sin(x_sl / 4.0 + f_shift) * np.cos(y_sl / 4.0 + f_shift) * 80 +
                   np.sin(x_sl / 11.0 + y_sl / 7.0) * 60 +
                   np.cos(x_sl / 2.0 - y_sl / 3.0) * 40 + 128)
        clutter = np.clip(clutter, 0, 255).astype(np.uint8)

        arr_slop = np.zeros((h_slop, w_slop, 3), dtype=np.uint8)
        arr_slop[:, :, 0] = np.clip(clutter * 0.95 + 10, 0, 255)
        arr_slop[:, :, 1] = np.clip(clutter * 0.90 + 20, 0, 255)
        arr_slop[:, :, 2] = np.clip(clutter * 1.05 - 10, 0, 255)

        buf = io.BytesIO()
        Image.fromarray(arr_slop).save(buf, 'JPEG', quality=85)
        samples.append({
            "id": f"ai_slop_{i:02d}",
            "cohort": "Procedural periodic pattern",
            "ground_truth": "synthetic",
            "is_authentic_gt": False,
            "bytes": buf.getvalue(),
            "has_camera": False,
            "file_name": f"ai_slop_{i:02d}.jpg"
        })

    return samples


# ═════════════════════════════════════════════════════════════
#  MODE A: EXTERNAL DATASET SCANNER
# ═════════════════════════════════════════════════════════════
def scan_external_dataset(data_dir: str, limit: Optional[int] = None) -> List[Dict[str, Any]]:
    """Read explicitly labelled folders; never guess labels from substrings."""
    root = Path(data_dir).resolve()
    labels = {'au': 'authentic', 'authentic': 'authentic', 'real': 'authentic', 'genuine': 'authentic',
              'tp': 'tampered', 'tampered': 'tampered', 'manipulated': 'tampered', 'spliced': 'tampered',
              'ai': 'synthetic', 'synthetic': 'synthetic', 'fake': 'unspecified_negative'}
    if not root.is_dir():
        raise ValueError('Dataset directory does not exist')
    samples, counts = [], {}
    metadata = MetadataAnalyzer()
    for directory in sorted(root.iterdir()):
        if not directory.is_dir() or directory.name.lower() not in labels:
            continue
        label = labels[directory.name.lower()]
        for path in sorted(directory.rglob('*')):
            if not path.is_file() or path.suffix.lower() not in IMAGE_EXTENSIONS:
                continue
            if limit and counts.get(label, 0) >= limit:
                break
            raw = path.read_bytes()
            with Image.open(io.BytesIO(raw)) as image:
                image.verify()
            samples.append({'id': str(path.relative_to(root)), 'cohort': 'External ' + label,
                            'ground_truth': label, 'is_authentic_gt': label == 'authentic',
                            'bytes': raw, 'has_camera': metadata.get_full_report(raw)['analysis']['has_camera_info'],
                            'file_name': path.name})
            counts[label] = counts.get(label, 0) + 1
    if not samples:
        raise ValueError('No labelled samples: use real/, tampered/, synthetic/, or CASIA Au/ and Tp/')
    return samples


def rank_auc(labels, scores):
    """Exact rank AUC with average ranks for ties; undefined for one class."""
    positives = sum(labels)
    negatives = len(labels) - positives
    if not positives or not negatives:
        return None
    ordered = sorted(zip(scores, labels))
    rank_sum, index = 0.0, 0
    while index < len(ordered):
        end = index + 1
        while end < len(ordered) and ordered[end][0] == ordered[index][0]:
            end += 1
        rank_sum += sum(label for _, label in ordered[index:end]) * (index + 1 + end) / 2
        index = end
    return round((rank_sum - positives * (positives + 1) / 2) / (positives * negatives), 6)


def wilson_interval(correct, total):
    if not total:
        return None
    z = 1.959963984540054
    p = correct / total
    denominator = 1 + z*z/total
    center = (p + z*z/(2*total)) / denominator
    radius = z * math.sqrt(p*(1-p)/total + z*z/(4*total*total)) / denominator
    return [round(100 * (center-radius), 2), round(100 * (center+radius), 2)]


def evaluate_samples(samples: List[Dict[str, Any]], verbose: bool = False, source_kind: str = 'procedural_regression') -> Dict[str, Any]:
    """
    Executes the multi-branch forensic detection pipeline on each sample,
    records latencies, and computes statistical performance metrics.
    """
    if not samples:
        raise ValueError('Cannot evaluate an empty dataset')
    fingerprints = [hashlib.sha256(sample['bytes']).hexdigest() for sample in samples]
    if len(set(fingerprints)) != len(fingerprints):
        raise ValueError('Duplicate image bytes in evaluation set; deduplicate before evaluation')
    detector = ForgeryDetector()
    results = []
    latencies_ms = []

    total_n = len(samples)
    print(f"\n[INFO] Starting empirical evaluation across N={total_n} images...")

    for idx, sample in enumerate(samples, 1):
        t0 = time.perf_counter()
        raw_bytes = sample["bytes"]
        file_size_kb = len(raw_bytes) / 1024.0
        has_cam = sample.get("has_camera", False)
        base_name = f"eval_{idx:06d}"

        res = detector.full_analysis(
            raw_bytes,
            upload_dir=TEMP_DIR,
            results_dir=TEMP_DIR,
            filename_base=base_name,
            has_camera=has_cam,
            file_size_kb=file_size_kb
        )
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        latencies_ms.append(elapsed_ms)

        pred_authentic = res["is_authentic"]
        gt_authentic = sample["is_authentic_gt"]
        auth_score = res["authenticity_score"]

        results.append({
            "id": sample["id"],
            "sha256": hashlib.sha256(raw_bytes).hexdigest(),
            "onnx_used": json.loads(res["forgery_details"])["ai_neural"].get("onnx_used", False),
            "cohort": sample["cohort"],
            "ground_truth": sample["ground_truth"],
            "is_authentic_gt": gt_authentic,
            "predicted_authentic": pred_authentic,
            "authenticity_score": auth_score,
            "verdict": res["verdict"],
            "tamper_integrity_score": res["tamper_integrity_score"],
            "origin_integrity_score": res["origin_integrity_score"],
            "ai_generation_prob": res["ai_generation_prob"],
            "ela_score": res["ela_score"],
            "noise_score": res["noise_score"],
            "fft_score": res["fft_score"],
            "latency_ms": round(elapsed_ms, 2)
        })

        if verbose or idx % 5 == 0 or idx == total_n:
            status = "PASS [CORRECT]" if (pred_authentic == gt_authentic) else "FAIL [INCORRECT]"
            print(f"  [{idx:03d}/{total_n:03d}] {sample['cohort']:<26} | Score: {auth_score:5.2f}% | Pred: {res['verdict']:<28} | {status} ({elapsed_ms:.1f}ms)")

    # ─────────────────────────────────────────────────────────
    # Compute Confusion Matrix (Authentic = Positive, Fake/Tampered = Negative)
    # ─────────────────────────────────────────────────────────
    tp = sum(1 for r in results if r["is_authentic_gt"] and r["predicted_authentic"])
    tn = sum(1 for r in results if not r["is_authentic_gt"] and not r["predicted_authentic"])
    fp = sum(1 for r in results if not r["is_authentic_gt"] and r["predicted_authentic"])
    fn = sum(1 for r in results if r["is_authentic_gt"] and not r["predicted_authentic"])

    total = len(results)
    actual_pos = tp + fn
    actual_neg = tn + fp

    accuracy = (tp + tn) / float(total) if total > 0 else 0.0
    precision = tp / float(tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / float(actual_pos) if actual_pos > 0 else 0.0
    specificity = tn / float(actual_neg) if actual_neg > 0 else 0.0
    fpr = fp / float(actual_neg) if actual_neg > 0 else 0.0
    fdr = fp / float(tp + fp) if (tp + fp) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    balanced_acc = (recall + specificity) / 2.0

    # ─────────────────────────────────────────────────────────
    # ROC-AUC Calculation (Sweeping Authenticity Threshold [0..100])
    # ─────────────────────────────────────────────────────────
    roc_auc = rank_auc([r['is_authentic_gt'] for r in results], [r['authenticity_score'] for r in results])

    cohorts_dict = {}
    for r in results:
        c = r["cohort"]
        if c not in cohorts_dict:
            cohorts_dict[c] = []
        cohorts_dict[c].append(r)

    cohort_metrics = {}
    for c_name, c_samples in cohorts_dict.items():
        c_tot = len(c_samples)
        c_corr = sum(1 for s in c_samples if s["predicted_authentic"] == s["is_authentic_gt"])
        scores = [s["authenticity_score"] for s in c_samples]
        ai_probs = [s["ai_generation_prob"] for s in c_samples]
        tampers = [s["tamper_integrity_score"] for s in c_samples]
        origins = [s["origin_integrity_score"] for s in c_samples]

        cohort_metrics[c_name] = {
            "total_samples": c_tot,
            "correct_classifications": c_corr,
            "accuracy_pct": round((c_corr / float(c_tot)) * 100.0, 2),
            "ground_truth": c_samples[0]["ground_truth"],
            "mean_authenticity_score": round(float(np.mean(scores)), 2),
            "std_authenticity_score": round(float(np.std(scores)), 2),
            "mean_ai_generation_prob": round(float(np.mean(ai_probs)), 4),
            "mean_tamper_score": round(float(np.mean(tampers)), 2),
            "mean_origin_score": round(float(np.mean(origins)), 2)
        }

    return {
        "evaluation_context": {"source_kind": source_kind, "python": platform.python_version(),
                               "platform": platform.platform(), "models": detector.deep_analyzer.model_status,
                               "positive_class": "authentic", "scores_calibrated": False,
                               "dataset_sha256": hashlib.sha256(''.join(sorted(fingerprints)).encode()).hexdigest(),
                               "external_generalization_established": False},
        "dataset_summary": {
            "total_images": total,
            "authentic_images": actual_pos,
            "manipulated_synthetic_images": actual_neg,
            "mean_latency_ms": round(float(np.mean(latencies_ms)), 2),
            "std_latency_ms": round(float(np.std(latencies_ms)), 2),
            "throughput_fps": round(1000.0 / float(np.mean(latencies_ms)), 2) if np.mean(latencies_ms) > 0 else 0.0
        },
        "confusion_matrix": {
            "true_positives": tp,
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn
        },
        "performance_metrics": {
            "accuracy_pct": round(accuracy * 100.0, 2),
            "accuracy_wilson_95_pct": wilson_interval(tp + tn, total),
            "precision_pct": round(precision * 100.0, 2),
            "recall_sensitivity_pct": round(recall * 100.0, 2),
            "specificity_pct": round(specificity * 100.0, 2),
            "false_positive_rate_pct": round(fpr * 100.0, 2),
            "false_discovery_rate_pct": round(fdr * 100.0, 2),
            "f1_score": round(f1, 4),
            "balanced_accuracy_pct": round(balanced_acc * 100.0, 2),
            "roc_auc": roc_auc
        },
        "cohort_breakdown": cohort_metrics,
        "sample_records": results
    }


# ═════════════════════════════════════════════════════════════
#  REPORT GENERATORS (CLI TABLE & MARKDOWN)
# ═════════════════════════════════════════════════════════════
def print_cli_summary(metrics: Dict[str, Any]):
    """Prints a structured ANSI / ASCII summary table to the console."""
    ds = metrics["dataset_summary"]
    cm = metrics["confusion_matrix"]
    pm = metrics["performance_metrics"]
    cb = metrics["cohort_breakdown"]

    print("\n" + "=" * 78)
    print("         IMAGEGUARD v2 -- EMPIRICAL DATASET ACCURACY REPORT")
    print("=" * 78)
    print(f" Dataset Scale : N = {ds['total_images']} images ({ds['authentic_images']} Authentic | {ds['manipulated_synthetic_images']} Forged/Synthetic)")
    print(f" Latency       : {ds['mean_latency_ms']:.1f} +/- {ds['std_latency_ms']:.1f} ms/image ({ds['throughput_fps']:.1f} images/sec)")
    print("-" * 78)
    print(" 1. CONFUSION MATRIX (Pos = Authentic, Neg = Manipulated/Synthetic):")
    print("      +------------------------+------------------------+")
    print("      | Predicted Authentic    | Predicted Forged / AI  |")
    print(" +----+------------------------+------------------------+")
    print(f" | GT | True Positive (TP):{cm['true_positives']:3d} | False Negative(FN):{cm['false_negatives']:3d} |")
    print(f" |    | False Positive(FP):{cm['false_positives']:3d} | True Negative (TN):{cm['true_negatives']:3d} |")
    print(" +----+------------------------+------------------------+")
    print("-" * 78)
    print(" 2. CORE PERFORMANCE METRICS:")
    print(f"   * Overall Accuracy        : {pm['accuracy_pct']:6.2f}%")
    print(f"   * Precision               : {pm['precision_pct']:6.2f}%")
    print(f"   * Recall (Sensitivity)    : {pm['recall_sensitivity_pct']:6.2f}%")
    print(f"   * Specificity             : {pm['specificity_pct']:6.2f}%")
    print(f"   * False Positive Rate     : {pm['false_positive_rate_pct']:6.2f}%")
    print(f"   * F1-Score                : {pm['f1_score']:6.4f}")
    print(f"   * Balanced Accuracy       : {pm['balanced_accuracy_pct']:6.2f}%")
    print(f"   * ROC-AUC Area            : {str(pm['roc_auc'])}")
    print("-" * 78)
    print(" 3. COHORT ACCURACY & FORENSIC PROFILE:")
    print(f"   {'Cohort Name':<28} | {'N':<3} | {'Acc %':<7} | {'Auth Score':<11} | {'Gate 1 (Tamper)':<15} | {'Gate 2 (Origin)':<15}")
    print("   " + "-" * 74)
    for c_name, c_data in cb.items():
        print(f"   {c_name:<28} | {c_data['total_samples']:<3} | {c_data['accuracy_pct']:5.1f}% | {c_data['mean_authenticity_score']:5.1f}+/-{c_data['std_authenticity_score']:3.1f} | {c_data['mean_tamper_score']:5.1f}%          | {c_data['mean_origin_score']:5.1f}%")
    print("=" * 78 + "\n")


def generate_markdown_report(metrics: Dict[str, Any], output_path: str):
    ds, pm = metrics['dataset_summary'], metrics['performance_metrics']
    context = metrics.get('evaluation_context', {})
    checks = [('Accuracy (%)', pm['accuracy_pct'], 90, '>='),
              ('Precision (%)', pm['precision_pct'], 90, '>='),
              ('Recall, authentic positive (%)', pm['recall_sensitivity_pct'], 90, '>='),
              ('Specificity (%)', pm['specificity_pct'], 90, '>='),
              ('False acceptance rate (%)', pm['false_positive_rate_pct'], 5, '<='),
              ('F1', pm['f1_score'], .90, '>='), ('ROC-AUC', pm['roc_auc'], .95, '>='),
              ('Mean latency (ms)', ds['mean_latency_ms'], 250, '<='),
              ('Sequential throughput (images/sec)', ds['throughput_fps'], 4, '>=')]
    lines = ['# ImageGuard evaluation report', '',
             '**Source:** ' + context.get('source_kind', 'legacy_unknown'),
             '**Samples:** ' + str(ds['total_images']),
             '**Accuracy Wilson 95% interval:** ' + str(pm.get('accuracy_wilson_95_pct', 'unavailable')), '',
             'Procedural fixtures test regressions, not real camera or generator accuracy. External folders use supplied labels; source independence and train/test separation require a dataset audit. Scores are uncalibrated. Targets below are project goals, not industry standards.', '',
             '| Metric | Measured | Project target | Status |', '|---|---:|---:|---|']
    for label, measured, target, direction in checks:
        passed = measured is not None and (measured >= target if direction == '>=' else measured <= target)
        status = 'UNDEFINED' if measured is None else ('PASS' if passed else 'FAIL')
        lines.append(f'| {label} | {measured} | {direction} {target} | {status} |')
    lines += ['', '## Cohorts', '', '| Cohort | N | Accuracy (%) |', '|---|---:|---:|']
    for name, values in metrics['cohort_breakdown'].items():
        lines.append(f"| {name} | {values['total_samples']} | {values['accuracy_pct']} |")
    lines += ['', '## Misclassifications', '']
    failures = [r for r in metrics['sample_records'] if r['is_authentic_gt'] != r['predicted_authentic']]
    for row in failures[:30]:
        safe_id = str(row['id']).replace('|', '/').replace('\n', ' ')
        lines.append(f"- `{safe_id}`: supplied label {row['ground_truth']}; prediction {row['verdict']}; score {row['authenticity_score']}")
    if not failures:
        lines.append('None in this sample set. This does not establish zero real-world error.')
    lines += ['', '## Reproducibility', '', '```json', json.dumps(context, indent=2), '```', '']
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text('\n'.join(lines), encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description="ImageGuard v2 External & Stress Dataset Evaluation Suite")
    parser.add_argument("--data-dir", type=str, default=None, help="Path to external dataset (e.g. CASIA v1/v2 Au/Tp or real/fake directory)")
    parser.add_argument("--limit", type=int, default=None, help="Maximum number of images per category to evaluate")
    parser.add_argument("--output-json", type=str, default=os.path.join(RESULTS_DIR, "dataset_evaluation_metrics.json"), help="Output JSON path")
    parser.add_argument("--output-report", type=str, default=os.path.join(RESULTS_DIR, "DATASET_ACCURACY_REPORT.md"), help="Output Markdown report path")
    parser.add_argument("--verbose", action="store_true", help="Print verbose per-sample classification log")
    parser.add_argument('--transform', choices=['original', 'jpeg75', 'resize50'], default='original')
    args = parser.parse_args()
    if args.limit is not None and args.limit < 1:
        parser.error('--limit must be positive')
    if args.data_dir and not Path(args.data_dir).is_dir():
        parser.error('--data-dir does not exist; refusing to substitute generated fixtures')

    if args.data_dir and os.path.exists(args.data_dir):
        print(f"[MODE A] Scanning external dataset: {args.data_dir}")
        samples = scan_external_dataset(args.data_dir, limit=args.limit)
    else:
        print("[MODE B] Generating procedural regression fixtures (camera-like, landscape, spliced, periodic patterns)...")
        n_per_cohort = args.limit if args.limit else 10
        samples = generate_stress_cohorts(samples_per_cohort=n_per_cohort)

    if not samples:
        print("[ERROR] No valid image samples discovered. Exiting.")
        sys.exit(1)

    if args.transform != 'original':
        for sample in samples:
            image = Image.open(io.BytesIO(sample['bytes'])).convert('RGB')
            if args.transform == 'resize50':
                image = image.resize((max(64, image.width // 2), max(64, image.height // 2)))
            buffer = io.BytesIO()
            image.save(buffer, 'JPEG', quality=75 if args.transform == 'jpeg75' else 95)
            sample['bytes'], sample['has_camera'] = buffer.getvalue(), False
    metrics = evaluate_samples(samples, verbose=args.verbose, source_kind='external_supplied_labels' if args.data_dir else 'procedural_regression')
    metrics['evaluation_context']['transform'] = args.transform
    Path(args.output_json).parent.mkdir(parents=True, exist_ok=True)
    print_cli_summary(metrics)

    # Save JSON metrics
    with open(args.output_json, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    print(f"[OK] Structured evaluation metrics saved to: {args.output_json}")

    # Generate Markdown Report
    generate_markdown_report(metrics, args.output_report)


if __name__ == "__main__":
    main()
