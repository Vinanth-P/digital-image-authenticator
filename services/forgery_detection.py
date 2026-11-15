"""
Forgery Detection Service for ImageGuard v2.
Multi-Branch Neural & Spectral Forensics combining:
1. Error Level Analysis (ELA)
2. Spatial Rich Model (SRM) Steganalysis Residuals & TruFor Exposure Reliability
3. 2D FFT Azimuthally Averaged Radial Power Spectrum (1/f^2 optical law)
4. Deep Neural ONNX Synthetic Classifier (cftcimert/cifake-efficientnet-b0) + Patch Saliency
"""

import os
import io
import json
import numpy as np
from PIL import Image, ImageChops, ImageFilter, ImageEnhance
import cv2
import hashlib

from services.ai_detector_onnx import DeepForensicAnalyzer


class ForgeryDetector:
    """AI-based multi-branch image forgery and synthetic media detection engine."""

    def __init__(self, ela_quality=90, ela_scale=15, models_dir=None):
        self.ela_quality = ela_quality
        self.ela_scale = ela_scale
        self.deep_analyzer = DeepForensicAnalyzer(models_dir=models_dir)

    def compute_file_hash(self, image_bytes: bytes) -> str:
        """Compute SHA-256 hash of image binary data."""
        return hashlib.sha256(image_bytes).hexdigest()

    def perform_ela(self, image: Image.Image, save_path: str = None) -> tuple:
        """
        Error Level Analysis (ELA).
        Re-compresses the image and computes pixel-level differences.
        Evaluates 100% of the image canvas using full-canvas structural gradient normalization
        and 2D Connected-Component Clustering on robust MAD z-scores (Z > 2.5).
        Distinguishes isolated thin text/edge contours (low cluster mass) from genuine
        regional splices and copy-move manipulations (contiguous 2D cluster mass),
        providing generalizable, position-invariant forensics without any spatial blind spots.
        Returns: (ela_image, ela_score)
        """
        if image.mode != 'RGB':
            image = image.convert('RGB')

        # Save at known quality, then reload
        buffer = io.BytesIO()
        image.save(buffer, 'JPEG', quality=self.ela_quality)
        buffer.seek(0)
        recompressed = Image.open(buffer)

        # Compute absolute difference
        ela_image = ImageChops.difference(image, recompressed)

        # Amplify differences for visualization
        extrema = ela_image.getextrema()
        max_diff = max([ex[1] for ex in extrema])
        if max_diff == 0:
            max_diff = 1
        scale = 255.0 / max_diff * self.ela_scale
        ela_visual = ImageEnhance.Brightness(ela_image).enhance(scale)

        # Full-Canvas Edge & Structural Normalization
        img_np = np.array(image)
        rec_np = np.array(recompressed)
        ela_diff = np.mean(np.abs(img_np.astype(np.float32) - rec_np.astype(np.float32)), axis=2) / 255.0
        h, w = ela_diff.shape

        gray = cv2.cvtColor(img_np, cv2.COLOR_RGB2GRAY).astype(np.float32) / 255.0
        gx = cv2.Sobel(gray, cv2.CV_32F, 1, 0, ksize=3)
        gy = cv2.Sobel(gray, cv2.CV_32F, 0, 1, ksize=3)
        sobel_mag = np.sqrt(gx**2 + gy**2)
        laplacian = np.abs(cv2.Laplacian(gray, cv2.CV_32F))
        structural_energy = sobel_mag + laplacian

        # 16x16 block map across 100% of canvas (zero spatial slicing)
        block_size = 16
        n_by = h // block_size
        n_bx = w // block_size

        if n_by >= 2 and n_bx >= 2:
            R_grid = np.zeros((n_by, n_bx), dtype=np.float32)
            E_grid = np.zeros((n_by, n_bx), dtype=np.float32)
            G_grid = np.zeros((n_by, n_bx), dtype=np.float32)

            # Adaptive gradient normalization floor for small web-compressed JPEGs (accounts for heavier 8x8 DCT quantization)
            mean_ela = float(np.mean(ela_diff))
            web_scale = max(0.0, 1.0 - max(h, w) / 800.0) if max(h, w) <= 800 else 0.0
            norm_floor = 0.05 + 0.04 * web_scale + 0.5 * mean_ela

            for by in range(n_by):
                for bx in range(n_bx):
                    e_blk = float(np.mean(ela_diff[by*block_size:(by+1)*block_size, bx*block_size:(bx+1)*block_size]))
                    g_blk = float(np.mean(structural_energy[by*block_size:(by+1)*block_size, bx*block_size:(bx+1)*block_size]))
                    E_grid[by, bx] = e_blk
                    G_grid[by, bx] = g_blk
                    R_grid[by, bx] = e_blk / (g_blk + norm_floor)

            # Robust Median and MAD across full block grid (two-sided robust z-score)
            M = float(np.median(R_grid))
            MAD = max(1e-4, float(np.median(np.abs(R_grid - M))))
            Z_grid = np.abs(R_grid - M) / (1.4826 * MAD)

            # Absolute ELA residual z-score (captures direct recompression outliers across different QF patches)
            M_e = float(np.median(E_grid))
            MAD_e = max(1e-4, float(np.median(np.abs(E_grid - M_e))))
            Z_e = (E_grid - M_e) / (1.4826 * MAD_e)

            # Anomalous blocks: significant normalized Z score AND non-negligible absolute error, OR extreme absolute ELA outlier
            min_err_thresh = max(0.005, 0.4 * mean_ela)
            anomalous_mask = (((Z_grid > 2.5) & (E_grid > min_err_thresh)) | (Z_e > 3.0)).astype(np.uint8)
            num_labels, labels, stats, centroids = cv2.connectedComponentsWithStats(anomalous_mask, connectivity=8)

            total_blocks = n_by * n_bx
            max_cluster_mass = 0.0
            max_cluster_area = 0

            for l in range(1, num_labels):
                area = int(stats[l, cv2.CC_STAT_AREA])
                frac = area / float(total_blocks)
                c_w = int(stats[l, cv2.CC_STAT_WIDTH])
                c_h = int(stats[l, cv2.CC_STAT_HEIGHT])
                # Regional splices form contiguous 2D clusters (area >= 4, 1.0% - 45% of total canvas, spanning >= 2 blocks in both dims)
                # Thin 1-block text/edge lines have min(c_w, c_h) == 1 and are excluded from cluster mass
                if area >= 4 and 0.010 <= frac <= 0.45 and min(c_w, c_h) >= 2:
                    cluster_z = float(np.mean(np.maximum(Z_grid[labels == l], Z_e[labels == l])))
                    mass = frac * cluster_z
                    if mass > max_cluster_mass:
                        max_cluster_mass = mass
                        max_cluster_area = area

            # Cross-stratum dispersion consistency (smooth vs textured)
            p40 = float(np.percentile(G_grid, 40))
            s_mask = G_grid <= p40
            t_mask = G_grid > p40

            if np.any(s_mask):
                s_vals = E_grid[s_mask]
                iqr_s = float(np.percentile(s_vals, 75) - np.percentile(s_vals, 25))
                med_s = float(np.median(s_vals))
                cv_s = iqr_s / (med_s + 0.01 + 0.01 * web_scale)
            else:
                cv_s = 0.1

            if np.any(t_mask):
                t_vals = R_grid[t_mask]
                iqr_t = float(np.percentile(t_vals, 75) - np.percentile(t_vals, 25))
                med_t = float(np.median(t_vals))
                cv_t = iqr_t / (med_t + 0.01 + 0.01 * web_scale)
            else:
                cv_t = 0.1

            stratum_cv = 0.50 * cv_s + 0.50 * cv_t
            cluster_penalty = min(65.0, max_cluster_mass * 350.0)
            ela_score = max(0.0, min(100.0, 95.0 - stratum_cv * 10.0 - cluster_penalty))
        else:
            mean_error = float(np.mean(ela_diff))
            std_error = float(np.std(ela_diff))
            grad_mean = float(np.mean(structural_energy))
            norm_std = std_error / (grad_mean + 0.01)
            ela_score = max(0.0, min(100.0, 92.0 - norm_std * 15.0))

        if save_path:
            os.makedirs(os.path.dirname(os.path.abspath(save_path)), exist_ok=True)
            ela_visual.save(save_path, 'PNG')

        return ela_visual, round(ela_score, 2)

    def analyze_noise(self, image: Image.Image) -> tuple:
        """
        Noise Analysis.
        Analyzes noise patterns across 100% of the image canvas using Laplacian sliding window,
        normalized by local structural gradient to prevent false penalties on textured surfaces.
        Returns: (noise_map, noise_score)
        """
        if image.mode != 'RGB':
            image = image.convert('RGB')

        img_array = np.array(image).astype(np.float32)
        gray_uint8 = cv2.cvtColor(img_array.astype(np.uint8), cv2.COLOR_RGB2GRAY)
        gray = gray_uint8.astype(np.float32) / 255.0
        h, w = gray.shape

        laplacian = cv2.Laplacian(gray, cv2.CV_32F)
        kernel_size = 7
        local_mean = cv2.blur(laplacian, (kernel_size, kernel_size))
        local_sq_mean = cv2.blur(laplacian ** 2, (kernel_size, kernel_size))
        local_variance = np.clip(local_sq_mean - local_mean ** 2, 0.0, None)

        if local_variance.max() > 0:
            noise_map = (local_variance / local_variance.max() * 255).astype(np.uint8)
        else:
            noise_map = np.zeros_like(gray_uint8, dtype=np.uint8)

        # Full-canvas texture-normalized noise consistency
        gx = cv2.Sobel(gray, cv2.CV_32F, 1, 0, ksize=3)
        gy = cv2.Sobel(gray, cv2.CV_32F, 0, 1, ksize=3)
        grad_mag = np.sqrt(gx**2 + gy**2)
        local_grad = cv2.blur(grad_mag, (kernel_size, kernel_size))

        norm_local_var = local_variance / (local_grad + 0.05)

        med_var = float(np.median(norm_local_var))
        iqr_var = float(np.percentile(norm_local_var, 75) - np.percentile(norm_local_var, 25))
        tail_var = float(np.percentile(norm_local_var, 98) - med_var)

        if med_var > 1e-6:
            consistency = (iqr_var / (med_var + 1e-4)) + 0.8 * max(0.0, (tail_var / (med_var + 1e-4)) - 2.5)
            noise_score = max(0.0, min(100.0, 95.0 - consistency * 12.0))
        else:
            noise_score = 95.0

        return noise_map, round(noise_score, 2)

    def generate_heatmap(self, image: Image.Image, ela_image: Image.Image,
                         noise_map: np.ndarray, save_path: str = None) -> Image.Image:
        """
        Generate a combined heatmap overlay showing suspected tampered regions.
        """
        if image.mode != 'RGB':
            image = image.convert('RGB')

        img_array = np.array(image).astype(np.float64)
        ela_array = np.array(ela_image.resize(image.size)).astype(np.float64)

        noise_resized = cv2.resize(noise_map, (image.size[0], image.size[1]))

        ela_gray = np.mean(ela_array, axis=2)
        combined = (ela_gray * 0.7 + noise_resized.astype(np.float64) * 0.3)

        if combined.max() > 0:
            combined = (combined / combined.max() * 255).astype(np.uint8)
        else:
            combined = np.zeros_like(noise_resized, dtype=np.uint8)

        heatmap = cv2.applyColorMap(combined, cv2.COLORMAP_JET)
        heatmap_rgb = cv2.cvtColor(heatmap, cv2.COLOR_BGR2RGB)

        overlay = (img_array * 0.5 + heatmap_rgb.astype(np.float64) * 0.5).astype(np.uint8)
        result = Image.fromarray(overlay)

        if save_path:
            os.makedirs(os.path.dirname(os.path.abspath(save_path)), exist_ok=True)
            result.save(save_path, 'PNG')

        return result

    def cnn_classify(self, image: Image.Image) -> float:
        """
        Frequency domain and block analysis heuristic for copy-move and splicing.
        """
        if image.mode != 'RGB':
            image = image.convert('RGB')

        img_resized = image.resize((256, 256))
        img_array = np.array(img_resized).astype(np.float64)

        features = []
        for channel in range(3):
            ch = img_array[:, :, channel]
            dct = cv2.dct(ch.astype(np.float32))

            features.extend([
                np.mean(np.abs(dct)),
                np.std(dct),
                np.median(np.abs(dct)),
                float(np.percentile(np.abs(dct), 95)),
                float(np.percentile(np.abs(dct), 5)),
            ])
            features.extend([
                np.mean(ch),
                np.std(ch),
                float(np.median(ch)),
            ])
            edges = cv2.Canny(ch.astype(np.uint8), 50, 150)
            features.append(np.mean(edges))

        gray = cv2.cvtColor(img_array.astype(np.uint8), cv2.COLOR_RGB2GRAY)
        block_size = 32
        block_means = []
        for i in range(0, gray.shape[0] - block_size, block_size):
            for j in range(0, gray.shape[1] - block_size, block_size):
                block = gray[i:i + block_size, j:j + block_size]
                block_means.append(np.mean(block))

        block_means = np.array(block_means)
        if len(block_means) > 1:
            mean_diffs = np.abs(np.diff(np.sort(block_means)))
            very_similar = np.sum(mean_diffs < 0.5) / len(mean_diffs)
        else:
            very_similar = 0

        features.append(very_similar)
        features.append(self._jpeg_ghost_score(image))

        score = 85.0
        dct_stds = [features[1], features[6], features[11]]
        dct_std_variance = np.std(dct_stds) / (np.mean(dct_stds) + 1e-6)
        if dct_std_variance > 0.3:
            score -= dct_std_variance * 20

        if very_similar > 0.3:
            score -= very_similar * 30

        edge_densities = [features[8], features[17], features[26]]
        edge_variance = np.std(edge_densities) / (np.mean(edge_densities) + 1e-6)
        if edge_variance > 0.5:
            score -= edge_variance * 10

        jpeg_ghost = features[-1]
        if jpeg_ghost > 0.5:
            score -= jpeg_ghost * 15

        return round(max(0.0, min(100.0, score)), 2)

    def _jpeg_ghost_score(self, image: Image.Image) -> float:
        """Detect JPEG ghost artifacts indicating double compression."""
        if image.mode != 'RGB':
            image = image.convert('RGB')

        img_array = np.array(image).astype(np.float64)
        min_diff = float('inf')
        ghost_quality = -1

        for quality in range(50, 100, 5):
            buffer = io.BytesIO()
            image.save(buffer, 'JPEG', quality=quality)
            buffer.seek(0)
            recompressed = np.array(Image.open(buffer)).astype(np.float64)
            diff = np.mean(np.abs(img_array - recompressed))
            if diff < min_diff:
                min_diff = diff
                ghost_quality = quality

        typical_range = range(75, 96)
        if ghost_quality not in typical_range:
            return min(1.0, abs(ghost_quality - 85) / 35.0)

        return 0.1

    def full_analysis(self, image_bytes: bytes, upload_dir: str,
                      results_dir: str, filename_base: str,
                      progress_callback=None, has_camera: bool = False,
                      file_size_kb: float = 0) -> dict:
        """
        Perform complete v2 multi-branch forgery & spectral analysis on an image.
        Supports optional progress_callback(stage, percent, detail), has_camera indicator,
        and Two-Gate Veto Logic (Tamper Integrity Gate vs. Generative Origin Gate).
        Returns dict with all scores, paths, metrics, and details.
        """
        if not file_size_kb and image_bytes:
            file_size_kb = len(image_bytes) / 1024.0
        # Stage 1: Ingestion & Integrity Hashing
        if progress_callback:
            progress_callback("Ingestion & Integrity Hashing", 15, "Computing SHA-256 binary hash and decoding pixels")

        image = Image.open(io.BytesIO(image_bytes))
        if image.mode != 'RGB':
            image = image.convert('RGB')
        width, height = image.size
        file_hash = self.compute_file_hash(image_bytes)
        rgb_np = np.array(image)

        # Stage 2: Error Level Analysis (ELA)
        if progress_callback:
            progress_callback("Error Level Analysis (ELA)", 30, "Recompressing at quality 90 to isolate compression residuals")

        ela_path = os.path.join(results_dir, f'{filename_base}_ela.png')
        ela_image, ela_score = self.perform_ela(image, save_path=ela_path)

        # Stage 3: Spatial Rich Model (SRM) Residuals & Confidence
        if progress_callback:
            progress_callback("Spatial Rich Model (SRM) Residuals", 50, "Convolving with 30 steganalysis filters and TruFor confidence map")

        noise_map, noise_score = self.analyze_noise(image)
        srm_result = self.deep_analyzer.analyze_srm(rgb_np)
        srm_score = srm_result['srm_score']
        confidence_map = srm_result['confidence_map']

        # Combined noise/SRM score (weighted blend of SRM residuals and local variance)
        s_srm_noise = round(0.65 * srm_score + 0.35 * noise_score, 2)

        # Stage 4: 2D FFT Radial Power Spectrum
        if progress_callback:
            progress_callback("2D FFT Radial Power Spectrum", 70, "Azimuthally averaging 32 frequency bins to test 1/f^2 optical law")

        fft_result = self.deep_analyzer.analyze_fft_spectrum(rgb_np)
        fft_score = fft_result['fft_score']

        # Stage 5: Deep Neural & Frequency Forensics (with Optical & Gradient Cross-Calibration)
        if progress_callback:
            progress_callback("Deep Neural & Frequency Forensics", 85, "Executing ONNX CIFAKE classification and patch attribution")

        cnn_score = self.cnn_classify(image)
        syn_result = self.deep_analyzer.classify_synthetic(
            rgb_np,
            fft_score=fft_score,
            spectral_slope=fft_result.get('spectral_slope', 2.0),
            res_max=fft_result.get('residual_max', 0.1),
            ela_score=ela_score,
            srm_score=s_srm_noise,
            has_camera=has_camera,
            file_size_kb=file_size_kb
        )
        p_real = syn_result['p_real']
        p_ai = syn_result['p_ai']
        onnx_used = syn_result['onnx_used']
        attribution_map = syn_result['attribution_map']

        # Generate Suspicion Heatmap
        heatmap_path = os.path.join(results_dir, f'{filename_base}_heatmap.png')
        self.generate_heatmap(image, ela_image, noise_map, save_path=heatmap_path)

        # Generate Saliency / Confidence Overlay
        saliency_path = os.path.join(results_dir, f'{filename_base}_saliency.png')
        self.deep_analyzer.generate_saliency_overlay(
            rgb_np, attribution_map, confidence_map, save_path=saliency_path
        )

        # Stage 6: Finalizing Multi-Branch Authenticity Score (Two-Gate Veto Scoring)
        if progress_callback:
            progress_callback("Finalizing Report", 100, "Synthesizing two-gate veto rules into final verdict")

        # Gate 1: Splice & Tamper Integrity (Measures localized splicing, copy-move, double-compression)
        tamper_integrity_score = round(0.55 * ela_score + 0.45 * s_srm_noise, 2)

        # Gate 2: Generative Origin Integrity (Measures real optical capture vs. synthetic AI generation)
        ai_prob_pct = round(p_ai * 100.0, 2)
        origin_integrity_score = round(0.70 * (100.0 - ai_prob_pct) + 0.30 * fft_score, 2)

        # Soft-Min Two-Gate Veto Rule:
        if ai_prob_pct >= 55.0:
            # Whole-canvas AI media veto: high ELA and SRM must NOT rescue synthetic generation
            authenticity_score = round(min(tamper_integrity_score, origin_integrity_score) * 0.85, 2)
            verdict = "AI-Generated / Synthetic Media"
        elif tamper_integrity_score < 55.0:
            # Localized splice veto: clean optical origin must NOT rescue spliced tampering
            authenticity_score = round(min(tamper_integrity_score, origin_integrity_score), 2)
            verdict = "Manipulated / Spliced Forgery"
        elif tamper_integrity_score >= 60.0 and ai_prob_pct < 50.0:
            # Both gates cleanly passed: authentic camera capture
            authenticity_score = round(0.50 * tamper_integrity_score + 0.50 * origin_integrity_score, 2)
            verdict = "Authentic Media"
        else:
            # Borderline transition zone (e.g. tamper between 55 and 60, or AI prob between 50 and 55)
            if tamper_integrity_score < 60.0:
                authenticity_score = round(min(tamper_integrity_score, origin_integrity_score), 2)
                verdict = "Manipulated / Spliced Forgery"
            else:
                authenticity_score = round(min(tamper_integrity_score, origin_integrity_score) * 0.90, 2)
                verdict = "Potentially Forged / Synthetic"

        authenticity_score = max(0.0, min(100.0, authenticity_score))
        is_authentic = (authenticity_score >= 60.0)

        details = {
            'ela': {
                'score': ela_score,
                'description': 'Error Level Analysis detects regions with different compression levels',
                'status': 'Pass' if ela_score >= 60 else 'Suspicious'
            },
            'noise': {
                'score': s_srm_noise,
                'srm_score': srm_score,
                'laplacian_noise_score': noise_score,
                'description': '30-Filter Spatial Rich Model (SRM) & TruFor exposure-weighted residual analysis',
                'status': 'Pass' if s_srm_noise >= 60 else 'Suspicious'
            },
            'fft': {
                'score': fft_score,
                'spectral_slope': fft_result['spectral_slope'],
                'residual_std': fft_result['residual_std'],
                'residual_max': fft_result['residual_max'],
                'description': '2D FFT Azimuthally Averaged Radial Power Spectrum test against 1/f^2 optical law',
                'status': 'Pass' if fft_score >= 60 else 'Suspicious'
            },
            'models': self.deep_analyzer.model_status,
            'scores_calibrated': False,
            'ai_neural': {
                'p_real': p_real,
                'p_ai': p_ai,
                'onnx_used': onnx_used,
                'flat_residual_std': syn_result.get('flat_residual_std'),
                'score': round(p_real * 100.0, 2),
                'description': 'Deep Neural Synthetic Media Classifier (CIFAKE & Detectra OpenFake) with slop analysis',
                'status': 'Pass' if p_ai < 0.45 else 'Suspicious'
            },
            'cnn': {
                'score': cnn_score,
                'description': 'Frequency domain DCT and block-matching heuristic for copy-move detection',
                'status': 'Pass' if cnn_score >= 60 else 'Suspicious'
            },
            'gates': {
                'tamper_integrity_score': tamper_integrity_score,
                'origin_integrity_score': origin_integrity_score,
                'tamper_pass': tamper_integrity_score >= 60.0,
                'origin_pass': origin_integrity_score >= 60.0
            },
            'verdict': verdict,
            'confidence': authenticity_score
        }

        return {
            'file_hash': file_hash,
            'width': width,
            'height': height,
            'authenticity_score': authenticity_score,
            'tamper_integrity_score': tamper_integrity_score,
            'origin_integrity_score': origin_integrity_score,
            'ela_score': ela_score,
            'noise_score': s_srm_noise,
            'cnn_score': cnn_score,
            'fft_score': fft_score,
            'ai_generation_prob': round(p_ai, 4),
            'spectral_slope': fft_result['spectral_slope'],
            'frequencies': fft_result['frequencies'],
            'radial_bins': fft_result['radial_bins'],
            'is_authentic': is_authentic,
            'verdict': verdict,
            'forgery_details': json.dumps(details),
            'heatmap_path': f'results/{filename_base}_heatmap.png',
            'ela_image_path': f'results/{filename_base}_ela.png',
            'saliency_map_path': f'results/{filename_base}_saliency.png',
        }
