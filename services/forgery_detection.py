"""
Forgery Detection Service for ImageGuard.
Implements Error Level Analysis (ELA), Noise Analysis, and CNN-based classification.
"""

import os
import io
import json
import numpy as np
from PIL import Image, ImageChops, ImageFilter, ImageEnhance
import cv2
import hashlib
import tempfile


class ForgeryDetector:
    """AI-based image forgery detection engine."""

    def __init__(self, ela_quality=90, ela_scale=15):
        self.ela_quality = ela_quality
        self.ela_scale = ela_scale

    def compute_file_hash(self, image_bytes: bytes) -> str:
        """Compute SHA-256 hash of image binary data."""
        return hashlib.sha256(image_bytes).hexdigest()

    def perform_ela(self, image: Image.Image, save_path: str = None) -> tuple:
        """
        Error Level Analysis (ELA).
        Re-compresses the image and computes pixel-level differences.
        Tampered regions show higher error levels.

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
        ela_image = ImageEnhance.Brightness(ela_image).enhance(scale)

        # Compute ELA score (higher = more suspicious)
        ela_array = np.array(ela_image).astype(np.float64)
        mean_error = np.mean(ela_array)
        std_error = np.std(ela_array)

        # Normalize score: higher std relative to mean indicates tampering
        # Score 0-100 where 100 = definitely authentic
        raw_score = (std_error / (mean_error + 1e-6)) * 10
        ela_score = max(0, min(100, 100 - raw_score * 5))

        if save_path:
            ela_image.save(save_path, 'PNG')

        return ela_image, round(ela_score, 2)

    def analyze_noise(self, image: Image.Image) -> tuple:
        """
        Noise Analysis.
        Analyzes noise patterns across the image.
        Spliced regions typically have different noise characteristics.

        Returns: (noise_map, noise_score)
        """
        if image.mode != 'RGB':
            image = image.convert('RGB')

        img_array = np.array(image).astype(np.float64)

        # Apply Laplacian filter to detect edges/noise
        gray = cv2.cvtColor(img_array.astype(np.uint8), cv2.COLOR_RGB2GRAY)
        laplacian = cv2.Laplacian(gray, cv2.CV_64F)

        # Compute local noise variance using sliding window
        kernel_size = 7
        local_mean = cv2.blur(laplacian, (kernel_size, kernel_size))
        local_sq_mean = cv2.blur(laplacian ** 2, (kernel_size, kernel_size))
        local_variance = local_sq_mean - local_mean ** 2
        local_variance = np.clip(local_variance, 0, None)

        # Normalize variance map
        if local_variance.max() > 0:
            noise_map = (local_variance / local_variance.max() * 255).astype(np.uint8)
        else:
            noise_map = np.zeros_like(gray, dtype=np.uint8)

        # Score based on variance consistency
        # Authentic images have consistent noise, forged ones don't
        variance_of_variance = np.std(local_variance)
        mean_variance = np.mean(local_variance)

        if mean_variance > 0:
            consistency = variance_of_variance / mean_variance
            noise_score = max(0, min(100, 100 - consistency * 2))
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

        # Resize noise map to match
        noise_resized = cv2.resize(noise_map, (image.size[0], image.size[1]))

        # Combine ELA and noise into a single suspicion map
        ela_gray = np.mean(ela_array, axis=2)
        combined = (ela_gray * 0.7 + noise_resized.astype(np.float64) * 0.3)

        # Normalize
        if combined.max() > 0:
            combined = (combined / combined.max() * 255).astype(np.uint8)
        else:
            combined = np.zeros_like(noise_resized, dtype=np.uint8)

        # Apply colormap for visualization
        heatmap = cv2.applyColorMap(combined, cv2.COLORMAP_JET)
        heatmap_rgb = cv2.cvtColor(heatmap, cv2.COLOR_BGR2RGB)

        # Overlay on original image
        overlay = (img_array * 0.5 + heatmap_rgb.astype(np.float64) * 0.5).astype(np.uint8)
        result = Image.fromarray(overlay)

        if save_path:
            result.save(save_path, 'PNG')

        return result

    def cnn_classify(self, image: Image.Image) -> float:
        """
        CNN-based forgery classification.
        Uses a lightweight approach based on statistical features
        extracted from the image's frequency domain.

        Returns: cnn_score (0-100 where 100 = authentic)
        """
        if image.mode != 'RGB':
            image = image.convert('RGB')

        # Resize for consistent analysis
        img_resized = image.resize((256, 256))
        img_array = np.array(img_resized).astype(np.float64)

        features = []

        for channel in range(3):
            ch = img_array[:, :, channel]

            # DCT-based features (frequency domain analysis)
            dct = cv2.dct(ch.astype(np.float32))

            # Statistical features from DCT coefficients
            features.extend([
                np.mean(np.abs(dct)),
                np.std(dct),
                np.median(np.abs(dct)),
                float(np.percentile(np.abs(dct), 95)),
                float(np.percentile(np.abs(dct), 5)),
            ])

            # Spatial domain features
            features.extend([
                np.mean(ch),
                np.std(ch),
                float(np.median(ch)),
            ])

            # Edge density
            edges = cv2.Canny(ch.astype(np.uint8), 50, 150)
            features.append(np.mean(edges))

        # Block-based analysis for copy-move detection
        gray = cv2.cvtColor(img_array.astype(np.uint8), cv2.COLOR_RGB2GRAY)
        block_size = 32
        block_means = []
        block_stds = []

        for i in range(0, gray.shape[0] - block_size, block_size):
            for j in range(0, gray.shape[1] - block_size, block_size):
                block = gray[i:i + block_size, j:j + block_size]
                block_means.append(np.mean(block))
                block_stds.append(np.std(block))

        # Check for suspiciously similar blocks (copy-move indicator)
        block_means = np.array(block_means)
        block_stds = np.array(block_stds)

        # Compute pairwise similarity
        if len(block_means) > 1:
            mean_diffs = np.abs(np.diff(np.sort(block_means)))
            very_similar = np.sum(mean_diffs < 0.5) / len(mean_diffs)
        else:
            very_similar = 0

        features.append(very_similar)

        # JPEG ghost detection
        features.append(self._jpeg_ghost_score(image))

        # Heuristic classifier based on feature analysis
        feature_array = np.array(features)

        # Scoring based on multiple indicators
        score = 85.0  # Base score (slight benefit of the doubt)

        # High frequency inconsistency suggests tampering
        dct_stds = [features[1], features[6], features[11]]
        dct_std_variance = np.std(dct_stds) / (np.mean(dct_stds) + 1e-6)
        if dct_std_variance > 0.3:
            score -= dct_std_variance * 20

        # Block similarity (copy-move)
        if very_similar > 0.3:
            score -= very_similar * 30

        # Edge consistency
        edge_densities = [features[8], features[17], features[26]]
        edge_variance = np.std(edge_densities) / (np.mean(edge_densities) + 1e-6)
        if edge_variance > 0.5:
            score -= edge_variance * 10

        # JPEG ghost
        jpeg_ghost = features[-1]
        if jpeg_ghost > 0.5:
            score -= jpeg_ghost * 15

        return round(max(0, min(100, score)), 2)

    def _jpeg_ghost_score(self, image: Image.Image) -> float:
        """
        Detect JPEG ghost artifacts indicating double compression.
        """
        if image.mode != 'RGB':
            image = image.convert('RGB')

        img_array = np.array(image).astype(np.float64)
        min_diff = float('inf')
        ghost_quality = -1

        # Test multiple quality levels
        for quality in range(50, 100, 5):
            buffer = io.BytesIO()
            image.save(buffer, 'JPEG', quality=quality)
            buffer.seek(0)
            recompressed = np.array(Image.open(buffer)).astype(np.float64)

            diff = np.mean(np.abs(img_array - recompressed))
            if diff < min_diff:
                min_diff = diff
                ghost_quality = quality

        # If the minimum difference quality is far from typical camera quality (75-95),
        # it suggests the image was previously compressed at a different quality
        typical_range = range(75, 96)
        if ghost_quality not in typical_range:
            return min(1.0, abs(ghost_quality - 85) / 35.0)

        return 0.1  # Low suspicion

    def full_analysis(self, image_bytes: bytes, upload_dir: str,
                      results_dir: str, filename_base: str) -> dict:
        """
        Perform complete forgery analysis on an image.

        Returns dict with all scores, paths, and details.
        """
        image = Image.open(io.BytesIO(image_bytes))
        width, height = image.size

        # File hash
        file_hash = self.compute_file_hash(image_bytes)

        # ELA
        ela_path = os.path.join(results_dir, f'{filename_base}_ela.png')
        ela_image, ela_score = self.perform_ela(image, save_path=ela_path)

        # Noise analysis
        noise_map, noise_score = self.analyze_noise(image)

        # CNN classification
        cnn_score = self.cnn_classify(image)

        # Generate heatmap
        heatmap_path = os.path.join(results_dir, f'{filename_base}_heatmap.png')
        self.generate_heatmap(image, ela_image, noise_map, save_path=heatmap_path)

        # Combined authenticity score (weighted average)
        authenticity_score = round(
            ela_score * 0.35 + noise_score * 0.25 + cnn_score * 0.40,
            2
        )

        is_authentic = authenticity_score >= 60

        details = {
            'ela': {
                'score': ela_score,
                'description': 'Error Level Analysis detects regions with different compression levels',
                'status': 'Pass' if ela_score >= 60 else 'Suspicious'
            },
            'noise': {
                'score': noise_score,
                'description': 'Noise analysis checks for inconsistent noise patterns across the image',
                'status': 'Pass' if noise_score >= 60 else 'Suspicious'
            },
            'cnn': {
                'score': cnn_score,
                'description': 'Frequency domain and block analysis detects copy-move and splicing',
                'status': 'Pass' if cnn_score >= 60 else 'Suspicious'
            },
            'verdict': 'Authentic' if is_authentic else 'Potentially Forged',
            'confidence': authenticity_score
        }

        return {
            'file_hash': file_hash,
            'width': width,
            'height': height,
            'authenticity_score': authenticity_score,
            'ela_score': ela_score,
            'noise_score': noise_score,
            'cnn_score': cnn_score,
            'is_authentic': is_authentic,
            'forgery_details': json.dumps(details),
            'heatmap_path': f'results/{filename_base}_heatmap.png',
            'ela_image_path': f'results/{filename_base}_ela.png',
        }
