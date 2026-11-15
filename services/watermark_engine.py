"""
Soft-Binding Survivability Engine & Adversarial Attack Simulator.
Implements:
1. Perceptual Difference Hashing (dHash 64-bit) & Hamming Distance Evaluation
2. Invisible Frequency Watermarking (64-bit ASCII payload "IG" + 6-digit ID) via Y-channel 8x8 DCT
3. Post-Signing Tamper Localization (cv2.absdiff with JET colormap diff overlay)
4. Adversarial Attack Regimes (whatsapp_compress, color_shift, pixel_splice)
"""

import os
import io
import math
import numpy as np
import cv2
from PIL import Image

try:
    from imwatermark import WaterMark
except ImportError:
    WaterMark = None


class SoftBindingService:
    """Soft-Binding Survivability and Tamper Localization Engine."""

    WATERMARK_PREFIX = "IG"
    DCT_DELTA = 22.0  # Modulation strength for JPEG QF 70 survivability

    # ═══════════════════════════════════════════════════════════
    #  1. Perceptual Difference Hashing (dHash 64-bit)
    # ═══════════════════════════════════════════════════════════
    @staticmethod
    def compute_dhash(image_input) -> str:
        """
        Compute 64-bit perceptual difference hash (dHash).
        Resizes grayscale image to 9x8 and compares adjacent horizontal pixels.
        Returns 16-character hexadecimal string.
        """
        if isinstance(image_input, bytes):
            image = Image.open(io.BytesIO(image_input))
        elif isinstance(image_input, np.ndarray):
            image = Image.fromarray(image_input)
        else:
            image = image_input

        # Convert to grayscale and resize to 9 width x 8 height
        gray = image.convert('L').resize((9, 8), Image.Resampling.LANCZOS)
        pixels = np.array(gray)

        # Difference computation: I(x+1, y) > I(x, y)
        difference = pixels[:, 1:] > pixels[:, :-1]
        bits = difference.flatten()

        # Convert 64 boolean bits to integer then 16-char hex
        decimal_val = 0
        for bit in bits:
            decimal_val = (decimal_val << 1) | int(bit)

        return f"{decimal_val:016x}"

    @staticmethod
    def hamming_distance(hash1: str, hash2: str) -> int:
        """
        Compute bitwise Hamming distance between two 64-bit hex hashes.
        d_H(h1, h2) = popcount(h1 XOR h2).
        """
        try:
            val1 = int(hash1, 16)
            val2 = int(hash2, 16)
            xor_val = val1 ^ val2
            return bin(xor_val).count('1')
        except Exception:
            return 64

    # ═══════════════════════════════════════════════════════════
    #  2. Invisible Frequency Watermarking (Y-channel 8x8 DCT)
    # ═══════════════════════════════════════════════════════════
    @classmethod
    def format_payload(cls, image_id: int) -> str:
        """Format 64-bit payload: 'IG' + 6-digit zero-padded id (e.g. 'IG000042')."""
        return f"{cls.WATERMARK_PREFIX}{int(image_id):06d}"

    @classmethod
    def payload_to_bits(cls, payload_str: str) -> list:
        """Convert 8-character string to 64 bits list."""
        payload_bytes = payload_str.encode('ascii')[:8].ljust(8, b'0')
        bits = []
        for b in payload_bytes:
            for i in range(7, -1, -1):
                bits.append((b >> i) & 1)
        return bits

    @classmethod
    def bits_to_payload(cls, bits: list) -> str:
        """Convert 64 bits list back to 8-character string."""
        if len(bits) < 64:
            return ""
        chars = []
        for byte_idx in range(8):
            byte_val = 0
            for bit_idx in range(8):
                byte_val = (byte_val << 1) | int(bits[byte_idx * 8 + bit_idx])
            chars.append(chr(byte_val))
        return "".join(chars)

    def embed_watermark(self, image_bytes: bytes, image_id: int) -> bytes:
        """
        Embed 64-bit watermark payload ('IG' + 6-digit ID) into Y-channel 8x8 DCT mid-bands.
        Returns watermarked image bytes.
        """
        payload_str = self.format_payload(image_id)
        bits = self.payload_to_bits(payload_str)

        img = Image.open(io.BytesIO(image_bytes))
        orig_format = img.format or 'PNG'
        if img.mode != 'RGB':
            img = img.convert('RGB')
        rgb = np.array(img)
        h, w = rgb.shape[:2]

        # Convert to YCrCb color space
        ycrcb = cv2.cvtColor(rgb, cv2.COLOR_RGB2YCrCb)
        y_channel = ycrcb[:, :, 0].astype(np.float32)

        blocks_y = h // 8
        blocks_x = w // 8
        total_blocks = blocks_y * blocks_x

        if total_blocks < 64:
            # Image too small to embed 64 blocks, return original
            return image_bytes

        # Select 64 deterministic block indices spread across the image
        stride = max(1, total_blocks // 64)
        selected_blocks = [i * stride for i in range(64)]

        # Mid-band frequency coefficient coordinates
        u1, v1 = 4, 3
        u2, v2 = 3, 4

        for bit_idx, block_num in enumerate(selected_blocks):
            by = (block_num // blocks_x) * 8
            bx = (block_num % blocks_x) * 8

            if by + 8 > h or bx + 8 > w:
                continue

            block = y_channel[by:by + 8, bx:bx + 8]
            dct_b = cv2.dct(block)

            target_bit = bits[bit_idx]
            diff = dct_b[u1, v1] - dct_b[u2, v2]

            # Modulate mid-band coefficients
            if target_bit == 1:
                if diff < self.DCT_DELTA:
                    dct_b[u1, v1] += (self.DCT_DELTA - diff) / 2.0
                    dct_b[u2, v2] -= (self.DCT_DELTA - diff) / 2.0
            else:
                if diff > -self.DCT_DELTA:
                    dct_b[u1, v1] -= (self.DCT_DELTA + diff) / 2.0
                    dct_b[u2, v2] += (self.DCT_DELTA + diff) / 2.0

            y_channel[by:by + 8, bx:bx + 8] = cv2.idct(dct_b)

        # Clip and reconstruct
        ycrcb[:, :, 0] = np.clip(y_channel, 0, 255).astype(np.uint8)
        watermarked_rgb = cv2.cvtColor(ycrcb, cv2.COLOR_YCrCb2RGB)

        out_buf = io.BytesIO()
        out_img = Image.fromarray(watermarked_rgb)
        out_img.save(out_buf, format=orig_format, quality=95)
        return out_buf.getvalue()

    def extract_watermark(self, image_bytes: bytes) -> dict:
        """
        Blindly extract 64-bit watermark from Y-channel 8x8 DCT mid-bands.
        Returns dict with payload, recovered_id, and is_valid.
        """
        try:
            img = Image.open(io.BytesIO(image_bytes))
            if img.mode != 'RGB':
                img = img.convert('RGB')
            rgb = np.array(img)
            h, w = rgb.shape[:2]

            ycrcb = cv2.cvtColor(rgb, cv2.COLOR_RGB2YCrCb)
            y_channel = ycrcb[:, :, 0].astype(np.float32)

            blocks_y = h // 8
            blocks_x = w // 8
            total_blocks = blocks_y * blocks_x

            if total_blocks < 64:
                return {"is_valid": False, "payload": "", "recovered_id": None}

            stride = max(1, total_blocks // 64)
            selected_blocks = [i * stride for i in range(64)]

            u1, v1 = 4, 3
            u2, v2 = 3, 4

            bits = []
            for block_num in selected_blocks:
                by = (block_num // blocks_x) * 8
                bx = (block_num % blocks_x) * 8

                if by + 8 > h or bx + 8 > w:
                    bits.append(0)
                    continue

                block = y_channel[by:by + 8, bx:bx + 8]
                dct_b = cv2.dct(block)
                diff = dct_b[u1, v1] - dct_b[u2, v2]
                bits.append(1 if diff > 0 else 0)

            payload = self.bits_to_payload(bits)

            if payload.startswith(self.WATERMARK_PREFIX):
                id_part = payload[len(self.WATERMARK_PREFIX):]
                if id_part.isdigit():
                    return {
                        "is_valid": True,
                        "payload": payload,
                        "recovered_id": int(id_part)
                    }

            return {"is_valid": False, "payload": payload, "recovered_id": None}
        except Exception as e:
            return {"is_valid": False, "payload": "", "recovered_id": None, "error": str(e)}

    # ═══════════════════════════════════════════════════════════
    #  3. Post-Signing Tamper Localization
    # ═══════════════════════════════════════════════════════════
    def localize_tampering(self, master_image_bytes: bytes,
                           derivative_image_bytes: bytes,
                           save_diff_path: str = None) -> dict:
        """
        Given a canonical signed master image and a recovered derivative,
        align dimensions, compute cv2.absdiff, calculate pixel_change_percentage,
        and render a JET colormap tamper-diff overlay.
        """
        master_img = Image.open(io.BytesIO(master_image_bytes)).convert('RGB')
        deriv_img = Image.open(io.BytesIO(derivative_image_bytes)).convert('RGB')

        orig_w, orig_h = master_img.size
        # Align derivative dimensions to master
        if deriv_img.size != (orig_w, orig_h):
            deriv_img = deriv_img.resize((orig_w, orig_h), Image.Resampling.LANCZOS)

        master_np = np.array(master_img)
        deriv_np = np.array(deriv_img)

        # Compute absolute difference
        diff_color = cv2.absdiff(master_np, deriv_np)
        diff_gray = cv2.cvtColor(diff_color, cv2.COLOR_RGB2GRAY)

        # Threshold to ignore minor compression noise (threshold > 18)
        _, thresh = cv2.threshold(diff_gray, 18, 255, cv2.THRESH_BINARY)
        tampered_pixels = int(np.count_nonzero(thresh))
        total_pixels = orig_w * orig_h
        pixel_change_pct = round((tampered_pixels / total_pixels) * 100.0, 2)

        # JET colormap tamper-diff heatmap
        diff_norm = (diff_gray.astype(np.float32) / (np.max(diff_gray) + 1e-6) * 255.0).astype(np.uint8)
        heatmap_jet = cv2.applyColorMap(diff_norm, cv2.COLORMAP_JET)
        heatmap_rgb = cv2.cvtColor(heatmap_jet, cv2.COLOR_BGR2RGB)

        # Alpha overlay
        overlay = (deriv_np.astype(np.float32) * 0.45 + heatmap_rgb.astype(np.float32) * 0.55).astype(np.uint8)

        if save_diff_path:
            os.makedirs(os.path.dirname(os.path.abspath(save_diff_path)), exist_ok=True)
            Image.fromarray(overlay).save(save_diff_path, 'PNG')

        return {
            'pixel_change_percentage': pixel_change_pct,
            'is_tampered': (pixel_change_pct > 1.5),
            'tampered_pixels': tampered_pixels,
            'total_pixels': total_pixels,
            'diff_overlay_saved': bool(save_diff_path),
        }

    # ═══════════════════════════════════════════════════════════
    #  4. Adversarial Attack Regimes
    # ═══════════════════════════════════════════════════════════
    def apply_attack(self, image_bytes: bytes, attack_type: str) -> bytes:
        """
        Executes controlled adversarial perturbations:
        1. whatsapp_compress: EXIF/JUMBF strip + JPEG QF 70 re-encode
        2. color_shift: Contrast & luminance shift
        3. pixel_splice: Localized synthetic patch injection
        """
        img = Image.open(io.BytesIO(image_bytes)).convert('RGB')
        np_img = np.array(img)
        h, w = np_img.shape[:2]

        if attack_type == 'whatsapp_compress':
            # Complete metadata strip + heavy JPEG QF 70 re-encode
            buf = io.BytesIO()
            img.save(buf, format='JPEG', quality=70)
            return buf.getvalue()

        elif attack_type == 'color_shift':
            # Luminance and contrast perturbation
            shifted = np.clip(np_img.astype(np.float32) * 1.08 + 14.0, 0, 255).astype(np.uint8)
            buf = io.BytesIO()
            Image.fromarray(shifted).save(buf, format='JPEG', quality=85)
            return buf.getvalue()

        elif attack_type == 'pixel_splice':
            # Inject an unnatural synthetic rectangular patch
            spliced = np_img.copy()
            patch_h = max(20, h // 4)
            patch_w = max(20, w // 4)
            y0 = h // 3
            x0 = w // 3

            # Create high-contrast synthetic patch
            patch = np.zeros((patch_h, patch_w, 3), dtype=np.uint8)
            patch[:, :] = [240, 50, 50]  # Bright red box
            cv2.putText(patch, "FORGED", (5, patch_h // 2), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 255, 255), 2)
            spliced[y0:y0 + patch_h, x0:x0 + patch_w] = patch

            buf = io.BytesIO()
            Image.fromarray(spliced).save(buf, format='JPEG', quality=85)
            return buf.getvalue()

        return image_bytes

