"""
Analysis PDF reports for ImageGuard, including signature and local audit status.
The PDF itself is an unsigned snapshot, not an ownership certificate.
"""

import os
import io
import json
import qrcode
from html import escape
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm, cm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                 TableStyle, Image as RLImage, HRFlowable)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from PIL import Image


class CertificateGenerator:
    """Generate an analysis report with explicitly qualified verification states."""

    def __init__(self, certificates_dir: str):
        self.certificates_dir = certificates_dir
        os.makedirs(certificates_dir, exist_ok=True)

    def generate_certificate(self, record_data: dict, image_path: str,
                              base_url: str = 'http://localhost:8000',
                              merkle_info: dict = None) -> str:
        """
        Generate an unsigned PDF snapshot of forensic signals, exact-byte
        signature verification, metadata status, and a local audit checkpoint.
        """
        merkle_info = merkle_info or {}
        cert_filename = f"certificate_{record_data['id']}_{datetime.now().strftime('%Y%m%d%H%M%S')}.pdf"
        cert_path = os.path.join(self.certificates_dir, cert_filename)

        doc = SimpleDocTemplate(
            cert_path,
            pagesize=A4,
            rightMargin=1.5 * cm,
            leftMargin=1.5 * cm,
            topMargin=1.2 * cm,
            bottomMargin=1.2 * cm
        )

        styles = getSampleStyleSheet()
        elements = []

        # Custom styles
        title_style = ParagraphStyle(
            'CertTitle',
            parent=styles['Title'],
            fontSize=22,
            textColor=colors.HexColor('#090a0f'),
            spaceAfter=2 * mm,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        )

        subtitle_style = ParagraphStyle(
            'CertSubtitle',
            parent=styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor('#2563eb'),
            spaceBefore=1 * mm,
            spaceAfter=3 * mm,
            alignment=TA_CENTER,
            fontName='Helvetica'
        )

        heading_style = ParagraphStyle(
            'SectionHeading',
            parent=styles['Heading2'],
            fontSize=10,
            textColor=colors.HexColor('#0f3460'),
            spaceBefore=3 * mm,
            spaceAfter=2 * mm,
            fontName='Helvetica-Bold'
        )

        body_style = ParagraphStyle(
            'CertBody',
            parent=styles['Normal'],
            fontSize=8,
            textColor=colors.HexColor('#333333'),
            spaceBefore=1 * mm,
            spaceAfter=1 * mm,
            fontName='Helvetica'
        )

        small_style = ParagraphStyle(
            'CertSmall',
            parent=styles['Normal'],
            fontSize=7,
            textColor=colors.HexColor('#64748b'),
            alignment=TA_CENTER,
            fontName='Helvetica'
        )

        # ===== HEADER (Clean Typography, No Emoji) =====
        elements.append(Paragraph('IMAGEGUARD FORENSIC ATTESTATION', ParagraphStyle(
            'SubTop', parent=styles['Normal'], fontSize=8,
            textColor=colors.HexColor('#64748b'), alignment=TA_CENTER, spaceAfter=1 * mm
        )))

        elements.append(Paragraph('IMAGE ANALYSIS REPORT', title_style))
        elements.append(Paragraph('ImageGuard v2.0 · Experimental Forensics, Signatures & Local Audit', subtitle_style))

        elements.append(HRFlowable(
            width='100%', thickness=1.5,
            color=colors.HexColor('#2563eb'),
            spaceBefore=1 * mm, spaceAfter=3 * mm
        ))

        cert_id = f"IG-v2-{record_data['id']:06d}-{datetime.now().strftime('%Y%m%d')}"
        elements.append(Paragraph(
            f'<b>Certificate ID:</b> {cert_id} &nbsp;|&nbsp; <b>Issuer:</b> ImageGuard Autonomous Forensics Engine',
            ParagraphStyle('CertID', parent=body_style, alignment=TA_CENTER,
                          fontSize=9, spaceAfter=3 * mm)
        ))

        # ===== IMAGE THUMBNAIL & BASIC DETAILS =====
        thumb_flowable = None
        try:
            if os.path.exists(image_path):
                img = Image.open(image_path)
                img.thumbnail((160, 160))
                thumb_buffer = io.BytesIO()
                img.save(thumb_buffer, 'PNG')
                thumb_buffer.seek(0)
                thumb_flowable = RLImage(thumb_buffer, width=32 * mm, height=32 * mm, kind='proportional')
        except Exception:
            pass

        details_data = [
            ['Original Filename', str(record_data.get('original_filename', 'N/A'))],
            ['Dimensions', f"{record_data.get('width', 'N/A')} × {record_data.get('height', 'N/A')} px"],
            ['File Size', self._format_size(record_data.get('file_size', 0))],
            ['SHA-256 Digest', str(record_data.get('file_hash', 'N/A'))[:36] + '...'],
            ['Perceptual dHash', str(record_data.get('perceptual_dhash', 'N/A'))],
            ['Upload Timestamp', str(record_data.get('upload_date', 'N/A'))[:19]],
        ]

        details_table = Table(details_data, colWidths=[38 * mm, 95 * mm])
        details_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f1f5f9')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#1e293b')),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
            ('TOPPADDING', (0, 0), (-1, -1), 2),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
            ('LEFTPADDING', (0, 0), (-1, -1), 4),
        ]))

        if thumb_flowable:
            top_layout = Table([[thumb_flowable, details_table]], colWidths=[38 * mm, 137 * mm])
            top_layout.setStyle(TableStyle([
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('ALIGN', (0, 0), (0, 0), 'CENTER'),
            ]))
            elements.append(top_layout)
        else:
            elements.append(details_table)

        # ===== AUTHENTICITY ANALYSIS (TWO-GATE FORENSICS & C2PA IPTC) =====
        elements.append(Paragraph('Experimental Forensic Assessment', heading_style))

        # Parse forgery details
        forgery_details = record_data.get('forgery_details')
        if isinstance(forgery_details, str):
            try:
                forgery_details = json.loads(forgery_details)
            except Exception:
                forgery_details = {}
        elif not isinstance(forgery_details, dict):
            forgery_details = {}

        ela_score = float(record_data.get('ela_score') or 0.0)
        noise_score = float(record_data.get('noise_score') or 0.0)
        fft_score = float(record_data.get('fft_score') or 0.0)
        ai_prob = float(record_data.get('ai_generation_prob') or 0.0)
        ai_prob_pct = ai_prob * 100.0 if ai_prob <= 1.0 else ai_prob

        # Gate 1 & Gate 2 scores
        gates = forgery_details.get('gates', {})
        tamper_score = gates.get('tamper_integrity_score')
        if tamper_score is None:
            tamper_score = round(0.55 * ela_score + 0.45 * noise_score, 1)
        else:
            tamper_score = float(tamper_score)

        origin_score = gates.get('origin_integrity_score')
        if origin_score is None:
            origin_score = round(0.70 * (100.0 - ai_prob_pct) + 0.30 * fft_score, 1)
        else:
            origin_score = float(origin_score)

        # 3-way verdict resolution
        verdict = record_data.get('verdict') or forgery_details.get('verdict')
        if not verdict:
            if ai_prob_pct >= 55.0:
                verdict = "AI-Generated / Synthetic Media"
            elif tamper_score < 60.0:
                verdict = "Manipulated / Spliced Forgery"
            else:
                verdict = "Authentic Media"

        # IPTC digitalSourceType resolution
        if ai_prob_pct >= 55.0:
            iptc_label = "trainedAlgorithmicMedia (Synthetic AI)"
            verdict_color = '#dc2626'
        elif tamper_score < 60.0:
            iptc_label = "compositeCapture (Spliced / Composite)"
            verdict_color = '#d97706'
        else:
            iptc_label = "digitalCapture (Optical Camera)"
            verdict_color = '#16a34a'

        score = float(record_data.get('authenticity_score') or 0.0)

        elements.append(Paragraph(
            f'<b>Forensic Verdict:</b> <font color="{verdict_color}"><b>{escape(verdict)}</b></font> &nbsp; (Analysis score: {score:.1f}/100; uncalibrated)',
            ParagraphStyle('Verdict', parent=body_style, fontSize=10,
                          alignment=TA_CENTER, spaceBefore=1 * mm, spaceAfter=2 * mm)
        ))

        auth_data = [
            ['Forensic Branch / Architecture', 'Score / Metric', 'Evaluation Status'],
            ['1. Error Level Analysis (ELA)', f"{ela_score:.1f}%", 'Pass' if ela_score >= 60 else 'Suspicious'],
            ['2. Spatial Rich Model (SRM) Residuals', f"{noise_score:.1f}%", 'Pass' if noise_score >= 60 else 'Suspicious'],
            ['3. 2D FFT Radial Power Spectrum (1/f²)', f"{fft_score:.1f}%", 'Pass' if fft_score >= 60 else 'Suspicious'],
            ['4. Deep Neural Classifier (CIFAKE / ViT)', f"P(AI) = {ai_prob_pct:.1f}%", 'Pass' if ai_prob_pct < 45 else 'Suspicious (Synthetic)'],
            ['Gate 1: Splice & Tamper Integrity (0.55*ELA + 0.45*SRM)', f"{tamper_score:.1f}%", 'PASS' if tamper_score >= 60 else 'VETO: LOCALIZED TAMPER'],
            ['Gate 2: Optical Origin Integrity (0.70*(100-P(AI)) + 0.30*FFT)', f"{origin_score:.1f}%", 'PASS' if origin_score >= 60 else 'VETO: SYNTHETIC AI ORIGIN'],
            ['Two-Gate Fused Verdict', f"{score:.1f}%", verdict],
            ['Capture origin', 'Not independently established', 'Detector estimate only'],
        ]

        auth_table = Table(auth_data, colWidths=[80 * mm, 45 * mm, 50 * mm])
        auth_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f172a')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 7.5),
            ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
            ('BACKGROUND', (0, -2), (-1, -2), colors.HexColor('#e0f2fe')),
            ('FONTNAME', (0, -2), (-1, -2), 'Helvetica-Bold'),
            ('BACKGROUND', (0, -1), (-1, -1), colors.HexColor('#f1f5f9')),
            ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#94a3b8')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 2),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
        ]))
        elements.append(auth_table)

        # ===== PROVENANCE & ZERO-TRUST SIGNATURE =====
        elements.append(Paragraph('Cryptographic Provenance & Dual-Mode Signature', heading_style))

        sig_status = 'VERIFIED (RSA-PSS)' if record_data.get('signature_valid') else ('UNVERIFIED SIGNATURE' if record_data.get('is_signed') else 'UNSIGNED')
        sig_data = [
            ['Signer Identity', str(record_data.get('signer_name', 'Anonymous / Public Ingestion'))],
            ['Public Key Identifier', str(record_data.get('public_key_id', 'N/A'))],
            ['Signed Timestamp', str(record_data.get('signed_date', 'N/A'))[:19]],
            ['Dual-Mode Verification', 'Dual RSA-PSS (Max Salt & W3C WebCrypto 32-byte) Supported'],
            ['Signature Token', (str(record_data.get('signature', ''))[:38] + '...') if record_data.get('is_signed') else 'N/A'],
            ['Signature Status', sig_status],
        ]

        sig_table = Table(sig_data, colWidths=[45 * mm, 130 * mm])
        sig_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f8fafc')),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 7.5),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 2),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
            ('LEFTPADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(sig_table)

        # ===== MERKLE AUDIT LEDGER & C2PA / RFC 3161 =====
        elements.append(Paragraph('Local Audit Checkpoint & Metadata Status', heading_style))

        merkle_root = merkle_info.get('root_hash', record_data.get('merkle_leaf_hash', 'N/A'))
        tree_size = merkle_info.get('tree_size', 1)
        timestamp = json.loads(record_data.get('timestamp_info') or '{}')
        has_wm = bool(record_data.get('watermark_embedded'))

        merkle_data = [
            ['Merkle Leaf Digest', str(record_data.get('merkle_leaf_hash', 'N/A'))[:40] + '...'],
            ['Active Merkle Ledger Root', str(merkle_root)[:40] + '...'],
            ['Transparency Tree Size', f"{tree_size} Events (Signed Local Checkpoint)"],
            ['RFC 3161 Timestamp', timestamp.get('status', 'unavailable')],
            ['Provenance status', record_data.get('provenance_status', 'unverified_metadata')],
            ['Soft-Binding Watermark', 'Y-channel 8x8 DCT Mid-band Embedded' if has_wm else 'Available for Embed'],
        ]

        merkle_table = Table(merkle_data, colWidths=[45 * mm, 130 * mm])
        merkle_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f1f5f9')),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 7.5),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 2),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
            ('LEFTPADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(merkle_table)

        # ===== QR CODE & VERIFICATION LINK =====
        elements.append(Spacer(1, 2 * mm))
        try:
            verify_url = f"{base_url}/verify/{record_data['id']}"
            qr = qrcode.make(verify_url, box_size=3, border=1)
            qr_buffer = io.BytesIO()
            qr.save(qr_buffer, 'PNG')
            qr_buffer.seek(0)

            qr_img = RLImage(qr_buffer, width=22 * mm, height=22 * mm)
            qr_desc = Paragraph(
                f'<b>Operator Verification Endpoint:</b><br/>'
                f'<font color="#2563eb">{verify_url}</font><br/>'
                f'<font color="#64748b">Scan or navigate to verify live Merkle inclusion and cryptographic signature integrity.</font>',
                body_style
            )

            qr_table = Table([[qr_img, qr_desc]], colWidths=[26 * mm, 149 * mm])
            qr_table.setStyle(TableStyle([
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('LEFTPADDING', (1, 0), (1, 0), 6),
            ]))
            elements.append(qr_table)
        except Exception:
            pass

        # ===== FOOTER =====
        elements.append(Spacer(1, 2 * mm))
        elements.append(HRFlowable(
            width='100%', thickness=0.8,
            color=colors.HexColor('#cbd5e1'),
            spaceBefore=1 * mm, spaceAfter=2 * mm
        ))

        elements.append(Paragraph(
            f'Generated by ImageGuard v2.0 Experimental Forensics Workbench · {datetime.now().strftime("%B %d, %Y at %I:%M:%S %p UTC")}<br/>'
            f'Analysis scores do not prove capture origin or ownership. Local checkpoints require external retention to detect rollback.',
            small_style
        ))

        doc.build(elements)
        return cert_path

    def _format_size(self, size_bytes: int) -> str:
        """Format file size in human-readable form."""
        if not size_bytes:
            return '0 B'
        units = ['B', 'KB', 'MB', 'GB']
        i = 0
        size = float(size_bytes)
        while size >= 1024 and i < len(units) - 1:
            size /= 1024
            i += 1
        return f'{size:.1f} {units[i]}'
