"""
Certificate Generator Service for ImageGuard.
Generates professional PDF ownership certificates
with QR codes and digital signature information.
"""

import os
import io
import json
import qrcode
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
    """Generates PDF ownership certificates for verified images."""

    def __init__(self, certificates_dir: str):
        self.certificates_dir = certificates_dir
        os.makedirs(certificates_dir, exist_ok=True)

    def generate_certificate(self, record_data: dict, image_path: str,
                              base_url: str = 'http://localhost:8000') -> str:
        """
        Generate a professional PDF certificate.

        Args:
            record_data: Dict with image record data
            image_path: Path to the original image
            base_url: Base URL for QR code verification link

        Returns: Path to generated PDF
        """
        cert_filename = f"certificate_{record_data['id']}_{datetime.now().strftime('%Y%m%d%H%M%S')}.pdf"
        cert_path = os.path.join(self.certificates_dir, cert_filename)

        doc = SimpleDocTemplate(
            cert_path,
            pagesize=A4,
            rightMargin=2 * cm,
            leftMargin=2 * cm,
            topMargin=1.5 * cm,
            bottomMargin=1.5 * cm
        )

        styles = getSampleStyleSheet()
        elements = []

        # Custom styles
        title_style = ParagraphStyle(
            'CertTitle',
            parent=styles['Title'],
            fontSize=28,
            textColor=colors.HexColor('#1a1a2e'),
            spaceAfter=5 * mm,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        )

        subtitle_style = ParagraphStyle(
            'CertSubtitle',
            parent=styles['Normal'],
            fontSize=14,
            textColor=colors.HexColor('#16213e'),
            spaceBefore=2 * mm,
            spaceAfter=8 * mm,
            alignment=TA_CENTER,
            fontName='Helvetica'
        )

        heading_style = ParagraphStyle(
            'SectionHeading',
            parent=styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor('#0f3460'),
            spaceBefore=6 * mm,
            spaceAfter=3 * mm,
            fontName='Helvetica-Bold'
        )

        body_style = ParagraphStyle(
            'CertBody',
            parent=styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor('#333333'),
            spaceBefore=1 * mm,
            spaceAfter=1 * mm,
            fontName='Helvetica'
        )

        small_style = ParagraphStyle(
            'CertSmall',
            parent=styles['Normal'],
            fontSize=8,
            textColor=colors.HexColor('#666666'),
            alignment=TA_CENTER,
            fontName='Helvetica'
        )

        # ===== HEADER =====
        elements.append(Spacer(1, 5 * mm))

        # Shield icon text
        elements.append(Paragraph('🛡️', ParagraphStyle(
            'ShieldIcon', parent=styles['Title'], fontSize=40,
            alignment=TA_CENTER, spaceAfter=2 * mm
        )))

        elements.append(Paragraph('CERTIFICATE OF DIGITAL AUTHENTICITY', title_style))
        elements.append(Paragraph('Image Ownership & Integrity Verification', subtitle_style))

        # Decorative line
        elements.append(HRFlowable(
            width='100%', thickness=2,
            color=colors.HexColor('#0f3460'),
            spaceBefore=2 * mm, spaceAfter=5 * mm
        ))

        # Certificate ID
        cert_id = f"IG-{record_data['id']:06d}-{datetime.now().strftime('%Y%m%d')}"
        elements.append(Paragraph(
            f'<b>Certificate ID:</b> {cert_id}',
            ParagraphStyle('CertID', parent=body_style, alignment=TA_CENTER,
                          fontSize=11, spaceAfter=5 * mm)
        ))

        # ===== IMAGE THUMBNAIL =====
        try:
            if os.path.exists(image_path):
                img = Image.open(image_path)
                img.thumbnail((200, 200))
                thumb_buffer = io.BytesIO()
                img.save(thumb_buffer, 'PNG')
                thumb_buffer.seek(0)

                rl_img = RLImage(thumb_buffer, width=50 * mm, height=50 * mm,
                                kind='proportional')
                elements.append(rl_img)
                elements.append(Spacer(1, 3 * mm))
        except Exception:
            pass

        # ===== IMAGE DETAILS =====
        elements.append(Paragraph('Image Details', heading_style))

        details_data = [
            ['Property', 'Value'],
            ['Original Filename', str(record_data.get('original_filename', 'N/A'))],
            ['Dimensions', f"{record_data.get('width', 'N/A')} × {record_data.get('height', 'N/A')} px"],
            ['File Size', self._format_size(record_data.get('file_size', 0))],
            ['SHA-256 Hash', str(record_data.get('file_hash', 'N/A'))[:32] + '...'],
            ['Upload Date', str(record_data.get('upload_date', 'N/A'))],
        ]

        details_table = Table(details_data, colWidths=[45 * mm, 120 * mm])
        details_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f3460')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f0f4f8')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cccccc')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(details_table)

        # ===== AUTHENTICITY RESULTS =====
        elements.append(Paragraph('Authenticity Analysis', heading_style))

        score = record_data.get('authenticity_score', 0)
        verdict = 'AUTHENTIC' if record_data.get('is_authentic', False) else 'POTENTIALLY FORGED'
        verdict_color = '#27ae60' if record_data.get('is_authentic', False) else '#e74c3c'

        elements.append(Paragraph(
            f'<b>Verdict:</b> <font color="{verdict_color}"><b>{verdict}</b></font>',
            ParagraphStyle('Verdict', parent=body_style, fontSize=14,
                          alignment=TA_CENTER, spaceBefore=3 * mm, spaceAfter=3 * mm)
        ))

        auth_data = [
            ['Analysis Method', 'Score', 'Status'],
            ['Error Level Analysis (ELA)', f"{record_data.get('ela_score', 0):.1f}%",
             'Pass' if record_data.get('ela_score', 0) >= 60 else 'Suspicious'],
            ['Noise Pattern Analysis', f"{record_data.get('noise_score', 0):.1f}%",
             'Pass' if record_data.get('noise_score', 0) >= 60 else 'Suspicious'],
            ['AI Classification (CNN)', f"{record_data.get('cnn_score', 0):.1f}%",
             'Pass' if record_data.get('cnn_score', 0) >= 60 else 'Suspicious'],
            ['Combined Score', f"{score:.1f}%", verdict],
        ]

        auth_table = Table(auth_data, colWidths=[65 * mm, 40 * mm, 60 * mm])
        auth_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#16213e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
            ('BACKGROUND', (0, -1), (-1, -1), colors.HexColor('#e8f4f8')),
            ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cccccc')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(auth_table)

        # ===== DIGITAL SIGNATURE =====
        if record_data.get('is_signed'):
            elements.append(Paragraph('Digital Signature', heading_style))

            sig_data = [
                ['Property', 'Value'],
                ['Signer', str(record_data.get('signer_name', 'N/A'))],
                ['Key ID', str(record_data.get('public_key_id', 'N/A'))],
                ['Signed Date', str(record_data.get('signed_date', 'N/A'))],
                ['Signature (truncated)', str(record_data.get('signature', ''))[:40] + '...'],
                ['Status', 'VERIFIED ✓'],
            ]

            sig_table = Table(sig_data, colWidths=[45 * mm, 120 * mm])
            sig_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#27ae60')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f0fff0')),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cccccc')),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ]))
            elements.append(sig_table)

        # ===== QR CODE =====
        elements.append(Spacer(1, 5 * mm))
        elements.append(Paragraph('Verification QR Code', heading_style))

        try:
            verify_url = f"{base_url}/verify/{record_data['id']}"
            qr = qrcode.make(verify_url, box_size=4, border=2)
            qr_buffer = io.BytesIO()
            qr.save(qr_buffer, 'PNG')
            qr_buffer.seek(0)

            qr_img = RLImage(qr_buffer, width=30 * mm, height=30 * mm)
            elements.append(qr_img)
            elements.append(Paragraph(
                f'Scan to verify: {verify_url}',
                small_style
            ))
        except Exception:
            pass

        # ===== FOOTER =====
        elements.append(Spacer(1, 8 * mm))
        elements.append(HRFlowable(
            width='100%', thickness=1,
            color=colors.HexColor('#cccccc'),
            spaceBefore=3 * mm, spaceAfter=3 * mm
        ))

        elements.append(Paragraph(
            f'Generated by ImageGuard Digital Authenticity System<br/>'
            f'Date: {datetime.now().strftime("%B %d, %Y at %I:%M %p")}<br/>'
            f'This certificate verifies the analysis results at the time of generation.',
            small_style
        ))

        # Build PDF
        doc.build(elements)

        return cert_path

    def _format_size(self, size_bytes: int) -> str:
        """Format file size in human-readable form."""
        if size_bytes == 0:
            return '0 B'
        units = ['B', 'KB', 'MB', 'GB']
        i = 0
        size = float(size_bytes)
        while size >= 1024 and i < len(units) - 1:
            size /= 1024
            i += 1
        return f'{size:.1f} {units[i]}'
