"""
Metadata Analyzer Service for ImageGuard.
Extracts and analyzes EXIF and other metadata from images
to detect signs of manipulation.
"""

import json
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
import io
from datetime import datetime


class MetadataAnalyzer:
    """Extracts and analyzes image metadata for authenticity clues."""

    # Known image editing software
    EDITING_SOFTWARE = [
        'photoshop', 'gimp', 'paint.net', 'lightroom', 'affinity',
        'pixlr', 'canva', 'snapseed', 'vsco', 'faceapp', 'facetune',
        'adobe', 'corel', 'paintshop', 'capture one', 'darktable',
        'rawtherapee', 'luminar', 'photoscape', 'fotor', 'befunky',
        'picsart', 'polish', 'remini', 'retouch', 'airbrush'
    ]

    # Trusted camera manufacturers
    CAMERA_MAKERS = [
        'canon', 'nikon', 'sony', 'fujifilm', 'panasonic', 'olympus',
        'pentax', 'leica', 'hasselblad', 'samsung', 'apple', 'google',
        'huawei', 'xiaomi', 'oneplus', 'oppo', 'vivo', 'realme',
        'motorola', 'lg', 'nokia', 'asus', 'htc', 'blackberry'
    ]

    def extract_metadata(self, image_bytes: bytes) -> dict:
        """
        Extract all available metadata from an image.

        Returns dict with categorized metadata.
        """
        image = Image.open(io.BytesIO(image_bytes))

        metadata = {
            'basic': {
                'format': image.format or 'Unknown',
                'mode': image.mode,
                'size': f'{image.size[0]}x{image.size[1]}',
                'width': image.size[0],
                'height': image.size[1],
            },
            'exif': {},
            'gps': {},
            'camera': {},
            'software': {},
            'timestamps': {},
            'warnings': [],
            'raw_exif': {}
        }

        # Try to extract EXIF data
        try:
            exif_data = image._getexif()
            if exif_data:
                for tag_id, value in exif_data.items():
                    tag_name = TAGS.get(tag_id, str(tag_id))

                    # Convert bytes to string for JSON serialization
                    if isinstance(value, bytes):
                        try:
                            value = value.decode('utf-8', errors='ignore')
                        except:
                            value = str(value)
                    elif isinstance(value, tuple):
                        value = str(value)

                    metadata['raw_exif'][tag_name] = str(value)

                    # Categorize metadata
                    self._categorize_tag(tag_name, value, metadata)

                # Extract GPS if present
                if 'GPSInfo' in metadata['raw_exif']:
                    self._extract_gps(exif_data, metadata)

        except Exception as e:
            metadata['warnings'].append(f'Could not read EXIF data: {str(e)}')

        return metadata

    def _categorize_tag(self, tag_name: str, value, metadata: dict):
        """Categorize an EXIF tag into the appropriate category."""
        camera_tags = ['Make', 'Model', 'LensModel', 'LensMake',
                       'BodySerialNumber', 'LensSerialNumber']
        software_tags = ['Software', 'ProcessingSoftware', 'HostComputer']
        timestamp_tags = ['DateTime', 'DateTimeOriginal', 'DateTimeDigitized',
                          'CreateDate', 'ModifyDate']

        str_value = str(value)

        if tag_name in camera_tags:
            metadata['camera'][tag_name] = str_value
        elif tag_name in software_tags:
            metadata['software'][tag_name] = str_value
        elif tag_name in timestamp_tags:
            metadata['timestamps'][tag_name] = str_value
        else:
            metadata['exif'][tag_name] = str_value

    def _extract_gps(self, exif_data, metadata: dict):
        """Extract GPS coordinates from EXIF data."""
        try:
            gps_info = exif_data.get(34853, {})  # GPSInfo tag
            if gps_info:
                gps_data = {}
                for key, val in gps_info.items():
                    tag_name = GPSTAGS.get(key, str(key))
                    gps_data[tag_name] = str(val)
                metadata['gps'] = gps_data
        except Exception:
            pass

    def analyze_metadata(self, metadata: dict) -> dict:
        """
        Analyze metadata for signs of manipulation.

        Returns analysis results with score and findings.
        """
        findings = []
        score = 100.0  # Start with perfect score
        risk_level = 'Low'

        # Check for editing software
        software_info = metadata.get('software', {})
        for key, value in software_info.items():
            value_lower = str(value).lower()
            for editor in self.EDITING_SOFTWARE:
                if editor in value_lower:
                    findings.append({
                        'type': 'warning',
                        'category': 'Software',
                        'message': f'Image was processed with editing software: {value}',
                        'severity': 'medium'
                    })
                    score -= 15
                    break

        # Check camera information
        camera_info = metadata.get('camera', {})
        if camera_info:
            make = camera_info.get('Make', '').lower()
            has_known_camera = any(cm in make for cm in self.CAMERA_MAKERS)
            if has_known_camera:
                findings.append({
                    'type': 'info',
                    'category': 'Camera',
                    'message': f'Image captured by known camera: {camera_info.get("Make", "")} {camera_info.get("Model", "")}',
                    'severity': 'low'
                })
            elif make:
                findings.append({
                    'type': 'warning',
                    'category': 'Camera',
                    'message': f'Unknown camera manufacturer: {camera_info.get("Make", "")}',
                    'severity': 'low'
                })
                score -= 5
        else:
            findings.append({
                'type': 'warning',
                'category': 'Camera',
                'message': 'No camera information found in metadata. Image may have been stripped or created digitally.',
                'severity': 'medium'
            })
            score -= 10

        # Check timestamps
        timestamps = metadata.get('timestamps', {})
        if timestamps:
            self._check_timestamp_consistency(timestamps, findings)
        else:
            findings.append({
                'type': 'warning',
                'category': 'Timestamps',
                'message': 'No timestamp information found. Metadata may have been stripped.',
                'severity': 'medium'
            })
            score -= 10

        # Check for missing EXIF data entirely
        if not metadata.get('raw_exif'):
            findings.append({
                'type': 'warning',
                'category': 'Metadata',
                'message': 'No EXIF metadata found. This is common in screenshots, web-downloaded images, or manipulated files.',
                'severity': 'high'
            })
            score -= 20

        # Check GPS
        if metadata.get('gps'):
            findings.append({
                'type': 'info',
                'category': 'GPS',
                'message': 'GPS location data is present in the image.',
                'severity': 'low'
            })

        # Determine risk level
        score = max(0, min(100, score))
        if score >= 80:
            risk_level = 'Low'
        elif score >= 60:
            risk_level = 'Medium'
        elif score >= 40:
            risk_level = 'High'
        else:
            risk_level = 'Critical'

        return {
            'score': round(score, 2),
            'risk_level': risk_level,
            'findings': findings,
            'total_findings': len(findings),
            'has_exif': bool(metadata.get('raw_exif')),
            'has_camera_info': bool(camera_info),
            'has_gps': bool(metadata.get('gps')),
            'has_timestamps': bool(timestamps),
            'has_editing_software': any(f['category'] == 'Software' and f['type'] == 'warning' for f in findings),
        }

    def _check_timestamp_consistency(self, timestamps: dict, findings: list):
        """Check if timestamps are consistent."""
        parsed_dates = {}
        for key, value in timestamps.items():
            try:
                # Common EXIF date formats
                for fmt in ['%Y:%m:%d %H:%M:%S', '%Y-%m-%d %H:%M:%S',
                            '%Y:%m:%d', '%Y-%m-%d']:
                    try:
                        parsed_dates[key] = datetime.strptime(str(value), fmt)
                        break
                    except ValueError:
                        continue
            except Exception:
                pass

        if len(parsed_dates) >= 2:
            dates = list(parsed_dates.values())
            max_diff = max((d1 - d2).total_seconds() for d1 in dates for d2 in dates)

            if abs(max_diff) > 86400:  # More than 24 hours difference
                findings.append({
                    'type': 'warning',
                    'category': 'Timestamps',
                    'message': f'Timestamp inconsistency detected: {abs(max_diff)/3600:.1f} hours difference between dates.',
                    'severity': 'high'
                })

        # Check for future dates
        now = datetime.now()
        for key, date in parsed_dates.items():
            if date > now:
                findings.append({
                    'type': 'warning',
                    'category': 'Timestamps',
                    'message': f'Future date detected in {key}: {date}',
                    'severity': 'high'
                })

    def get_full_report(self, image_bytes: bytes) -> dict:
        """
        Generate a complete metadata report.

        Returns dict with metadata and analysis.
        """
        metadata = self.extract_metadata(image_bytes)
        analysis = self.analyze_metadata(metadata)

        return {
            'metadata': metadata,
            'analysis': analysis,
            'metadata_score': analysis['score'],
            'metadata_json': json.dumps({
                'basic': metadata['basic'],
                'camera': metadata['camera'],
                'software': metadata['software'],
                'timestamps': metadata['timestamps'],
                'gps': metadata['gps'],
                'warnings': metadata['warnings'],
                'analysis': analysis
            })
        }
