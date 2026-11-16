"""Explicit download of revision-pinned, checksum-verified model artifacts."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from config import Config
from services.ai_detector_onnx import DeepForensicAnalyzer

if __name__ == '__main__':
    Config.ALLOW_MODEL_DOWNLOADS = True
    analyzer = DeepForensicAnalyzer()
    for name, status in analyzer.model_status.items():
        print(name, status)
    raise SystemExit(0 if analyzer.onnx_available and analyzer.detectra_available else 1)
