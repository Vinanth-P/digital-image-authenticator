import os
from pathlib import Path

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    DATA_DIR = os.path.abspath(os.environ.get('IMAGEGUARD_DATA_DIR', BASE_DIR))
    DB_PATH = os.path.join(DATA_DIR, 'instance', 'imageguard.db')
    MASTER_PEPPER = os.environ.get('MASTER_PEPPER', '').encode('utf-8')
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{DB_PATH}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    UPLOAD_FOLDER = os.path.join(DATA_DIR, 'static', 'uploads')
    RESULTS_FOLDER = os.path.join(DATA_DIR, 'static', 'results')
    CERTIFICATES_FOLDER = os.path.join(DATA_DIR, 'static', 'certificates')
    KEYS_FOLDER = os.path.join(DATA_DIR, 'instance', 'keys')
    ORIGINALS_FOLDER = os.path.join(DATA_DIR, 'instance', 'originals')
    MODELS_FOLDER = os.path.abspath(os.environ.get('IMAGEGUARD_MODELS_DIR', os.path.join(BASE_DIR, 'instance', 'models')))
    LEDGER_KEY_PATH = os.path.join(DATA_DIR, 'instance', 'ledger-signing-key.pem')
    ADMIN_USER = os.environ.get('IMAGEGUARD_ADMIN_USER', 'admin')
    ADMIN_PASSWORD = os.environ.get('IMAGEGUARD_ADMIN_PASSWORD', '')
    ALLOWED_HOSTS = os.environ.get('IMAGEGUARD_ALLOWED_HOSTS', 'localhost,127.0.0.1,::1').split(',')
    PUBLIC_BASE_URL = os.environ.get('IMAGEGUARD_BASE_URL', 'http://localhost:8000').rstrip('/')
    ALLOW_MODEL_DOWNLOADS = os.environ.get('IMAGEGUARD_DOWNLOAD_MODELS', '0') == '1'
    MAX_IMAGE_PIXELS = 20_000_000

    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max upload
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'bmp', 'tiff', 'webp'}

    # ELA settings
    ELA_QUALITY = 90
    ELA_SCALE = 15

    # RSA settings
    RSA_KEY_SIZE = 2048

    # RFC 3161 Timestamp Server
    RFC3161_TSA_URL = os.environ.get('RFC3161_TSA_URL', '')

    @staticmethod
    def init_app(app=None):
        """Create required directories."""
        for folder in [Config.UPLOAD_FOLDER, Config.RESULTS_FOLDER,
                       Config.CERTIFICATES_FOLDER, Config.KEYS_FOLDER,
                       Config.MODELS_FOLDER, Config.ORIGINALS_FOLDER,
                       os.path.dirname(Config.DB_PATH)]:
            os.makedirs(folder, exist_ok=True)
        if Config.ADMIN_PASSWORD and len(Config.ADMIN_PASSWORD) < 12:
            raise ValueError('IMAGEGUARD_ADMIN_PASSWORD must contain at least 12 characters')
        if not Config.MASTER_PEPPER:
            pepper_path = Path(Config.DATA_DIR) / 'instance' / 'master-pepper'
            if not pepper_path.exists():
                try:
                    fd = os.open(pepper_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(fd, 'wb') as stream:
                        stream.write(os.urandom(32))
                except FileExistsError:
                    pass
            Config.MASTER_PEPPER = pepper_path.read_bytes()
