import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'imageguard-secret-key-2024')
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{os.path.join(BASE_DIR, 'instance', 'imageguard.db')}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
    RESULTS_FOLDER = os.path.join(BASE_DIR, 'static', 'results')
    CERTIFICATES_FOLDER = os.path.join(BASE_DIR, 'static', 'certificates')
    KEYS_FOLDER = os.path.join(BASE_DIR, 'static', 'keys')

    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max upload
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'bmp', 'tiff', 'webp'}

    # ELA settings
    ELA_QUALITY = 90
    ELA_SCALE = 15

    # RSA settings
    RSA_KEY_SIZE = 2048

    @staticmethod
    def init_app(app):
        """Create required directories."""
        for folder in [Config.UPLOAD_FOLDER, Config.RESULTS_FOLDER,
                       Config.CERTIFICATES_FOLDER, Config.KEYS_FOLDER,
                       os.path.join(BASE_DIR, 'instance')]:
            os.makedirs(folder, exist_ok=True)
