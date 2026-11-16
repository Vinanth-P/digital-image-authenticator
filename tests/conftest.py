"""Tests never touch the operator's database, files, secrets, or remote TSAs."""
import os
import tempfile
from pathlib import Path
import pytest

_test_data = tempfile.TemporaryDirectory(prefix='imageguard-tests-')
os.environ['IMAGEGUARD_DATA_DIR'] = _test_data.name
os.environ.setdefault('IMAGEGUARD_MODELS_DIR', str(Path(__file__).resolve().parents[1] / 'instance' / 'models'))
os.environ['IMAGEGUARD_DOWNLOAD_MODELS'] = '0'
os.environ['HF_HUB_OFFLINE'] = '1'
os.environ['RFC3161_TSA_URL'] = ''
os.environ['IMAGEGUARD_ADMIN_PASSWORD'] = ''
os.environ['MASTER_PEPPER'] = 'test-only-pepper-never-used-outside-this-temporary-test-database'


@pytest.fixture(scope='session')
def client():
    from app import app
    from fastapi.testclient import TestClient
    with TestClient(app, base_url='http://localhost', client=('127.0.0.1', 50000)) as test_client:
        yield test_client


def pytest_unconfigure(config):
    import gc
    gc.collect()
    _test_data.cleanup()
