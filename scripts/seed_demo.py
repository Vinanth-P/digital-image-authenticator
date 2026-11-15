"""Seed procedural demo fixtures into a separate, non-destructive data directory."""
import os
import sys
from pathlib import Path
root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))
os.environ.setdefault('IMAGEGUARD_DATA_DIR', str(root / 'demo-data'))
from fastapi.testclient import TestClient
from config import Config
from app import app
from scripts.evaluate_dataset import generate_stress_cohorts


def seed():
    auth = (Config.ADMIN_USER, Config.ADMIN_PASSWORD) if Config.ADMIN_PASSWORD else None
    with TestClient(app, base_url='http://localhost', client=('127.0.0.1', 50000)) as client:
        client.auth = auth
        if client.get('/api/images').json()['data']:
            print('Demo directory already contains records; nothing deleted or replaced.')
            return
        key = client.post('/api/keys/generate', data={'owner_name':'Demo operator', 'passphrase':'demo-passphrase-2026'}).json()['data']
        samples = generate_stress_cohorts(samples_per_cohort=1)
        for index in (0, 2, 3):
            sample = samples[index]
            response = client.post('/api/analyze', files={'file':('procedural-'+sample['file_name'], sample['bytes'], 'image/jpeg')})
            response.raise_for_status()
            record = response.json()['data']
            if index == 0:
                signed = client.post('/api/sign/'+str(record['id']), data={'key_id':key['key_id'],'passphrase':'demo-passphrase-2026'})
                signed.raise_for_status()
            print(sample['cohort'], record['verdict'], record['authenticity_score'])
        print('Procedural demo created in', Config.DATA_DIR)
        print('Demo key passphrase: demo-passphrase-2026 (demo data only)')


if __name__ == '__main__':
    seed()
