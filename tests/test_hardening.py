import base64
import hashlib
import io
import json
from pathlib import Path

import numpy as np
import pytest
from PIL import Image
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

import app as server
from config import Config
from models.database import AuditEvent, ImageRecord, KeyPair, MerkleCheckpoint
from services.digital_signature import DigitalSignatureService
from services.merkle_ledger import MerkleAuditTree
from scripts.evaluate_dataset import rank_auc, wilson_interval, scan_external_dataset, generate_markdown_report


def upload(client, seed=178):
    buffer = io.BytesIO()
    Image.fromarray(np.random.default_rng(seed).integers(0, 255, (128, 128, 3), dtype=np.uint8)).save(buffer, 'PNG')
    raw = buffer.getvalue()
    response = client.post('/api/analyze', files={'file': ('regression.png', raw, 'image/png')})
    assert response.status_code == 200, response.text
    return response.json()['data'], raw


def server_key(client):
    response = client.post('/api/keys/generate', data={'owner_name': 'Regression signer', 'passphrase': 'regression-secret-2026'})
    assert response.status_code == 200
    assert 'raw_private_key_pem' not in response.json()['data']
    return response.json()['data']['key_id']


def test_corrupt_model_is_rejected_before_inference(tmp_path):
    from services.ai_detector_onnx import DeepForensicAnalyzer
    manifest = json.loads((Path(__file__).resolve().parents[1] / 'model-manifest.json').read_text())
    for spec in manifest.values():
        for artifact in spec['files'].values():
            (tmp_path / artifact['local']).write_bytes(b'corrupt model fixture')
    analyzer = DeepForensicAnalyzer(str(tmp_path))
    assert not analyzer.onnx_available and not analyzer.detectra_available
    assert all('checksum mismatch' in status['reason'] for status in analyzer.model_status.values())
    prediction = analyzer.classify_synthetic(np.zeros((64, 64, 3), dtype=np.uint8))
    assert prediction['onnx_used'] is False


def test_additive_upgrade_preserves_rows_and_marks_old_checkpoints(tmp_path):
    import sqlite3
    from models.database import init_db
    path = tmp_path / 'old-installation.db'
    factory = init_db(str(path))
    with factory() as db:
        db.add(ImageRecord(filename='old.png', original_filename='old.png', file_hash='a' * 64))
        db.add(MerkleCheckpoint(root_hash='b' * 64, tree_size=1))
        db.commit()
    factory.kw['bind'].dispose()
    # Recreate the pre-upgrade shape while retaining its original rows.
    with sqlite3.connect(path) as db:
        for column in ('original_storage_name', 'original_file_hash', 'provenance_status', 'timestamp_info'):
            db.execute(f'ALTER TABLE image_records DROP COLUMN {column}')
        for column in ('version', 'signature', 'public_key'):
            db.execute(f'ALTER TABLE merkle_checkpoints DROP COLUMN {column}')
        db.execute('DROP TABLE audit_events')
    upgraded = init_db(str(path))
    try:
        with upgraded() as db:
            row = db.query(ImageRecord).one()
            assert row.file_hash == 'a' * 64
            assert row.provenance_status == 'unverified_metadata'
            checkpoint = db.query(MerkleCheckpoint).one()
            assert checkpoint.root_hash == 'b' * 64
            assert checkpoint.version == 1 and checkpoint.signature == ''
            assert db.query(AuditEvent).count() == 0
            assert MerkleAuditTree.verify_record(db, row)['ledger_status'] == 'legacy_unanchored'
    finally:
        upgraded.kw['bind'].dispose()


def test_failed_signing_preserves_bytes_and_success_retains_original(client):
    record, raw = upload(client)
    key_id = server_key(client)
    path = Path(Config.UPLOAD_FOLDER) / record['filename']
    before_files = set(Path(Config.UPLOAD_FOLDER).iterdir())
    bad = client.post(f"/api/sign/{record['id']}", data={'key_id': key_id, 'passphrase': 'wrong'})
    assert bad.status_code == 403
    assert path.read_bytes() == raw
    assert set(Path(Config.UPLOAD_FOLDER).iterdir()) == before_files
    response = client.post(f"/api/sign/{record['id']}", data={'key_id': key_id, 'passphrase': 'regression-secret-2026'})
    assert response.status_code == 200, response.text
    assert response.json()['data']['has_rfc3161'] is False
    assert client.get(f"/api/images/{record['id']}/original").content == raw
    assert client.post(f"/api/verify-signature/{record['id']}").json()['data']['is_valid'] is True
    detail = client.get(f"/api/images/{record['id']}").json()['data']
    assert detail['filename'] != record['filename']
    assert detail['merkle_verified'] is True
    assert json.loads(detail['timestamp_info'])['status'] == 'local_receipt'


def test_client_signature_round_trip_and_identity_binding(client):
    record, raw = upload(client, 179)
    pair = DigitalSignatureService().generate_key_pair('Browser test')
    register = client.post('/api/keys/generate', data={'owner_name': 'Browser test', 'custody_mode': 'CLIENT_WEBCRYPTO', 'public_key_pem': pair['public_key_pem']})
    assert register.status_code == 200
    key_id = register.json()['data']['key_id']
    assert register.json()['data']['public_key_pem'] == pair['public_key_pem']
    private = serialization.load_pem_private_key(pair['raw_private_key_pem'].encode(), password=None)
    signature = base64.b64encode(private.sign(hashlib.sha256(raw).hexdigest().encode(), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())).decode()
    fields = {'signature_b64': signature, 'public_key_pem': pair['public_key_pem'], 'signer_name': 'Browser test', 'key_id': key_id}
    wrong = {**fields, 'public_key_pem': DigitalSignatureService().generate_key_pair('Other')['public_key_pem']}
    assert client.post(f"/api/sign-client/{record['id']}", data=wrong).status_code == 403
    assert client.post(f"/api/sign-client/{record['id']}", data={**fields, 'signer_name':'Impersonator'}).status_code == 403
    signed = client.post(f"/api/sign-client/{record['id']}", data=fields)
    assert signed.status_code == 200, signed.text
    assert (Path(Config.UPLOAD_FOLDER) / record['filename']).read_bytes() == raw
    assert client.post(f"/api/verify-signature/{record['id']}").json()['data']['is_valid'] is True
    assert client.post('/api/verify', files={'file':('signed.png', raw, 'image/png')}).json()['data']['is_valid'] is True


def test_plaintext_legacy_key_cannot_bypass_passphrase(client):
    record, raw = upload(client, 280)
    pair = DigitalSignatureService().generate_key_pair('Legacy plaintext')
    with server.Session() as db:
        db.add(KeyPair(key_id=pair['key_id'], owner_name='Legacy plaintext',
                       public_key_pem=pair['public_key_pem'], private_key_pem=pair['raw_private_key_pem'],
                       custody_mode='SERVER_AES_GCM', is_envelope_encrypted=False))
        db.commit()
    response = client.post(f"/api/sign/{record['id']}", data={'key_id': pair['key_id'], 'passphrase': 'anything'})
    assert response.status_code == 409
    assert (Path(Config.UPLOAD_FOLDER) / record['filename']).read_bytes() == raw


def test_legacy_import_is_explicit_and_cannot_rewrite_history(client):
    # A pre-upgrade row has no event, even if its legacy leaf field was filled.
    _, raw = upload(client, 281)
    name = 'legacy-import-fixture.png'
    (Path(Config.UPLOAD_FOLDER) / name).write_bytes(raw)
    with server.Session() as db:
        record = ImageRecord(filename=name, original_filename=name,
                             file_hash=hashlib.sha256(raw).hexdigest(), file_size=len(raw),
                             merkle_leaf_hash='0' * 64)
        db.add(record)
        db.commit()
        image_id = record.id
    detail = client.get(f'/api/images/{image_id}').json()['data']
    assert detail['ledger_status'] == 'legacy_unanchored'
    assert detail['merkle_verified'] is False
    imported = client.post(f'/api/images/{image_id}/import-legacy')
    assert imported.status_code == 200, imported.text
    assert client.get(f'/api/images/{image_id}').json()['data']['merkle_verified'] is True
    assert client.post(f'/api/images/{image_id}/import-legacy').status_code == 409
    with server.Session() as db:
        events = db.query(AuditEvent).filter_by(image_id=image_id).all()
        assert [event.event_type for event in events] == ['legacy_import']


def test_record_tampering_is_rejected_without_reanchoring(client):
    record, _ = upload(client, 180)
    with server.Session() as db:
        row = db.get(ImageRecord, record['id'])
        previous = row.authenticity_score
        row.authenticity_score = 12.34
        db.commit()
    try:
        detail = client.get(f"/api/images/{record['id']}").json()['data']
        assert detail['merkle_verified'] is False
        assert detail['ledger_status'] == 'integrity_failure'
        assert client.post(f"/api/certificate/{record['id']}").status_code == 409
        assert client.post(f"/api/images/{record['id']}/import-legacy").status_code == 409
    finally:
        with server.Session() as db:
            db.get(ImageRecord, record['id']).authenticity_score = previous
            db.commit()
    assert client.get(f"/api/images/{record['id']}").json()['data']['merkle_verified'] is True


def test_checkpoint_signature_and_event_tampering(client):
    record, _ = upload(client, 181)
    detail = client.get(f"/api/images/{record['id']}").json()['data']
    cp = detail['checkpoint']
    assert MerkleAuditTree.verify_inclusion_proof(detail['merkle_leaf_hash'], detail['merkle_proof'], cp['root_hash'])
    with server.Session() as db:
        checkpoint = db.get(MerkleCheckpoint, cp['id'])
        original_sig = checkpoint.signature
        checkpoint.signature = base64.b64encode(b'bad signature').decode()
        db.commit()
    try:
        assert client.get(f"/api/images/{record['id']}").json()['data']['merkle_verified'] is False
    finally:
        with server.Session() as db:
            db.get(MerkleCheckpoint, cp['id']).signature = original_sig
            db.commit()
    with server.Session() as db:
        event = db.query(AuditEvent).filter_by(image_id=record['id']).first()
        original_payload, event_id = event.payload, event.id
        event.payload += ' '
        db.commit()
    try:
        assert client.get(f"/api/images/{record['id']}").json()['data']['merkle_verified'] is False
    finally:
        with server.Session() as db:
            db.get(AuditEvent, event_id).payload = original_payload
            db.commit()


def test_deletion_retains_events_and_never_reuses_identity(client):
    record, _ = upload(client, 182)
    old = client.get(f"/api/images/{record['id']}").json()['data']['checkpoint']
    assert client.delete(f"/api/images/{record['id']}").status_code == 200
    with server.Session() as db:
        assert db.query(AuditEvent).filter_by(image_id=record['id'], event_type='deletion').count() == 1
        assert db.get(MerkleCheckpoint, old['id']).root_hash == old['root_hash']
    next_record, _ = upload(client, 183)
    assert next_record['id'] > record['id']


def test_failed_signing_commit_leaves_no_derivative(client, monkeypatch):
    record, raw = upload(client, 184)
    key = server_key(client)
    before = set(Path(Config.UPLOAD_FOLDER).iterdir())
    def fail(*args, **kwargs):
        raise RuntimeError('Simulated ledger write failure')
    monkeypatch.setattr(MerkleAuditTree, 'append_event', fail)
    with pytest.raises(RuntimeError, match='Simulated ledger'):
        client.post(f"/api/sign/{record['id']}", data={'key_id':key, 'passphrase':'regression-secret-2026'})
    assert before == set(Path(Config.UPLOAD_FOLDER).iterdir())
    assert (Path(Config.UPLOAD_FOLDER) / record['filename']).read_bytes() == raw
    with server.Session() as db:
        assert db.get(ImageRecord, record['id']).is_signed is False


@pytest.mark.parametrize('endpoint', ['/api/analyze', '/api/verify', '/api/recover-provenance'])
def test_all_upload_routes_reject_bad_and_oversized_images(client, monkeypatch, endpoint):
    assert client.post(endpoint, files={'file':('bad.png', b'not an image', 'image/png')}).status_code == 400
    monkeypatch.setattr(Config, 'MAX_CONTENT_LENGTH', 128)
    assert client.post(endpoint, files={'file':('big.png', b'x' * 129, 'image/png')}).status_code == 413


def test_pixel_budget_and_extension_validation(client, monkeypatch):
    buffer = io.BytesIO()
    Image.new('RGB', (128,128)).save(buffer, 'PNG')
    monkeypatch.setattr(Config, 'MAX_IMAGE_PIXELS', 100)
    assert client.post('/api/analyze', files={'file':('huge.png',buffer.getvalue(),'image/png')}).status_code == 413
    assert client.post('/api/analyze', files={'file':('fake.jpg',buffer.getvalue(),'image/jpeg')}).status_code == 400


def test_authentication_protects_files_mutations_and_websockets(client, monkeypatch):
    record, _ = upload(client, 185)
    monkeypatch.setattr(Config, 'ADMIN_PASSWORD', 'operator-password-2026')
    for path in ['/api/images', '/static/uploads/' + record['filename'], '/verify/' + str(record['id'])]:
        assert client.get(path).status_code == 401
        assert client.get(path, auth=('admin','operator-password-2026')).status_code == 200
    assert client.delete(f"/api/images/{record['id']}").status_code == 401
    assert client.post('/api/keys/generate', auth=('admin','operator-password-2026'), headers={'Origin':'https://evil.example'}, data={'owner_name':'bad'}).status_code == 403
    from starlette.websockets import WebSocketDisconnect
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect('/ws/analyze/unauthorized'):
            pass
    assert client.get('/static/keys/private.pem', auth=('admin','operator-password-2026')).status_code == 404


def test_local_mode_rejects_remote_and_untrusted_host(client):
    remote = TestClient(server.app, base_url='http://localhost', client=('203.0.113.1',50000))
    try:
        assert remote.get('/api/images').status_code == 403
    finally:
        remote.close()
    assert client.get('/api/images', headers={'Host':'evil.example'}).status_code == 403


def test_merkle_tree_matches_rfc_hashing_and_odd_tree_shape():
    leaves = [MerkleAuditTree.hash_leaf(c) for c in ('a','b','c')]
    expected = hashlib.sha256(b'\x01' + bytes.fromhex(MerkleAuditTree.hash_pair(*leaves[:2])) + bytes.fromhex(leaves[2])).hexdigest()
    for index in range(3):
        tree = MerkleAuditTree.build_tree_and_proof(leaves,index)
        assert tree['root'] == expected
        assert MerkleAuditTree.verify_inclusion_proof(leaves[index],tree['proof'],expected)
    assert MerkleAuditTree.build_tree_and_proof([])['root'] == hashlib.sha256(b'').hexdigest()


def test_metric_math_and_strict_external_labels(tmp_path):
    assert rank_auc([True,False], [1,0]) == 1
    assert rank_auc([True,False], [0,1]) == 0
    assert rank_auc([True,False], [1,1]) == .5
    assert rank_auc([True,True], [1,2]) is None
    assert wilson_interval(40,40)[0] < 100
    with pytest.raises(ValueError, match='No labelled'):
        scan_external_dataset(str(tmp_path))


def test_report_flags_missed_targets(tmp_path):
    output = tmp_path/'report.md'
    generate_markdown_report({'dataset_summary':{'total_images':2,'mean_latency_ms':1000,'throughput_fps':1},
        'performance_metrics':{'accuracy_pct':50,'precision_pct':50,'recall_sensitivity_pct':50,'specificity_pct':50,'false_positive_rate_pct':50,'f1_score':.5,'roc_auc':None},
        'cohort_breakdown':{}, 'sample_records':[]},str(output))
    report = output.read_text()
    assert '| Mean latency (ms) | 1000 | <= 250 | FAIL |' in report
    assert '| ROC-AUC | None | >= 0.95 | UNDEFINED |' in report
