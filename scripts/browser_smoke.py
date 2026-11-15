"""Opt-in browser regression checks against an isolated real HTTP server."""
import argparse
import base64
import io
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

import numpy as np
from PIL import Image
from playwright.sync_api import sync_playwright, expect


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--browser-executable', default=None)
    parser.add_argument('--screenshot', default=None)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    url = f'http://127.0.0.1:{port}'
    password = 'browser-test-only-secret'
    with tempfile.TemporaryDirectory(prefix='imageguard-browser-') as data:
        env = {**os.environ, 'IMAGEGUARD_DATA_DIR': data, 'IMAGEGUARD_DOWNLOAD_MODELS': '0',
               'IMAGEGUARD_ADMIN_PASSWORD': password, 'IMAGEGUARD_ADMIN_USER': 'admin',
               'IMAGEGUARD_ALLOWED_HOSTS': 'localhost,127.0.0.1', 'RFC3161_TSA_URL': '',
               'MASTER_PEPPER': 'browser-test-only-installation-secret'}
        with open(Path(data) / 'server.log', 'w+', encoding='utf-8') as log:
            process = subprocess.Popen([sys.executable, '-m', 'uvicorn', 'app:app', '--host', '127.0.0.1', '--port', str(port)],
                                       cwd=root, env=env, stdout=log, stderr=log,
                                       creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
            try:
                authorization = 'Basic ' + base64.b64encode(('admin:' + password).encode()).decode()
                deadline = time.monotonic() + 45
                while True:
                    try:
                        urllib.request.urlopen(urllib.request.Request(url + '/api/health', headers={'Authorization':authorization}), timeout=1).close()
                        break
                    except Exception:
                        if process.poll() is not None or time.monotonic() > deadline:
                            log.seek(0)
                            raise RuntimeError(log.read())
                        time.sleep(.2)
                with sync_playwright() as playwright:
                    browser = playwright.chromium.launch(headless=True, executable_path=args.browser_executable)
                    context = browser.new_context(http_credentials={'username':'admin','password':password})
                    page = context.new_page()
                    errors = []
                    page.on('pageerror', lambda error: errors.append(str(error)))
                    page.goto(url)
                    page.evaluate("showPage('keys')")
                    hostile = '<img src=x onerror="window.__injected=true">'
                    page.locator('#keyOwnerName').fill(hostile)
                    page.locator('#keyCustodyMode').select_option('CLIENT_WEBCRYPTO')
                    page.evaluate('generateKeys()')
                    expect(page.locator('.key-name').first).to_be_visible()
                    assert page.locator('.key-name').first.inner_text() == hostile
                    assert page.evaluate('window.__injected === undefined')
                    assert page.evaluate("localStorage.getItem('imageguard_webcrypto_keys')") is None
                    key = page.evaluate("async () => {const keys=await browserKeyStore.all(); return {id:keys[0].key_id, extractable:keys[0].privateKey.extractable}}")
                    assert key['extractable'] is False
                    page.reload()
                    assert page.evaluate("async () => (await browserKeyStore.all())[0].privateKey.extractable") is False
                    buffer = io.BytesIO()
                    Image.fromarray(np.random.default_rng(928).integers(0,255,(128,128,3),dtype=np.uint8)).save(buffer,'PNG')
                    encoded = base64.b64encode(buffer.getvalue()).decode()
                    image_id = page.evaluate("""async encoded => {
                        const bytes=Uint8Array.from(atob(encoded), c=>c.charCodeAt(0));
                        const body=new FormData();body.append('file',new File([bytes],'browser.png',{type:'image/png'}));
                        const response=await fetch('/api/analyze',{method:'POST',body});
                        const result=await response.json(); if (!response.ok) throw new Error(JSON.stringify(result));
                        return result.data.id;
                    }""", encoded)
                    page.evaluate("showPage('sign')")
                    page.locator('#signImageSelect option').nth(1).wait_for(state='attached')
                    page.locator('#signImageSelect').select_option(str(image_id))
                    page.locator('#signModeSelect').select_option('CLIENT_WEBCRYPTO')
                    page.locator('#signKeySelect option').nth(1).wait_for(state='attached')
                    page.locator('#signKeySelect').select_option(key['id'])
                    page.evaluate('executeSign()')
                    verified = context.request.post(url + f'/api/verify-signature/{image_id}')
                    assert verified.ok, verified.text()
                    assert verified.json()['data']['is_valid'] is True
                    page.evaluate(f'viewImageDetail({image_id})')
                    assert 'browser.png' in page.locator('#detailContent').inner_text(), {'errors': errors, 'toasts': page.locator('#toastContainer').inner_text()}
                    assert not errors, errors
                    if args.screenshot:
                        page.evaluate("showPage('home')")
                        page.locator('#toastContainer').evaluate('(element) => element.replaceChildren()')
                        screenshot = Path(args.screenshot)
                        screenshot.parent.mkdir(parents=True, exist_ok=True)
                        page.screenshot(path=str(screenshot), full_page=True, animations='disabled')
                    browser.close()
                    print('Browser checks passed: escaped names, non-exportable persisted keys, client signing, signature verification, detail rendering.')
            finally:
                if os.name == 'nt':
                    # Windows venv python.exe is a redirector: stop its child
                    # server too, so temporary SQLite files are released.
                    subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'],
                                   capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
                else:
                    process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


if __name__ == '__main__':
    main()
