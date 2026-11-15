// Treat every user-controlled string as text at HTML rendering boundaries.
function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;'}[c]));
}

const browserKeyStore = {
    async open() {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open('imageguard-keys', 1);
            request.onupgradeneeded = () => request.result.createObjectStore('keys', {keyPath: 'key_id'});
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
        });
    },
    async operation(mode, action) {
        const db = await this.open();
        return new Promise((resolve, reject) => {
            const tx = db.transaction('keys', mode);
            const request = action(tx.objectStore('keys'));
            tx.oncomplete = () => { db.close(); resolve(request.result); };
            tx.onerror = () => { db.close(); reject(tx.error); };
            tx.onabort = () => { db.close(); reject(tx.error); };
        });
    },
    async put(key) { return this.operation('readwrite', store => store.put(key)); },
    async all() { return this.operation('readonly', store => store.getAll()); }
};

let migrationPromise;
async function localBrowserKeys() {
    if (!migrationPromise) migrationPromise = (async () => {
        const legacy = JSON.parse(localStorage.getItem('imageguard_webcrypto_keys') || '{}');
        for (const old of Object.values(legacy)) {
            const privateKey = await crypto.subtle.importKey('jwk', old.jwk, {name:'RSA-PSS', hash:'SHA-256'}, false, ['sign']);
            const body = new FormData();
            body.append('owner_name', old.owner_name);
            body.append('custody_mode', 'CLIENT_WEBCRYPTO');
            body.append('public_key_pem', old.public_pem);
            const response = await fetch('/api/keys/generate', {method:'POST', body});
            const result = await response.json();
            if (!response.ok) throw new Error(result.detail || 'Legacy key migration failed');
            await browserKeyStore.put({key_id:result.data.key_id, owner_name:old.owner_name, public_pem:old.public_pem, privateKey});
        }
        // Only remove legacy plaintext after every key has been saved successfully.
        localStorage.removeItem('imageguard_webcrypto_keys');
    })().catch(error => { migrationPromise = null; throw error; });
    await migrationPromise;
    const keys = await browserKeyStore.all();
    return Object.fromEntries(keys.map(key => [key.key_id, key]));
}

/**
 * ImageGuard v2 — Frontend Application
 * Multi-Branch Neural & Spectral Media Forensics, Dual-Layer C2PA Provenance,
 * Zero-Trust Key Custody, and Merkle Transparency Audit Platform.
 */

// ═══════════════════════════════════════════════════════════
//  STATE
// ═══════════════════════════════════════════════════════════
const state = {
    currentPage: 'home',
    selectedFile: null,
    currentAnalysis: null,
    images: [],
    keys: [],
    localWebCryptoKeys: {}, // Local browser key storage
    ws: null,
    clientId: 'client_' + Math.random().toString(36).substring(2, 9),
};

// ═══════════════════════════════════════════════════════════
//  NAVIGATION
// ═══════════════════════════════════════════════════════════
function showPage(pageName) {
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));

    const page = document.getElementById(`page-${pageName}`);
    if (page) {
        page.classList.add('active');
        page.style.animation = 'none';
        page.offsetHeight; // force reflow
        page.style.animation = '';
    }

    const link = document.querySelector(`.nav-link[data-page="${pageName}"]`);
    if (link) link.classList.add('active');

    state.currentPage = pageName;

    if (pageName === 'dashboard') loadDashboard();
    if (pageName === 'keys') loadKeys();
    if (pageName === 'sign') loadSignData();
}

function switchSignMode(mode) {
    document.querySelectorAll('#page-sign .tab-btn').forEach(b => b.classList.remove('active'));
    event.target.classList.add('active');

    if (mode === 'sign-verify') {
        document.getElementById('sign-verify-section').style.display = 'block';
        document.getElementById('recover-provenance-section').style.display = 'none';
    } else {
        document.getElementById('sign-verify-section').style.display = 'none';
        document.getElementById('recover-provenance-section').style.display = 'block';
    }
}

// ═══════════════════════════════════════════════════════════
//  FILE UPLOAD & WEBSOCKET PROGRESS
// ═══════════════════════════════════════════════════════════
const uploadZone = document.getElementById('uploadZone');
const fileInput = document.getElementById('fileInput');
const uploadPreview = document.getElementById('uploadPreview');
const previewImage = document.getElementById('previewImage');
const fileInfo = document.getElementById('fileInfo');

if (uploadZone && fileInput) {
    uploadZone.addEventListener('click', (e) => {
        if (e.target !== fileInput) {
            fileInput.click();
        }
    });

    fileInput.addEventListener('click', (e) => {
        e.stopPropagation();
    });

    uploadZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadZone.classList.add('dragover');
    });

    uploadZone.addEventListener('dragleave', () => {
        uploadZone.classList.remove('dragover');
    });

    uploadZone.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadZone.classList.remove('dragover');
        const files = e.dataTransfer ? e.dataTransfer.files : null;
        if (files && files.length > 0) handleFileSelect(files[0]);
    });
}

if (fileInput) {
    fileInput.addEventListener('change', (e) => {
        if (e.target && e.target.files && e.target.files.length > 0) {
            handleFileSelect(e.target.files[0]);
        }
    });
}

function handleFileSelect(file) {
    if (!file) return;

    const allowedMime = ['image/png', 'image/jpeg', 'image/jpg', 'image/bmp', 'image/tiff', 'image/webp'];
    const ext = file.name ? file.name.split('.').pop().toLowerCase() : '';
    const allowedExts = ['png', 'jpg', 'jpeg', 'bmp', 'tiff', 'webp'];

    if (!allowedMime.includes(file.type) && !allowedExts.includes(ext)) {
        showToast('Invalid file type. Use PNG, JPG, BMP, TIFF, or WEBP.', 'error');
        return;
    }

    if (file.size > 16 * 1024 * 1024) {
        showToast('File too large. Maximum size is 16 MB.', 'error');
        return;
    }

    state.selectedFile = file;

    const reader = new FileReader();
    reader.onload = (e) => {
        if (previewImage) previewImage.src = e.target.result;
        if (fileInfo) fileInfo.textContent = `${file.name} — ${formatSize(file.size)}`;

        const fileNameEl = document.getElementById('fileName');
        if (fileNameEl) fileNameEl.textContent = file.name;
        const fileSizeEl = document.getElementById('fileSize');
        if (fileSizeEl) fileSizeEl.textContent = formatSize(file.size);

        if (uploadPreview) {
            uploadPreview.classList.remove('hidden');
            uploadPreview.classList.add('visible', 'active');
            uploadPreview.style.display = 'block';
        }

        const analyzeBtn = document.getElementById('analyzeBtn');
        if (analyzeBtn) {
            analyzeBtn.classList.remove('hidden');
            analyzeBtn.style.display = 'block';
        }
    };
    reader.readAsDataURL(file);

    const resultsContainer = document.getElementById('resultsContainer');
    if (resultsContainer) {
        resultsContainer.classList.remove('visible', 'active');
        resultsContainer.classList.add('hidden');
        resultsContainer.style.display = 'none';
    }

    const stepper = document.getElementById('stepperContainer');
    if (stepper) {
        stepper.classList.remove('visible', 'active');
        stepper.classList.add('hidden');
        stepper.style.display = 'none';
    }
}

function clearSelectedFile() {
    state.selectedFile = null;
    if (fileInput) fileInput.value = '';
    if (previewImage) previewImage.src = '';
    if (fileInfo) fileInfo.textContent = '';

    const fileNameEl = document.getElementById('fileName');
    if (fileNameEl) fileNameEl.textContent = '';
    const fileSizeEl = document.getElementById('fileSize');
    if (fileSizeEl) fileSizeEl.textContent = '';

    if (uploadPreview) {
        uploadPreview.classList.remove('visible', 'active');
        uploadPreview.classList.add('hidden');
        uploadPreview.style.display = 'none';
    }

    const resultsContainer = document.getElementById('resultsContainer');
    if (resultsContainer) {
        resultsContainer.classList.remove('visible', 'active');
        resultsContainer.classList.add('hidden');
        resultsContainer.style.display = 'none';
    }

    const stepper = document.getElementById('stepperContainer');
    if (stepper) {
        stepper.classList.remove('visible', 'active');
        stepper.classList.add('hidden');
        stepper.style.display = 'none';
    }
}

function initWebSocket() {
    try {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws/analyze/${state.clientId}`;
        state.ws = new WebSocket(wsUrl);

        state.ws.onmessage = (event) => {
            try {
                const msg = JSON.parse(event.data);
                if (msg.type === 'progress') {
                    updateStepper(msg.stage, msg.percent, msg.detail);
                }
            } catch (err) {}
        };

        state.ws.onerror = () => {};
    } catch (e) {}
}

function updateStepper(stage, percent, detail) {
    const stepper = document.getElementById('stepperContainer');
    if (!stepper) return;
    stepper.style.display = 'block';

    document.getElementById('stepperStageTitle').textContent = stage;
    document.getElementById('stepperStagePercent').textContent = `${percent}%`;
    document.getElementById('stepperBarFill').style.width = `${percent}%`;
    document.getElementById('stepperDetail').textContent = detail;

    const stepMapping = [
        { id: 'step-1', min: 10 },
        { id: 'step-2', min: 25 },
        { id: 'step-3', min: 45 },
        { id: 'step-4', min: 65 },
        { id: 'step-5', min: 80 },
        { id: 'step-6', min: 95 },
    ];

    stepMapping.forEach((s, idx) => {
        const el = document.getElementById(s.id);
        if (!el) return;
        if (percent >= s.min) {
            el.classList.add('done');
            el.classList.remove('active');
        } else if (idx === 0 || percent >= stepMapping[idx - 1].min) {
            el.classList.add('active');
            el.classList.remove('done');
        } else {
            el.classList.remove('active', 'done');
        }
    });
}

// ═══════════════════════════════════════════════════════════
//  ANALYZE IMAGE (v2 MULTI-BRANCH FORENSICS)
// ═══════════════════════════════════════════════════════════
async function analyzeImage() {
    if (!state.selectedFile) {
        showToast('Please select an image first.', 'warning');
        return;
    }

    initWebSocket();
    updateStepper("Ingestion & Integrity Hashing", 10, "Uploading image bytes and initializing forensic branches");

    // Clean HTTP fallback stepper timer if WebSocket disconnects or is blocked
    let fallbackStageIdx = 0;
    const fallbackStages = [
        { stage: "Ingestion & Integrity Hashing", percent: 15, detail: "Ingesting image stream and calculating SHA-256 + 64-bit dHash" },
        { stage: "ELA Compression Residuals", percent: 35, detail: "Computing high-frequency quantization differentials at QF 90" },
        { stage: "30-Filter SRM Steganalysis", percent: 55, detail: "Convolving with fixed spatial rich model kernels & TruFor reliability map" },
        { stage: "2D FFT Radial Spectrum", percent: 75, detail: "Azimuthal integration across 32 radial bins and fitting optical 1/f² decay" },
        { stage: "ONNX Synthetic Classifier", percent: 90, detail: "EfficientNet-B0 inference and 7x7 patch-occlusion sensitivity attribution" },
        { stage: "Merkle Audit Commitment", percent: 98, detail: "Composing deterministic leaf hash and synchronizing Merkle root" }
    ];
    let lastWsMessageTime = Date.now();
    const fallbackInterval = setInterval(() => {
        if (Date.now() - lastWsMessageTime > 500 && fallbackStageIdx < fallbackStages.length) {
            const s = fallbackStages[fallbackStageIdx++];
            updateStepper(s.stage, s.percent, s.detail);
        }
    }, 450);

    const formData = new FormData();
    formData.append('file', state.selectedFile);
    formData.append('client_id', state.clientId);

    try {
        const response = await fetch('/api/analyze', {
            method: 'POST',
            body: formData,
        });

        clearInterval(fallbackInterval);
        const result = await response.json();

        if (result.status === 'success') {
            updateStepper("Complete", 100, "All forensic branches executed and Merkle leaf committed.");
            state.currentAnalysis = result.data;
            renderAnalysisResults(result.data);
            showToast('v2 Multi-Branch Analysis complete!', 'success');
        } else {
            showToast(result.detail || 'Analysis failed', 'error');
        }
    } catch (err) {
        clearInterval(fallbackInterval);
        showToast(`Error: ${err.message}`, 'error');
    }
}

function getVerdictBadge(verdictText) {
    if (verdictText === 'Authentic Media') {
        return `<div class="verdict-badge authentic">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>
            No strong manipulation signal
        </div>`;
    } else if (verdictText === 'AI-Generated / Synthetic Media') {
        return `<div class="verdict-badge synthetic">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;"><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><line x1="9" y1="1" x2="9" y2="4"/><line x1="15" y1="1" x2="15" y2="4"/><line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/><line x1="20" y1="9" x2="23" y2="9"/><line x1="20" y1="14" x2="23" y2="14"/><line x1="1" y1="9" x2="4" y2="9"/><line x1="1" y1="14" x2="4" y2="14"/></svg>
            Synthetic indicators detected
        </div>`;
    } else {
        return `<div class="verdict-badge spliced">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
            Manipulated / Spliced Forgery
        </div>`;
    }
}

function renderTwoGateCard(tamperScore, originScore, aiProb) {
    const gate1Pass = (tamperScore >= 60.0);
    const gate2Pass = (aiProb < 50.0);

    return `
        <div class="glass-card mt-lg two-gate-card">
            <div class="card-header">
                <div class="icon violet">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                </div>
                <div>
                    <h2>Two-Gate Veto Architecture (Decoupled Forensics)</h2>
                    <p>Experimental compression, noise, and synthetic-signal checks; scores are not calibrated probabilities</p>
                </div>
            </div>
            <div class="gates-grid">
                <div class="gate-box ${gate1Pass ? 'gate-pass' : 'gate-veto'}">
                    <div class="gate-header">
                        <span class="gate-title">Gate 1 — Splice &amp; Tamper Integrity (G₁)</span>
                        <span class="gate-badge ${gate1Pass ? 'pass' : 'veto'}">${gate1Pass ? 'PASS' : 'VETO: LOCALIZED TAMPER'}</span>
                    </div>
                    <div class="gate-score-row">
                        <span class="gate-score-val tabular-nums">${Number(tamperScore).toFixed(1)}%</span>
                        <span class="gate-formula">0.55·ELA + 0.45·SRM (Threshold ≥ 60.0%)</span>
                    </div>
                    <div class="gate-bar-track">
                        <div class="gate-bar-fill ${gate1Pass ? 'pass' : 'veto'}" style="width: ${Math.min(100, Math.max(0, tamperScore))}%"></div>
                    </div>
                    <p class="gate-desc">Evaluates local compression boundary continuity and 30-filter micro-steganalysis noise variance across all 16×16 blocks.</p>
                </div>
                <div class="gate-box ${gate2Pass ? 'gate-pass' : 'gate-veto'}">
                    <div class="gate-header">
                        <span class="gate-title">Gate 2 — Synthetic Signal (G₂)</span>
                        <span class="gate-badge ${gate2Pass ? 'pass' : 'veto'}">${gate2Pass ? 'PASS' : 'ELEVATED SYNTHETIC SIGNAL'}</span>
                    </div>
                    <div class="gate-score-row">
                        <span class="gate-score-val tabular-nums">${Number(originScore).toFixed(1)}%</span>
                        <span class="gate-formula">0.70·(100 - synthetic score) + 0.30·FFT</span>
                    </div>
                    <div class="gate-bar-track">
                        <div class="gate-bar-fill ${gate2Pass ? 'pass' : 'veto'}" style="width: ${Math.min(100, Math.max(0, originScore))}%"></div>
                    </div>
                    <p>Uses available neural or heuristic signals and spectral measurements. A synthetic score below 50 passes; 50–55 is borderline; 55 or higher triggers a veto.</p>
                </div>
            </div>
            <div class="gate-explanation">
                <span class="info-badge">Soft-Min Veto Rule</span>
                <span>Scoring rule: passing checks average G₁ and G₂. Otherwise the lower score caps the result, with a 0.85 multiplier for the synthetic veto or 0.90 for the borderline synthetic case. These rules are experimental, not proof of origin.</span>
            </div>
        </div>
    `;
}

function renderAnalysisResults(data) {
    const container = document.getElementById('resultsContainer');
    const score = data.authenticity_score;
    const isAuthentic = data.is_authentic;
    const circumference = 2 * Math.PI * 65;
    const offset = circumference - (score / 100) * circumference;

    let metadataReport = data.metadata_report || {};
    let metadataAnalysis = metadataReport.analysis || {};
    let metadata = metadataReport.metadata || {};
    let c2paInfo = metadataReport.c2pa || {};

    const aiProb = (data.ai_generation_prob || 0) * 100;
    let forgeryDetails = {};
    try {
        forgeryDetails = typeof data.forgery_details === 'string' ? JSON.parse(data.forgery_details) : (data.forgery_details || {});
    } catch (e) {
        forgeryDetails = {};
    }
    const verdictText = forgeryDetails.verdict || (isAuthentic ? 'Authentic Media' : (aiProb >= 55 ? 'AI-Generated / Synthetic Media' : 'Manipulated / Spliced Forgery'));

    const gates = forgeryDetails.gates || {};
    const tamperScore = typeof gates.tamper_integrity_score === 'number'
        ? gates.tamper_integrity_score
        : parseFloat((0.55 * (data.ela_score || 0) + 0.45 * (data.noise_score || 0)).toFixed(1));
    const originScore = typeof gates.origin_integrity_score === 'number'
        ? gates.origin_integrity_score
        : parseFloat((0.70 * (100 - aiProb) + 0.30 * (data.fft_score || 0)).toFixed(1));

    container.innerHTML = `
        <!-- Score Overview & Forensic Breakdown -->
        <div class="results-grid">
            <div class="glass-card">
                <div class="score-ring-container">
                    <div class="score-ring">
                        <svg viewBox="0 0 140 140">
                            <circle class="ring-bg" cx="70" cy="70" r="65"/>
                            <circle class="ring-progress ${isAuthentic ? 'authentic' : 'forged'}"
                                cx="70" cy="70" r="65"
                                stroke-dasharray="${circumference}"
                                stroke-dashoffset="${circumference}"
                                data-target-offset="${offset}"/>
                        </svg>
                        <div class="score-value">
                            <span class="score-number" style="color: ${isAuthentic ? 'var(--success-400)' : 'var(--danger-400)'}"
                                  data-target="${score}">0</span>
                            <span class="score-label">Analysis score</span>
                        </div>
                    </div>
                    ${getVerdictBadge(verdictText)}
                    <div class="mt-sm">
                        <span class="c2pa-badge">Provenance: ${escapeHtml(c2paInfo.status || 'unavailable')}</span><span class="c2pa-badge">Analysis: ${forgeryDetails.ai_neural?.onnx_used ? 'neural + heuristics' : 'heuristic fallback'} &middot; uncalibrated</span>
                    </div>
                </div>
            </div>

            <div class="glass-card">
                <div class="card-header">
                    <div class="icon blue">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>
                    </div>
                    <div><h2>v2 Multi-Branch Forensic Breakdown</h2><p>Neural &amp; Spectral Domain Scores</p></div>
                </div>

                <div class="score-bar-item">
                    <div class="score-bar-header">
                        <span class="score-bar-label">1. Error Level Analysis (ELA)</span>
                        <span class="score-bar-value tabular-nums" style="color:${getScoreColor(data.ela_score)}">${data.ela_score}%</span>
                    </div>
                    <div class="score-bar-track">
                        <div class="score-bar-fill ${getScoreClass(data.ela_score)}" data-width="${data.ela_score}"></div>
                    </div>
                </div>

                <div class="score-bar-item">
                    <div class="score-bar-header">
                        <span class="score-bar-label">2. 30-Filter SRM Steganalysis Residuals</span>
                        <span class="score-bar-value tabular-nums" style="color:${getScoreColor(data.noise_score)}">${data.noise_score}%</span>
                    </div>
                    <div class="score-bar-track">
                        <div class="score-bar-fill ${getScoreClass(data.noise_score)}" data-width="${data.noise_score}"></div>
                    </div>
                </div>

                <div class="score-bar-item">
                    <div class="score-bar-header">
                        <span class="score-bar-label">3. 2D FFT Radial Power Spectrum (1/f²)</span>
                        <span class="score-bar-value tabular-nums" style="color:${getScoreColor(data.fft_score)}">${data.fft_score}%</span>
                    </div>
                    <div class="score-bar-track">
                        <div class="score-bar-fill ${getScoreClass(data.fft_score)}" data-width="${data.fft_score}"></div>
                    </div>
                </div>

                <div class="score-bar-item">
                    <div class="score-bar-header">
                        <span class="score-bar-label">4. Deep Neural CIFAKE Classifier</span>
                        <span class="score-bar-value tabular-nums" style="color:${aiProb > 50 ? 'var(--danger-400)' : 'var(--success-400)'}">AI signal: ${aiProb.toFixed(1)}%</span>
                    </div>
                    <div class="score-bar-track">
                        <div class="score-bar-fill ${aiProb > 50 ? 'low' : 'high'}" data-width="${100 - aiProb}"></div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Two-Gate Veto Diagnostic Matrix -->
        ${renderTwoGateCard(tamperScore, originScore, aiProb)}

        <!-- 2D FFT Radial Spectrum Chart & Merkle Attestation -->
        <div class="results-grid mt-lg">
            <div class="glass-card">
                <div class="card-header">
                    <div class="icon violet">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
                    </div>
                    <div>
                        <h2>2D FFT Radial Power Spectrum</h2>
                        <p>Azimuthal Power vs. Natural 1/f² Optical Baseline (Slope α = ${escapeHtml(data.spectral_slope ?? 'unavailable')})</p>
                    </div>
                </div>
                <div class="fft-chart-box">
                    <canvas id="fftChartCanvas" width="480" height="220"></canvas>
                </div>
            </div>

            <div class="glass-card">
                <div class="card-header">
                    <div class="icon green">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22v-7"/><path d="M9 9a3 3 0 0 1 6 0c0 2-3 3-3 6"/><circle cx="12" cy="6" r="3"/></svg>
                    </div>
                    <div><h2>Merkle Audit &amp; Provenance Ledger</h2><p>Cryptographic Transparency Ledger Commit</p></div>
                </div>
                <table class="metadata-table">
                    <tr><th>Parameter</th><th>Value</th></tr>
                    <tr><td>Merkle Leaf Digest</td><td class="text-mono tabular-nums" style="font-size:0.7rem;">${data.merkle_leaf_hash || 'L_i computed'}</td></tr>
                    <tr><td>Perceptual dHash</td><td class="text-mono tabular-nums">${data.perceptual_dhash || 'N/A'}</td></tr>
                    <tr><td>SHA-256 Binary Hash</td><td class="text-mono tabular-nums" style="font-size:0.7rem;">${data.file_hash}</td></tr>
                    <tr><td>Ledger Status</td><td><span class="status-indicator verified">Committed to Merkle Tree</span></td></tr>
                </table>
            </div>
        </div>

        <!-- 4-Layer Visual Analysis with Synchronized 3x Loupe -->
        <div class="glass-card mt-lg">
            <div class="card-header">
                <div class="icon orange">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>
                </div>
                <div>
                    <h2>4-Layer Visual Forensics (Synchronized 3x Loupe)</h2>
                    <p>Hover cursor over any quadrant to inspect synchronized pixel residuals at 3x magnification</p>
                </div>
            </div>
            <div class="loupe-grid" id="loupeGrid">
                <div class="loupe-card" data-layer="original">
                    <img src="${escapeHtml(previewImage.src)}" alt="Original" id="loupe-img-orig">
                    <div class="loupe-lens" id="loupe-lens-orig"></div>
                    <div class="loupe-label">1. Original Image</div>
                </div>
                <div class="loupe-card" data-layer="ela">
                    <img src="/static/${escapeHtml(data.ela_image_path)}" alt="ELA" id="loupe-img-ela">
                    <div class="loupe-lens" id="loupe-lens-ela"></div>
                    <div class="loupe-label">2. Error Level Analysis (ELA)</div>
                </div>
                <div class="loupe-card" data-layer="heatmap">
                    <img src="/static/${escapeHtml(data.heatmap_path)}" alt="Heatmap" id="loupe-img-heat">
                    <div class="loupe-lens" id="loupe-lens-heat"></div>
                    <div class="loupe-label">3. Suspicion Heatmap</div>
                </div>
                <div class="loupe-card" data-layer="saliency">
                    <img src="/static/${escapeHtml(data.saliency_map_path)}" alt="Saliency" id="loupe-img-sal">
                    <div class="loupe-lens" id="loupe-lens-sal"></div>
                    <div class="loupe-label">4. SRM / Neural Saliency Overlay</div>
                </div>
            </div>
        </div>

        <!-- Actions -->
        <div class="glass-card mt-lg text-center" style="padding:var(--space-lg);">
            <div style="display:flex; gap:12px; justify-content:center; flex-wrap:wrap;">
                <button class="btn btn-primary" onclick="showPage('sign')">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>
                    Sign &amp; Anchor This Image
                </button>
                <button class="btn btn-success" onclick="downloadCertificate(${data.id})">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
                    Download Analysis PDF
                </button>
                <button class="btn btn-ghost" onclick="viewImageDetail(${data.id})">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                    Full Forensic Report
                </button>
            </div>
        </div>
    `;

    container.classList.remove('hidden');
    container.classList.add('visible', 'active');
    container.style.display = 'block';

    // Trigger score animations
    requestAnimationFrame(() => {
        const ring = container.querySelector('.ring-progress');
        if (ring) ring.style.strokeDashoffset = ring.dataset.targetOffset;

        const scoreNum = container.querySelector('.score-number');
        if (scoreNum) animateNumber(scoreNum, 0, score, 1200);

        container.querySelectorAll('.score-bar-fill').forEach(bar => {
            setTimeout(() => { bar.style.width = bar.dataset.width + '%'; }, 200);
        });

        // Render HTML5 Canvas 2D FFT Radial Spectrum Chart
        if (data.frequencies && data.radial_bins) {
            renderFFTChart('fftChartCanvas', data.frequencies, data.radial_bins, data.spectral_slope || 2.0);
        }

        // Initialize Synchronized 3x Cursor Loupe
        initSynchronizedLoupe();
    });
}

// ═══════════════════════════════════════════════════════════
//  HTML5 CANVAS 32-BIN 2D FFT RADIAL SPECTRUM CHART
// ═══════════════════════════════════════════════════════════
function renderFFTChart(canvasId, frequencies, radialBins, spectralSlope) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const w = canvas.width;
    const h = canvas.height;

    ctx.clearRect(0, 0, w, h);

    const padLeft = 45;
    const padRight = 20;
    const padTop = 25;
    const padBottom = 35;
    const plotW = w - padLeft - padRight;
    const plotH = h - padTop - padBottom;

    // Background
    ctx.fillStyle = '#111113';
    ctx.fillRect(0, 0, w, h);

    // Find min and max log power
    let minP = -6.0;
    let maxP = 2.0;
    radialBins.forEach(b => {
        if (b > maxP) maxP = b;
        if (b < minP && b > -10) minP = b;
    });
    maxP += 0.5;
    minP -= 0.5;

    // Grid Lines
    ctx.strokeStyle = '#242429';
    ctx.lineWidth = 1;

    for (let i = 0; i <= 4; i++) {
        const y = padTop + (plotH / 4) * i;
        ctx.beginPath();
        ctx.moveTo(padLeft, y);
        ctx.lineTo(w - padRight, y);
        ctx.stroke();

        const pVal = (maxP - (i / 4) * (maxP - minP)).toFixed(1);
        ctx.fillStyle = '#71717A';
        ctx.font = '10px "JetBrains Mono", monospace';
        ctx.textAlign = 'right';
        ctx.fillText(pVal, padLeft - 6, y + 3);
    }

    // X Axis Labels (Frequencies)
    ctx.textAlign = 'center';
    for (let f = 0.0; f <= 1.0; f += 0.25) {
        const x = padLeft + f * plotW;
        ctx.beginPath();
        ctx.moveTo(x, padTop);
        ctx.lineTo(x, h - padBottom);
        ctx.stroke();
        ctx.fillText(f.toFixed(2), x, h - padBottom + 14);
    }

    ctx.fillText("Normalized Frequency (f)", padLeft + plotW / 2, h - 6);

    // Reference Line: Natural 1/f^2 Power Law (alpha = 2.0)
    ctx.strokeStyle = '#71717A';
    ctx.lineWidth = 1.5;
    ctx.setLineDash([4, 4]);
    ctx.beginPath();
    for (let i = 0; i < frequencies.length; i++) {
        const f = frequencies[i];
        const refP = maxP - 0.5 - 2.0 * Math.log10(1 + f * 9);
        const x = padLeft + (i / (frequencies.length - 1)) * plotW;
        const y = padTop + ((maxP - refP) / (maxP - minP)) * plotH;
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
    }
    ctx.stroke();
    ctx.setLineDash([]);

    // Measured Radial Power Curve
    ctx.strokeStyle = '#FAFAFA';
    ctx.lineWidth = 2;
    ctx.shadowBlur = 0;
    ctx.beginPath();

    for (let i = 0; i < radialBins.length; i++) {
        const p = radialBins[i];
        const x = padLeft + (i / (radialBins.length - 1)) * plotW;
        const y = padTop + Math.max(0, Math.min(plotH, ((maxP - p) / (maxP - minP)) * plotH));
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
    }
    ctx.stroke();

    // Points
    ctx.fillStyle = '#10B981';
    for (let i = 0; i < radialBins.length; i += 2) {
        const p = radialBins[i];
        const x = padLeft + (i / (radialBins.length - 1)) * plotW;
        const y = padTop + Math.max(0, Math.min(plotH, ((maxP - p) / (maxP - minP)) * plotH));
        ctx.beginPath();
        ctx.arc(x, y, 3, 0, Math.PI * 2);
        ctx.fill();
    }

    // Legend
    ctx.font = '10px "JetBrains Mono", monospace';
    ctx.fillStyle = '#FAFAFA';
    ctx.fillText("— Measured Spectrum", padLeft + 60, padTop + 14);
    ctx.fillStyle = '#71717A';
    ctx.fillText("--- 1/f² Optical Baseline (α=2.0)", padLeft + 200, padTop + 14);
}

// ═══════════════════════════════════════════════════════════
//  SYNCHRONIZED 3X CURSOR MAGNIFIER LOUPE
// ═══════════════════════════════════════════════════════════
function initSynchronizedLoupe() {
    const cards = document.querySelectorAll('#loupeGrid .loupe-card, .loupe-card');
    if (!cards || cards.length === 0) return;

    const layers = Array.from(cards).map(card => ({
        img: card.querySelector('img'),
        lens: card.querySelector('.loupe-lens')
    }));

    layers.forEach(l => {
        if (l.img && l.lens) {
            l.lens.style.backgroundImage = `url("${l.img.src}")`;
            l.lens.style.backgroundSize = `${l.img.offsetWidth * 3}px ${l.img.offsetHeight * 3}px`;
        }
    });

    cards.forEach(card => {
        card.addEventListener('mousemove', (e) => {
            const rect = card.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;

            const xRatio = Math.max(0, Math.min(1, x / rect.width));
            const yRatio = Math.max(0, Math.min(1, y / rect.height));

            layers.forEach(l => {
                if (!l.img || !l.lens) return;
                l.lens.style.display = 'block';
                const lensW = l.lens.offsetWidth || 80;
                const lensH = l.lens.offsetHeight || 80;

                const posX = xRatio * l.img.offsetWidth - lensW / 2;
                const posY = yRatio * l.img.offsetHeight - lensH / 2;

                l.lens.style.left = `${posX}px`;
                l.lens.style.top = `${posY}px`;

                const bgX = -(xRatio * l.img.offsetWidth * 3 - lensW / 2);
                const bgY = -(yRatio * l.img.offsetHeight * 3 - lensH / 2);

                l.lens.style.backgroundPosition = `${bgX}px ${bgY}px`;
                l.lens.style.backgroundSize = `${l.img.offsetWidth * 3}px ${l.img.offsetHeight * 3}px`;
            });
        });

        card.addEventListener('mouseleave', () => {
            layers.forEach(l => {
                if (l.lens) l.lens.style.display = 'none';
            });
        });
    });
}

// ═══════════════════════════════════════════════════════════
//  W3C WEBCRYPTO CLIENT SIGNING & SERVER KEYS
// ═══════════════════════════════════════════════════════════
function toggleSignMode() {
    const mode = document.getElementById('signModeSelect').value;
    const serverKeyGroup = document.getElementById('serverKeyGroup');
    const passphraseGroup = document.getElementById('passphraseGroup');
    const clientKeyGroup = document.getElementById('clientKeyGroup');

    if (mode === 'CLIENT_WEBCRYPTO') {
        serverKeyGroup.style.display = 'block';
        passphraseGroup.style.display = 'none';
        clientKeyGroup.style.display = 'block';
        updateClientKeyStatus().catch(error => showToast(error.message, 'error'));
    } else {
        serverKeyGroup.style.display = 'block';
        passphraseGroup.style.display = 'block';
        clientKeyGroup.style.display = 'none';
    }
    populateSigningKeys().catch(error => showToast(error.message, 'error'));
}

function toggleKeyGenMode() {
    const mode = document.getElementById('keyCustodyMode').value;
    const pGroup = document.getElementById('keyGenPassphraseGroup');
    if (pGroup) {
        pGroup.style.display = (mode === 'CLIENT_WEBCRYPTO') ? 'none' : 'block';
    }
}

async function populateSigningKeys() {
    const select = document.getElementById('signKeySelect');
    const current = select.value;
    const mode = document.getElementById('signModeSelect').value;
    const locals = mode === 'CLIENT_WEBCRYPTO' ? await localBrowserKeys() : {};
    const keys = state.keys.filter(key => key.custody_mode === mode && (mode !== 'CLIENT_WEBCRYPTO' || locals[key.key_id]));
    select.replaceChildren(new Option('-- Select your key --', ''));
    keys.forEach(key => select.add(new Option(key.owner_name + ' [' + mode + ']', key.key_id)));
    if (keys.some(key => key.key_id === current)) select.value = current;
    else if (keys.length === 1) select.value = keys[0].key_id;
}

async function updateClientKeyStatus() {
    const statusDiv = document.getElementById('clientKeyStatus');
    const keys = await localBrowserKeys();
    statusDiv.textContent = Object.keys(keys).length
        ? Object.keys(keys).length + ' local key(s) stored as non-exportable CryptoKeys in IndexedDB. Select a key above. Clearing browser data deletes them.'
        : 'No local browser key. Generate one in Key Manager.';
}

async function generateKeys() {
    const name = document.getElementById('keyOwnerName').value.trim();
    const email = document.getElementById('keyOwnerEmail').value.trim();
    const custodyMode = document.getElementById('keyCustodyMode').value;
    const passphrase = document.getElementById('keyPassphrase') ? document.getElementById('keyPassphrase').value : '';

    if (!name) {
        showToast('Owner name is required.', 'warning');
        return;
    }

    if (custodyMode === 'CLIENT_WEBCRYPTO') {
        // Generate RSA-PSS 2048 in browser via W3C WebCrypto SubtleCrypto
        showLoading('Generating local W3C WebCrypto key pair...', '2048-bit RSA-PSS in browser');
        try {
            const keyPair = await window.crypto.subtle.generateKey(
                {
                    name: "RSA-PSS",
                    modulusLength: 2048,
                    publicExponent: new Uint8Array([1, 0, 1]),
                    hash: "SHA-256"
                },
                false,
                ["sign", "verify"]
            );

            // Export public key to SPKI PEM
            const spki = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
            const spkiB64 = btoa(String.fromCharCode.apply(null, new Uint8Array(spki)));
            const publicPem = `-----BEGIN PUBLIC KEY-----\n${spkiB64.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----`;

            // The private CryptoKey is non-exportable and stored by structured clone.

            // Register key identity on server
            const formData = new FormData();
            formData.append('owner_name', name);
            formData.append('owner_email', email);
            formData.append('custody_mode', 'CLIENT_WEBCRYPTO');
            formData.append('public_key_pem', publicPem);

            const response = await fetch('/api/keys/generate', {
                method: 'POST',
                body: formData
            });
            const result = await response.json();
            hideLoading();

            if (result.status === 'success') {
                const keyId = result.data.key_id;
                await browserKeyStore.put({key_id: keyId, owner_name: name,
                    privateKey: keyPair.privateKey, public_pem: publicPem});

                showToast(`Non-custodial WebCrypto key pair generated for ${name}!`, 'success');
                await loadKeys();
                await updateClientKeyStatus();
            } else {
                showToast(result.detail || 'Key registration failed', 'error');
            }
        } catch (err) {
            hideLoading();
            showToast(`WebCrypto error: ${err.message}`, 'error');
        }
        return;
    }

    // Server-side envelope encryption
    showLoading('Generating envelope-encrypted RSA key pair...', 'AES-256-GCM AEAD encryption');
    try {
        const formData = new FormData();
        formData.append('owner_name', name);
        formData.append('owner_email', email);
        formData.append('custody_mode', 'SERVER_AES_GCM');
        formData.append('passphrase', passphrase);

        const response = await fetch('/api/keys/generate', {
            method: 'POST',
            body: formData,
        });

        const result = await response.json();
        hideLoading();

        if (result.status === 'success') {
            showToast(`Encrypted key pair generated for ${name}!`, 'success');
            document.getElementById('keyOwnerName').value = '';
            document.getElementById('keyOwnerEmail').value = '';
            loadKeys();
        } else {
            showToast(result.detail || 'Key generation failed', 'error');
        }
    } catch (err) {
        hideLoading();
        showToast(`Error: ${err.message}`, 'error');
    }
}

async function executeSign() {
    const imageId = document.getElementById('signImageSelect').value;
    if (!imageId) {
        showToast('Please select an image to sign.', 'warning');
        return;
    }

    const signMode = document.getElementById('signModeSelect').value;

    if (signMode === 'CLIENT_WEBCRYPTO') {
        const localKeys = await localBrowserKeys();
        const keyIds = Object.keys(localKeys);
        if (keyIds.length === 0) {
            showToast('No local WebCrypto key found. Generate one in Key Manager.', 'warning');
            return;
        }

        const activeKey = localKeys[document.getElementById('signKeySelect').value];
        if (!activeKey) { showToast('Select a local browser key.', 'warning'); return; }
        showLoading('Signing locally with W3C WebCrypto...', 'Private key never leaves browser');

        try {
            const privateKey = activeKey.privateKey;

            // Fetch image binary to compute SHA-256
            const imgRecord = state.images.find(i => i.id == imageId);
            const imgRes = await fetch(`/static/uploads/${imgRecord.filename}`);
            const imgBytes = await imgRes.arrayBuffer();

            // Hash image with SHA-256
            const hashBuffer = await window.crypto.subtle.digest("SHA-256", imgBytes);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

            // Sign the hash hex string as bytes (matching backend convention)
            const enc = new TextEncoder();
            const dataToSign = enc.encode(hashHex);

            const signatureBuffer = await window.crypto.subtle.sign(
                { name: "RSA-PSS", saltLength: 32 },
                privateKey,
                dataToSign
            );

            const signatureB64 = btoa(String.fromCharCode.apply(null, new Uint8Array(signatureBuffer)));

            // Post client signature to server
            const formData = new FormData();
            formData.append('signature_b64', signatureB64);
            formData.append('public_key_pem', activeKey.public_pem);
            formData.append('signer_name', activeKey.owner_name);
            formData.append('key_id', activeKey.key_id);

            const signResponse = await fetch(`/api/sign-client/${imageId}`, {
                method: 'POST',
                body: formData
            });
            const signResult = await signResponse.json();
            hideLoading();

            if (signResult.status === 'success') {
                showToast(`Signed locally with W3C WebCrypto! Merkle root updated.`, 'success');
                loadSignData();
            } else {
                showToast(signResult.detail || 'Signing failed', 'error');
            }
        } catch (err) {
            hideLoading();
            showToast(`Client signing error: ${err.message}`, 'error');
        }
        return;
    }

    // Server-side envelope signing
    const keyId = document.getElementById('signKeySelect').value;
    const passphrase = document.getElementById('signPassphrase').value;
    if (!keyId) {
        showToast('Please select your key.', 'warning');
        return;
    }

    showLoading('Signing with envelope-encrypted key...', 'Preparing and signing a derivative; retaining the original');

    try {
        const formData = new FormData();
        formData.append('key_id', keyId);
        formData.append('passphrase', passphrase);

        const response = await fetch(`/api/sign/${imageId}`, {
            method: 'POST',
            body: formData,
        });

        const result = await response.json();
        hideLoading();

        if (result.status === 'success') {
            showToast(`Image signed by ${result.data.signer}. Original retained; analysis metadata is unverified.`, 'success');
            loadSignData();
        } else {
            showToast(result.detail || 'Signing failed', 'error');
        }
    } catch (err) {
        hideLoading();
        showToast(`Error: ${err.message}`, 'error');
    }
}

// ═══════════════════════════════════════════════════════════
//  SOFT-BINDING PROVENANCE RECOVERY
// ═══════════════════════════════════════════════════════════
const recoverZone = document.getElementById('recoverUploadZone');
const recoverInput = document.getElementById('recoverFileInput');

if (recoverZone && recoverInput) {
    recoverZone.addEventListener('click', (e) => {
        if (e.target !== recoverInput) {
            recoverInput.click();
        }
    });

    recoverInput.addEventListener('click', (e) => {
        e.stopPropagation();
    });

    recoverZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        recoverZone.classList.add('dragover');
    });

    recoverZone.addEventListener('dragleave', () => {
        recoverZone.classList.remove('dragover');
    });

    recoverZone.addEventListener('drop', (e) => {
        e.preventDefault();
        recoverZone.classList.remove('dragover');
        const files = e.dataTransfer ? e.dataTransfer.files : null;
        if (files && files.length > 0) executeRecoverProvenance(files[0]);
    });
}

if (recoverInput) {
    recoverInput.addEventListener('change', (e) => {
        if (e.target && e.target.files && e.target.files.length > 0) {
            executeRecoverProvenance(e.target.files[0]);
        }
    });
}

async function executeRecoverProvenance(file) {
    if (!file) return;

    showLoading('Recovering provenance...', 'Extracting 64-bit invisible frequency watermark and perceptual dHash');

    const formData = new FormData();
    formData.append('file', file);

    try {
        const response = await fetch('/api/recover-provenance', {
            method: 'POST',
            body: formData,
        });

        const result = await response.json();
        hideLoading();
        if (recoverInput) recoverInput.value = '';

        const resultDiv = document.getElementById('recoverResult');
        if (resultDiv) {
            resultDiv.classList.remove('hidden');
            resultDiv.classList.add('visible', 'active');
            resultDiv.style.display = 'block';
        }

        if (result.status === 'success') {
            const d = result.data;
            resultDiv.innerHTML = `
                <div class="glass-card" style="border-left:4px solid var(--success-500); padding:var(--space-lg);">
                    <div class="flex-between mb-md">
                        <span class="status-indicator verified">Provenance Recovered ✓</span>
                        <span class="text-mono" style="font-size:0.8rem;">Hamming Distance d_H: ${d.hamming_distance}</span>
                    </div>
                    <table class="metadata-table">
                        <tr><th>Master Record ID</th><td>#${d.recovered_master_id} (${escapeHtml(d.original_filename)})</td></tr>
                        <tr><th>Registered Signer</th><td><strong>${escapeHtml(d.signer_name)}</strong></td></tr>
                        <tr><th>Signed Date</th><td>${formatDate(d.signed_date)}</td></tr>
                        <tr><th>Watermark Found</th><td>${d.watermark_recovered ? '✅ 64-bit Frequency Watermark Decoded' : '⚠️ Recovered via dHash Match (dH ≤ 10)'}</td></tr>
                        <tr><th>Post-Signing Tamper Status</th><td>${d.tamper_detected ? `⚠️ Localized Alteration Detected (${d.pixel_change_percentage}% pixels changed)` : '✅ No differences above the selected threshold'}</td></tr>
                    </table>

                    ${d.diff_overlay_url ? `
                        <div class="mt-md">
                            <label class="form-label">Post-Signing Tamper Localization (JET Colormap Diff Overlay)</label>
                            <img src="${escapeHtml(d.diff_overlay_url)}" alt="Diff Overlay" style="width:100%; max-height:260px; object-fit:contain; border-radius:var(--radius-md); border:1px solid var(--surface-600); background:#000;">
                        </div>
                    ` : ''}
                </div>
            `;
            showToast('Candidate original found; provenance is not verified.', 'success');
        } else {
            resultDiv.innerHTML = `
                <div class="glass-card" style="border-left:4px solid var(--danger-500); padding:var(--space-md);">
                    <span class="status-indicator failed">Recovery Failed</span>
                    <p style="font-size:0.85rem; color:var(--surface-300); margin-top:var(--space-sm);">${escapeHtml(result.detail)}</p>
                </div>
            `;
            showToast('No matching provenance record found', 'error');
        }
    } catch (err) {
        hideLoading();
        showToast(`Error: ${err.message}`, 'error');
    }
}

// ═══════════════════════════════════════════════════════════
//  ADVERSARIAL ATTACK SIMULATOR
// ═══════════════════════════════════════════════════════════
async function runAttackSimulator(imageId, containerId = 'attackSimulatorContainer') {
    showLoading('Simulating adversarial attack regimes...', 'Executing WhatsApp strip, color shift, and pixel splice perturbations');

    try {
        const response = await fetch(`/api/simulate-attack/${imageId}`, {
            method: 'POST'
        });
        const result = await response.json();
        hideLoading();

        if (result.status === 'success') {
            renderAttackSimulatorResults(result.data, containerId);
            showToast('Attack simulation complete!', 'success');
        } else {
            showToast(result.detail || 'Simulation failed', 'error');
        }
    } catch (err) {
        hideLoading();
        showToast(`Error: ${err.message}`, 'error');
    }
}

function renderAttackSimulatorResults(data, containerId = 'attackSimulatorContainer') {
    let container = document.getElementById(containerId);
    if (!container) {
        container = document.getElementById('attackSimulatorContainer');
    }
    if (!container) return;

    const attacks = data.attacks;

    container.innerHTML = `
        <div class="attack-grid">
            <!-- 1. WhatsApp Recompression -->
            <div class="attack-card">
                <h4>1. WhatsApp Re-Compression & Strip</h4>
                <p>EXIF/JUMBF metadata stripped, JPEG Quality Factor 70</p>
                <div class="attack-images">
                    <img src="${escapeHtml(attacks.whatsapp_compress.attacked_image_url)}" alt="Attacked">
                </div>
                <div class="binding-row">
                    <span>Hard Binding (SHA-256):</span>
                    <span class="binding-badge ${attacks.whatsapp_compress.hard_binding_valid ? 'survived' : 'broken'}">
                        ${attacks.whatsapp_compress.hard_binding_valid ? 'VALID ✓' : 'BROKEN ❌'}
                    </span>
                </div>
                <div class="binding-row">
                    <span>Soft Binding (Watermark + dHash):</span>
                    <span class="binding-badge ${attacks.whatsapp_compress.soft_binding_recovered ? 'survived' : 'broken'}">
                        ${attacks.whatsapp_compress.soft_binding_recovered ? 'SURVIVED ✓' : 'FAILED ❌'}
                    </span>
                </div>
                <div class="binding-row">
                    <span>Hamming Distance:</span>
                    <span class="text-mono">${attacks.whatsapp_compress.hamming_distance}</span>
                </div>
            </div>

            <!-- 2. Color Shift -->
            <div class="attack-card">
                <h4>2. Color & Luminance Shift</h4>
                <p>Contrast & gamma perturbation</p>
                <div class="attack-images">
                    <img src="${escapeHtml(attacks.color_shift.attacked_image_url)}" alt="Color Shift">
                </div>
                <div class="binding-row">
                    <span>Hard Binding (SHA-256):</span>
                    <span class="binding-badge ${attacks.color_shift.hard_binding_valid ? 'survived' : 'broken'}">
                        ${attacks.color_shift.hard_binding_valid ? 'VALID ✓' : 'BROKEN ❌'}
                    </span>
                </div>
                <div class="binding-row">
                    <span>Soft Binding (Watermark + dHash):</span>
                    <span class="binding-badge ${attacks.color_shift.soft_binding_recovered ? 'survived' : 'broken'}">
                        ${attacks.color_shift.soft_binding_recovered ? 'SURVIVED ✓' : 'FAILED ❌'}
                    </span>
                </div>
                <div class="binding-row">
                    <span>Hamming Distance:</span>
                    <span class="text-mono">${attacks.color_shift.hamming_distance}</span>
                </div>
            </div>

            <!-- 3. Pixel Splice -->
            <div class="attack-card">
                <h4>3. Localized Synthetic Patch Splice</h4>
                <p>Injects artificial patch into pixels</p>
                <div class="attack-images">
                    <img src="${escapeHtml(attacks.pixel_splice.attacked_image_url)}" alt="Spliced" title="Attacked Spliced Image">
                    <img src="${escapeHtml(attacks.pixel_splice.diff_overlay_url)}" alt="Diff Overlay" title="JET Colormap Tamper Diff">
                </div>
                <div class="binding-row">
                    <span>Hard Binding (SHA-256):</span>
                    <span class="binding-badge ${attacks.pixel_splice.hard_binding_valid ? 'survived' : 'broken'}">
                        ${attacks.pixel_splice.hard_binding_valid ? 'VALID ✓' : 'BROKEN ❌'}
                    </span>
                </div>
                <div class="binding-row">
                    <span>Candidate Match:</span>
                    <span class="binding-badge ${attacks.pixel_splice.soft_binding_recovered ? 'survived' : 'broken'}">
                        ${attacks.pixel_splice.soft_binding_recovered ? 'SURVIVED ✓' : 'FAILED ❌'}
                    </span>
                </div>
                <div class="binding-row">
                    <span>Tamper Localization:</span>
                    <span style="color:var(--danger-400); font-weight:700;">${attacks.pixel_splice.pixel_change_percentage}% Isolated</span>
                </div>
            </div>
        </div>
    `;
}

// ═══════════════════════════════════════════════════════════
//  DATA LOADERS (DASHBOARD, SIGN, KEYS)
// ═══════════════════════════════════════════════════════════
async function loadSignData() {
    try {
        const [imagesRes, keysRes] = await Promise.all([
            fetch('/api/images'),
            fetch('/api/keys')
        ]);

        const imagesData = await imagesRes.json();
        const keysData = await keysRes.json();

        state.images = imagesData.data || [];
        state.keys = keysData.data || [];

        const signImageSelect = document.getElementById('signImageSelect');
        const signKeySelect = document.getElementById('signKeySelect');
        const verifyImageSelect = document.getElementById('verifyImageSelect');

        signImageSelect.innerHTML = '<option value="">-- Select an analyzed image --</option>' +
            state.images.filter(i => !i.is_signed).map(i => {
                let v = 'Authentic Media';
                try {
                    const fd = typeof i.forgery_details === 'string' ? JSON.parse(i.forgery_details) : (i.forgery_details || {});
                    const aiP = (i.ai_generation_prob || 0) * (i.ai_generation_prob <= 1.0 ? 100 : 1);
                    v = fd.verdict || (i.is_authentic ? 'Authentic Media' : (aiP >= 55 ? 'AI-Generated / Synthetic Media' : 'Manipulated / Spliced Forgery'));
                } catch (e) {
                    v = i.is_authentic ? 'Authentic Media' : 'Potentially Forged';
                }
                return `<option value="${i.id}">${escapeHtml(i.original_filename)} [${i.authenticity_score}% • ${escapeHtml(v)}]</option>`;
            }).join('');

        await populateSigningKeys();

        verifyImageSelect.innerHTML = '<option value="">-- Select a signed image --</option>' +
            state.images.filter(i => i.is_signed).map(i =>
                `<option value="${i.id}">${escapeHtml(i.original_filename)} — signed by ${escapeHtml(i.signer_name)}</option>`
            ).join('');

        await updateClientKeyStatus();
    } catch (err) {
        showToast(`Failed to load data: ${err.message}`, 'error');
    }
}

async function verifySignature() {
    const imageId = document.getElementById('verifyImageSelect').value;
    if (!imageId) {
        showToast('Please select a signed image.', 'warning');
        return;
    }

    showLoading('Verifying signature...', 'Checking Dual-Mode RSA-PSS signature');

    try {
        const response = await fetch(`/api/verify-signature/${imageId}`, {
            method: 'POST',
        });

        const result = await response.json();
        hideLoading();

        if (result.status === 'success') {
            const v = result.data;
            const resultDiv = document.getElementById('verificationResult');
            resultDiv.style.display = 'block';

            resultDiv.innerHTML = `
                <div class="glass-card" style="border-color: ${v.is_valid ? 'rgba(34,197,94,0.3)' : 'rgba(239,68,68,0.3)'}; padding:var(--space-md);">
                    <div class="verdict-badge ${v.is_valid ? 'authentic' : 'forged'}" style="margin-bottom:var(--space-md);">
                        ${v.is_valid ? '✅ VALID SIGNATURE' : '❌ INVALID SIGNATURE'}
                    </div>
                    <p style="font-size:0.85rem; color:var(--surface-300); margin-bottom:var(--space-sm);">
                        ${escapeHtml(v.message)}
                    </p>
                    <table class="metadata-table">
                        <tr><th>Signer</th><td>${escapeHtml(v.signer)}</td></tr>
                        <tr><th>Verification Mode</th><td>${escapeHtml(v.pss_mode)}</td></tr>
                        <tr><th>Integrity</th><td>${escapeHtml(v.integrity)}</td></tr>
                        <tr><th>Current Hash</th><td class="text-mono" style="font-size:0.7rem;">${v.current_hash}</td></tr>
                    </table>
                    ${v.is_valid ? `
                    <div class="mt-md" style="border-top:1px solid var(--border-color); padding-top:var(--space-md);">
                        <button class="btn btn-ghost btn-sm" onclick="runAttackSimulator(${imageId}, 'signAttackSimulatorContainer')">⚔️ Test Adversarial Attack Regimes on this Image</button>
                        <div id="signAttackSimulatorContainer" class="mt-md"></div>
                    </div>
                    ` : ''}
                </div>
            `;

            showToast(v.is_valid ? 'Signature verified successfully!' : 'Signature invalid!', v.is_valid ? 'success' : 'error');
        }
    } catch (err) {
        hideLoading();
        showToast(`Error: ${err.message}`, 'error');
    }
}

async function loadKeys() {
    try {
        const response = await fetch('/api/keys');
        const result = await response.json();
        state.keys = result.data || [];
        renderKeysList(state.keys);
    } catch (err) {
        showToast(`Failed to load keys: ${err.message}`, 'error');
    }
}

function renderKeysList(keys) {
    const container = document.getElementById('keysList');
    if (keys.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">
                    <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6"/><path d="m15.5 7.5 3 3L22 7l-3-3"/></svg>
                </div>
                <h3>No keys registered</h3>
                <p>Generate your first RSA key pair to begin signing images.</p>
            </div>
        `;
        return;
    }

    container.innerHTML = keys.map(k => `
        <div class="key-card">
            <div class="key-info">
                <div class="key-icon">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6"/><path d="m15.5 7.5 3 3L22 7l-3-3"/></svg>
                </div>
                <div>
                    <div class="key-name">${escapeHtml(k.owner_name)}</div>
                    <div class="key-id text-mono">${escapeHtml(k.key_id)} · ${escapeHtml(k.custody_mode || 'SERVER_AES_GCM')}</div>
                </div>
            </div>
            <div>
                <span class="status-indicator ${k.custody_mode === 'CLIENT_WEBCRYPTO' ? 'unverified' : 'verified'}">
                    ${k.custody_mode === 'CLIENT_WEBCRYPTO' ? 'Client WebCrypto' : 'Envelope Encrypted'}
                </span>
            </div>
        </div>
    `).join('');
}

async function loadDashboard() {
    try {
        const [statsRes, imagesRes] = await Promise.all([
            fetch('/api/stats'),
            fetch('/api/images')
        ]);

        const statsData = await statsRes.json();
        const imagesData = await imagesRes.json();

        const stats = statsData.data || {};
        state.images = imagesData.data || [];

        renderStats(stats);
        renderGallery(state.images);

        const mRootEl = document.getElementById('dashboardMerkleRoot');
        if (mRootEl) mRootEl.textContent = stats.merkle_root || 'GENESIS';
        const tSizeEl = document.getElementById('dashboardTreeSize');
        if (tSizeEl) tSizeEl.textContent = `${stats.merkle_tree_size || 0} Records`;
    } catch (err) {
        showToast(`Dashboard load failed: ${err.message}`, 'error');
    }
}

function renderStats(stats) {
    const grid = document.getElementById('statsGrid');
    grid.innerHTML = `
        <div class="stat-card">
            <div class="stat-icon">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>
            </div>
            <div class="stat-value tabular-nums">${stats.total_images || 0}</div>
            <div class="stat-label">Total Images</div>
        </div>
        <div class="stat-card">
            <div class="stat-icon" style="color:var(--success-400)">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
            </div>
            <div class="stat-value tabular-nums" style="color:var(--success-400)">${stats.authentic_count || 0}</div>
            <div class="stat-label">Authentic</div>
        </div>
        <div class="stat-card">
            <div class="stat-icon" style="color:var(--danger-400)">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
            </div>
            <div class="stat-value tabular-nums" style="color:var(--danger-400)">${stats.forged_count || 0}</div>
            <div class="stat-label">Suspicious</div>
        </div>
        <div class="stat-card">
            <div class="stat-icon" style="color:var(--accent-400)">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>
            </div>
            <div class="stat-value tabular-nums" style="color:var(--accent-400)">${stats.signed_count || 0}</div>
            <div class="stat-label">Signed</div>
        </div>
        <div class="stat-card">
            <div class="stat-icon">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>
            </div>
            <div class="stat-value tabular-nums">${stats.avg_authenticity || 0}%</div>
            <div class="stat-label">Avg Authenticity</div>
        </div>
    `;
}

function renderGallery(images) {
    const grid = document.getElementById('galleryGrid');

    if (images.length === 0) {
        grid.innerHTML = `
            <div class="empty-state" style="grid-column: 1/-1;">
                <div class="empty-icon">
                    <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>
                </div>
                <h3>No images analyzed yet</h3>
                <p>Upload and analyze an image to view it in the transparency ledger.</p>
                <button class="btn btn-primary mt-md" onclick="showPage('analyze')">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                    Analyze Image
                </button>
            </div>
        `;
        return;
    }

    grid.innerHTML = images.map(img => `
        <div class="gallery-card" onclick="viewImageDetail(${img.id})">
            <img class="card-image" src="/static/uploads/${escapeHtml(img.filename)}" alt="${escapeHtml(img.original_filename)}"
                 onerror="this.src='data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 width=%22300%22 height=%22180%22 fill=%22%231e293b%22><rect width=%22300%22 height=%22180%22/><text x=%2250%25%22 y=%2250%25%22 text-anchor=%22middle%22 fill=%22%23475569%22 font-size=%2214%22>Image</text></svg>'">
            <div class="card-body">
                <div class="card-title">${escapeHtml(img.original_filename)}</div>
                <div class="card-meta">${formatDate(img.upload_date)} · ${formatSize(img.file_size)}</div>
                <div class="card-footer">
                    <div class="mini-score">
                        <div class="dot ${img.is_authentic ? 'authentic' : 'forged'}"></div>
                        <span style="color:${img.is_authentic ? 'var(--success-400)' : 'var(--danger-400)'}">${img.authenticity_score}%</span>
                    </div>
                    ${img.is_signed ? '<span class="signed-badge">✍️ Signed</span>' : ''}
                </div>
            </div>
        </div>
    `).join('');
}

// ═══════════════════════════════════════════════════════════
//  DETAIL VIEW
// ═══════════════════════════════════════════════════════════
async function viewImageDetail(imageId) {
    showLoading('Loading forensic report and Merkle proofs...');

    try {
        const response = await fetch(`/api/images/${imageId}`);
        const result = await response.json();
        hideLoading();

        if (result.status === 'success') {
            renderDetailView(result.data);
            showPage('detail');
        }
    } catch (err) {
        hideLoading();
        showToast(`Failed to load: ${err.message}`, 'error');
    }
}

function renderDetailView(data) {
    const container = document.getElementById('detailContent');
    const isAuthentic = data.is_authentic;
    const score = data.authenticity_score;
    const circumference = 2 * Math.PI * 65;
    const offset = circumference - (score / 100) * circumference;

    let metadataParsed = data.metadata_parsed || {};
    let metadataAnalysis = metadataParsed.analysis || {};
    let c2paParsed = data.c2pa_parsed || {};

    let detailVerdict = isAuthentic ? 'Authentic Media' : 'Potentially Forged / Synthetic';
    let parsedDetails = {};
    try {
        parsedDetails = typeof data.forgery_details === 'string' ? JSON.parse(data.forgery_details) : (data.forgery_details || {});
        detailVerdict = parsedDetails.verdict || (isAuthentic ? 'Authentic Media' : (((data.ai_generation_prob || 0) * (data.ai_generation_prob <= 1.0 ? 100 : 1)) >= 55 ? 'AI-Generated / Synthetic Media' : 'Manipulated / Spliced Forgery'));
    } catch (e) {
        parsedDetails = {};
        detailVerdict = isAuthentic ? 'Authentic Media' : 'Potentially Forged';
    }

    const gates = parsedDetails.gates || {};
    const aiP = (data.ai_generation_prob || 0) * (data.ai_generation_prob <= 1.0 ? 100 : 1);
    const tamperScore = typeof gates.tamper_integrity_score === 'number'
        ? gates.tamper_integrity_score
        : parseFloat((0.55 * (data.ela_score || 0) + 0.45 * (data.noise_score || 0)).toFixed(1));
    const originScore = typeof gates.origin_integrity_score === 'number'
        ? gates.origin_integrity_score
        : parseFloat((0.70 * (100 - aiP) + 0.30 * (data.fft_score || 0)).toFixed(1));

    container.innerHTML = `
        <div class="detail-header">
            <button class="back-btn" onclick="showPage('dashboard')">←</button>
            <div>
                <h1 style="font-size:1.25rem; font-weight:700; color:var(--surface-50);">${escapeHtml(data.original_filename)}</h1>
                <p style="font-size:0.8rem; color:var(--surface-400);">Analyzed ${formatDate(data.upload_date)} · ID #${data.id}</p>
            </div>
        </div>

        <div class="detail-actions">
            <button class="btn btn-primary btn-sm" onclick="showPage('sign')">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>
                Sign &amp; Anchor
            </button>
            <button class="btn btn-success btn-sm" onclick="downloadCertificate(${data.id})">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
                Download Analysis PDF
            </button>
            <button class="btn btn-danger btn-sm" onclick="deleteImage(${data.id})">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                Delete
            </button>
        </div>

        <!-- Tabs -->
        <div class="tabs">
            <button class="tab-btn active" onclick="switchTab(this, 'tab-overview')">Overview</button>
            <button class="tab-btn" onclick="switchTab(this, 'tab-visual')">4-Layer Visual Loupe</button>
            <button class="tab-btn" onclick="switchTab(this, 'tab-merkle')">Audit &amp; Metadata</button>
            <button class="tab-btn" onclick="switchTab(this, 'tab-attacks')">Adversarial Simulator</button>
            <button class="tab-btn" onclick="switchTab(this, 'tab-metadata')">Metadata</button>
        </div>

        <!-- Tab: Overview -->
        <div id="tab-overview" class="tab-content active">
            <div class="results-grid">
                <div class="glass-card">
                    <div class="score-ring-container">
                        <div class="score-ring">
                            <svg viewBox="0 0 140 140">
                                <circle class="ring-bg" cx="70" cy="70" r="65"/>
                                <circle class="ring-progress ${isAuthentic ? 'authentic' : 'forged'}"
                                    cx="70" cy="70" r="65"
                                    stroke-dasharray="${circumference}"
                                    stroke-dashoffset="${offset}"/>
                            </svg>
                            <div class="score-value">
                                <span class="score-number tabular-nums" style="color: ${isAuthentic ? 'var(--success-400)' : 'var(--danger-400)'}">${score}</span>
                                <span class="score-label">Analysis score</span>
                            </div>
                        </div>
                        ${getVerdictBadge(detailVerdict)}
                    </div>
                </div>

                <div class="glass-card">
                    <div class="card-header">
                        <div class="icon blue">
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>
                        </div>
                        <div><h2>Forensic Metrics</h2></div>
                    </div>
                    <div class="score-bar-item">
                        <div class="score-bar-header"><span>ELA Score</span><span class="tabular-nums">${data.ela_score}%</span></div>
                        <div class="score-bar-track"><div class="score-bar-fill ${getScoreClass(data.ela_score)}" style="width:${data.ela_score}%"></div></div>
                    </div>
                    <div class="score-bar-item">
                        <div class="score-bar-header"><span>SRM Steganalysis Noise</span><span class="tabular-nums">${data.noise_score}%</span></div>
                        <div class="score-bar-track"><div class="score-bar-fill ${getScoreClass(data.noise_score)}" style="width:${data.noise_score}%"></div></div>
                    </div>
                    <div class="score-bar-item">
                        <div class="score-bar-header"><span>2D FFT Radial Spectrum</span><span class="tabular-nums">${data.fft_score}%</span></div>
                        <div class="score-bar-track"><div class="score-bar-fill ${getScoreClass(data.fft_score)}" style="width:${data.fft_score}%"></div></div>
                    </div>
                    <div class="score-bar-item">
                        <div class="score-bar-header"><span>Synthetic Signal (uncalibrated)</span><span class="tabular-nums">${aiP.toFixed(1)}%</span></div>
                        <div class="score-bar-track"><div class="score-bar-fill ${aiP > 50 ? 'low' : 'high'}" style="width:${100 - aiP}%"></div></div>
                    </div>
                </div>
            </div>

            <!-- Two-Gate Veto Diagnostic Matrix -->
            ${renderTwoGateCard(tamperScore, originScore, aiP)}

            <!-- Forensic Telemetry Grid -->
            <div class="glass-card mt-lg">
                <div class="card-header">
                    <div class="icon blue">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>
                    </div>
                    <div>
                        <h2>Forensic Telemetry &amp; Physical Observables</h2>
                        <p>Low-level sensor, spectral, and neural classifier telemetry</p>
                    </div>
                </div>
                <div class="telemetry-grid">
                    <div class="telemetry-item">
                        <div class="telemetry-label">Synthetic signal (uncalibrated)</div>
                        <div class="telemetry-val tabular-nums">${(aiP / 100).toFixed(4)}</div>
                        <div class="telemetry-sub">${aiP >= 55 ? 'Higher synthetic signal' : 'Lower synthetic signal'}</div>
                    </div>
                    <div class="telemetry-item">
                        <div class="telemetry-label">Flat-Patch Residual</div>
                        <div class="telemetry-val tabular-nums">σ = ${escapeHtml(parsedDetails?.ai_neural?.flat_residual_std ?? 'unavailable')}</div>
                        <div class="telemetry-sub">Noise proxy, not a camera fingerprint</div>
                    </div>
                    <div class="telemetry-item">
                        <div class="telemetry-label">2D FFT Slope (α)</div>
                        <div class="telemetry-val tabular-nums">α = ${escapeHtml(parsedDetails?.fft?.spectral_slope ?? 'unavailable')}</div>
                        <div class="telemetry-sub">Frequency-decay proxy; not origin evidence</div>
                    </div>
                    <div class="telemetry-item">
                        <div class="telemetry-label">Perceptual dHash</div>
                        <div class="telemetry-val tabular-nums text-mono">${data.perceptual_dhash || 'N/A'}</div>
                        <div class="telemetry-sub">64-bit Difference Hash</div>
                    </div>
                    <div class="telemetry-item full-width">
                        <div class="telemetry-label">Analysis Backend</div>
                        <div class="telemetry-val">${parsedDetails.ai_neural?.onnx_used ? 'ONNX neural inference with heuristic fusion' : 'Heuristic fallback'}</div>
                        <div class="telemetry-sub">Scores are uncalibrated; model availability is recorded with this analysis</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Tab: 4-Layer Visual Loupe -->
        <div id="tab-visual" class="tab-content">
            <div class="glass-card">
                <div class="card-header">
                    <div class="icon orange">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                    </div>
                    <div>
                        <h2>Synchronized 3x Cursor Loupe</h2>
                        <p>Hover cursor over any visual layer to inspect synchronized micro-residuals</p>
                    </div>
                </div>
                <div class="loupe-grid">
                    <div class="loupe-card" data-layer="original">
                        <img src="${data.original_file_hash ? '/api/images/' + data.id + '/original' : '/static/uploads/' + escapeHtml(data.filename)}" alt="Original" id="detail-loupe-orig">
                        <div class="loupe-lens" id="detail-lens-orig"></div>
                        <div class="loupe-label">1. Original Image</div>
                    </div>
                    <div class="loupe-card" data-layer="ela">
                        <img src="/static/${escapeHtml(data.ela_image_path)}" alt="ELA" id="detail-loupe-ela">
                        <div class="loupe-lens" id="detail-lens-ela"></div>
                        <div class="loupe-label">2. Error Level Analysis (ELA)</div>
                    </div>
                    <div class="loupe-card" data-layer="heatmap">
                        <img src="/static/${escapeHtml(data.heatmap_path)}" alt="Heatmap" id="detail-loupe-heat">
                        <div class="loupe-lens" id="detail-lens-heat"></div>
                        <div class="loupe-label">3. Suspicion Heatmap</div>
                    </div>
                    <div class="loupe-card" data-layer="saliency">
                        <img src="/static/${escapeHtml(data.saliency_map_path)}" alt="Saliency" id="detail-loupe-sal">
                        <div class="loupe-lens" id="detail-lens-sal"></div>
                        <div class="loupe-label">4. SRM / Neural Saliency Overlay</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Tab: Merkle & C2PA Ledger -->
        <div id="tab-merkle" class="tab-content">
            <div class="glass-card">
                <div class="card-header">
                    <div class="icon green">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22v-7"/><path d="M9 9a3 3 0 0 1 6 0c0 2-3 3-3 6"/><circle cx="12" cy="6" r="3"/></svg>
                    </div>
                    <div><h2>Signed Local Audit Checkpoint</h2></div>
                </div>
                <table class="metadata-table">
                    <tr><th>Active Merkle Root</th><td class="text-mono tabular-nums" style="font-size:0.75rem;">${data.merkle_root || 'Calculated at Checkpoint'}</td></tr>
                    <tr><th>Record Leaf Digest (L_i)</th><td class="text-mono tabular-nums" style="font-size:0.75rem;">${data.merkle_leaf_hash || 'L_i'}</td></tr>
                    <tr><th>Merkle Inclusion Proof</th><td><span class="status-indicator ${data.merkle_verified ? 'verified' : 'unverified'}">${data.merkle_verified ? 'VERIFIED INCLUSION PROOF ✓' : 'UNVERIFIED / PENDING CHECKPOINT'}</span></td></tr>
                    <tr><th>Timestamp status</th><td>${escapeHtml(JSON.parse(data.timestamp_info || '{}').status || 'not_requested')} (no trusted timestamp validation)</td></tr>
                    <tr><th>Provenance status</th><td>${escapeHtml(data.provenance_status || 'unverified_metadata')}</td></tr>
                    <tr><th>Perceptual dHash</th><td class="text-mono tabular-nums">${data.perceptual_dhash || 'N/A'}</td></tr>
                    <tr><th>Watermark Status</th><td>${data.watermark_embedded ? '64-bit Frequency Watermark Embedded' : 'Unwatermarked Master'}</td></tr>
                </table>

                ${data.c2pa_parsed && data.c2pa_parsed.assertions ? `
                    <h3 style="font-size:0.95rem; font-weight:700; color:var(--surface-100); margin-top:var(--space-lg); margin-bottom:var(--space-sm);">Unverified Analysis Metadata</h3>
                    <pre style="background:var(--surface-900); padding:var(--space-md); border-radius:var(--radius-sm); font-size:0.75rem; color:var(--primary-300); overflow-x:auto;">${escapeHtml(JSON.stringify(data.c2pa_parsed, null, 2))}</pre>
                ` : ''}
            </div>
        </div>

        <!-- Tab: Adversarial Attack Simulator -->
        <div id="tab-attacks" class="tab-content">
            <div class="glass-card">
                <div class="card-header">
                    <div class="icon violet">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
                    </div>
                    <div>
                        <h2>Adversarial Attack Simulation Workbench</h2>
                        <p>Stress-test hard-binding vs. soft-binding survivability across WhatsApp recompression, color shift, and pixel splicing</p>
                    </div>
                </div>
                <button class="btn btn-primary" onclick="runAttackSimulator(${data.id})">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
                    Run 3-Branch Attack Simulation
                </button>
                <div id="attackSimulatorContainer" class="mt-md"></div>
            </div>
        </div>

        <!-- Tab: Metadata -->
        <div id="tab-metadata" class="tab-content">
            <div class="glass-card">
                <div class="card-header">
                    <div class="icon green">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                    </div>
                    <div><h2>EXIF &amp; C2PA Metadata</h2></div>
                </div>
                ${renderMetadataFindings(metadataAnalysis)}
                ${renderMetadataTable(metadataParsed)}
            </div>
        </div>
    `;

    setTimeout(() => {
        initDetailLoupe();
    }, 200);
}

function initDetailLoupe() {
    const cards = document.querySelectorAll('#tab-visual .loupe-card, .loupe-card');
    if (!cards || cards.length === 0) return;

    const layers = Array.from(cards).map(card => ({
        img: card.querySelector('img'),
        lens: card.querySelector('.loupe-lens')
    }));

    layers.forEach(l => {
        if (l.img && l.lens) {
            l.lens.style.backgroundImage = `url("${l.img.src}")`;
        }
    });

    document.querySelectorAll('#tab-visual .loupe-card').forEach(card => {
        card.addEventListener('mousemove', (e) => {
            const rect = card.getBoundingClientRect();
            const xRatio = Math.max(0, Math.min(1, (e.clientX - rect.left) / rect.width));
            const yRatio = Math.max(0, Math.min(1, (e.clientY - rect.top) / rect.height));

            layers.forEach(l => {
                if (!l.img || !l.lens) return;
                l.lens.style.display = 'block';
                const lensW = l.lens.offsetWidth || 80;
                const lensH = l.lens.offsetHeight || 80;

                l.lens.style.left = `${xRatio * l.img.offsetWidth - lensW / 2}px`;
                l.lens.style.top = `${yRatio * l.img.offsetHeight - lensH / 2}px`;

                const bgX = -(xRatio * l.img.offsetWidth * 3 - lensW / 2);
                const bgY = -(yRatio * l.img.offsetHeight * 3 - lensH / 2);

                l.lens.style.backgroundPosition = `${bgX}px ${bgY}px`;
                l.lens.style.backgroundSize = `${l.img.offsetWidth * 3}px ${l.img.offsetHeight * 3}px`;
            });
        });

        card.addEventListener('mouseleave', () => {
            layers.forEach(l => { if (l.lens) l.lens.style.display = 'none'; });
        });
    });
}

function switchTab(btn, tabId) {
    btn.closest('.page').querySelectorAll('.tab-btn').forEach(t => t.classList.remove('active'));
    btn.closest('.page').querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById(tabId).classList.add('active');
}

// ═══════════════════════════════════════════════════════════
//  CERTIFICATES & DELETE
// ═══════════════════════════════════════════════════════════
async function downloadCertificate(imageId) {
    showLoading('Generating PDF certificate...', 'Embedding Merkle proof and QR code');
    try {
        const response = await fetch(`/api/certificate/${imageId}`, { method: 'POST' });

        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `imageguard_certificate_${imageId}.pdf`;
            document.body.appendChild(a);
            a.click();
            a.remove();
            window.URL.revokeObjectURL(url);
            hideLoading();
            showToast('PDF certificate downloaded successfully!', 'success');
        } else {
            hideLoading();
            showToast('Failed to generate certificate', 'error');
        }
    } catch (err) {
        hideLoading();
        showToast(`Error: ${err.message}`, 'error');
    }
}

async function deleteImage(imageId) {
    if (!confirm('Delete this image and all associated forensic data?')) return;

    try {
        const response = await fetch(`/api/images/${imageId}`, { method: 'DELETE' });
        const result = await response.json();
        if (result.status === 'success') {
            showToast('Image deleted from database and Merkle ledger updated.', 'info');
            showPage('dashboard');
        }
    } catch (err) {
        showToast(`Error: ${err.message}`, 'error');
    }
}

// ═══════════════════════════════════════════════════════════
//  HELPERS
// ═══════════════════════════════════════════════════════════
function renderMetadataFindings(analysis) {
    if (!analysis || !analysis.findings || analysis.findings.length === 0) {
        return '<p style="font-size:0.85rem; color:var(--surface-400);">No suspicious metadata findings detected.</p>';
    }

    return `
        <div class="mb-md">
            <div style="display:flex; gap:4px; flex-wrap:wrap; margin-bottom:var(--space-md);">
                <span class="status-indicator ${analysis.risk_level === 'Low' ? 'verified' : analysis.risk_level === 'Medium' ? 'unverified' : 'failed'}">
                    Risk: ${escapeHtml(analysis.risk_level)}
                </span>
                <span class="status-indicator ${analysis.score >= 60 ? 'verified' : 'failed'}">
                    Score: ${analysis.score}%
                </span>
            </div>
            ${analysis.findings.map(f => `
                <div class="finding-tag ${f.type === 'warning' ? 'warning' : f.type === 'info' ? 'info' : 'error'}">
                    ${f.type === 'warning' ? '⚠️' : f.type === 'info' ? 'ℹ️' : '❌'} ${escapeHtml(f.message)}
                </div>
            `).join('')}
        </div>
    `;
}

function renderMetadataTable(metadata) {
    if (!metadata) return '';
    const rows = [];
    if (metadata.camera) {
        Object.entries(metadata.camera).forEach(([k, v]) => {
            rows.push(`<tr><td>Camera ${escapeHtml(k)}</td><td>${escapeHtml(v)}</td></tr>`);
        });
    }
    if (metadata.software) {
        Object.entries(metadata.software).forEach(([k, v]) => {
            rows.push(`<tr><td>Software ${escapeHtml(k)}</td><td>${escapeHtml(v)}</td></tr>`);
        });
    }
    if (rows.length === 0) return '';

    return `
        <table class="metadata-table mt-md">
            <tr><th>Tag</th><th>Value</th></tr>
            ${rows.join('')}
        </table>
    `;
}

function getScoreColor(score) {
    if (score >= 70) return 'var(--success-400)';
    if (score >= 40) return 'var(--warning-400)';
    return 'var(--danger-400)';
}

function getScoreClass(score) {
    if (score >= 70) return 'high';
    if (score >= 40) return 'medium';
    return 'low';
}

function formatSize(bytes) {
    if (!bytes) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB'];
    let i = 0;
    let size = bytes;
    while (size >= 1024 && i < units.length - 1) { size /= 1024; i++; }
    return `${size.toFixed(1)} ${units[i]}`;
}

function formatDate(isoString) {
    if (!isoString) return 'N/A';
    try {
        const d = new Date(isoString);
        return d.toLocaleDateString('en-US', {
            year: 'numeric', month: 'short', day: 'numeric',
            hour: '2-digit', minute: '2-digit'
        });
    } catch { return isoString; }
}

function animateNumber(element, start, end, duration) {
    const startTime = performance.now();
    function update(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3);
        const current = (start + (end - start) * eased).toFixed(1);
        element.textContent = current;
        if (progress < 1) requestAnimationFrame(update);
    }
    requestAnimationFrame(update);
}

function showLoading(text = 'Processing...', subtext = '') {
    const overlay = document.getElementById('loadingOverlay');
    if (!overlay) return;
    document.getElementById('loadingText').textContent = text;
    document.getElementById('loadingSubtext').textContent = subtext;
    overlay.classList.add('visible');
}

function hideLoading() {
    const overlay = document.getElementById('loadingOverlay');
    if (overlay) overlay.classList.remove('visible');
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    if (!container) return;
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    const icons = { success: '✅', error: '❌', warning: '⚠️', info: 'ℹ️' };
    toast.innerHTML = `<span>${icons[type] || 'ℹ️'}</span><span class="toast-message">${escapeHtml(message)}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
        toast.classList.add('removing');
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

// ═══════════════════════════════════════════════════════════
//  INIT
// ═══════════════════════════════════════════════════════════
document.addEventListener('DOMContentLoaded', () => {
    if (window.__VERIFY_IMAGE_ID) {
        viewImageDetail(window.__VERIFY_IMAGE_ID);
        return;
    }
    const path = window.location.pathname;
    if (path.startsWith('/verify/')) {
        const id = path.split('/verify/')[1];
        if (id) viewImageDetail(parseInt(id));
    }
});
