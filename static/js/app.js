/**
 * ImageGuard — Frontend Application
 * Digital Image Authenticity & Ownership Verification
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
};

// ═══════════════════════════════════════════════════════════
//  NAVIGATION
// ═══════════════════════════════════════════════════════════
function showPage(pageName) {
    // Hide all pages
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));

    // Show target page
    const page = document.getElementById(`page-${pageName}`);
    if (page) {
        page.classList.add('active');
        // Re-trigger animation
        page.style.animation = 'none';
        page.offsetHeight; // force reflow
        page.style.animation = '';
    }

    // Highlight nav link
    const link = document.querySelector(`.nav-link[data-page="${pageName}"]`);
    if (link) link.classList.add('active');

    state.currentPage = pageName;

    // Load data for specific pages
    if (pageName === 'dashboard') loadDashboard();
    if (pageName === 'keys') loadKeys();
    if (pageName === 'sign') loadSignData();
}

// ═══════════════════════════════════════════════════════════
//  FILE UPLOAD
// ═══════════════════════════════════════════════════════════
const uploadZone = document.getElementById('uploadZone');
const fileInput = document.getElementById('fileInput');
const uploadPreview = document.getElementById('uploadPreview');
const previewImage = document.getElementById('previewImage');
const fileInfo = document.getElementById('fileInfo');

if (uploadZone) {
    uploadZone.addEventListener('click', () => fileInput.click());

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
        const files = e.dataTransfer.files;
        if (files.length > 0) handleFileSelect(files[0]);
    });
}

if (fileInput) {
    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) handleFileSelect(e.target.files[0]);
    });
}

function handleFileSelect(file) {
    const allowedTypes = ['image/png', 'image/jpeg', 'image/bmp', 'image/tiff', 'image/webp'];
    if (!allowedTypes.includes(file.type)) {
        showToast('Invalid file type. Use PNG, JPG, BMP, TIFF, or WEBP.', 'error');
        return;
    }

    if (file.size > 16 * 1024 * 1024) {
        showToast('File too large. Maximum size is 16 MB.', 'error');
        return;
    }

    state.selectedFile = file;

    // Show preview
    const reader = new FileReader();
    reader.onload = (e) => {
        previewImage.src = e.target.result;
        fileInfo.textContent = `${file.name} — ${formatSize(file.size)}`;
        uploadPreview.classList.add('visible');
    };
    reader.readAsDataURL(file);

    // Hide previous results
    document.getElementById('resultsContainer').classList.remove('visible');
}

// ═══════════════════════════════════════════════════════════
//  ANALYZE IMAGE
// ═══════════════════════════════════════════════════════════
async function analyzeImage() {
    if (!state.selectedFile) {
        showToast('Please select an image first.', 'warning');
        return;
    }

    showLoading('Analyzing image...', 'Running ELA, noise analysis, and AI classification');

    const formData = new FormData();
    formData.append('file', state.selectedFile);

    try {
        const response = await fetch('/api/analyze', {
            method: 'POST',
            body: formData,
        });

        const result = await response.json();
        hideLoading();

        if (result.status === 'success') {
            state.currentAnalysis = result.data;
            renderAnalysisResults(result.data);
            showToast('Analysis complete!', 'success');
        } else {
            showToast(result.detail || 'Analysis failed', 'error');
        }
    } catch (err) {
        hideLoading();
        showToast(`Error: ${err.message}`, 'error');
    }
}

function renderAnalysisResults(data) {
    const container = document.getElementById('resultsContainer');
    const score = data.authenticity_score;
    const isAuthentic = data.is_authentic;
    const circumference = 2 * Math.PI * 65; // radius = 65
    const offset = circumference - (score / 100) * circumference;

    let forgeryDetails = {};
    try { forgeryDetails = JSON.parse(data.forgery_details); } catch (e) {}

    let metadataReport = data.metadata_report || {};
    let metadataAnalysis = metadataReport.analysis || {};
    let metadata = metadataReport.metadata || {};

    container.innerHTML = `
        <!-- Score Overview -->
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
                            <span class="score-label">Authenticity</span>
                        </div>
                    </div>
                    <div class="verdict-badge ${isAuthentic ? 'authentic' : 'forged'}">
                        ${isAuthentic ? '✅' : '⚠️'} ${isAuthentic ? 'Authentic' : 'Potentially Forged'}
                    </div>
                </div>
            </div>

            <div class="glass-card">
                <div class="card-header">
                    <div class="icon blue">📊</div>
                    <div><h2>Detailed Scores</h2><p>Individual analysis results</p></div>
                </div>

                <div class="score-bar-item">
                    <div class="score-bar-header">
                        <span class="score-bar-label">Error Level Analysis</span>
                        <span class="score-bar-value" style="color:${getScoreColor(data.ela_score)}">${data.ela_score}%</span>
                    </div>
                    <div class="score-bar-track">
                        <div class="score-bar-fill ${getScoreClass(data.ela_score)}" data-width="${data.ela_score}"></div>
                    </div>
                </div>

                <div class="score-bar-item">
                    <div class="score-bar-header">
                        <span class="score-bar-label">Noise Analysis</span>
                        <span class="score-bar-value" style="color:${getScoreColor(data.noise_score)}">${data.noise_score}%</span>
                    </div>
                    <div class="score-bar-track">
                        <div class="score-bar-fill ${getScoreClass(data.noise_score)}" data-width="${data.noise_score}"></div>
                    </div>
                </div>

                <div class="score-bar-item">
                    <div class="score-bar-header">
                        <span class="score-bar-label">AI Classification</span>
                        <span class="score-bar-value" style="color:${getScoreColor(data.cnn_score)}">${data.cnn_score}%</span>
                    </div>
                    <div class="score-bar-track">
                        <div class="score-bar-fill ${getScoreClass(data.cnn_score)}" data-width="${data.cnn_score}"></div>
                    </div>
                </div>

                <div class="score-bar-item">
                    <div class="score-bar-header">
                        <span class="score-bar-label">Metadata Integrity</span>
                        <span class="score-bar-value" style="color:${getScoreColor(data.metadata_score)}">${data.metadata_score}%</span>
                    </div>
                    <div class="score-bar-track">
                        <div class="score-bar-fill ${getScoreClass(data.metadata_score)}" data-width="${data.metadata_score}"></div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Image Comparison -->
        <div class="glass-card mt-lg">
            <div class="card-header">
                <div class="icon orange">🖼️</div>
                <div><h2>Visual Analysis</h2><p>Heatmap and ELA visualization</p></div>
            </div>
            <div class="image-comparison">
                <div class="comparison-item">
                    <img src="${previewImage.src}" alt="Original">
                    <div class="label">Original Image</div>
                </div>
                <div class="comparison-item">
                    <img src="/static/${data.ela_image_path}" alt="ELA" onerror="this.src='data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 width=%22200%22 height=%22200%22><text x=%2250%25%22 y=%2250%25%22 text-anchor=%22middle%22 fill=%22%23666%22>ELA</text></svg>'">
                    <div class="label">Error Level Analysis</div>
                </div>
                <div class="comparison-item">
                    <img src="/static/${data.heatmap_path}" alt="Heatmap" onerror="this.src='data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 width=%22200%22 height=%22200%22><text x=%2250%25%22 y=%2250%25%22 text-anchor=%22middle%22 fill=%22%23666%22>Heatmap</text></svg>'">
                    <div class="label">Suspicion Heatmap</div>
                </div>
            </div>
        </div>

        <!-- Image Details & Hash -->
        <div class="results-grid mt-lg">
            <div class="glass-card">
                <div class="card-header">
                    <div class="icon blue">📋</div>
                    <div><h2>Image Details</h2><p>File information</p></div>
                </div>
                <table class="metadata-table">
                    <tr><th>Property</th><th>Value</th></tr>
                    <tr><td>Filename</td><td>${data.original_filename}</td></tr>
                    <tr><td>Dimensions</td><td>${data.width} × ${data.height} px</td></tr>
                    <tr><td>File Size</td><td>${formatSize(data.file_size)}</td></tr>
                    <tr><td>Upload Date</td><td>${formatDate(data.upload_date)}</td></tr>
                </table>
                <div class="mt-md">
                    <label class="form-label">SHA-256 Hash</label>
                    <div class="hash-display" onclick="copyToClipboard('${data.file_hash}')" title="Click to copy">
                        ${data.file_hash}
                    </div>
                </div>
            </div>

            <div class="glass-card">
                <div class="card-header">
                    <div class="icon green">🔍</div>
                    <div><h2>Metadata Analysis</h2><p>EXIF data findings</p></div>
                </div>
                ${renderMetadataFindings(metadataAnalysis)}
                ${renderMetadataTable(metadata)}
            </div>
        </div>

        <!-- Actions -->
        <div class="glass-card mt-lg text-center" style="padding:var(--space-lg);">
            <div style="display:flex; gap:12px; justify-content:center; flex-wrap:wrap;">
                <button class="btn btn-primary" onclick="showPage('sign')">✍️ Sign This Image</button>
                <button class="btn btn-success" onclick="downloadCertificate(${data.id})">📜 Download Certificate</button>
                <button class="btn btn-ghost" onclick="viewImageDetail(${data.id})">📄 Full Report</button>
            </div>
        </div>
    `;

    container.classList.add('visible');

    // Animate scores
    requestAnimationFrame(() => {
        // Animate ring
        const ring = container.querySelector('.ring-progress');
        if (ring) {
            ring.style.strokeDashoffset = ring.dataset.targetOffset;
        }

        // Animate number
        const scoreNum = container.querySelector('.score-number');
        if (scoreNum) animateNumber(scoreNum, 0, score, 1500);

        // Animate bars
        container.querySelectorAll('.score-bar-fill').forEach(bar => {
            setTimeout(() => {
                bar.style.width = bar.dataset.width + '%';
            }, 300);
        });
    });
}

// ═══════════════════════════════════════════════════════════
//  DIGITAL SIGNATURES
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

        // Populate sign selects
        const signImageSelect = document.getElementById('signImageSelect');
        const signKeySelect = document.getElementById('signKeySelect');
        const verifyImageSelect = document.getElementById('verifyImageSelect');

        signImageSelect.innerHTML = '<option value="">-- Select an analyzed image --</option>' +
            state.images.filter(i => !i.is_signed).map(i =>
                `<option value="${i.id}">${i.original_filename} (Score: ${i.authenticity_score}%)</option>`
            ).join('');

        signKeySelect.innerHTML = '<option value="">-- Select your RSA key --</option>' +
            state.keys.map(k =>
                `<option value="${k.key_id}">🔑 ${k.owner_name} (${k.key_id})</option>`
            ).join('');

        verifyImageSelect.innerHTML = '<option value="">-- Select a signed image --</option>' +
            state.images.filter(i => i.is_signed).map(i =>
                `<option value="${i.id}">${i.original_filename} — signed by ${i.signer_name}</option>`
            ).join('');

    } catch (err) {
        showToast(`Failed to load data: ${err.message}`, 'error');
    }
}

async function signImage() {
    const imageId = document.getElementById('signImageSelect').value;
    const keyId = document.getElementById('signKeySelect').value;

    if (!imageId || !keyId) {
        showToast('Please select both an image and a key.', 'warning');
        return;
    }

    showLoading('Signing image...', 'Generating RSA digital signature');

    try {
        const formData = new FormData();
        formData.append('key_id', keyId);

        const response = await fetch(`/api/sign/${imageId}`, {
            method: 'POST',
            body: formData,
        });

        const result = await response.json();
        hideLoading();

        if (result.status === 'success') {
            showToast(`Image signed by ${result.data.signer}!`, 'success');
            loadSignData();
        } else {
            showToast(result.detail || 'Signing failed', 'error');
        }
    } catch (err) {
        hideLoading();
        showToast(`Error: ${err.message}`, 'error');
    }
}

async function verifySignature() {
    const imageId = document.getElementById('verifyImageSelect').value;
    if (!imageId) {
        showToast('Please select a signed image.', 'warning');
        return;
    }

    showLoading('Verifying signature...', 'Checking RSA signature integrity');

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
                        ${v.is_valid ? '✅ VALID' : '❌ INVALID'}
                    </div>
                    <p style="font-size:0.85rem; color:var(--surface-300); margin-bottom:var(--space-sm);">
                        ${v.message}
                    </p>
                    <p style="font-size:0.75rem; color:var(--surface-400);">
                        <strong>Signer:</strong> ${v.signer}<br>
                        <strong>Integrity:</strong> ${v.integrity}
                    </p>
                    <div class="mt-sm">
                        <label class="form-label">Current SHA-256 Hash</label>
                        <div class="hash-display" onclick="copyToClipboard('${v.current_hash}')" title="Click to copy">
                            ${v.current_hash}
                        </div>
                    </div>
                </div>
            `;

            showToast(v.is_valid ? 'Signature verified!' : 'Signature invalid!', v.is_valid ? 'success' : 'error');
        }
    } catch (err) {
        hideLoading();
        showToast(`Error: ${err.message}`, 'error');
    }
}

// ═══════════════════════════════════════════════════════════
//  KEY MANAGEMENT
// ═══════════════════════════════════════════════════════════
async function generateKeys() {
    const name = document.getElementById('keyOwnerName').value.trim();
    const email = document.getElementById('keyOwnerEmail').value.trim();

    if (!name) {
        showToast('Owner name is required.', 'warning');
        return;
    }

    showLoading('Generating RSA key pair...', '2048-bit key generation');

    try {
        const formData = new FormData();
        formData.append('owner_name', name);
        formData.append('owner_email', email);

        const response = await fetch('/api/keys/generate', {
            method: 'POST',
            body: formData,
        });

        const result = await response.json();
        hideLoading();

        if (result.status === 'success') {
            showToast(`Key pair generated for ${name}!`, 'success');
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
                <div class="empty-icon">🔑</div>
                <h3>No keys yet</h3>
                <p>Generate your first RSA key pair to start signing images.</p>
            </div>
        `;
        return;
    }

    container.innerHTML = keys.map(k => `
        <div class="key-card">
            <div class="key-info">
                <div class="key-icon">🔑</div>
                <div>
                    <div class="key-name">${k.owner_name}</div>
                    <div class="key-id">${k.key_id} ${k.owner_email ? '· ' + k.owner_email : ''}</div>
                </div>
            </div>
            <div style="display:flex; gap:6px;">
                <span class="status-indicator verified">Active</span>
            </div>
        </div>
    `).join('');
}

// ═══════════════════════════════════════════════════════════
//  DASHBOARD
// ═══════════════════════════════════════════════════════════
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
    } catch (err) {
        showToast(`Dashboard load failed: ${err.message}`, 'error');
    }
}

function renderStats(stats) {
    const grid = document.getElementById('statsGrid');
    grid.innerHTML = `
        <div class="stat-card">
            <div class="stat-icon">📷</div>
            <div class="stat-value">${stats.total_images || 0}</div>
            <div class="stat-label">Total Images</div>
        </div>
        <div class="stat-card">
            <div class="stat-icon">✅</div>
            <div class="stat-value" style="color:var(--success-400)">${stats.authentic_count || 0}</div>
            <div class="stat-label">Authentic</div>
        </div>
        <div class="stat-card">
            <div class="stat-icon">⚠️</div>
            <div class="stat-value" style="color:var(--danger-400)">${stats.forged_count || 0}</div>
            <div class="stat-label">Suspicious</div>
        </div>
        <div class="stat-card">
            <div class="stat-icon">✍️</div>
            <div class="stat-value" style="color:var(--accent-400)">${stats.signed_count || 0}</div>
            <div class="stat-label">Signed</div>
        </div>
        <div class="stat-card">
            <div class="stat-icon">📊</div>
            <div class="stat-value">${stats.avg_authenticity || 0}%</div>
            <div class="stat-label">Avg Score</div>
        </div>
    `;
}

function renderGallery(images) {
    const grid = document.getElementById('galleryGrid');

    if (images.length === 0) {
        grid.innerHTML = `
            <div class="empty-state" style="grid-column: 1/-1;">
                <div class="empty-icon">📷</div>
                <h3>No images analyzed yet</h3>
                <p>Upload and analyze your first image to see it here.</p>
                <button class="btn btn-primary mt-md" onclick="showPage('analyze')">🔍 Analyze Image</button>
            </div>
        `;
        return;
    }

    grid.innerHTML = images.map(img => `
        <div class="gallery-card" onclick="viewImageDetail(${img.id})">
            <img class="card-image" src="/static/uploads/${img.filename}" alt="${img.original_filename}"
                 onerror="this.src='data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 width=%22300%22 height=%22180%22 fill=%22%231e293b%22><rect width=%22300%22 height=%22180%22/><text x=%2250%25%22 y=%2250%25%22 text-anchor=%22middle%22 fill=%22%23475569%22 font-size=%2214%22>Image</text></svg>'">
            <div class="card-body">
                <div class="card-title">${img.original_filename}</div>
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
    showLoading('Loading details...');

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
    let forgeryDetails = data.forgery_details_parsed || {};

    container.innerHTML = `
        <div class="detail-header">
            <button class="back-btn" onclick="showPage('dashboard')">←</button>
            <div>
                <h1 style="font-size:1.25rem; font-weight:700; color:var(--surface-50);">${data.original_filename}</h1>
                <p style="font-size:0.8rem; color:var(--surface-400);">Analyzed ${formatDate(data.upload_date)}</p>
            </div>
        </div>

        <div class="detail-actions">
            <button class="btn btn-primary btn-sm" onclick="showPage('sign')">✍️ Sign</button>
            <button class="btn btn-success btn-sm" onclick="downloadCertificate(${data.id})">📜 Certificate</button>
            <button class="btn btn-danger btn-sm" onclick="deleteImage(${data.id})">🗑️ Delete</button>
        </div>

        <!-- Tabs -->
        <div class="tabs">
            <button class="tab-btn active" onclick="switchTab(this, 'tab-overview')">Overview</button>
            <button class="tab-btn" onclick="switchTab(this, 'tab-visual')">Visual Analysis</button>
            <button class="tab-btn" onclick="switchTab(this, 'tab-metadata')">Metadata</button>
            <button class="tab-btn" onclick="switchTab(this, 'tab-signature')">Signature</button>
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
                                <span class="score-number" style="color: ${isAuthentic ? 'var(--success-400)' : 'var(--danger-400)'}">${score}</span>
                                <span class="score-label">Authenticity</span>
                            </div>
                        </div>
                        <div class="verdict-badge ${isAuthentic ? 'authentic' : 'forged'}">
                            ${isAuthentic ? '✅ Authentic' : '⚠️ Potentially Forged'}
                        </div>
                    </div>
                </div>
                <div class="glass-card">
                    <div class="card-header">
                        <div class="icon blue">📊</div>
                        <div><h2>Analysis Breakdown</h2></div>
                    </div>
                    <div class="score-bar-item">
                        <div class="score-bar-header">
                            <span class="score-bar-label">ELA</span>
                            <span class="score-bar-value" style="color:${getScoreColor(data.ela_score)}">${data.ela_score}%</span>
                        </div>
                        <div class="score-bar-track"><div class="score-bar-fill ${getScoreClass(data.ela_score)}" style="width:${data.ela_score}%"></div></div>
                    </div>
                    <div class="score-bar-item">
                        <div class="score-bar-header">
                            <span class="score-bar-label">Noise</span>
                            <span class="score-bar-value" style="color:${getScoreColor(data.noise_score)}">${data.noise_score}%</span>
                        </div>
                        <div class="score-bar-track"><div class="score-bar-fill ${getScoreClass(data.noise_score)}" style="width:${data.noise_score}%"></div></div>
                    </div>
                    <div class="score-bar-item">
                        <div class="score-bar-header">
                            <span class="score-bar-label">AI Classification</span>
                            <span class="score-bar-value" style="color:${getScoreColor(data.cnn_score)}">${data.cnn_score}%</span>
                        </div>
                        <div class="score-bar-track"><div class="score-bar-fill ${getScoreClass(data.cnn_score)}" style="width:${data.cnn_score}%"></div></div>
                    </div>
                    <div class="score-bar-item">
                        <div class="score-bar-header">
                            <span class="score-bar-label">Metadata</span>
                            <span class="score-bar-value" style="color:${getScoreColor(data.metadata_score)}">${data.metadata_score}%</span>
                        </div>
                        <div class="score-bar-track"><div class="score-bar-fill ${getScoreClass(data.metadata_score)}" style="width:${data.metadata_score}%"></div></div>
                    </div>

                    <hr class="section-divider">

                    <table class="metadata-table">
                        <tr><th>Property</th><th>Value</th></tr>
                        <tr><td>Dimensions</td><td>${data.width} × ${data.height} px</td></tr>
                        <tr><td>File Size</td><td>${formatSize(data.file_size)}</td></tr>
                        <tr><td>SHA-256</td><td style="word-break:break-all; font-size:0.7rem;">${data.file_hash}</td></tr>
                    </table>
                </div>
            </div>
        </div>

        <!-- Tab: Visual -->
        <div id="tab-visual" class="tab-content">
            <div class="glass-card">
                <div class="image-comparison">
                    <div class="comparison-item">
                        <img src="/static/uploads/${data.filename}" alt="Original">
                        <div class="label">Original</div>
                    </div>
                    <div class="comparison-item">
                        <img src="/static/${data.ela_image_path}" alt="ELA">
                        <div class="label">Error Level Analysis</div>
                    </div>
                    <div class="comparison-item">
                        <img src="/static/${data.heatmap_path}" alt="Heatmap">
                        <div class="label">Suspicion Heatmap</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Tab: Metadata -->
        <div id="tab-metadata" class="tab-content">
            <div class="glass-card">
                <div class="card-header">
                    <div class="icon green">🔍</div>
                    <div><h2>Metadata Report</h2></div>
                </div>
                ${renderMetadataFindings(metadataAnalysis)}
                ${renderCameraInfo(metadataParsed)}
                ${renderTimestamps(metadataParsed)}
            </div>
        </div>

        <!-- Tab: Signature -->
        <div id="tab-signature" class="tab-content">
            <div class="glass-card">
                ${data.is_signed ? `
                    <div class="card-header">
                        <div class="icon green">✅</div>
                        <div><h2>Digitally Signed</h2><p>Ownership verified</p></div>
                    </div>
                    <table class="metadata-table">
                        <tr><th>Property</th><th>Value</th></tr>
                        <tr><td>Signer</td><td>${data.signer_name}</td></tr>
                        <tr><td>Key ID</td><td class="text-mono">${data.public_key_id}</td></tr>
                        <tr><td>Signed Date</td><td>${formatDate(data.signed_date)}</td></tr>
                    </table>
                    <div class="mt-md">
                        <label class="form-label">Digital Signature</label>
                        <div class="hash-display">${data.signature}</div>
                    </div>
                    <button class="btn btn-success btn-block mt-lg" onclick="verifyFromDetail(${data.id})">✅ Verify Signature Now</button>
                ` : `
                    <div class="empty-state">
                        <div class="empty-icon">✍️</div>
                        <h3>Not yet signed</h3>
                        <p>This image hasn't been digitally signed. Sign it to claim ownership.</p>
                        <button class="btn btn-primary mt-md" onclick="showPage('sign')">✍️ Sign This Image</button>
                    </div>
                `}
            </div>
        </div>
    `;
}

async function verifyFromDetail(imageId) {
    showLoading('Verifying...');
    try {
        const response = await fetch(`/api/verify-signature/${imageId}`, { method: 'POST' });
        const result = await response.json();
        hideLoading();
        if (result.status === 'success') {
            const v = result.data;
            showToast(v.is_valid ? '✅ Signature is VALID!' : '❌ Signature INVALID!', v.is_valid ? 'success' : 'error');
        }
    } catch (err) {
        hideLoading();
        showToast(`Error: ${err.message}`, 'error');
    }
}

function switchTab(btn, tabId) {
    btn.closest('.page').querySelectorAll('.tab-btn').forEach(t => t.classList.remove('active'));
    btn.closest('.page').querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById(tabId).classList.add('active');
}

// ═══════════════════════════════════════════════════════════
//  CERTIFICATES
// ═══════════════════════════════════════════════════════════
async function downloadCertificate(imageId) {
    showLoading('Generating certificate...', 'Creating PDF with QR code');
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
            showToast('Certificate downloaded!', 'success');
        } else {
            hideLoading();
            showToast('Failed to generate certificate', 'error');
        }
    } catch (err) {
        hideLoading();
        showToast(`Error: ${err.message}`, 'error');
    }
}

// ═══════════════════════════════════════════════════════════
//  DELETE
// ═══════════════════════════════════════════════════════════
async function deleteImage(imageId) {
    if (!confirm('Delete this image and all associated data?')) return;

    try {
        const response = await fetch(`/api/images/${imageId}`, { method: 'DELETE' });
        const result = await response.json();
        if (result.status === 'success') {
            showToast('Image deleted.', 'info');
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
        return '<p style="font-size:0.85rem; color:var(--surface-400);">No specific findings.</p>';
    }

    return `
        <div class="mb-md">
            <div style="display:flex; gap:4px; flex-wrap:wrap; margin-bottom:var(--space-md);">
                <span class="status-indicator ${analysis.risk_level === 'Low' ? 'verified' : analysis.risk_level === 'Medium' ? 'unverified' : 'failed'}">
                    Risk: ${analysis.risk_level}
                </span>
                <span class="status-indicator ${analysis.score >= 60 ? 'verified' : 'failed'}">
                    Score: ${analysis.score}%
                </span>
            </div>
            ${analysis.findings.map(f => `
                <div class="finding-tag ${f.type === 'warning' ? 'warning' : f.type === 'info' ? 'info' : 'error'}">
                    ${f.type === 'warning' ? '⚠️' : f.type === 'info' ? 'ℹ️' : '❌'} ${f.message}
                </div>
            `).join('')}
        </div>
    `;
}

function renderMetadataTable(metadata) {
    if (!metadata || !metadata.camera) return '';

    const rows = [];
    if (metadata.camera) {
        Object.entries(metadata.camera).forEach(([k, v]) => {
            rows.push(`<tr><td>${k}</td><td>${v}</td></tr>`);
        });
    }
    if (metadata.software) {
        Object.entries(metadata.software).forEach(([k, v]) => {
            rows.push(`<tr><td>${k}</td><td>${v}</td></tr>`);
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

function renderCameraInfo(metadata) {
    if (!metadata || !metadata.camera || Object.keys(metadata.camera).length === 0) {
        return '<p style="font-size:0.85rem; color:var(--surface-500); margin-top:var(--space-md);">No camera information available.</p>';
    }
    return `
        <h3 style="font-size:0.9rem; font-weight:600; color:var(--surface-200); margin-top:var(--space-md); margin-bottom:var(--space-sm);">📷 Camera Info</h3>
        <table class="metadata-table">
            <tr><th>Property</th><th>Value</th></tr>
            ${Object.entries(metadata.camera).map(([k, v]) => `<tr><td>${k}</td><td>${v}</td></tr>`).join('')}
        </table>
    `;
}

function renderTimestamps(metadata) {
    if (!metadata || !metadata.timestamps || Object.keys(metadata.timestamps).length === 0) {
        return '<p style="font-size:0.85rem; color:var(--surface-500); margin-top:var(--space-md);">No timestamp data available.</p>';
    }
    return `
        <h3 style="font-size:0.9rem; font-weight:600; color:var(--surface-200); margin-top:var(--space-md); margin-bottom:var(--space-sm);">🕐 Timestamps</h3>
        <table class="metadata-table">
            <tr><th>Type</th><th>Date/Time</th></tr>
            ${Object.entries(metadata.timestamps).map(([k, v]) => `<tr><td>${k}</td><td>${v}</td></tr>`).join('')}
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
        const eased = 1 - Math.pow(1 - progress, 3); // ease-out cubic
        const current = Math.round(start + (end - start) * eased);
        element.textContent = current;
        if (progress < 1) requestAnimationFrame(update);
    }
    requestAnimationFrame(update);
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showToast('Copied to clipboard!', 'info');
    }).catch(() => {
        showToast('Failed to copy', 'error');
    });
}

// ═══════════════════════════════════════════════════════════
//  LOADING & TOASTS
// ═══════════════════════════════════════════════════════════
function showLoading(text = 'Processing...', subtext = '') {
    const overlay = document.getElementById('loadingOverlay');
    document.getElementById('loadingText').textContent = text;
    document.getElementById('loadingSubtext').textContent = subtext;
    overlay.classList.add('visible');
}

function hideLoading() {
    document.getElementById('loadingOverlay').classList.remove('visible');
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;

    const icons = { success: '✅', error: '❌', warning: '⚠️', info: 'ℹ️' };
    toast.innerHTML = `
        <span>${icons[type] || 'ℹ️'}</span>
        <span class="toast-message">${message}</span>
    `;

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
    // Check if we need to show verification page
    const path = window.location.pathname;
    if (path.startsWith('/verify/')) {
        const id = path.split('/verify/')[1];
        if (id) viewImageDetail(parseInt(id));
    }
});
