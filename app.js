document.addEventListener('DOMContentLoaded', () => {
    const uploadZone = document.getElementById('upload-zone');
    const fileInput = document.getElementById('file-input');
    const progressContainer = document.getElementById('progress-container');
    const progressFill = document.getElementById('progress-fill');
    const progressPercentage = document.getElementById('progress-percentage');
    const progressStatus = document.getElementById('progress-status');
    const dailyCreditsEl = document.getElementById('daily-credits');
    const downloadSection = document.getElementById('download-section');
    const downloadBtn = document.getElementById('download-btn');
    const resetBtn = document.getElementById('reset-btn');

    const statValid = document.getElementById('stat-valid');
    const statInvalid = document.getElementById('stat-invalid');
    const statCatchall = document.getElementById('stat-catchall');
    const statRisky = document.getElementById('stat-risky');
    
    const statsGrid = document.getElementById('stats-grid');
    const liveFeedSection = document.getElementById('live-feed-section');
    const liveValidList = document.getElementById('live-valid-list');
    const liveInvalidList = document.getElementById('live-invalid-list');

    // Fetch initial credits
    fetch('/api/credits')
        .then(res => res.json())
        .then(data => { dailyCreditsEl.textContent = data.credits; })
        .catch(() => { dailyCreditsEl.textContent = '?'; });

    // ======================== DRAG & DROP / FILE SELECT ========================

    uploadZone.addEventListener('click', () => fileInput.click());

    uploadZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadZone.style.borderColor = 'var(--accent)';
        uploadZone.style.background = 'rgba(59, 130, 246, 0.05)';
    });

    uploadZone.addEventListener('dragleave', () => {
        uploadZone.style.borderColor = 'var(--glass-border)';
        uploadZone.style.background = 'rgba(255,255,255,0.02)';
    });

    uploadZone.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadZone.style.borderColor = 'var(--glass-border)';
        uploadZone.style.background = 'rgba(255,255,255,0.02)';
        if (e.dataTransfer.files.length > 0) {
            handleFile(e.dataTransfer.files[0]);
        }
    });

    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            handleFile(e.target.files[0]);
        }
    });

    // ======================== BULK FILE HANDLER ========================

    async function handleFile(file) {
        if (!file.name.endsWith('.csv')) {
            alert('Please upload a CSV file.');
            return;
        }

        uploadZone.style.display = 'none';
        progressContainer.style.display = 'block';
        downloadSection.style.display = 'none';
        statsGrid.style.display = 'grid';
        liveFeedSection.style.display = 'flex';
        progressStatus.textContent = 'Uploading...';

        const formData = new FormData();
        formData.append('list', file);

        try {
            const uploadRes = await fetch('/api/upload', {
                method: 'POST',
                body: formData,
            });
            const jobData = await uploadRes.json();

            if (jobData.error) {
                alert(jobData.error);
                uploadZone.style.display = 'block';
                progressContainer.style.display = 'none';
                return;
            }

            const jobId = jobData.jobId;
            const total = jobData.total;
            progressStatus.textContent = 'Verifying...';

            const poll = setInterval(async () => {
                try {
                    const res = await fetch(`/api/progress/${jobId}`);
                    const data = await res.json();

                    const percent = total > 0 ? Math.floor((data.processed / total) * 100) : 100;
                    progressFill.style.width = `${percent}%`;
                    progressPercentage.textContent = `${percent}%`;
                    progressStatus.textContent = `Verifying... (${data.processed}/${total})`;

                    statValid.textContent = data.valid;
                    statInvalid.textContent = data.invalid;
                    statCatchall.textContent = data.catchall;
                    if (statRisky) statRisky.textContent = data.risky || 0;

                    // Update live feeds
                    if (data.recentValid) {
                        liveValidList.innerHTML = data.recentValid.map(e => `<div>✅ ${e}</div>`).join('');
                    }
                    if (data.recentInvalid) {
                        liveInvalidList.innerHTML = data.recentInvalid.map(e => `<div style="display:flex; justify-content:space-between"><span>❌ ${e.email}</span><span style="opacity:0.6; font-size:0.75rem">${e.reason}</span></div>`).join('');
                    }

                    // Update credits
                    fetch('/api/credits')
                        .then(r => r.json())
                        .then(c => dailyCreditsEl.textContent = c.credits)
                        .catch(() => {});

                    if (data.status === 'complete' || data.status === 'out_of_credits') {
                        clearInterval(poll);
                        progressStatus.textContent = data.status === 'complete'
                            ? '✅ Verification Complete!'
                            : '⚠️ Stopped — Out of Credits';

                        // Show download button
                        downloadBtn.href = `/api/download/${jobId}`;
                        downloadSection.style.display = 'flex';
                    }
                } catch (pollErr) {
                    console.error('Polling error:', pollErr);
                }
            }, 800);

        } catch (e) {
            console.error(e);
            alert('Error communicating with the server. Is it running?');
            uploadZone.style.display = 'block';
            progressContainer.style.display = 'none';
        }
    }

    resetBtn.addEventListener('click', () => {
        uploadZone.style.display = 'block';
        progressContainer.style.display = 'none';
        statsGrid.style.display = 'none';
        liveFeedSection.style.display = 'none';
        downloadSection.style.display = 'none';
        progressFill.style.width = '0%';
        progressPercentage.textContent = '0%';
        statValid.textContent = '0';
        statInvalid.textContent = '0';
        statCatchall.textContent = '0';
        if (statRisky) statRisky.textContent = '0';
        liveValidList.innerHTML = '';
        liveInvalidList.innerHTML = '';
        fileInput.value = '';
    });

    // ======================== SINGLE EMAIL CHECK ========================

    const singleEmailInput = document.getElementById('single-email-input');
    const singleEmailBtn = document.getElementById('single-email-btn');
    const singleEmailResult = document.getElementById('single-email-result');

    // Allow Enter key to trigger check
    singleEmailInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') singleEmailBtn.click();
    });

    singleEmailBtn.addEventListener('click', async () => {
        const email = singleEmailInput.value.trim();
        if (!email || !email.includes('@')) {
            singleEmailResult.textContent = 'Please enter a valid email address.';
            singleEmailResult.className = 'text-warning';
            return;
        }

        singleEmailResult.innerHTML = '<span class="text-muted">Verifying... (checking DNS & SMTP)</span>';
        singleEmailBtn.disabled = true;

        try {
            const res = await fetch('/api/verify-single', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email }),
            });
            const data = await res.json();

            if (data.error) {
                singleEmailResult.textContent = data.error;
                singleEmailResult.className = 'text-danger';
            } else {
                // Determine status color
                let statusColor = 'text-warning';
                let statusIcon = '⚠️';
                if (data.status === 'valid') { statusColor = 'text-success'; statusIcon = '✅'; }
                else if (data.status === 'invalid' || data.status === 'disposable') { statusColor = 'text-danger'; statusIcon = '❌'; }
                else if (data.status === 'risky') { statusColor = 'text-risky'; statusIcon = '🟡'; }
                else if (data.status === 'catch_all') { statusIcon = '🟠'; }
                else if (data.status === 'role_based') { statusColor = 'text-success'; statusIcon = '📧'; }

                // Build flags list
                let flags = [];
                if (data.flags.catchAll) flags.push('Catch-All');
                if (data.flags.roleBased) flags.push('Role-Based');
                if (data.flags.disposable) flags.push('Disposable');
                let flagsHtml = flags.length > 0
                    ? `<div class="result-flags">${flags.map(f => `<span class="flag-badge">${f}</span>`).join(' ')}</div>`
                    : '';

                singleEmailResult.innerHTML = `
                    <div class="result-card">
                        <div class="result-header">
                            <span class="result-icon">${statusIcon}</span>
                            <span class="${statusColor} result-status">${data.status.toUpperCase()}</span>
                        </div>
                        <div class="result-grid">
                            <div class="result-item">
                                <span class="result-label">Provider</span>
                                <span class="result-value">${data.providerType}</span>
                            </div>
                            <div class="result-item">
                                <span class="result-label">Category</span>
                                <span class="result-value">${data.emailCategory || 'N/A'}</span>
                            </div>
                            <div class="result-item">
                                <span class="result-label">Activity</span>
                                <span class="result-value">${data.activity || 'N/A'}</span>
                            </div>
                            <div class="result-item">
                                <span class="result-label">Score</span>
                                <span class="result-value score-badge">${data.score}/100</span>
                            </div>
                        </div>
                        <div class="result-reason">
                            <span class="result-label">Reason:</span> ${data.reasonCode.replace(/_/g, ' ')}
                        </div>
                        ${flagsHtml}
                    </div>
                `;
                singleEmailResult.className = '';
            }

            // Update credits
            fetch('/api/credits')
                .then(r => r.json())
                .then(c => dailyCreditsEl.textContent = c.credits)
                .catch(() => {});

        } catch (e) {
            console.error('Frontend Exception:', e);
            singleEmailResult.textContent = `Verification failed: ${e.message}. Is the server running?`;
            singleEmailResult.className = 'text-danger';
        } finally {
            singleEmailBtn.disabled = false;
        }
    });
});
