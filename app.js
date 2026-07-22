document.addEventListener('DOMContentLoaded', () => {

    // Mark body as JS-loaded so CSS reveal animations activate
    document.body.classList.add('js-loaded');

    // ======================== STATE ========================
    let authToken = localStorage.getItem('ts_token') || null;
    let currentUser = null;
    let pendingEmail = null;

    const fileInput = document.getElementById('file-input');
    const progressContainer = document.getElementById('progress-container');
    const progressFill = document.getElementById('progress-fill');
    const progressPercentage = document.getElementById('progress-percentage');
    const progressStatus = document.getElementById('progress-status');
    const dailyCreditsEl = document.getElementById('daily-credits');
    const downloadSection = document.getElementById('download-section');
    const resetBtn = document.getElementById('reset-btn');
    const statValid = document.getElementById('stat-valid');
    const statInvalid = document.getElementById('stat-invalid');
    const statsGrid = document.getElementById('stats-grid');
    const liveFeedSection = document.getElementById('live-feed-section');
    const liveValidList = document.getElementById('live-valid-list');
    const liveInvalidList = document.getElementById('live-invalid-list');
    const singleEmailInput = document.getElementById('single-email-input');
    const singleEmailBtn = document.getElementById('single-email-btn');
    const singleEmailResult = document.getElementById('single-email-result');
    const authGate = document.getElementById('auth-gate');
    const toolContent = document.getElementById('tool-content');
    const creditsPill = document.getElementById('credits-pill');
    const navAuthBtn = document.getElementById('nav-auth-btn');
    const navLogoutBtn = document.getElementById('nav-logout-btn');

    // ======================== PARTICLES ========================
    (function initParticles() {
        const container = document.getElementById('particles');
        if (!container) return;
        for (let i = 0; i < 30; i++) {
            const p = document.createElement('div');
            p.classList.add('particle');
            p.style.left = Math.random() * 100 + '%';
            p.style.animationDuration = (10 + Math.random() * 18) + 's';
            p.style.animationDelay = (Math.random() * 12) + 's';
            const size = 1 + Math.random() * 3;
            p.style.width = size + 'px';
            p.style.height = size + 'px';
            p.style.opacity = 0.1 + Math.random() * 0.35;
            container.appendChild(p);
        }
    })();

    // ======================== FLUID MOUSE ORB ========================
    (function initFluidOrb() {
        const orb = document.getElementById('mouse-orb');
        if (!orb) return;
        if (window.matchMedia('(hover:none)').matches) return;

        let cx = window.innerWidth / 2, cy = window.innerHeight / 2;
        let tx = cx, ty = cy;
        let entered = false;

        function tick() {
            cx += (tx - cx) * 0.06;
            cy += (ty - cy) * 0.06;
            orb.style.transform = `translate(${cx - 200}px, ${cy - 200}px)`;
            requestAnimationFrame(tick);
        }

        document.addEventListener('mousemove', e => {
            tx = e.clientX; ty = e.clientY;
            if (!entered) { entered = true; cx = tx; cy = ty; orb.classList.add('visible'); tick(); }
        }, { passive: true });

        document.addEventListener('mouseleave', () => orb.classList.remove('visible'));
        document.addEventListener('mouseenter', () => { if (entered) orb.classList.add('visible'); });
    })();

    // ======================== NAVBAR SCROLL ========================
    const navbar = document.getElementById('navbar');
    if (navbar) {
        window.addEventListener('scroll', () => {
            navbar.classList.toggle('scrolled', window.scrollY > 50);
        }, { passive: true });
    }

    // ======================== MOBILE MENU ========================
    const mobileMenuBtn = document.getElementById('mobile-menu-btn');
    const mobileMenu = document.getElementById('mobile-menu');
    if (mobileMenuBtn) {
        mobileMenuBtn.addEventListener('click', () => mobileMenu.classList.toggle('open'));
        mobileMenu.querySelectorAll('a').forEach(a => a.addEventListener('click', () => mobileMenu.classList.remove('open')));
    }

    // ======================== SCROLL REVEAL ========================
    const revealObserver = new IntersectionObserver((entries) => {
        entries.forEach(e => { if (e.isIntersecting) { e.target.classList.add('visible'); revealObserver.unobserve(e.target); } });
    }, { threshold: 0.1, rootMargin: '0px 0px -50px 0px' });
    document.querySelectorAll('.reveal').forEach(el => revealObserver.observe(el));

    // ======================== COUNTERS ========================
    const counterObserver = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (!entry.isIntersecting) return;
            const el = entry.target;
            const target = parseFloat(el.dataset.target);
            const isDecimal = target % 1 !== 0;
            const start = performance.now();
            function tick(now) {
                const p = Math.min((now - start) / 2000, 1);
                const eased = 1 - Math.pow(1 - p, 3);
                el.textContent = isDecimal ? (target * eased).toFixed(1) : Math.floor(target * eased).toLocaleString();
                if (p < 1) requestAnimationFrame(tick);
            }
            requestAnimationFrame(tick);
            counterObserver.unobserve(el);
        });
    }, { threshold: 0.5 });
    document.querySelectorAll('.counter').forEach(el => counterObserver.observe(el));

    // ======================== SMOOTH SCROLL ========================
    document.querySelectorAll('a[href^="#"]').forEach(a => {
        a.addEventListener('click', e => {
            e.preventDefault();
            const t = document.querySelector(a.getAttribute('href'));
            if (t) t.scrollIntoView({ behavior: 'smooth', block: 'start' });
        });
    });

    // ======================== MODAL SYSTEM ========================
    window.showModal = function(id) {
        document.querySelectorAll('.modal-overlay').forEach(m => m.classList.remove('open'));
        document.querySelectorAll('.form-error').forEach(e => e.textContent = '');
        document.querySelectorAll('.form-success').forEach(e => e.textContent = '');
        document.getElementById(id).classList.add('open');
    };

    window.closeModal = function(id) {
        document.getElementById(id).classList.remove('open');
        if (id === 'modal-otp') document.querySelectorAll('.otp-digit').forEach(d => d.value = '');
        if (id === 'modal-forgot') { document.getElementById('forgot-email').value = ''; }
    };

    // Close modal on overlay click
    document.querySelectorAll('.modal-overlay').forEach(overlay => {
        overlay.addEventListener('click', e => {
            if (e.target === overlay) overlay.classList.remove('open');
        });
    });

    // ======================== AUTH HELPERS ========================
    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    function authHeaders() {
        return { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + authToken };
    }

    async function apiPost(url, body) {
        try {
            const res = await fetch(url, { method: 'POST', headers: authHeaders(), body: JSON.stringify(body) });
            return res.json();
        } catch (e) {
            return { error: 'Network error. Please try again.' };
        }
    }

    function saveToken(token) {
        authToken = token;
        localStorage.setItem('ts_token', token);
    }

    function updateUI() {
        const navDashBtn = document.getElementById('nav-dashboard-btn');
        const mobileDash = document.getElementById('mobile-dashboard-link');
        const mobileSignin = document.getElementById('mobile-signin-link');
        if (currentUser) {
            if (authGate) authGate.style.display = 'none';
            if (toolContent) toolContent.style.display = 'block';
            if (creditsPill) creditsPill.style.display = 'flex';
            if (navAuthBtn) navAuthBtn.style.display = 'none';
            if (navLogoutBtn) navLogoutBtn.style.display = 'block';
            if (navDashBtn) navDashBtn.style.display = 'inline-flex';
            if (mobileDash) mobileDash.style.display = 'block';
            if (mobileSignin) mobileSignin.style.display = 'none';
            if (dailyCreditsEl) dailyCreditsEl.textContent = currentUser.credits.toLocaleString();
        } else {
            if (authGate) authGate.style.display = 'block';
            if (toolContent) toolContent.style.display = 'none';
            if (creditsPill) creditsPill.style.display = 'none';
            if (navAuthBtn) navAuthBtn.style.display = 'inline-flex';
            if (navLogoutBtn) navLogoutBtn.style.display = 'none';
            if (navDashBtn) navDashBtn.style.display = 'none';
            if (mobileDash) mobileDash.style.display = 'none';
            if (mobileSignin) mobileSignin.style.display = 'block';
        }
    }

    async function loadUser() {
        if (!authToken) { updateUI(); return; }
        try {
            const res = await fetch('/api/auth/me', { headers: { 'Authorization': 'Bearer ' + authToken } });
            const data = await res.json();
            if (data.user) { currentUser = data.user; }
            else { authToken = null; localStorage.removeItem('ts_token'); }
        } catch { authToken = null; localStorage.removeItem('ts_token'); }
        updateUI();
    }

    window.logout = function() {
        authToken = null;
        currentUser = null;
        localStorage.removeItem('ts_token');
        updateUI();
        resetVerifyUI();
    };

    // ======================== REGISTER ========================
    document.getElementById('reg-btn').addEventListener('click', async () => {
        const email = document.getElementById('reg-email').value.trim();
        const username = document.getElementById('reg-username').value.trim();
        const password = document.getElementById('reg-password').value;
        const errEl = document.getElementById('reg-error');
        errEl.textContent = '';

        if (!email || !username || !password) { errEl.textContent = 'All fields required.'; return; }

        const data = await apiPost('/api/auth/register', { email, username, password });
        if (data.error) { errEl.textContent = data.error; return; }

        saveToken(data.token);
        pendingEmail = email;
        closeModal('modal-register');
        document.getElementById('otp-target-email').textContent = email;
        showModal('modal-otp');
        if (data.devOTP) {
            const hint = document.getElementById('otp-error');
            hint.style.color = 'var(--success)';
            hint.textContent = `Dev mode — your code: ${data.devOTP}`;
        }
    });

    // ======================== LOGIN ========================
    document.getElementById('login-btn').addEventListener('click', async () => {
        const email = document.getElementById('login-email').value.trim();
        const password = document.getElementById('login-password').value;
        const errEl = document.getElementById('login-error');
        errEl.textContent = '';

        if (!email || !password) { errEl.textContent = 'Email and password required.'; return; }

        const data = await apiPost('/api/auth/login', { email, password });
        if (data.error) { errEl.textContent = data.error; return; }

        saveToken(data.token);

        if (data.needsVerification) {
            pendingEmail = email;
            closeModal('modal-login');
            document.getElementById('otp-target-email').textContent = email;
            showModal('modal-otp');
            return;
        }

        currentUser = data.user;
        closeModal('modal-login');
        updateUI();
    });

    // ======================== OTP VERIFICATION ========================
    // Auto-advance OTP digits
    document.querySelectorAll('.otp-digit').forEach((input, idx, all) => {
        input.addEventListener('input', (e) => {
            const val = e.target.value.replace(/\D/g, '');
            e.target.value = val.slice(0, 1);
            if (val && idx < all.length - 1) all[idx + 1].focus();
        });
        input.addEventListener('keydown', (e) => {
            if (e.key === 'Backspace' && !input.value && idx > 0) all[idx - 1].focus();
        });
        input.addEventListener('paste', (e) => {
            e.preventDefault();
            const text = (e.clipboardData || window.clipboardData).getData('text').replace(/\D/g, '');
            for (let i = 0; i < Math.min(text.length, all.length); i++) {
                all[i].value = text[i];
            }
            const focusIdx = Math.min(text.length, all.length - 1);
            all[focusIdx].focus();
        });
    });

    document.getElementById('otp-verify-btn').addEventListener('click', async () => {
        const digits = document.querySelectorAll('.otp-digit');
        const otp = Array.from(digits).map(d => d.value).join('');
        const errEl = document.getElementById('otp-error');
        errEl.textContent = '';

        if (otp.length !== 6) { errEl.textContent = 'Enter all 6 digits.'; return; }

        const email = pendingEmail || document.getElementById('otp-target-email').textContent;
        const data = await apiPost('/api/auth/verify-otp', { email, otp });
        if (data.error) { errEl.textContent = data.error; return; }

        saveToken(data.token);
        currentUser = data.user;
        closeModal('modal-otp');
        updateUI();
        digits.forEach(d => d.value = '');
    });

    document.getElementById('resend-otp-btn').addEventListener('click', async () => {
        const email = pendingEmail || document.getElementById('otp-target-email').textContent;
        const data = await apiPost('/api/auth/resend-otp', { email, purpose: 'verify' });
        const el = document.getElementById('otp-error');
        el.style.color = 'var(--success)';
        el.textContent = data.devOTP ? `Dev mode — your code: ${data.devOTP}` : 'New code sent!';
        setTimeout(() => { if (!data.devOTP) { el.textContent = ''; el.style.color = ''; } }, 5000);
    });

    // ======================== FORGOT PASSWORD ========================
    document.getElementById('forgot-btn').addEventListener('click', async () => {
        const email = document.getElementById('forgot-email').value.trim();
        document.getElementById('forgot-error').textContent = '';
        document.getElementById('forgot-success').textContent = '';
        if (!email) { document.getElementById('forgot-error').textContent = 'Email required.'; return; }

        const data = await apiPost('/api/auth/forgot-password', { email });
        document.getElementById('forgot-success').textContent = data.message || 'Code sent if account exists.';
    });

    // ======================== RESET PASSWORD ========================
    document.getElementById('reset-btn-submit').addEventListener('click', async () => {
        const email = document.getElementById('reset-email').value.trim();
        const otp = document.getElementById('reset-otp').value.trim();
        const newPassword = document.getElementById('reset-password').value;
        document.getElementById('reset-error').textContent = '';
        document.getElementById('reset-success').textContent = '';

        if (!email || !otp || !newPassword) { document.getElementById('reset-error').textContent = 'All fields required.'; return; }

        const data = await apiPost('/api/auth/reset-password', { email, otp, newPassword });
        if (data.error) { document.getElementById('reset-error').textContent = data.error; return; }

        document.getElementById('reset-success').textContent = data.message;
        setTimeout(() => { closeModal('modal-reset'); showModal('modal-login'); }, 2000);
    });

    // ======================== DRAG & DROP ========================
    const uploadZone = document.getElementById('upload-zone');
    if (uploadZone) {
        uploadZone.addEventListener('click', () => fileInput.click());
        uploadZone.addEventListener('dragover', e => { e.preventDefault(); uploadZone.style.borderColor = 'var(--purple)'; uploadZone.style.background = 'rgba(168,85,247,0.04)'; });
        uploadZone.addEventListener('dragleave', () => { uploadZone.style.borderColor = ''; uploadZone.style.background = ''; });
        uploadZone.addEventListener('drop', e => { e.preventDefault(); uploadZone.style.borderColor = ''; uploadZone.style.background = ''; if (e.dataTransfer.files.length > 0) handleFile(e.dataTransfer.files[0]); });
    }
    if (fileInput) fileInput.addEventListener('change', e => { if (e.target.files.length > 0) handleFile(e.target.files[0]); });

    // ======================== BULK FILE ========================
    async function handleFile(file) {
        const validExts = ['.csv', '.txt', '.xlsx', '.xls', '.pdf', '.docx'];
        if (!validExts.some(ext => file.name.toLowerCase().endsWith(ext))) { alert('Unsupported format.'); return; }

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
                headers: { 'Authorization': 'Bearer ' + authToken },
                body: formData,
            });
            const jobData = await uploadRes.json();
            if (jobData.error) { alert(jobData.error); resetVerifyUI(); return; }

            const jobId = jobData.jobId;
            const total = jobData.total;

            const poll = setInterval(async () => {
                try {
                    const res = await fetch(`/api/progress/${jobId}`, { headers: { 'Authorization': 'Bearer ' + authToken } });
                    const data = await res.json();
                    const percent = total > 0 ? Math.floor((data.processed / total) * 100) : 100;
                    progressFill.style.width = `${percent}%`;
                    progressPercentage.textContent = `${percent}%`;
                    progressStatus.textContent = `Verifying... (${data.processed.toLocaleString()}/${total.toLocaleString()})`;
                    statValid.textContent = data.valid.toLocaleString();
                    statInvalid.textContent = data.invalid.toLocaleString();

                    if (data.recentValid) {
                        liveValidList.replaceChildren(...data.recentValid.map(e => {
                            const d = document.createElement('div');
                            d.style.cssText = 'padding:0.2rem 0';
                            d.textContent = '✅ ' + e;
                            return d;
                        }));
                    }
                    if (data.recentInvalid) {
                        liveInvalidList.replaceChildren(...data.recentInvalid.map(e => {
                            const d = document.createElement('div');
                            d.style.cssText = 'display:flex;justify-content:space-between;padding:0.2rem 0';
                            d.innerHTML = '<span>❌ ' + escapeHtml(e.email) + '</span><span style="opacity:0.5;font-size:0.75rem">' + escapeHtml(e.reason) + '</span>';
                            return d;
                        }));
                    }

                    // Refresh credits
                    fetch('/api/credits', { headers: { 'Authorization': 'Bearer ' + authToken } })
                        .then(r => r.json()).then(c => { dailyCreditsEl.textContent = c.credits.toLocaleString(); if (currentUser) currentUser.credits = c.credits; }).catch(() => {});

                    if (data.status === 'complete' || data.status === 'out_of_credits') {
                        clearInterval(poll);
                        progressStatus.textContent = data.status === 'complete' ? '✅ Verification Complete!' : '⚠️ Out of Credits';
                        // Set up download buttons (fetch via API, not URL token)
                        ['csv','excel','txt'].forEach(fmt => {
                            const btn = document.getElementById('download-btn-' + fmt);
                            btn.removeAttribute('href');
                            btn.onclick = async (ev) => {
                                ev.preventDefault();
                                const res = await fetch(`/api/download/${jobId}?format=${fmt}`, { headers: authHeaders() });
                                const blob = await res.blob();
                                const url = URL.createObjectURL(blob);
                                const a = document.createElement('a');
                                a.href = url;
                                a.download = `truesendy_verified_${jobId}.${fmt === 'excel' ? 'xlsx' : fmt}`;
                                a.click();
                                URL.revokeObjectURL(url);
                            };
                        });
                        downloadSection.style.display = 'block';
                    }
                } catch (err) { console.error('Poll error:', err); }
            }, 800);
        } catch (e) { alert('Server error. Is it running?'); resetVerifyUI(); }
    }

    function resetVerifyUI() {
        uploadZone.style.display = 'block';
        progressContainer.style.display = 'none';
        statsGrid.style.display = 'none';
        liveFeedSection.style.display = 'none';
        downloadSection.style.display = 'none';
        progressFill.style.width = '0%';
        progressPercentage.textContent = '0%';
        statValid.textContent = '0';
        statInvalid.textContent = '0';
        liveValidList.replaceChildren();
        liveInvalidList.replaceChildren();
        fileInput.value = '';
    }

    resetBtn.addEventListener('click', resetVerifyUI);

    // ======================== SINGLE EMAIL ========================
    singleEmailInput.addEventListener('keydown', e => { if (e.key === 'Enter') singleEmailBtn.click(); });

    singleEmailBtn.addEventListener('click', async () => {
        const email = singleEmailInput.value.trim();
        if (!email || !email.includes('@')) {
            singleEmailResult.textContent = 'Enter a valid email.';
            singleEmailResult.className = 'text-warning';
            return;
        }

        singleEmailResult.textContent = 'Verifying...';
        singleEmailResult.className = 'text-muted';
        singleEmailBtn.disabled = true;

        try {
            const res = await fetch('/api/verify-single', { method: 'POST', headers: authHeaders(), body: JSON.stringify({ email }) });
            const data = await res.json();

            if (data.error) {
                singleEmailResult.textContent = data.error;
                singleEmailResult.className = 'text-danger';
            } else {
                const color = (data.status === 'safe' || data.status === 'valid') ? 'text-success' : (data.status === 'catch_all' ? 'text-warning' : (data.status === 'unknown' ? 'text-muted' : 'text-danger'));
                const icon = (data.status === 'safe' || data.status === 'valid') ? '\u2705' : (data.status === 'catch_all' ? '\u26A0\uFE0F' : (data.status === 'unknown' ? '\u2753' : '\u274C'));
                const flags = [];
                if (data.flags.roleBased) flags.push('Role');
                if (data.flags.catchAll) flags.push('Catch-all');
                if (data.flags.disposable) flags.push('Disposable');
                if (data.flags.spamtrap) flags.push('Spamtrap');
                if (data.flags.freeEmail) flags.push('Free Email');
                const flagsText = flags.length > 0 ? flags.join(', ') : 'None';

                const score = data.overallScore !== undefined ? data.overallScore : 0;
                const scoreColor = score >= 75 ? 'var(--success)' : score >= 50 ? 'var(--warning)' : 'var(--danger)';

                const card = document.createElement('div');
                card.className = 'result-card';
                card.innerHTML =
                    '<div class="result-header">' +
                        '<span class="result-icon">' + icon + '</span>' +
                        '<span class="' + color + ' result-status">' + escapeHtml(data.status.toUpperCase()) + '</span>' +
                        '<span style="margin-left:auto;font-family:JetBrains Mono,monospace;font-size:1.5rem;font-weight:800;color:' + scoreColor + '">' + score + '</span>' +
                    '</div>' +
                    '<div style="width:100%;height:6px;background:var(--bg-subtle);border-radius:3px;margin-bottom:1rem;overflow:hidden">' +
                        '<div style="height:100%;width:' + score + '%;background:' + scoreColor + ';border-radius:3px;transition:width 0.5s"></div>' +
                    '</div>' +
                    '<div class="result-grid">' +
                        '<div class="result-item"><span class="result-label">Provider</span><span class="result-value"></span></div>' +
                        '<div class="result-item"><span class="result-label">Category</span><span class="result-value"></span></div>' +
                        '<div class="result-item"><span class="result-label">Reason</span><span class="result-value"></span></div>' +
                        '<div class="result-item"><span class="result-label">Flags</span><span class="result-value"></span></div>' +
                    '</div>';
                const values = card.querySelectorAll('.result-value');
                values[0].textContent = data.mxProvider || data.providerType || 'N/A';
                values[1].textContent = data.emailCategory || 'N/A';
                values[2].textContent = (data.reasonCode || '').replace(/_/g, ' ');
                values[3].textContent = flagsText;

                singleEmailResult.replaceChildren(card);
                singleEmailResult.className = '';
            }

            // Refresh credits
            fetch('/api/credits', { headers: { 'Authorization': 'Bearer ' + authToken } })
                .then(r => r.json()).then(c => { dailyCreditsEl.textContent = c.credits.toLocaleString(); if (currentUser) currentUser.credits = c.credits; }).catch(() => {});
        } catch (e) {
            singleEmailResult.textContent = 'Verification failed. Is the server running?';
            singleEmailResult.className = 'text-danger';
        } finally { singleEmailBtn.disabled = false; }
    });

    // ======================== INIT ========================
    loadUser();
});

// ======================== GLOBAL FUNCTIONS ========================
// Called by onclick="subscribePlan('starter')" etc in index.html
window.subscribePlan = function(plan) {
    window.location.href = '/subscribePlan?plan=' + encodeURIComponent(plan);
};
