const express = require('express');
const multer = require('multer');
const fs = require('fs');
const csv = require('csv-parser');
const path = require('path');
const verifier = require('./verifier');

const app = express();
const upload = multer({ dest: 'uploads/' });

// Serve frontend
app.use(express.static(path.join(__dirname)));
app.use(express.json());

// Dummy ledger — in a real app this connects to PostgreSQL
let userCredits = 9999999; // Set high for testing large lists
let activeJobs = {};

// ======================== BULK CSV UPLOAD ========================

app.post('/api/upload', upload.single('list'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

    const emails = [];
    fs.createReadStream(req.file.path)
        .pipe(csv())
        .on('data', (data) => {
            let emailAddress = null;
            if (data.email) {
                emailAddress = data.email;
            } else {
                const vals = Object.values(data);
                emailAddress = vals.find(v => typeof v === 'string' && v.includes('@')) || vals[0];
            }
            if (emailAddress && typeof emailAddress === 'string') {
                emails.push(emailAddress.trim());
            }
        })
        .on('end', () => {
            // GDPR: delete uploaded file immediately
            try { fs.unlinkSync(req.file.path); } catch (_) {}

            const validEmails = emails.filter(e => e && e.includes('@'));

            if (userCredits < validEmails.length) {
                return res.status(402).json({ error: `Insufficient credits! You have ${userCredits} but need ${validEmails.length}.` });
            }

            const jobId = Date.now().toString();
            activeJobs[jobId] = {
                emails: validEmails,
                processed: 0,
                valid: 0,
                invalid: 0,
                catchall: 0,
                risky: 0,
                results: [],    // Store every result for download
                recentValid: [], // For real-time UI
                recentInvalid: [], // For real-time UI
                status: 'running',
            };
            res.json({ jobId, total: validEmails.length });

            // Fire and forget — processJob handles its own errors
            processJob(jobId);
        })
        .on('error', (err) => {
            try { fs.unlinkSync(req.file.path); } catch (_) {}
            res.status(500).json({ error: 'Failed to parse CSV file.' });
        });
});

// ======================== PROGRESS POLLING ========================

app.get('/api/progress/:jobId', (req, res) => {
    const job = activeJobs[req.params.jobId];
    if (!job) return res.status(404).json({ error: 'Job not found' });

    res.json({
        processed: job.processed,
        total: job.emails.length,
        valid: job.valid,
        invalid: job.invalid,
        catchall: job.catchall,
        risky: job.risky,
        status: job.status,
        recentValid: job.recentValid,
        recentInvalid: job.recentInvalid
    });
});

// ======================== BULK PROCESSOR ========================

async function processJob(jobId) {
    const job = activeJobs[jobId];
    const concurrencyLimit = 50; // Process 50 emails concurrently for massive speedup
    let index = 0;

    async function worker() {
        while (index < job.emails.length) {
            if (userCredits <= 0) {
                job.status = 'out_of_credits';
                break;
            }
            if (job.status !== 'running') {
                break;
            }

            const i = index++;
            const email = job.emails[i];
            userCredits--;

            try {
                const data = await verifier.verifyEmail(email);
                job.results.push(data);

                if (data.status === 'valid' || data.status === 'role_based') {
                    job.valid++;
                    job.recentValid.unshift(email);
                    if (job.recentValid.length > 5) job.recentValid.pop();
                } else if (data.status === 'catch_all') {
                    job.catchall++;
                } else if (data.status === 'risky' || data.status === 'unknown') {
                    job.risky++;
                } else {
                    job.invalid++;
                    job.recentInvalid.unshift({email: email, reason: data.reasonCode});
                    if (job.recentInvalid.length > 5) job.recentInvalid.pop();
                }
            } catch (err) {
                console.error(`[VerifyPro] Error verifying "${email}":`, err.message);
                job.results.push({
                    email,
                    domain: email.split('@')[1] || 'unknown',
                    providerType: 'Unknown',
                    emailCategory: 'Unknown',
                    status: 'error',
                    score: 0,
                    activity: 'Unknown',
                    flags: { disposable: false, roleBased: false, catchAll: false },
                    reasonCode: 'internal_error',
                });
                job.invalid++;
                job.recentInvalid.unshift({email: email, reason: 'internal_error'});
                if (job.recentInvalid.length > 5) job.recentInvalid.pop();
            }

            job.processed++;
        }
    }

    const workers = [];
    for (let w = 0; w < concurrencyLimit; w++) {
        workers.push(worker());
    }

    await Promise.all(workers);
    
    if (job.status === 'running') {
        job.status = 'complete';
    }
}

// ======================== DOWNLOAD RESULTS CSV ========================

app.get('/api/download/:jobId', (req, res) => {
    const job = activeJobs[req.params.jobId];
    if (!job) return res.status(404).json({ error: 'Job not found' });
    if (job.status !== 'complete' && job.status !== 'out_of_credits') {
        return res.status(400).json({ error: 'Job still processing.' });
    }

    // Build CSV string
    const header = 'Email,Status,Score,Provider,Category,Activity,Reason,Disposable,RoleBased,CatchAll';
    const rows = job.results.map((r) => {
        return [
            `"${r.email}"`,
            r.status,
            r.score,
            `"${r.providerType}"`,
            `"${r.emailCategory || ''}"`,
            `"${r.activity || ''}"`,
            r.reasonCode,
            r.flags.disposable,
            r.flags.roleBased,
            r.flags.catchAll,
        ].join(',');
    });
    const csvContent = [header, ...rows].join('\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="verified_emails_${req.params.jobId}.csv"`);
    res.send(csvContent);
});

// ======================== SINGLE EMAIL CHECK ========================

app.post('/api/verify-single', async (req, res) => {
    const { email } = req.body;
    if (!email || !email.includes('@')) {
        return res.status(400).json({ error: 'Invalid email provided.' });
    }
    if (userCredits <= 0) {
        return res.status(402).json({ error: 'Insufficient credits! Time to top up.' });
    }

    userCredits--;
    try {
        const data = await verifier.verifyEmail(email);
        res.json(data);
    } catch (e) {
        console.error('[VerifyPro] Single check error:', e.message);
        res.status(500).json({ error: 'Internal server error during verification.' });
    }
});

// ======================== CREDITS ========================

app.get('/api/credits', (req, res) => {
    res.json({ credits: userCredits });
});

// ======================== START ========================

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`[VerifyPro] Engine roaring on http://localhost:${PORT}`);
});
