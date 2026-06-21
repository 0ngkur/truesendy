const express = require('express');
const multer = require('multer');
const fs = require('fs');
const csv = require('csv-parser');
const path = require('path');
const verifier = require('./verifier');
const xlsx = require('xlsx');
const pdfParse = require('pdf-parse');
const mammoth = require('mammoth');

const app = express();
const upload = multer({ dest: 'uploads/' });

// Serve frontend
app.use(express.static(path.join(__dirname)));
app.use(express.json());

// Dummy ledger — in a real app this connects to PostgreSQL
let userCredits = 9999999; // Set high for testing large lists
let activeJobs = {};

// ======================== BULK CSV UPLOAD ========================

app.post('/api/upload', upload.single('list'), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

    const emails = new Set();
    const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
    const ext = path.extname(req.file.originalname).toLowerCase();
    
    try {
        let rawText = '';
        if (ext === '.xlsx' || ext === '.xls') {
            const workbook = xlsx.readFile(req.file.path);
            workbook.SheetNames.forEach(sheetName => {
                const sheet = workbook.Sheets[sheetName];
                rawText += xlsx.utils.sheet_to_csv(sheet) + ' ';
            });
        } else if (ext === '.pdf') {
            const dataBuffer = fs.readFileSync(req.file.path);
            const data = await pdfParse(dataBuffer);
            rawText = data.text;
        } else if (ext === '.docx') {
            const result = await mammoth.extractRawText({path: req.file.path});
            rawText = result.value;
        } else {
            // For csv, txt, or anything else, just read as string
            rawText = fs.readFileSync(req.file.path, 'utf8');
        }

        const found = rawText.match(emailRegex);
        if (found) {
            found.forEach(e => emails.add(e.toLowerCase().trim()));
        }
    } catch (e) {
        console.error("Extraction error:", e);
        try { fs.unlinkSync(req.file.path); } catch (_) {}
        return res.status(500).json({ error: 'Failed to parse the file.' });
    }

    try { fs.unlinkSync(req.file.path); } catch (_) {}

    const validEmails = Array.from(emails);

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

    const format = req.query.format || 'csv';

    // Filter to only include valid emails
    const validResults = job.results.filter(r => r.status === 'valid' || r.status === 'role_based');

    if (format === 'txt') {
        const txtContent = validResults.map(r => `${r.email} - ${r.providerType}`).join('\n');
        res.setHeader('Content-Type', 'text/plain');
        res.setHeader('Content-Disposition', `attachment; filename="verified_emails_${req.params.jobId}.txt"`);
        return res.send(txtContent);
    }

    // Build CSV/Excel arrays
    const headerRow = ['Email', 'Type'];
    const rows = validResults.map(r => [r.email, r.providerType]);
    
    if (format === 'excel') {
        const ws = xlsx.utils.aoa_to_sheet([headerRow, ...rows]);
        const wb = xlsx.utils.book_new();
        xlsx.utils.book_append_sheet(wb, ws, "Valid Emails");
        const excelBuffer = xlsx.write(wb, { type: 'buffer', bookType: 'xlsx' });
        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        res.setHeader('Content-Disposition', `attachment; filename="verified_emails_${req.params.jobId}.xlsx"`);
        return res.send(excelBuffer);
    }

    // Default CSV
    const csvContent = [
        headerRow.join(','),
        ...rows.map(row => `"${row[0]}","${row[1]}"`)
    ].join('\n');

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
