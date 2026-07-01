const nodemailer = require('nodemailer');

/**
 * Email service for sending OTPs.
 * 
 * Configure SMTP via environment variables:
 *   SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS
 * 
 * For Gmail: Use an App Password (not your regular password)
 *   SMTP_HOST=smtp.gmail.com
 *   SMTP_PORT=587
 *   SMTP_USER=yourmail@gmail.com
 *   SMTP_PASS=your-app-password
 * 
 * If SMTP is not configured, OTP will be logged to console (dev mode).
 */

let transporter = null;

function getTransporter() {
    if (transporter) return transporter;

    const host = process.env.SMTP_HOST;
    const port = parseInt(process.env.SMTP_PORT || '587', 10);
    const user = process.env.SMTP_USER;
    const pass = process.env.SMTP_PASS;

    if (!host || !user || !pass) {
        console.log('[TrueSendy] ⚠ SMTP not configured — OTPs will print to console (dev mode)');
        return null;
    }

    transporter = nodemailer.createTransport({
        host,
        port,
        secure: port === 465,
        auth: { user, pass },
    });

    return transporter;
}

const crypto = require('crypto');

function generateOTP() {
    // crypto.randomInt is CSPRNG — Math.random() is NOT safe for OTPs
    return crypto.randomInt(100000, 999999).toString();
}

function isDevMode() {
    return !transporter && !getTransporter();
}

async function sendOTP(email, otp, purpose) {
    const transport = getTransporter();

    const subjects = {
        verify: 'TrueSendy — Verify Your Email',
        reset: 'TrueSendy — Password Reset Code',
    };

    const bodies = {
        verify: `
            <div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 480px; margin: 0 auto; background: #0f0a1a; color: #f1f5f9; padding: 40px; border-radius: 16px; border: 1px solid rgba(168, 85, 247, 0.2);">
                <h1 style="color: #a855f7; font-size: 24px; margin-bottom: 8px;">TrueSendy</h1>
                <p style="color: #94a3b8; margin-bottom: 24px;">Verify your email to get started.</p>
                <div style="background: rgba(168, 85, 247, 0.1); border: 1px solid rgba(168, 85, 247, 0.3); padding: 24px; border-radius: 12px; text-align: center; margin-bottom: 24px;">
                    <p style="color: #94a3b8; font-size: 14px; margin-bottom: 8px;">Your verification code</p>
                    <p style="font-size: 36px; font-weight: 800; color: #a855f7; letter-spacing: 8px; margin: 0;">${otp}</p>
                </div>
                <p style="color: #64748b; font-size: 13px;">This code expires in 10 minutes. If you didn't create a TrueSendy account, ignore this email.</p>
            </div>
        `,
        reset: `
            <div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 480px; margin: 0 auto; background: #0f0a1a; color: #f1f5f9; padding: 40px; border-radius: 16px; border: 1px solid rgba(168, 85, 247, 0.2);">
                <h1 style="color: #a855f7; font-size: 24px; margin-bottom: 8px;">TrueSendy</h1>
                <p style="color: #94a3b8; margin-bottom: 24px;">Use this code to reset your password.</p>
                <div style="background: rgba(168, 85, 247, 0.1); border: 1px solid rgba(168, 85, 247, 0.3); padding: 24px; border-radius: 12px; text-align: center; margin-bottom: 24px;">
                    <p style="color: #94a3b8; font-size: 14px; margin-bottom: 8px;">Your reset code</p>
                    <p style="font-size: 36px; font-weight: 800; color: #a855f7; letter-spacing: 8px; margin: 0;">${otp}</p>
                </div>
                <p style="color: #64748b; font-size: 13px;">This code expires in 10 minutes. If you didn't request a password reset, ignore this email.</p>
            </div>
        `,
    };

    if (!transport) {
        // Dev mode fallback — print to console
        console.log(`\n[TrueSendy] ══════════════════════════════════`);
        console.log(`[TrueSendy] 📧 OTP for ${email}`);
        console.log(`[TrueSendy] 🔑 Code: ${otp}`);
        console.log(`[TrueSendy] 📋 Purpose: ${purpose}`);
        console.log(`[TrueSendy] ══════════════════════════════════\n`);
        return true;
    }

    try {
        await transport.sendMail({
            from: `"TrueSendy" <${process.env.MAIL_FROM || 'noreply@truesendy.com'}>`,
            to: email,
            subject: subjects[purpose] || 'TrueSendy — Your Code',
            html: bodies[purpose] || `Your code is: <strong>${otp}</strong>`,
        });
        return true;
    } catch (err) {
        // SMTP was configured but delivery failed. Do NOT log the OTP code.
        // Return false so the caller can tell the user the email didn't go out
        // (rather than reporting "account created" when no code was delivered).
        console.error(`[TrueSendy] ⚠ OTP delivery failed for ${email}:`, err.message, '(code redacted from logs)');
        return false;
    }
}

// ── Send a purchased verification key to the buyer ──
// Called by the Stripe webhook after a key_purchase payment. In dev mode (no
// SMTP), the key is printed to the server console so the flow is testable
// without an email provider — real delivery works once SMTP is configured.
async function sendApiKeyEmail(email, key, tokens, validityDays) {
    const transport = getTransporter();
    const days  = validityDays || 30;
    const count = Number(tokens || 100000).toLocaleString();

    const html = `
        <div style="font-family:'Segoe UI',Arial,sans-serif;max-width:520px;margin:0 auto;background:#0f0a1a;color:#f1f5f9;padding:40px;border-radius:16px;border:1px solid rgba(168,85,247,0.2);">
            <h1 style="color:#a855f7;font-size:24px;margin-bottom:8px;">TrueSendy</h1>
            <p style="color:#94a3b8;margin-bottom:24px;">Your verification key is ready. Thank you for your purchase!</p>
            <div style="background:rgba(168,85,247,0.1);border:1px solid rgba(168,85,247,0.3);padding:24px;border-radius:12px;margin-bottom:16px;">
                <p style="color:#94a3b8;font-size:14px;margin-bottom:8px;">Your API key — <strong>${count} emails</strong> · valid ${days} days</p>
                <p style="font-family:'JetBrains Mono',monospace;font-size:17px;font-weight:700;color:#a855f7;word-break:break-all;margin:0;">${key}</p>
            </div>
            <p style="color:#cbd5e1;font-size:14px;margin-bottom:16px;">Activate it in the TrueSendy app with:</p>
            <p style="background:rgba(255,255,255,0.08);padding:10px 14px;border-radius:8px;font-family:'JetBrains Mono',monospace;font-size:13px;color:#e2e8f0;word-break:break-all;">TrueSendy set-key ${key}</p>
            <p style="color:#64748b;font-size:13px;margin-top:16px;">Store this key securely — it is shown only here. Do not share it.</p>
        </div>`;

    if (!transport) {
        console.log(`\n[TrueSendy] ═════ KEY PURCHASE (dev — no SMTP) ═════`);
        console.log(`[TrueSendy] 📧 Key for ${email}`);
        console.log(`[TrueSendy] 🔑 ${key}  (${count} emails, ${days}d)`);
        console.log(`[TrueSendy] ════════════════════════════════════════\n`);
        return true;
    }

    try {
        await transport.sendMail({
            from: `"TrueSendy" <${process.env.MAIL_FROM || 'noreply@truesendy.com'}>`,
            to: email,
            subject: 'TrueSendy — Your Verification Key',
            html,
        });
        return true;
    } catch (err) {
        console.error(`[TrueSendy] Key email delivery failed for ${email}:`, err.message, '(key redacted from logs)');
        return false;
    }
}

module.exports = { generateOTP, sendOTP, isDevMode, sendApiKeyEmail };
