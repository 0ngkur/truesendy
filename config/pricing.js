const fs = require('fs');
const path = require('path');

const PRICING_PATH = path.join(__dirname, 'pricing.json');

// ── Load pricing config ──
function loadPricing() {
    try {
        return JSON.parse(fs.readFileSync(PRICING_PATH, 'utf8'));
    } catch (_) {
        return { plans: {}, currency: 'usd' };
    }
}

function savePricing(config) {
    fs.writeFileSync(PRICING_PATH, JSON.stringify(config, null, 2));
}

function getPlan(planId) {
    const config = loadPricing();
    return config.plans[planId] || null;
}

function getAllPlans() {
    const config = loadPricing();
    return config.plans;
}

function updatePlanPrice(planId, priceMonthly, priceAnnual) {
    const config = loadPricing();
    if (!config.plans[planId]) return { error: 'Plan not found' };
    if (typeof priceMonthly === 'number' && priceMonthly >= 0) {
        config.plans[planId].priceMonthly = priceMonthly;
    }
    if (typeof priceAnnual === 'number' && priceAnnual >= 0) {
        config.plans[planId].priceAnnual = priceAnnual;
    }
    savePricing(config);
    return { success: true, plan: config.plans[planId] };
}

// ── Stripe initialization ──
// Key resolution: boss-managed db/settings.json FIRST, then STRIPE_SECRET_KEY
// env fallback. This lets the master admin swap the Stripe account from the
// panel without a redeploy.
let stripeInstance = null;
let _stripeKeyUsed = null;   // which key the cached instance was built from

function getStripe() {
    const settings = require('../db/settings');
    const key = settings.getStripeKeys().secretKey || process.env.STRIPE_SECRET_KEY;
    if (!key) return null;
    // Rebuild if the boss changed the key since we cached the instance
    if (!stripeInstance || _stripeKeyUsed !== key) {
        const Stripe = require('stripe');
        stripeInstance = Stripe(key);
        _stripeKeyUsed = key;
    }
    return stripeInstance;
}

function isStripeConfigured() {
    const settings = require('../db/settings');
    return !!(settings.getStripeKeys().secretKey || process.env.STRIPE_SECRET_KEY);
}

function getStripeWebhookSecret() {
    const settings = require('../db/settings');
    return settings.getStripeKeys().webhookSecret || process.env.STRIPE_WEBHOOK_SECRET || '';
}

// Called by the admin "save Stripe keys" handler so the next request rebuilds
// the Stripe client with the new key.
function resetStripeCache() {
    stripeInstance = null;
    _stripeKeyUsed = null;
}

// ── Create Stripe Checkout Session ──
async function createCheckoutSession(planId, billingCycle, successUrl, cancelUrl, customerEmail, userId) {
    const stripe = getStripe();
    if (!stripe) return { error: 'Stripe not configured' };

    const plan = getPlan(planId);
    if (!plan) return { error: 'Invalid plan' };

    const amount = billingCycle === 'annual' ? plan.priceAnnual : plan.priceMonthly;
    if (amount === 0) return { error: 'Free plan does not require payment' };

    try {
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            mode: 'payment',
            customer_email: customerEmail || undefined,
            client_reference_id: userId || undefined,
            line_items: [{
                price_data: {
                    currency: loadPricing().currency || 'usd',
                    product_data: {
                        name: `TrueSendy ${plan.name} — ${billingCycle === 'annual' ? 'Annual' : 'Monthly'}`,
                        description: `${plan.credits.toLocaleString()} email verification credits`,
                    },
                    unit_amount: Math.round(amount * 100), // Stripe uses cents
                },
                quantity: 1,
            }],
            success_url: successUrl,
            cancel_url: cancelUrl,
            metadata: {
                userId: userId || '',        // primary key the webhook uses to upgrade the right user
                plan: planId,
                billingCycle: billingCycle,
                credits: plan.credits.toString(),
                email: customerEmail || '',   // fallback for the webhook if userId is missing
            },
        });
        return { sessionId: session.id, url: session.url };
    } catch (err) {
        return { error: `Stripe error: ${err.message}` };
    }
}

// ── Stripe webhook signature verification (NEW-1) ─────────────────────────────
// Verifies the raw request body against STRIPE_WEBHOOK_SECRET. Used by the
// /api/stripe-webhook route so plan upgrades happen server-side, never via a
// client-controlled redirect.
function constructEvent(rawBody, signature) {
    const stripe = getStripe();
    if (!stripe) throw new Error('Stripe not configured');
    const secret = getStripeWebhookSecret();
    if (!secret) throw new Error('Stripe webhook secret not configured');
    return stripe.webhooks.constructEvent(rawBody, signature, secret);
}

// ── Create a one-time checkout session for buying a verification key ──
// Distinct from createCheckoutSession (which sells plan subscriptions): a key
// purchase is a single product at the boss-configured price, and the webhook
// uses metadata.type === 'key_purchase' to know it must mint + email a key.
async function createKeyCheckoutSession(successUrl, cancelUrl, customerEmail, userId, pkg) {
    const stripe = getStripe();
    if (!stripe) return { error: 'Stripe not configured' };

    const settings  = require('../db/settings');
    const product   = settings.getKeyProduct();

    // If a package override is passed, use its price/tokens; otherwise fall back to keyProduct.
    const pkgTokens = pkg ? Number(pkg.tokens) : product.tokens;
    const pkgPrice  = pkg ? Number(pkg.priceUsd) : product.priceUsd;
    const pkgName   = pkg ? pkg.name : '';

    try {
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            mode: 'payment',
            customer_email: customerEmail || undefined,
            client_reference_id: userId || undefined,
            line_items: [{
                price_data: {
                    currency: product.currency || 'usd',
                    product_data: {
                        name: `TrueSendy Verification Key — ${pkgTokens.toLocaleString()} emails${pkgName ? ' (' + pkgName + ')' : ''}`,
                        description: `One API key. Verifies up to ${pkgTokens.toLocaleString()} emails. Valid ${product.validityDays} days.`,
                    },
                    unit_amount: Math.round(pkgPrice * 100), // cents
                },
                quantity: 1,
            }],
            success_url: successUrl,
            cancel_url: cancelUrl,
            metadata: {
                type:   'key_purchase',
                userId: userId || '',
                email:  customerEmail || '',
                tokens: String(pkgTokens),
                price:  String(pkgPrice),
            },
        });
        return { sessionId: session.id, url: session.url };
    } catch (err) {
        return { error: `Stripe error: ${err.message}` };
    }
}

module.exports = {
    loadPricing,
    constructEvent,
    savePricing,
    getPlan,
    getAllPlans,
    updatePlanPrice,
    getStripe,
    isStripeConfigured,
    getStripeWebhookSecret,
    resetStripeCache,
    createCheckoutSession,
    createKeyCheckoutSession,
    calculatePrice,
    createCustomCheckoutSession,
};

// ── Volume-tiered pricing for custom credit amounts (the slider) ─────────────
// The more you buy, the cheaper per email. Matches the preset packages so the
// slider produces the same price at tier boundaries.
function calculatePrice(tokens) {
    const t = Math.floor(Number(tokens) || 0);
    if (t < 100) return null;           // minimum 100 credits
    if (t > 100000) return null;        // maximum 100k credits
    let perEmail;
    if (t <= 1000)        perEmail = 0.0020;
    else if (t <= 5000)   perEmail = 0.0014;
    else if (t <= 10000)  perEmail = 0.0012;
    else if (t <= 25000)  perEmail = 0.0010;
    else if (t <= 50000)  perEmail = 0.0008;
    else                  perEmail = 0.0005;
    const price = t * perEmail;
    return {
        tokens: t,
        priceUsd: Math.round(price * 100) / 100,   // round to cents
        perEmail: '$' + perEmail.toFixed(5).replace(/0+$/, '').replace(/\.$/, ''),
    };
}

// Create a checkout session for a CUSTOM credit amount (from the slider).
// Price is calculated server-side from calculatePrice() so clients can't tamper.
async function createCustomCheckoutSession(successUrl, cancelUrl, customerEmail, userId, tokens) {
    const stripe = getStripe();
    if (!stripe) return { error: 'Stripe not configured' };

    const calc = calculatePrice(tokens);
    if (!calc) return { error: 'Amount must be between 100 and 100,000 credits.' };

    const settings = require('../db/settings');
    const product  = settings.getKeyProduct();

    try {
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            mode: 'payment',
            customer_email: customerEmail || undefined,
            client_reference_id: userId || undefined,
            line_items: [{
                price_data: {
                    currency: product.currency || 'usd',
                    product_data: {
                        name: `TrueSendy Credits — ${calc.tokens.toLocaleString()} emails`,
                        description: `One-time purchase. Verifies up to ${calc.tokens.toLocaleString()} emails.`,
                    },
                    unit_amount: Math.round(calc.priceUsd * 100),
                },
                quantity: 1,
            }],
            success_url: successUrl,
            cancel_url: cancelUrl,
            metadata: {
                type:   'key_purchase',
                userId: userId || '',
                email:  customerEmail || '',
                tokens: String(calc.tokens),
                price:  String(calc.priceUsd),
            },
        });
        return { sessionId: session.id, url: session.url, tokens: calc.tokens, priceUsd: calc.priceUsd };
    } catch (err) {
        return { error: `Stripe error: ${err.message}` };
    }
}
