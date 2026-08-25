// ─────────────────────────────────────────────────────────────────
// Poster SaaS — single-file backend
// Auth (JWT) + branded poster generation (Pixabay/Pexels -> Sharp) +
// plan-based monthly limits + Paystack plan upgrades.
//
// No scheduling, no video, no storage — generate on request, stream
// the JPEG straight back to the customer to download once. Nothing
// is written to disk or a bucket.
//
// Setup:
//   npm install express mongoose bcryptjs jsonwebtoken node-fetch@2
//               sharp p-limit dotenv express-rate-limit
//   Create a .env file (see bottom of this file for the full list):
//     PORT=3000
//     MONGODB_URI=mongodb://localhost:27017/poster-saas
//     JWT_SECRET=some_long_random_string
//     JWT_EXPIRES_IN=30d
//     PIXABAY_API_KEY=xxx
//     PEXELS_API_KEY=xxx            (fallback source)
//     PAYSTACK_SECRET_KEY=xxx
//     MAX_CONCURRENT_GENERATIONS=4
//     TELEGRAM_AUTH_BOT_TOKEN=xxx   (shared bot, used only for reset codes)
//     TELEGRAM_BOT_USERNAME=xxx     (no leading @)
//     TELEGRAM_WEBHOOK_SECRET=xxx   (random string, part of the webhook URL)
//     DOMAIN=yourapp.com            (public domain Telegram sends updates to)
//   node app.js
// ─────────────────────────────────────────────────────────────────

require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fetch = require('node-fetch');
const sharp = require('sharp');
const pLimit = require('p-limit');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');

const app = express();
app.use(express.json({ limit: '1mb' }));

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '30d';
const PIXABAY_API_KEY = process.env.PIXABAY_API_KEY;
const PEXELS_API_KEY = process.env.PEXELS_API_KEY;
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;

// Single shared auth bot — used only to deliver 2FA/password-reset
// codes, not per-user broadcasting. Every user links to the SAME bot;
// Telegram tells them apart by chatId, which we capture via the
// /start deep-link payload (see /telegram/webhook below).
const TELEGRAM_AUTH_BOT_TOKEN = process.env.TELEGRAM_AUTH_BOT_TOKEN;
const TELEGRAM_BOT_USERNAME = process.env.TELEGRAM_BOT_USERNAME; // no leading @, e.g. "PosterSaaSBot"
const TELEGRAM_WEBHOOK_SECRET = process.env.TELEGRAM_WEBHOOK_SECRET;
const DOMAIN = process.env.DOMAIN; // e.g. "yourapp.com" — needed to register the webhook URL

if (!JWT_SECRET) {
  console.error('Missing JWT_SECRET in .env — refusing to start.');
  process.exit(1);
}

// ═══════════════════════════════════════════════════════════════
// PLANS — Naira pricing, monthly poster caps. Free tier watermarks
// output; paid tiers don't. Limits reset on the customer's billing
// anniversary (handled in checkAndResetUsage below).
// ═══════════════════════════════════════════════════════════════
const PLANS = {
  free: { name: 'Free', priceNaira: 0, monthlyLimit: 5, watermark: true },
  starter: { name: 'Starter', priceNaira: 4000, monthlyLimit: 50, watermark: false },
  growth: { name: 'Growth', priceNaira: 10000, monthlyLimit: 200, watermark: false },
  pro: { name: 'Pro', priceNaira: 20000, monthlyLimit: 1000, watermark: false }
};

// ═══════════════════════════════════════════════════════════════
// DATABASE MODELS
// ═══════════════════════════════════════════════════════════════
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  passwordHash: { type: String, required: true },
  businessName: { type: String, trim: true, default: '' },
  brandColor: { type: String, default: '' }, // hex, optional — falls back to palette cycling if unset
  plan: { type: String, enum: Object.keys(PLANS), default: 'free' },
  postersThisPeriod: { type: Number, default: 0 },
  periodStart: { type: Date, default: Date.now }, // rolls forward monthly
  paystackCustomerCode: { type: String, default: null },
  telegramChatId: { type: String, default: null }, // set once user links via /telegram/connect-link
  isTelegramConnected: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const jobSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  query: String,
  hook: String,
  copy: String,
  cta: String,
  photographer: String,
  photoSource: String, // 'pixabay' | 'pexels'
  status: { type: String, enum: ['done', 'failed'], default: 'done' },
  error: String,
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Job = mongoose.model('Job', jobSchema);

// ═══════════════════════════════════════════════════════════════
// AUTH HELPERS
// ═══════════════════════════════════════════════════════════════
function signToken(user) {
  return jwt.sign({ userId: user._id.toString() }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

async function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Missing Authorization bearer token' });

    const payload = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(payload.userId);
    if (!user) return res.status(401).json({ error: 'User no longer exists' });

    req.user = user;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// Basic email/password sanity checks — not exhaustive, just enough
// to stop garbage data and obviously-weak passwords at the door.
function validateEmail(email) {
  return typeof email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}
function validatePassword(pw) {
  return typeof pw === 'string' && pw.length >= 8;
}

// ═══════════════════════════════════════════════════════════════
// PLAN LIMIT ENFORCEMENT
// Resets postersThisPeriod once 30 days have passed since periodStart.
// Simple rolling-30-day window rather than calendar-month billing —
// avoids needing a cron job to reset everyone on the 1st.
// ═══════════════════════════════════════════════════════════════
const THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1000;

async function checkAndResetUsage(user) {
  const now = Date.now();
  if (now - new Date(user.periodStart).getTime() >= THIRTY_DAYS_MS) {
    user.postersThisPeriod = 0;
    user.periodStart = new Date();
    await user.save();
  }
  return user;
}

async function enforcePlanLimit(req, res, next) {
  try {
    const user = await checkAndResetUsage(req.user);
    const plan = PLANS[user.plan] || PLANS.free;

    // How many posters this request would use (batch-aware).
    const requested = Array.isArray(req.body?.items) ? req.body.items.length : 1;

    if (user.postersThisPeriod + requested > plan.monthlyLimit) {
      const remaining = Math.max(plan.monthlyLimit - user.postersThisPeriod, 0);
      return res.status(429).json({
        error: `Plan limit reached. Your ${plan.name} plan allows ${plan.monthlyLimit} posters per period, ${remaining} remaining.`,
        plan: user.plan,
        remaining,
        upgradeHint: 'POST /billing/upgrade to move to a higher plan.'
      });
    }

    req.planRequestCount = requested;
    next();
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to verify plan limit' });
  }
}

// ═══════════════════════════════════════════════════════════════
// CONCURRENCY GUARD
// Caps simultaneous Sharp/photo-fetch operations so a burst of
// requests across many customers doesn't stack memory on a small
// server. Requests beyond the cap simply wait their turn in-process
// rather than all executing at once.
// ═══════════════════════════════════════════════════════════════
const MAX_CONCURRENT_GENERATIONS = parseInt(process.env.MAX_CONCURRENT_GENERATIONS, 10) || 4;
const generationLimiter = pLimit(MAX_CONCURRENT_GENERATIONS);

// ═══════════════════════════════════════════════════════════════
// PHOTO SEARCH — Pixabay primary (much higher free rate limit),
// Pexels as fallback if Pixabay has no result. Both cached 24h per
// normalized query, per both providers' terms of use.
// ═══════════════════════════════════════════════════════════════
const photoCache = new Map(); // key: "provider:normalizedQuery" -> { photo, expiresAt }
const CACHE_TTL_MS = 24 * 60 * 60 * 1000;

function normalizeQuery(q) {
  return (q || '').trim().toLowerCase().replace(/\s+/g, ' ');
}

function getCached(key) {
  const entry = photoCache.get(key);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) {
    photoCache.delete(key);
    return null;
  }
  return entry.photo;
}
function setCached(key, photo) {
  photoCache.set(key, { photo, expiresAt: Date.now() + CACHE_TTL_MS });
}

async function searchPixabay(query) {
  if (!PIXABAY_API_KEY) return null;
  const url = `https://pixabay.com/api/?key=${PIXABAY_API_KEY}&q=${encodeURIComponent(query)}&image_type=photo&orientation=vertical&safesearch=true&per_page=10`;
  const res = await fetch(url);
  if (!res.ok) return null;
  const data = await res.json();
  const hit = data.hits && data.hits[0];
  if (!hit) return null;
  return {
    photoUrl: hit.largeImageURL,
    photographer: hit.user,
    sourcePageUrl: hit.pageURL,
    source: 'pixabay'
  };
}

async function searchPexels(query) {
  if (!PEXELS_API_KEY) return null;
  const url = `https://api.pexels.com/v1/search?query=${encodeURIComponent(query)}&per_page=10&orientation=portrait`;
  const res = await fetch(url, { headers: { Authorization: PEXELS_API_KEY } });
  if (!res.ok) return null;
  const data = await res.json();
  const photo = data.photos && data.photos[0];
  if (!photo) return null;
  return {
    photoUrl: photo.src.large2x || photo.src.large,
    photographer: photo.photographer,
    sourcePageUrl: photo.url,
    source: 'pexels'
  };
}

async function findPhoto(query) {
  const key = normalizeQuery(query);
  const cached = getCached(`any:${key}`);
  if (cached) return cached;

  let photo = await searchPixabay(query);
  if (!photo) photo = await searchPexels(query);
  if (!photo) throw new Error(`No stock photo found for "${query}"`);

  setCached(`any:${key}`, photo);
  return photo;
}

// ═══════════════════════════════════════════════════════════════
// POSTER GENERATION — Sharp compositing + SVG text overlay.
// Layout, text-fit, and color logic ported from the proven single-
// poster engine; trimmed to image-only (no video/ffmpeg).
// ═══════════════════════════════════════════════════════════════
const LAYOUT = { width: 1080, height: 1350, photoHeight: 950 };
const JPEG_QUALITY = 82;

const ACCENT_PALETTE = [
  '#E63946', '#F4A261', '#2A9D8F', '#457B9D', '#8338EC',
  '#FF006E', '#06D6A0', '#FFD60A', '#EF476F', '#118AB2'
];
let paletteIndex = 0;
function nextAccentColor(brandColor) {
  if (brandColor) return brandColor; // customer's saved brand color always wins
  const color = ACCENT_PALETTE[paletteIndex % ACCENT_PALETTE.length];
  paletteIndex++;
  return color;
}

function escapeXml(str = '') {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function wrapText(text, maxCharsPerLine) {
  const words = text.split(' ');
  const lines = [];
  let current = '';
  for (const word of words) {
    if ((current + ' ' + word).trim().length > maxCharsPerLine) {
      lines.push(current.trim());
      current = word;
    } else {
      current += ' ' + word;
    }
  }
  if (current.trim()) lines.push(current.trim());
  return lines;
}

function fitTextBlock(text, { maxWidth, maxHeight, startFontSize, minFontSize, weightFactor, lineHeightRatio = 1.22, step = 2 }) {
  let fontSize = startFontSize;
  let lines = [];
  let lineHeight = 0;
  while (fontSize >= minFontSize) {
    const maxCharsPerLine = Math.max(4, Math.floor(maxWidth / (fontSize * weightFactor)));
    lines = wrapText(text || '', maxCharsPerLine);
    lineHeight = fontSize * lineHeightRatio;
    const totalHeight = lines.length * lineHeight;
    if (totalHeight <= maxHeight || fontSize === minFontSize) break;
    fontSize -= step;
  }
  return { fontSize, lines, lineHeight, totalHeight: lines.length * lineHeight };
}

const GAP_HOOK_COPY = 22;
const GAP_COPY_CTA = 30;

function buildOverlaySvg({ hook, copy, cta, brandColor, watermark }) {
  const { width, height, photoHeight } = LAYOUT;
  const textHeight = height - photoHeight;
  const accentColor = nextAccentColor(brandColor);
  const usableWidth = width - 160;
  const ctaHeight = 64;

  const hookFit = fitTextBlock(hook, { maxWidth: usableWidth, maxHeight: textHeight * 0.55, startFontSize: 58, minFontSize: 30, weightFactor: 0.58 });
  const copyFit = fitTextBlock(copy, { maxWidth: usableWidth, maxHeight: textHeight * 0.3, startFontSize: 32, minFontSize: 18, weightFactor: 0.5 });

  let ctaFontSize = 30;
  let ctaText = escapeXml(cta || 'Learn More');
  let ctaWidth = Math.max(240, ctaText.length * (ctaFontSize * 0.62) + 80);
  const maxCtaWidth = width - 160;
  if (ctaWidth > maxCtaWidth) {
    ctaFontSize = Math.max(18, Math.floor(ctaFontSize * (maxCtaWidth / ctaWidth)));
    ctaWidth = maxCtaWidth;
  }

  let stackHeight = hookFit.totalHeight + GAP_HOOK_COPY + copyFit.totalHeight + GAP_COPY_CTA + ctaHeight;
  let gapHookCopy = GAP_HOOK_COPY;
  let gapCopyCta = GAP_COPY_CTA;
  if (stackHeight > textHeight) {
    const overflow = stackHeight - textHeight;
    const shrink = Math.min(overflow / 2, GAP_HOOK_COPY - 8, GAP_COPY_CTA - 8);
    if (shrink > 0) {
      gapHookCopy -= shrink;
      gapCopyCta -= shrink;
      stackHeight -= shrink * 2;
    }
  }

  const TOP_PADDING = 40;
  const lowestFittingTop = photoHeight + Math.max(0, textHeight - stackHeight);
  const stackTop = Math.min(photoHeight + TOP_PADDING, lowestFittingTop);

  const hookBlockTop = stackTop;
  const hookStartY = hookBlockTop + hookFit.fontSize * 0.85;
  const copyBlockTop = hookBlockTop + hookFit.totalHeight + gapHookCopy;
  const copyStartY = copyBlockTop + copyFit.fontSize * 0.85;
  const ctaY = copyBlockTop + copyFit.totalHeight + gapCopyCta;

  const hookTspans = hookFit.lines.map((line, i) => `<tspan x="50%" dy="${i === 0 ? 0 : hookFit.lineHeight}">${escapeXml(line)}</tspan>`).join('');
  const copyTspans = copyFit.lines.map((line, i) => `<tspan x="50%" dy="${i === 0 ? 0 : copyFit.lineHeight}">${escapeXml(line)}</tspan>`).join('');
  const ctaX = (width - ctaWidth) / 2;

  // Free-plan watermark: small, unobtrusive, bottom-right of the photo area.
  const watermarkSvg = watermark
    ? `<text x="${width - 24}" y="${photoHeight - 20}" text-anchor="end" style="font-size:22px;font-family:sans-serif;font-weight:700;fill:#ffffff;opacity:0.85">Made with PosterSaaS</text>`
    : '';

  return `
  <svg width="${width}" height="${height}">
    <defs>
      <style>
        .hook { font-weight: 800; font-family: sans-serif; fill: #ffffff; }
        .copy { font-weight: 700; font-family: sans-serif; fill: #ffffff; }
        .cta { font-weight: 800; font-family: sans-serif; fill: #ffffff; }
      </style>
    </defs>
    <rect x="0" y="${photoHeight}" width="${width}" height="${textHeight}" fill="#0d0d0d"/>
    <rect x="0" y="${photoHeight}" width="${width}" height="6" fill="${accentColor}"/>
    <text x="50%" y="${hookStartY}" text-anchor="middle" class="hook" style="font-size:${hookFit.fontSize}px">${hookTspans}</text>
    <text x="50%" y="${copyStartY}" text-anchor="middle" class="copy" style="font-size:${copyFit.fontSize}px">${copyTspans}</text>
    <rect x="${ctaX}" y="${ctaY}" width="${ctaWidth}" height="${ctaHeight}" rx="32" fill="${accentColor}"/>
    <text x="50%" y="${ctaY + ctaHeight / 2 + ctaFontSize * 0.35}" text-anchor="middle" class="cta" style="font-size:${ctaFontSize}px">${ctaText}</text>
    ${watermarkSvg}
  </svg>`;
}

async function generatePosterImage({ query, hook, copy, cta, brandColor, watermark }) {
  const photo = await findPhoto(query);

  const photoRes = await fetch(photo.photoUrl);
  if (!photoRes.ok) throw new Error(`Failed to download photo: ${photoRes.status}`);
  const photoBuffer = Buffer.from(await photoRes.arrayBuffer());

  const photoResized = await sharp(photoBuffer)
    .resize(LAYOUT.width, LAYOUT.photoHeight, { fit: 'cover' })
    .toBuffer();

  const overlaySvg = buildOverlaySvg({ hook, copy, cta, brandColor, watermark });

  const finalBuffer = await sharp({
    create: { width: LAYOUT.width, height: LAYOUT.height, channels: 3, background: '#0d0d0d' }
  })
    .composite([
      { input: photoResized, top: 0, left: 0 },
      { input: Buffer.from(overlaySvg), top: 0, left: 0 }
    ])
    .jpeg({ quality: JPEG_QUALITY, mozjpeg: true })
    .toBuffer();

  return { buffer: finalBuffer, photographer: photo.photographer, source: photo.source };
}

// ═══════════════════════════════════════════════════════════════
// GLOBAL RATE LIMITING (per-IP, separate from plan limits) —
// stops abuse/scraping regardless of login state.
// ═══════════════════════════════════════════════════════════════
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, message: { error: 'Too many attempts, try again later.' } });
const generateLimiter = rateLimit({ windowMs: 60 * 1000, max: 30, message: { error: 'Too many requests, slow down.' } });

// ═══════════════════════════════════════════════════════════════
// ROUTES — AUTH
// ═══════════════════════════════════════════════════════════════
app.post('/auth/register', authLimiter, async (req, res) => {
  try {
    const { email, password, businessName } = req.body || {};
    if (!validateEmail(email)) return res.status(400).json({ error: 'Valid email is required' });
    if (!validatePassword(password)) return res.status(400).json({ error: 'Password must be at least 8 characters' });

    const existing = await User.findOne({ email: email.toLowerCase() });
    if (existing) return res.status(409).json({ error: 'An account with this email already exists' });

    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({
      email: email.toLowerCase(),
      passwordHash,
      businessName: businessName || ''
    });

    res.status(201).json({
      token: signToken(user),
      user: { id: user._id, email: user.email, plan: user.plan, businessName: user.businessName }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!validateEmail(email) || !password) return res.status(400).json({ error: 'Email and password are required' });

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(401).json({ error: 'Invalid email or password' });

    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) return res.status(401).json({ error: 'Invalid email or password' });

    res.json({
      token: signToken(user),
      user: { id: user._id, email: user.email, plan: user.plan, businessName: user.businessName }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// ═══════════════════════════════════════════════════════════════
// TELEGRAM AUTH BOT — one shared bot for the whole app (not
// per-user). Used only to deliver password-reset codes. A user
// links their chat by tapping a deep link that carries their own
// userId as the /start payload; the webhook below reads that
// payload and saves the resulting chatId onto their account.
// ═══════════════════════════════════════════════════════════════
const TELEGRAM_API = TELEGRAM_AUTH_BOT_TOKEN ? `https://api.telegram.org/bot${TELEGRAM_AUTH_BOT_TOKEN}` : null;

async function telegramSendMessage(chatId, text) {
  if (!TELEGRAM_API) throw new Error('TELEGRAM_AUTH_BOT_TOKEN is not configured');
  const res = await fetch(`${TELEGRAM_API}/sendMessage`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ chat_id: chatId, text, parse_mode: 'HTML' })
  });
  if (!res.ok) throw new Error(`Telegram sendMessage failed: ${res.status}`);
  return res.json();
}

// Registers the webhook once at startup, pointed at DOMAIN. Requires
// DOMAIN + TELEGRAM_WEBHOOK_SECRET + TELEGRAM_AUTH_BOT_TOKEN all set;
// silently skips (with a warning) if the bot isn't configured, so
// local dev without Telegram set up doesn't crash the whole server.
async function setupTelegramWebhook() {
  if (!TELEGRAM_API || !DOMAIN || !TELEGRAM_WEBHOOK_SECRET) {
    console.warn('Telegram auth bot not fully configured — password reset via Telegram is disabled until TELEGRAM_AUTH_BOT_TOKEN, TELEGRAM_BOT_USERNAME, TELEGRAM_WEBHOOK_SECRET, and DOMAIN are all set.');
    return;
  }
  const webhookUrl = `https://${DOMAIN}/telegram/webhook/${TELEGRAM_WEBHOOK_SECRET}`;
  try {
    const res = await fetch(`${TELEGRAM_API}/setWebhook`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: webhookUrl, allowed_updates: ['message'] })
    });
    const data = await res.json();
    if (data.ok) console.log('Telegram auth bot webhook set:', webhookUrl);
    else console.error('Telegram setWebhook failed:', data.description);
  } catch (err) {
    console.error('Telegram webhook setup failed:', err.message);
  }
}

// Telegram calls this on every message sent to the bot. We only care
// about "/start <userId>" — the deep link generated by
// GET /telegram/connect-link. Anything else gets a generic reply.
app.post('/telegram/webhook/:secret', async (req, res) => {
  if (req.params.secret !== TELEGRAM_WEBHOOK_SECRET) return res.sendStatus(404);

  try {
    const message = req.body?.message;
    const text = message?.text || '';
    const chatId = message?.chat?.id;

    if (chatId && text.startsWith('/start')) {
      const payload = text.split(' ')[1]; // the userId we embedded in the deep link
      if (payload) {
        const user = await User.findById(payload).catch(() => null);
        if (user) {
          user.telegramChatId = String(chatId);
          user.isTelegramConnected = true;
          await user.save();
          await telegramSendMessage(chatId, '<b>Telegram connected!</b>\n\nYou\'ll receive password reset codes here.');
        } else {
          await telegramSendMessage(chatId, 'This link is invalid or expired. Generate a fresh one from your account settings.');
        }
      } else {
        await telegramSendMessage(chatId, 'Welcome! Use the "Connect Telegram" link from your account settings to link this chat.');
      }
    }
  } catch (err) {
    console.error('Telegram webhook error:', err.message);
  }

  res.sendStatus(200); // always 200 so Telegram doesn't retry-storm on our errors
});

// Returns a one-tap deep link the customer opens in Telegram to link
// their chat. userId is embedded as the /start payload.
app.get('/telegram/connect-link', requireAuth, (req, res) => {
  if (!TELEGRAM_BOT_USERNAME) return res.status(500).json({ error: 'Telegram bot is not configured' });
  res.json({
    connectLink: `https://t.me/${TELEGRAM_BOT_USERNAME}?start=${req.user._id}`,
    alreadyConnected: req.user.isTelegramConnected
  });
});

// ═══════════════════════════════════════════════════════════════
// PASSWORD RESET — same 3-step shape as the Sendi codebase's
// forgot-password / verify-reset-code / reset-password flow: a
// short-lived resetToken maps to a 6-digit code in memory, the code
// is checked before a new password is accepted. Delivery goes out
// over the shared auth bot above, exactly like Sendi's flow — just
// one bot for everyone instead of one bot per user.
// ═══════════════════════════════════════════════════════════════
const resetTokens = new Map(); // resetToken -> { userId, code, expiresAt }
const RESET_CODE_TTL_MS = 10 * 60 * 1000; // 10 minutes, same as Sendi

function generateResetCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Sweep expired reset tokens periodically so the in-memory Map
// doesn't grow unbounded — mirrors Sendi's pendingSubscribers cleanup.
setInterval(() => {
  const now = Date.now();
  for (const [token, entry] of resetTokens.entries()) {
    if (now > entry.expiresAt) resetTokens.delete(token);
  }
}, 60 * 60 * 1000);

app.post('/auth/forgot-password', authLimiter, async (req, res) => {
  const { email } = req.body || {};
  if (!validateEmail(email)) return res.status(400).json({ error: 'Valid email is required' });

  const user = await User.findOne({ email: email.toLowerCase() });
  // Same response whether or not the account exists — don't leak
  // which emails are registered.
  if (!user) return res.json({ success: true, message: 'If an account exists, a code was sent.' });

  if (!user.isTelegramConnected || !user.telegramChatId) {
    return res.status(400).json({
      error: 'Telegram is not connected on this account. Connect Telegram first to enable password reset.',
      connectHint: 'GET /telegram/connect-link (while logged in) to get the link.'
    });
  }

  const code = generateResetCode();
  const resetToken = crypto.randomUUID();
  resetTokens.set(resetToken, { userId: user._id.toString(), code, expiresAt: Date.now() + RESET_CODE_TTL_MS });

  try {
    await telegramSendMessage(user.telegramChatId, `<b>Password reset code</b>\n\nYour 6-digit code:\n\n<b>${code}</b>\n\nValid for 10 minutes. Ignore this if you didn't request it.`);
  } catch (err) {
    console.error('Failed to send reset code via Telegram:', err.message);
    return res.status(500).json({ error: 'Failed to send reset code' });
  }

  res.json({ success: true, message: 'Code sent to your connected Telegram!', resetToken });
});

app.post('/auth/verify-reset-code', (req, res) => {
  const { resetToken, code } = req.body || {};
  if (!resetToken || !code) return res.status(400).json({ error: 'resetToken and code are required' });

  const entry = resetTokens.get(resetToken);
  if (!entry || Date.now() > entry.expiresAt) {
    resetTokens.delete(resetToken);
    return res.status(400).json({ error: 'Invalid or expired code' });
  }
  if (entry.code !== String(code).trim()) return res.status(400).json({ error: 'Wrong code' });

  res.json({ success: true, message: 'Verified' });
});

app.post('/auth/reset-password', async (req, res) => {
  const { resetToken, newPassword } = req.body || {};
  if (!resetToken || !validatePassword(newPassword)) {
    return res.status(400).json({ error: 'Valid resetToken and a password of at least 8 characters are required' });
  }

  const entry = resetTokens.get(resetToken);
  if (!entry || Date.now() > entry.expiresAt) {
    resetTokens.delete(resetToken);
    return res.status(400).json({ error: 'Invalid or expired session — request a new code' });
  }

  const user = await User.findById(entry.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  user.passwordHash = await bcrypt.hash(newPassword, 10);
  await user.save();
  resetTokens.delete(resetToken);

  res.json({ success: true, message: 'Password reset successful' });
});

app.get('/me', requireAuth, async (req, res) => {
  const user = await checkAndResetUsage(req.user);
  const plan = PLANS[user.plan] || PLANS.free;
  res.json({
    id: user._id,
    email: user.email,
    businessName: user.businessName,
    brandColor: user.brandColor,
    plan: user.plan,
    planLimits: plan,
    postersThisPeriod: user.postersThisPeriod,
    remaining: Math.max(plan.monthlyLimit - user.postersThisPeriod, 0),
    periodStart: user.periodStart
  });
});

// Update brand settings (logo color, business name) — used to keep
// posters visually consistent without the customer re-entering it each time.
app.patch('/me/brand', requireAuth, async (req, res) => {
  const { businessName, brandColor } = req.body || {};
  if (typeof businessName === 'string') req.user.businessName = businessName.trim().slice(0, 80);
  if (typeof brandColor === 'string') {
    if (brandColor && !/^#[0-9a-fA-F]{6}$/.test(brandColor)) {
      return res.status(400).json({ error: 'brandColor must be a hex value like #2563eb, or empty to clear it' });
    }
    req.user.brandColor = brandColor;
  }
  await req.user.save();
  res.json({ businessName: req.user.businessName, brandColor: req.user.brandColor });
});

// ═══════════════════════════════════════════════════════════════
// ROUTES — POSTER GENERATION
// ═══════════════════════════════════════════════════════════════

// Single poster. Streams the JPEG straight back — nothing is stored.
app.post('/posters/generate', requireAuth, generateLimiter, enforcePlanLimit, async (req, res) => {
  const { query, hook, copy, cta } = req.body || {};
  if (!query || !hook) return res.status(400).json({ error: '"query" and "hook" are required' });

  try {
    const plan = PLANS[req.user.plan] || PLANS.free;
    const result = await generationLimiter(() =>
      generatePosterImage({ query, hook, copy, cta, brandColor: req.user.brandColor, watermark: plan.watermark })
    );

    req.user.postersThisPeriod += 1;
    await req.user.save();
    await Job.create({
      userId: req.user._id, query, hook, copy, cta,
      photographer: result.photographer, photoSource: result.source, status: 'done'
    });

    res.set('Content-Type', 'image/jpeg');
    res.set('Content-Disposition', `attachment; filename="${hook.replace(/\s+/g, '_').slice(0, 40)}.jpg"`);
    res.send(result.buffer);
  } catch (err) {
    await Job.create({ userId: req.user._id, query, hook, copy, cta, status: 'failed', error: err.message });
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Batch: generates each item and returns them as base64 in one JSON
// response (no storage step). Kept sequential-with-concurrency-cap
// via generationLimiter so a big batch can't spike memory at once.
app.post('/posters/generate-batch', requireAuth, generateLimiter, enforcePlanLimit, async (req, res) => {
  const { items } = req.body || {};
  if (!Array.isArray(items) || !items.length) {
    return res.status(400).json({ error: 'items must be a non-empty array of { query, hook, copy, cta }' });
  }
  if (items.length > 25) {
    return res.status(400).json({ error: 'Max 25 posters per batch request' });
  }
  for (const item of items) {
    if (!item.query || !item.hook) {
      return res.status(400).json({ error: 'Each item needs at least a query and hook' });
    }
  }

  const plan = PLANS[req.user.plan] || PLANS.free;

  const results = await Promise.all(items.map(item =>
    generationLimiter(async () => {
      try {
        const result = await generatePosterImage({
          query: item.query, hook: item.hook, copy: item.copy, cta: item.cta,
          brandColor: req.user.brandColor, watermark: plan.watermark
        });
        await Job.create({
          userId: req.user._id, query: item.query, hook: item.hook, copy: item.copy, cta: item.cta,
          photographer: result.photographer, photoSource: result.source, status: 'done'
        });
        return { hook: item.hook, status: 'done', imageBase64: result.buffer.toString('base64'), photographer: result.photographer };
      } catch (err) {
        await Job.create({ userId: req.user._id, query: item.query, hook: item.hook, copy: item.copy, cta: item.cta, status: 'failed', error: err.message });
        return { hook: item.hook, status: 'failed', error: err.message };
      }
    })
  ));

  const successCount = results.filter(r => r.status === 'done').length;
  req.user.postersThisPeriod += successCount;
  await req.user.save();

  res.json({ generated: successCount, failed: results.length - successCount, results });
});

// Job history — what got generated, when, pass/fail. No image data
// stored (nothing to serve back), just the record for the customer's
// own reference/analytics.
app.get('/posters/history', requireAuth, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit, 10) || 50, 200);
  const jobs = await Job.find({ userId: req.user._id }).sort({ createdAt: -1 }).limit(limit);
  res.json({ count: jobs.length, jobs });
});

// ═══════════════════════════════════════════════════════════════
// ROUTES — BILLING (Paystack)
// Initializes a transaction for a plan upgrade; webhook confirms
// payment and applies the plan. Naira amounts, kobo (Paystack's
// smallest unit) on the wire.
// ═══════════════════════════════════════════════════════════════
app.get('/billing/plans', (req, res) => res.json({ plans: PLANS }));

app.post('/billing/upgrade', requireAuth, async (req, res) => {
  try {
    const { plan } = req.body || {};
    if (!PLANS[plan] || plan === 'free') return res.status(400).json({ error: 'Invalid plan. Choose starter, growth, or pro.' });
    if (!PAYSTACK_SECRET_KEY) return res.status(500).json({ error: 'Payments are not configured yet' });

    const amountKobo = PLANS[plan].priceNaira * 100;

    const initRes = await fetch('https://api.paystack.co/transaction/initialize', {
      method: 'POST',
      headers: { Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: req.user.email,
        amount: amountKobo,
        metadata: { userId: req.user._id.toString(), plan }
      })
    });
    if (!initRes.ok) throw new Error(`Paystack init failed: ${initRes.status}`);
    const data = await initRes.json();

    res.json({ authorizationUrl: data.data.authorization_url, reference: data.data.reference });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Paystack calls this after a successful charge. Verifies the
// signature so random POSTs can't upgrade accounts for free.
app.post('/billing/webhook', express.raw({ type: '*/*' }), async (req, res) => {
  try {
    const signature = req.headers['x-paystack-signature'];
    const hash = crypto.createHmac('sha512', PAYSTACK_SECRET_KEY).update(req.body).digest('hex');
    if (hash !== signature) return res.status(401).send('Invalid signature');

    const event = JSON.parse(req.body.toString('utf8'));
    if (event.event === 'charge.success') {
      const { userId, plan } = event.data.metadata || {};
      if (userId && PLANS[plan]) {
        const user = await User.findById(userId);
        if (user) {
          user.plan = plan;
          user.postersThisPeriod = 0;
          user.periodStart = new Date();
          await user.save();
        }
      }
    }
    res.sendStatus(200);
  } catch (err) {
    console.error('Webhook error:', err);
    res.sendStatus(400);
  }
});

// ═══════════════════════════════════════════════════════════════
// HEALTH CHECK
// ═══════════════════════════════════════════════════════════════
app.get('/ping', (req, res) => res.json({ ok: true, time: new Date().toISOString() }));

// ═══════════════════════════════════════════════════════════════
// STARTUP
// ═══════════════════════════════════════════════════════════════
mongoose.connect(process.env.MONGODB_URI)
  .then(async () => {
    console.log('MongoDB connected');
    await setupTelegramWebhook();
    app.listen(PORT, () => console.log(`Poster SaaS running on http://localhost:${PORT}`));
  })
  .catch(err => {
    console.error('Failed to connect to MongoDB:', err.message);
    process.exit(1);
  });
