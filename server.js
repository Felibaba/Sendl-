require('dotenv').config();

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const rateLimit = require('express-rate-limit');
const { Telegraf } = require('telegraf');
const path = require('path');
const mongoose = require('mongoose');
const axios = require('axios');
const crypto = require('crypto');
const IORedis = require('ioredis');
const { Queue, Worker } = require('bullmq');
const sanitizeHtml = require('sanitize-html');

// Bump this string any time you deploy a fix and want an unambiguous way
// to confirm from the OUTSIDE (via /ping or the boot logs) that the
// server actually running is the version you think it is.
const BUILD_TAG = 'telegram-connect-route-2026-08-04-inputvalidation-v1';

const app = express();
console.log('=== BUILD TAG: ' + BUILD_TAG + ' ===');
const PORT = process.env.PORT || 3000;
app.set('trust proxy', 3);

app.use(function(req, res, next) {
  res.setHeader('X-Sendm-Build', BUILD_TAG);
  next();
});

// Two SEPARATE readiness flags: auth (login/2FA) must never be blocked
// by the broadcast bot pool.
let authBotReady = false;
let serverReady = false;

// ==================== CONFIG & SECRETS ====================
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_weak_secret_change_me_immediately';
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY || 'sk_test_fallback_change_me';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'midas';
const DOMAIN = process.env.DOMAIN;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;

// Shared Paystack account model: this single /api/subscription/webhook
// endpoint may receive charge events that were actually initiated by a
// DIFFERENT product on the same Paystack account. Every payment this app
// initiates is tagged with metadata.app = PAYSTACK_APP_TAG at initiate time.
// At webhook time, any event whose metadata.app does NOT match gets
// forwarded verbatim (raw body + original signature header) to
// OTHER_SAAS_WEBHOOK_URL instead of being processed here.
const PAYSTACK_APP_TAG = process.env.PAYSTACK_APP_TAG || 'sendm';
const OTHER_SAAS_WEBHOOK_URL = process.env.OTHER_SAAS_WEBHOOK_URL || '';

if (!DOMAIN) {
  console.error('ERROR: DOMAIN environment variable is required for webhooks!');
  process.exit(1);
}

if (!WEBHOOK_SECRET || !WEBHOOK_SECRET.trim()) {
  console.error('ERROR: WEBHOOK_SECRET must be set in env and stable across restarts/instances.');
  process.exit(1);
}

if (JWT_SECRET.includes('fallback')) {
  console.warn('WARNING: JWT_SECRET not set in .env! Using insecure fallback.');
}
if (PAYSTACK_SECRET_KEY.startsWith('sk_test_fallback')) {
  console.warn('WARNING: PAYSTACK_SECRET_KEY not set in .env!');
}

const MONTHLY_PRICE_KOBO = 150000; // NGN 5,000 in kobo

// ==================== INPUT VALIDATION: LENGTH CAPS & CHARACTER RULES ====================
// Centralized here so every route that accepts free-text user input enforces
// a sane upper bound BEFORE that value touches the DB, gets hashed, or gets
// echoed into a rendered page / outgoing Telegram message. Unbounded strings
// are a cheap DoS vector (huge bcrypt hashes, huge broadcast signatures,
// huge rendered pages) even when they're not "malicious" in a script-injection
// sense.

// Human name (contact form name, account fullName). Unicode letters/marks so
// non-Latin-script names aren't blocked, plus spaces/hyphens/apostrophes/periods
// for things like "Mary-Jane", "O'Brien", "J.R.".
const NAME_MAX_LENGTH = 80;
const NAME_REGEX = /^[\p{L}\p{M}\s.'-]{1,80}$/u;

// Email: reasonable RFC-ish check + hard length cap (matches common practical
// limits; local part + @ + domain kept well under mail-system maximums).
const EMAIL_MAX_LENGTH = 254;
const EMAIL_REGEX = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,24}$/;

// Contact field on subscribe forms accepts EITHER a phone number OR an email.
// Phone branch was already capped (7-20 chars); email branch previously had
// no upper bound at all, so a huge string ending in "@x.co" would pass.
const CONTACT_REGEX = new RegExp(
  '^(\\+?[0-9\\s\\-\\(\\)]{7,20}|[a-zA-Z0-9._%+-]{1,64}@[a-zA-Z0-9.-]{1,190}\\.[a-zA-Z]{2,24})$'
);

// Passwords: bcrypt silently truncates at 72 BYTES, so anything beyond that
// is wasted (and hashing a multi-KB/MB string first is needless CPU work an
// attacker can abuse). Keep a generous but firm ceiling, plus the existing
// minimum of 6 used at reset time, applied consistently everywhere.
const PASSWORD_MIN_LENGTH = 6;
const PASSWORD_MAX_LENGTH = 72;

// Titles for landing pages / forms - shown in dashboards and rendered pages.
const TITLE_MAX_LENGTH = 150;

// Welcome message sent to new subscribers via Telegram.
const WELCOME_MESSAGE_MAX_LENGTH = 2000;

// Bulk contact deletion - cap how many contacts can be sent in one request
// so a single call can't force a huge $in query.
const CONTACTS_DELETE_MAX = 1000;

const MAX_MSG_LENGTH = 4000;
const BATCH_SIZE = 25;
// Lowered from 8000 -> 2000ms. Safe to lower because message-level pacing
// is now handled by the PER-BOT rate limiter below (which is what actually
// protects each bot token from Telegram's ~30 msg/sec ceiling), not by this
// inter-batch sleep. This interval now just avoids hammering Mongo/Redis
// with back-to-back batch reads for very large lists.
const BATCH_INTERVAL_MS = 2000;

function isNonEmptyString(val) {
  return typeof val === 'string' && val.trim().length > 0;
}

// Validates + trims a human name field (contact form name, account fullName).
// Returns { ok: true, value } or { ok: false, error }.
function validateName(raw, fieldLabel) {
  if (!isNonEmptyString(raw)) return { ok: false, error: (fieldLabel || 'Name') + ' is required' };
  const trimmed = raw.trim();
  if (trimmed.length > NAME_MAX_LENGTH) {
    return { ok: false, error: (fieldLabel || 'Name') + ' must be ' + NAME_MAX_LENGTH + ' characters or fewer' };
  }
  if (!NAME_REGEX.test(trimmed)) {
    return { ok: false, error: (fieldLabel || 'Name') + ' contains invalid characters' };
  }
  return { ok: true, value: trimmed };
}

// Validates + normalizes an email field.
function validateEmail(raw) {
  if (!isNonEmptyString(raw)) return { ok: false, error: 'Email is required' };
  const trimmed = raw.trim().toLowerCase();
  if (trimmed.length > EMAIL_MAX_LENGTH) {
    return { ok: false, error: 'Email must be ' + EMAIL_MAX_LENGTH + ' characters or fewer' };
  }
  if (!EMAIL_REGEX.test(trimmed)) {
    return { ok: false, error: 'Please provide a valid email address' };
  }
  return { ok: true, value: trimmed };
}

// Validates a password's length (used both at registration and reset).
function validatePasswordLength(raw) {
  if (typeof raw !== 'string' || raw.length < PASSWORD_MIN_LENGTH) {
    return { ok: false, error: 'Password must be at least ' + PASSWORD_MIN_LENGTH + ' characters' };
  }
  if (raw.length > PASSWORD_MAX_LENGTH) {
    return { ok: false, error: 'Password must be ' + PASSWORD_MAX_LENGTH + ' characters or fewer' };
  }
  return { ok: true, value: raw };
}

// Validates a title field (landing pages / forms).
function validateTitle(raw) {
  if (!isNonEmptyString(raw)) return { ok: false, error: 'Title is required' };
  const trimmed = raw.trim();
  if (trimmed.length > TITLE_MAX_LENGTH) {
    return { ok: false, error: 'Title must be ' + TITLE_MAX_LENGTH + ' characters or fewer' };
  }
  return { ok: true, value: trimmed };
}

// ==================== REDIS + BULLMQ ====================
let redisConnection;
if (process.env.REDIS_URL) {
  redisConnection = new IORedis(process.env.REDIS_URL, { maxRetriesPerRequest: null, enableReadyCheck: false });
} else {
  console.warn('WARNING: REDIS_URL not set in .env, falling back to localhost:6379');
  redisConnection = new IORedis({ host: 'localhost', port: 6379, maxRetriesPerRequest: null, enableReadyCheck: false });
}
const broadcastQueue = new Queue('telegram-broadcasts', { connection: redisConnection });

// ==================== MONGODB CONNECTION ====================
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/sendm';
console.log('Connecting to MongoDB:', MONGODB_URI.replace(/:([^:@]+)@/, ':****@'));

mongoose.connect(MONGODB_URI, {
  serverSelectionTimeoutMS: 30000,
  socketTimeoutMS: 45000,
  connectTimeoutMS: 30000,
}).then(function() {
  console.log('MongoDB connected');
}).catch(function(err) {
  console.error('MongoDB connection failed:', err.message);
  process.exit(1);
});

// ==================== SCHEMAS & MODELS ====================
const userSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  fullName: String,
  email: { type: String, required: true, unique: true, lowercase: true },
  password: String,
  telegramChatId: String,
  isTelegramConnected: { type: Boolean, default: false },
  isSubscribed: { type: Boolean, default: false },
  subscriptionEndDate: Date,
  subscriptionPlan: String,
  pendingPaymentReference: String,
  createdAt: { type: Date, default: Date.now },
}, { timestamps: true });

const landingPageSchema = new mongoose.Schema({
  shortId: { type: String, required: true, unique: true },
  userId: { type: String, required: true },
  title: String,
  config: Object,
}, { timestamps: true });

const formPageSchema = new mongoose.Schema({
  shortId: { type: String, required: true, unique: true },
  userId: { type: String, required: true },
  title: String,
  state: Object,
  welcomeMessage: String,
}, { timestamps: true });

// NOTE: botIndex is assigned ONCE at signup time and never recomputed.
// This is what makes it safe to add/remove bots from BROADCAST_BOT_TOKENS
// later without breaking delivery to contacts who already connected.
const contactSchema = new mongoose.Schema({
  userId: { type: String, required: true },
  shortId: String,
  name: String,
  contact: { type: String, required: true },
  telegramChatId: String,
  telegramUsername: String,
  botIndex: { type: Number, default: null },
  status: { type: String, default: 'pending' },
  submittedAt: Date,
  subscribedAt: Date,
  unsubscribedAt: Date,
}, { timestamps: true });

const pendingSubscriberSchema = new mongoose.Schema({
  payload: { type: String, required: true, unique: true },
  userId: { type: String, required: true },
  shortId: String,
  name: String,
  contact: { type: String, required: true },
  botIndex: { type: Number, required: true }, // carries the locked-in assignment from subscribe -> bot start
  createdAt: { type: Date, default: Date.now, expires: 1800 } // 30 min TTL
});

const scheduledBroadcastSchema = new mongoose.Schema({
  broadcastId: { type: String, required: true, unique: true },
  userId: { type: String, required: true },
  message: String,
  recipients: { type: String, default: 'all' },
  scheduledTime: Date,
  status: { type: String, default: 'pending' },
}, { timestamps: true });

const broadcastDailySchema = new mongoose.Schema({
  userId: { type: String, required: true },
  date: { type: String, required: true },
  count: { type: Number, default: 1 },
}, { timestamps: true });

const adminSettingsSchema = new mongoose.Schema({
  dailyBroadcastLimit: { type: Number, default: 3, min: 1 },
  maxLandingPages: { type: Number, default: 5, min: 1 },
  maxForms: { type: Number, default: 5, min: 1 },
}, { timestamps: true });

adminSettingsSchema.statics.getSettings = async function() {
  let settings = await this.findOne();
  if (!settings) settings = await this.create({});
  return settings;
};
adminSettingsSchema.statics.updateSettings = async function(updates) {
  let settings = await this.findOne();
  if (!settings) settings = new this();
  Object.assign(settings, updates);
  await settings.save();
  return settings;
};

const AdminSettings = mongoose.model('AdminSettings', adminSettingsSchema);
const User = mongoose.model('User', userSchema);
const LandingPage = mongoose.model('LandingPage', landingPageSchema);
const FormPage = mongoose.model('FormPage', formPageSchema);
const Contact = mongoose.model('Contact', contactSchema);
const PendingSubscriber = mongoose.model('PendingSubscriber', pendingSubscriberSchema);
const ScheduledBroadcast = mongoose.model('ScheduledBroadcast', scheduledBroadcastSchema);
const BroadcastDaily = mongoose.model('BroadcastDaily', broadcastDailySchema);

contactSchema.index({ userId: 1 });
contactSchema.index({ userId: 1, contact: 1 });
contactSchema.index({ userId: 1, status: 1 });
contactSchema.index({ status: 1 });
contactSchema.index({ botIndex: 1 });
landingPageSchema.index({ userId: 1 });
formPageSchema.index({ userId: 1 });
scheduledBroadcastSchema.index({ userId: 1 });
scheduledBroadcastSchema.index({ status: 1 });
scheduledBroadcastSchema.index({ scheduledTime: 1 });
broadcastDailySchema.index({ userId: 1, date: 1 }, { unique: true });

// ==================== IN-MEMORY (auth-only, small scale) ====================
const resetTokens = new Map();

// ==================== PER-USER & PUBLIC CACHE WITH TTL ====================
const userCache = new Map();
const publicCache = new Map();

const TTL = {
  pages: 5 * 60 * 1000,
  forms: 5 * 60 * 1000,
  contacts: 2 * 60 * 1000,
  public: 10 * 60 * 1000
};

function getUserCache(userId) {
  let bucket = userCache.get(userId);
  if (!bucket) {
    bucket = { pages: null, forms: null, contacts: null, pagesTs: 0, formsTs: 0, contactsTs: 0, lastAccess: Date.now() };
    userCache.set(userId, bucket);
  } else {
    bucket.lastAccess = Date.now();
  }
  return bucket;
}

function invalidateUserCache(userId, type) {
  if (!type) type = 'all';
  const bucket = userCache.get(userId);
  if (!bucket) return;
  if (type === 'pages' || type === 'all') { bucket.pages = null; bucket.pagesTs = 0; }
  if (type === 'forms' || type === 'all') { bucket.forms = null; bucket.formsTs = 0; }
  if (type === 'contacts' || type === 'all') { bucket.contacts = null; bucket.contactsTs = 0; }
  bucket.lastAccess = Date.now();
}

function invalidatePublicCache(key) {
  publicCache.delete(key);
}

setInterval(function() {
  const now = Date.now();
  const INACTIVE_THRESHOLD = 30 * 60 * 1000;

  for (const [key, val] of publicCache.entries()) {
    if (now - val.timestamp > TTL.public) publicCache.delete(key);
  }
  for (const [userId, bucket] of userCache.entries()) {
    if (now - bucket.lastAccess > INACTIVE_THRESHOLD) {
      userCache.delete(userId);
      console.log('Cleaned cache for inactive user: ' + userId);
    }
  }
}, 10 * 60 * 1000);

let adminSettingsCache = { dailyBroadcastLimit: 3, maxLandingPages: 5, maxForms: 5 };

// ==================== SHARED BOT POOL ====================
const botPool = {
  authBot: null,
  broadcastBots: [],

  get poolSize() {
    return this.broadcastBots.length;
  },

  // Used ONLY at signup time to assign a brand-new contact to a bot.
  // Never used again for that contact after assignment - see contact.botIndex.
  //
  // IMPORTANT: the hash key is `userId:contactValue`, NOT just contactValue.
  // If it were only contactValue, the same physical person subscribing to
  // two different creators would ALWAYS land on the identical bot index
  // (same email/phone hashes the same way every time) - meaning both
  // creators' broadcasts would land in the SAME Telegram chat, looking like
  // one bot randomly sending unrelated content from different "senders."
  // Keying by userId+contact spreads different creators' relationships with
  // the same subscriber across different bots, so each creator gets what
  // looks like its own independent bot chat with that person.
  getBotForContact(userId, contactValue) {
    if (this.poolSize === 0) return null;
    const key = String(userId) + ':' + String(contactValue).toLowerCase().trim();
    const hash = crypto.createHash('md5').update(key).digest('hex');
    const n = parseInt(hash.slice(0, 8), 16);
    const idx = n % this.poolSize;
    return this.broadcastBots[idx] || null;
  },

  getBroadcastBotByIndex(index) {
    return this.broadcastBots[index] || null;
  },
};

async function getMeWithRetry(bot, label, maxAttempts) {
  if (!maxAttempts) maxAttempts = 5;
  let attempts = 0;
  while (attempts < maxAttempts) {
    attempts++;
    try {
      return await bot.telegram.getMe();
    } catch (err) {
      console.warn(label + ' getMe attempt ' + attempts + '/' + maxAttempts + ' failed: ' + err.message);
      if (attempts >= maxAttempts) throw err;
      await new Promise(function(r) { setTimeout(r, 5000); });
    }
  }
}

async function initAuthBot() {
  const authToken = process.env.AUTH_BOT_TOKEN;
  if (!authToken) throw new Error('AUTH_BOT_TOKEN is required - the auth bot is not optional.');

  const authBot = new Telegraf(authToken);
  authBot.webhookReply = false;
  authBot.options.webhookReply = false;
  authBot.catch(function(err) { console.error('Auth bot error:', err.message); });

  const authInfo = await getMeWithRetry(authBot, 'auth bot');
  authBot.username = authInfo.username;
  botPool.authBot = authBot;
  console.log('Auth bot ready: @' + authInfo.username);
}

async function initBroadcastPool() {
  const rawBroadcastTokens = (process.env.BROADCAST_BOT_TOKENS || '')
    .split(',').map(function(t) { return t.trim(); }).filter(Boolean);

  if (rawBroadcastTokens.length === 0) {
    throw new Error('BROADCAST_BOT_TOKENS is required - need at least 1 broadcast bot, recommend 3-4.');
  }

  for (let i = 0; i < rawBroadcastTokens.length; i++) {
    const token = rawBroadcastTokens[i];
    const bot = new Telegraf(token);
    bot.webhookReply = false;
    bot.options.webhookReply = false;
    bot.catch(function(err) { console.error('Broadcast bot[' + i + '] error:', err.message); });

    const info = await getMeWithRetry(bot, 'broadcast bot[' + i + ']');
    botPool.broadcastBots.push({ bot: bot, index: i, token: token, username: info.username });
    console.log('Broadcast bot[' + i + '] ready: @' + info.username);
  }

  console.log('Broadcast pool initialized: ' + botPool.broadcastBots.length + ' bot(s)');
}

// ==================== WEBHOOK SETUP (once per bot, at boot) ====================
async function setWebhookWithRetry(bot, url, label, maxAttempts) {
  if (!maxAttempts) maxAttempts = 5;
  let attempts = 0;
  while (attempts < maxAttempts) {
    attempts++;
    try {
      const current = await bot.telegram.getWebhookInfo();
      if (current.url === url && current.pending_update_count < 50) {
        console.log('Webhook already correct for ' + label);
        return;
      }

      await bot.telegram.deleteWebhook({ drop_pending_updates: false });

      const ok = await bot.telegram.setWebhook(url, {
        allowed_updates: ['message', 'callback_query', 'my_chat_member']
      });

      if (ok) {
        console.log('Webhook set for ' + label + ' -> ' + url);
        return;
      }
    } catch (err) {
      if (err.response && err.response.error_code === 429) {
        const retryAfter = (err.response.parameters && err.response.parameters.retry_after) || 30;
        console.warn(label + ' rate limited, waiting ' + (retryAfter + 5) + 's');
        await new Promise(function(r) { setTimeout(r, (retryAfter + 5) * 1000); });
        continue;
      }
      console.error(label + ' webhook attempt ' + attempts + ' failed: ' + err.message);
      if (attempts >= maxAttempts) throw err;
      await new Promise(function(r) { setTimeout(r, 5000); });
    }
  }
  throw new Error('Gave up setting webhook for ' + label + ' after ' + maxAttempts + ' attempts');
}

async function setupAuthWebhook() {
  const authUrl = 'https://' + DOMAIN + '/webhook/auth/' + WEBHOOK_SECRET;
  await setWebhookWithRetry(botPool.authBot, authUrl, 'auth bot');
}

async function setupBroadcastWebhooks() {
  for (const entry of botPool.broadcastBots) {
    const url = 'https://' + DOMAIN + '/webhook/broadcast/' + entry.index + '/' + WEBHOOK_SECRET;
    await setWebhookWithRetry(entry.bot, url, 'broadcast bot[' + entry.index + '] (@' + entry.username + ')');
  }
  console.log('Broadcast webhooks registered.');
}

// ==================== PER-BOT RATE LIMITER ====================
// WHY THIS EXISTS: the bot pool is SHARED across every user on the platform.
// Two different users' contacts can land on the exact same bot token (same
// botIndex), and BullMQ runs up to `concurrency: 4` broadcast jobs at once.
// Without a gate here, two users broadcasting at the same moment could push
// 50+ simultaneous sendMessage calls through one bot token, blowing past
// Telegram's ~30 msg/sec-per-bot ceiling and causing silent 429 failures
// that used to just get marked "failed" with no retry.
//
// This is a token-bucket limiter keyed PER BOT INDEX (not per job, not per
// user) so it correctly throttles the shared resource regardless of which
// job or which user is sending through it.
const BOT_RATE_LIMIT_PER_SEC = 25; // stay safely under Telegram's ~30/sec ceiling per bot
const botRateLimiters = new Map(); // botIndex -> { tokens, lastRefill, queue }

function getBotLimiter(botIndex) {
  let limiter = botRateLimiters.get(botIndex);
  if (!limiter) {
    limiter = { tokens: BOT_RATE_LIMIT_PER_SEC, lastRefill: Date.now(), queue: [] };
    botRateLimiters.set(botIndex, limiter);
  }
  return limiter;
}

function refillBotLimiter(limiter) {
  const now = Date.now();
  if (now - limiter.lastRefill >= 1000) {
    limiter.tokens = BOT_RATE_LIMIT_PER_SEC;
    limiter.lastRefill = now;
  }
}

function drainBotLimiterQueue(botIndex) {
  const limiter = getBotLimiter(botIndex);
  refillBotLimiter(limiter);
  while (limiter.tokens > 0 && limiter.queue.length > 0) {
    limiter.tokens--;
    const resolve = limiter.queue.shift();
    resolve();
  }
  if (limiter.queue.length > 0) {
    setTimeout(function() { drainBotLimiterQueue(botIndex); }, 100);
  }
}

// Every single Telegram send for a given bot MUST pass through here first.
// Resolves immediately if a token is available, otherwise queues and waits.
function acquireBotSlot(botIndex) {
  return new Promise(function(resolve) {
    const limiter = getBotLimiter(botIndex);
    refillBotLimiter(limiter);
    if (limiter.tokens > 0) {
      limiter.tokens--;
      resolve();
    } else {
      limiter.queue.push(resolve);
      setTimeout(function() { drainBotLimiterQueue(botIndex); }, 100);
    }
  });
}

// Sends one chunk through the rate limiter, with automatic retry-on-429
// using Telegram's own retry_after hint instead of just giving up and
// marking the contact as "failed" in the delivery report.
async function sendChunkWithLimiterAndRetry(entry, chatId, chunk, attempt) {
  if (!attempt) attempt = 1;
  await acquireBotSlot(entry.index);
  try {
    await entry.bot.telegram.sendMessage(chatId, chunk, { parse_mode: 'HTML' });
  } catch (err) {
    const is429 = err.response && err.response.error_code === 429;
    if (is429 && attempt <= 3) {
      const retryAfter = (err.response.parameters && err.response.parameters.retry_after) || 2;
      console.warn('Bot[' + entry.index + '] 429 - retrying in ' + retryAfter + 's (attempt ' + attempt + '/3)');
      await new Promise(function(r) { setTimeout(r, (retryAfter + 0.5) * 1000); });
      return sendChunkWithLimiterAndRetry(entry, chatId, chunk, attempt + 1);
    }
    throw err;
  }
}

// ==================== TEXT / HTML UTILITIES ====================
function escapeHtml(unsafe) {
  if (!unsafe) unsafe = '';
  return unsafe.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}

function sanitizeTelegramHtml(unsafe) {
  if (!unsafe || typeof unsafe !== 'string') return '';
  const allowedTags = new Set(['b', 'strong', 'i', 'em', 'u', 'ins', 's', 'strike', 'del', 'span', 'tg-spoiler', 'a', 'code', 'pre', 'tg-emoji', 'blockquote']);
  const allowedAttrs = { a: ['href'], 'tg-emoji': ['emoji-id'], 'blockquote': ['expandable'] };

  let clean = unsafe
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
    .replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, '')
    .replace(/on\w+="[^"]*"/gi, '')
    .replace(/javascript:/gi, '');

  clean = clean.replace(/<\/?([a-z][a-z0-9]*)\b[^>]*>/gi, function(match, tagName) {
    const tag = tagName.toLowerCase();
    if (!allowedTags.has(tag)) return '';
    if (match.startsWith('</')) return '</' + tag + '>';

    let attrs = '';
    const attrRegex = /([a-z0-9-]+)="([^"]*)"/gi;
    let attrMatch;
    while ((attrMatch = attrRegex.exec(match)) !== null) {
      const attrName = attrMatch[1].toLowerCase();
      let attrValue = attrMatch[2];
      if (allowedAttrs[tag] && allowedAttrs[tag].includes(attrName)) {
        if (attrName === 'href' && !/^https?:\/\//i.test(attrValue) && !attrValue.startsWith('/')) {
          attrValue = '#';
        }
        attrs += ' ' + attrName + '="' + attrValue.replace(/"/g, '&quot;') + '"';
      }
    }
    return '<' + tag + attrs + '>';
  });
  return clean.trim();
}

// Sanitizes the raw HTML a user pastes/builds into a landing page "form"
// block. This HTML is rendered on the PUBLIC /p/:shortId page for anyone
// who visits it, so unlike sanitizeTelegramHtml (which only ever reaches
// Telegram's own renderer) this is a real browser-facing XSS surface.
// Previously this only stripped <script> tags via regex, which does nothing
// against onerror=, javascript: hrefs, <iframe>, <object>, etc. sanitize-html
// is a real parser-based sanitizer, not a regex blocklist, so it isn't
// bypassable the same way.
const FORM_BLOCK_ALLOWED_TAGS = [
  'form', 'label', 'input', 'select', 'option', 'textarea', 'button',
  'div', 'span', 'p', 'br', 'strong', 'em', 'b', 'i', 'u', 'small',
  'ul', 'ol', 'li', 'a', 'img', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6'
];

const FORM_BLOCK_ALLOWED_ATTRIBUTES = {
  '*': ['class', 'id', 'style'],
  form: ['action', 'method', 'name'],
  input: ['type', 'name', 'placeholder', 'required', 'value', 'checked', 'min', 'max', 'maxlength', 'pattern'],
  select: ['name', 'required'],
  option: ['value', 'selected'],
  textarea: ['name', 'placeholder', 'required', 'maxlength'],
  button: ['type'],
  a: ['href', 'target', 'rel'],
  img: ['src', 'alt', 'width', 'height']
};

function sanitizeLandingPageFormHtml(rawHtml) {
  if (!rawHtml || typeof rawHtml !== 'string') return '';
  return sanitizeHtml(rawHtml, {
    allowedTags: FORM_BLOCK_ALLOWED_TAGS,
    allowedAttributes: FORM_BLOCK_ALLOWED_ATTRIBUTES,
    // Only allow href/src to actually point somewhere safe - blocks
    // javascript:, data:, vbscript:, etc.
    allowedSchemes: ['http', 'https', 'mailto'],
    allowProtocolRelative: false,
    // Belt-and-suspenders: sanitize-html already drops on* attributes
    // because they're not in allowedAttributes, and drops <style>/<script>
    // because they're not in allowedTags, but disallowedTagsMode 'discard'
    // (the default) makes that explicit rather than relying on defaults.
    disallowedTagsMode: 'discard',
    // When a disallowed tag like <style>/<script>/<noscript> is stripped,
    // also drop its inner text instead of leaving the raw JS/CSS behind as
    // a text node.
    nonTextTags: ['style', 'script', 'noscript']
  }).trim();
}

function textToHtmlForDisplay(text) {
  if (!text) return '';
  return text.replace(/\n{2,}/g, '</p><p>').replace(/\n/g, '<br>');
}

function prepareTelegramMessage(raw) {
  if (!raw || typeof raw !== 'string') return '';
  let msg = raw.trim();
  msg = msg
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/p>\s*<p[^>]*>/gi, '\n\n')
    .replace(/<p[^>]*>/gi, '')
    .replace(/<\/p>/gi, '\n')
    .replace(/<div[^>]*>/gi, '\n')
    .replace(/<\/div>/gi, '\n')
    .replace(/\n{3,}/g, '\n\n');
  return sanitizeTelegramHtml(msg);
}

// Converts plain ASCII letters/digits to Unicode "Mathematical Sans-Serif Bold"
// code points. This is the closest Telegram gets to a "beautiful custom font" -
// Telegram's message formatting has no font-family concept, so this swaps the
// actual characters for bold-styled Unicode look-alikes instead. Anything that
// isn't a plain a-z/A-Z/0-9 character (emoji, punctuation, accents) passes through
// unchanged.
function toBoldSansUnicode(str) {
  if (!str) return '';
  const upperBase = 0x1D5D4;
  const lowerBase = 0x1D5EE;
  const digitBase = 0x1D7EC;
  let out = '';
  for (const ch of str) {
    const code = ch.codePointAt(0);
    if (code >= 65 && code <= 90) out += String.fromCodePoint(upperBase + (code - 65));
    else if (code >= 97 && code <= 122) out += String.fromCodePoint(lowerBase + (code - 97));
    else if (code >= 48 && code <= 57) out += String.fromCodePoint(digitBase + (code - 48));
    else out += ch;
  }
  return out;
}

function splitTelegramMessage(text) {
  if (!text) return [];
  const chunks = [];
  let current = '';
  const lines = text.split(/\r?\n/);

  for (let i = 0; i < lines.length; i++) {
    let line = lines[i];
    while (line.length > MAX_MSG_LENGTH) {
      if (current) { chunks.push(current.trim()); current = ''; }
      chunks.push(line.substring(0, MAX_MSG_LENGTH).trim());
      line = line.substring(MAX_MSG_LENGTH);
    }
    if (current.length + line.length + (current ? 1 : 0) <= MAX_MSG_LENGTH) {
      current += (current ? '\n' : '') + line;
    } else {
      if (current) chunks.push(current.trim());
      current = line;
    }
  }
  if (current) chunks.push(current.trim());

  if (chunks.length <= 1) return chunks;
  const total = chunks.length;
  return chunks.map(function(chunk, i) {
    const header = '(' + (i + 1) + '/' + total + ')\n\n';
    return header.length + chunk.length > MAX_MSG_LENGTH ? chunk : header + chunk;
  });
}

function getTodayDateString() {
  return new Date().toISOString().slice(0, 10);
}

function hasActiveSubscription(user) {
  return user.isSubscribed && user.subscriptionEndDate && new Date(user.subscriptionEndDate) > new Date();
}

function getUserLimits(user) {
  if (hasActiveSubscription(user)) return { dailyBroadcasts: Infinity, maxLandingPages: Infinity, maxForms: Infinity };
  return {
    dailyBroadcasts: adminSettingsCache.dailyBroadcastLimit,
    maxLandingPages: adminSettingsCache.maxLandingPages,
    maxForms: adminSettingsCache.maxForms
  };
}

async function incrementDailyBroadcast(userId) {
  const today = getTodayDateString();
  const record = await BroadcastDaily.findOneAndUpdate(
    { userId: userId, date: today }, { $inc: { count: 1 } }, { upsert: true, new: true }
  );
  return record.count;
}

function generate2FACode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

async function send2FACodeViaBot(user, code) {
  if (!user.isTelegramConnected || !user.telegramChatId) return false;
  try {
    await botPool.authBot.telegram.sendMessage(
      user.telegramChatId,
      'Security Alert - Password Reset\n\nYour 6-digit code:\n\n<b>' + code + '</b>\n\nValid for 10 minutes.',
      { parse_mode: 'HTML' }
    );
    return true;
  } catch (err) {
    console.error('Failed to send 2FA code:', err.message);
    return false;
  }
}

// ==================== BOT HANDLERS ====================
function registerAuthBotHandlers(authBot) {
  authBot.start(async function(ctx) {
    const payload = ctx.startPayload || '';
    const chatId = ctx.chat.id.toString();

    if (!payload) {
      await ctx.replyWithHTML('<b>Sendm Security Bot</b>\n\nUse the connect link from your Sendm dashboard to link 2FA.');
      return;
    }

    const user = await User.findOne({ id: payload });
    if (!user) {
      await ctx.replyWithHTML('<b>Invalid or expired link.</b>\n\nPlease generate a new connect link from your dashboard.');
      return;
    }

    user.telegramChatId = chatId;
    user.isTelegramConnected = true;
    await user.save();

    await ctx.replyWithHTML('<b>Sendm 2FA Connected Successfully!</b>\n\nYou will receive login codes here.');
  });

  authBot.command('status', async function(ctx) {
    const chatId = ctx.chat.id.toString();
    const user = await User.findOne({ telegramChatId: chatId, isTelegramConnected: true });
    if (!user) {
      await ctx.replyWithHTML('No Sendm account is linked to this chat.');
      return;
    }
    await ctx.replyWithHTML('<b>Sendm 2FA Status</b>\nAccount: <code>' + user.email + '</code>\nStatus: <b>Connected</b>');
  });
}

function registerBroadcastBotHandlers(bot, botIndex) {
  bot.start(async function(ctx) {
    const payload = ctx.startPayload || '';
    const chatId = ctx.chat.id.toString();
    const tgUsername = ctx.from && ctx.from.username ? ctx.from.username : null;

    if (!payload.startsWith('sub_')) {
      await ctx.replyWithHTML('<b>Welcome!</b>\n\nSubscribe from the page to get updates.');
      return;
    }

    const pending = await PendingSubscriber.findOne({ payload: payload });

    if (!pending) {
      await ctx.replyWithHTML(
        '<b>This subscription link has expired or was already used.</b>\n\n' +
        'Please go back to the page and submit the form again to get a fresh link.'
      );
      return;
    }

    let targetContact = await Contact.findOne({ userId: pending.userId, telegramChatId: chatId });
    const contactsByValue = await Contact.find({ userId: pending.userId, contact: pending.contact });

    if (!targetContact) {
      targetContact = contactsByValue.find(function(c) { return c.status === 'subscribed'; }) ||
        contactsByValue.find(function(c) { return c.shortId === pending.shortId; }) ||
        contactsByValue[0];
    }

    if (!targetContact) {
      targetContact = new Contact({
        userId: pending.userId,
        shortId: pending.shortId,
        name: pending.name,
        contact: pending.contact,
        telegramChatId: chatId,
        telegramUsername: tgUsername,
        botIndex: pending.botIndex, // locked-in assignment from signup time, never recomputed
        status: 'subscribed',
        submittedAt: new Date(),
        subscribedAt: new Date()
      });
    } else {
      targetContact.name = pending.name;
      targetContact.contact = pending.contact;
      targetContact.shortId = pending.shortId;
      targetContact.telegramChatId = chatId;
      targetContact.telegramUsername = tgUsername;
      // Only set botIndex if this contact doesn't already have one (e.g. legacy record).
      // If it already has one, keep it - this contact's Telegram session lives with that bot.
      if (targetContact.botIndex == null) {
        targetContact.botIndex = pending.botIndex;
      }
      targetContact.status = 'subscribed';
      targetContact.subscribedAt = targetContact.subscribedAt || new Date();
      targetContact.submittedAt = new Date();
    }

    try {
      await targetContact.save();
      await Contact.deleteMany({
        userId: pending.userId,
        $or: [
          { contact: pending.contact, _id: { $ne: targetContact._id } },
          { telegramChatId: chatId, _id: { $ne: targetContact._id } }
        ]
      });
    } catch (err) {
      console.error('Failed to save contact for user ' + pending.userId + ': ' + err.message);
      await ctx.replyWithHTML(
        '<b>Something went wrong saving your subscription.</b>\n\n' +
        'Please try submitting the form again. If this keeps happening, contact support.'
      );
      return;
    }

    await PendingSubscriber.deleteOne({ payload: payload });

    const form = await FormPage.findOne({ shortId: pending.shortId });
    let welcomeText = '<b>Subscription Confirmed!</b>\n\nHi <b>' + escapeHtml(pending.name) + '</b>!\n\nYou\'re now subscribed.\n\nThank you';

    if (form && form.welcomeMessage && form.welcomeMessage.trim()) {
      welcomeText = form.welcomeMessage
        .replace(/\{name\}/gi, '<b>' + escapeHtml(pending.name) + '</b>')
        .replace(/\{contact\}/gi, escapeHtml(pending.contact));
    }

    await ctx.replyWithHTML(welcomeText);
  });
}

// ==================== BROADCAST WORKER ====================
async function sendToContact(contact, chunks) {
  // ALWAYS use the locked-in botIndex stored on the contact. Never recompute
  // via hash here - that's what breaks when the pool size changes.
  let entry = null;
  if (contact.botIndex != null) {
    entry = botPool.getBroadcastBotByIndex(contact.botIndex);
  }
  if (!entry) {
    // Fallback path only for legacy contacts saved before botIndex existed
    // and never backfilled. Run backfillBotIndexes() to eliminate this path.
    entry = botPool.getBotForContact(contact.userId, contact.contact);
  }
  if (!entry) throw new Error('No broadcast bot available for contact ' + contact.contact);

  // Every chunk goes through the per-bot rate limiter + 429 retry. This is
  // what protects a shared bot token from being overloaded when multiple
  // users' broadcasts land on it at the same time.
  for (const chunk of chunks) {
    await sendChunkWithLimiterAndRetry(entry, contact.telegramChatId, chunk);
  }
}

async function sendBatch(batch, chunks, stats) {
  const sendPromises = batch.map(async function(contact) {
    try {
      await sendToContact(contact, chunks);
      stats.sent++;
    } catch (err) {
      stats.failed++;
      const isBlocked = (err.response && err.response.error_code === 403) ||
        /blocked|forbidden|chat not found|deactivated/i.test(err.message || '');
      if (isBlocked) {
        await Contact.findByIdAndUpdate(contact._id, {
          status: 'unsubscribed',
          unsubscribedAt: new Date(),
          telegramChatId: null
        });
      }
    }
  });
  await Promise.all(sendPromises);
}

async function processBroadcast(job) {
  const userId = job.data.userId;
  const message = job.data.message;
  const broadcastId = job.data.broadcastId;

  // Fetch the user once, up front - used both to build the "From <Name>"
  // signature on the outgoing message and to send the delivery report DM.
  const user = await User.findOne({ id: userId });

  const firstName = (user && user.fullName ? user.fullName.trim() : '').split(' ')[0] || 'Sendm';
  const senderName = toBoldSansUnicode(firstName);

  // Signature is prepended ONCE, before splitting into chunks, so it only
  // ever appears at the very top of the first message part - never repeated
  // on "(2/3)"-style continuation chunks.
  const signedMessage = 'From ' + senderName + '\n\n' + message;
  const chunks = splitTelegramMessage(signedMessage);

  const targets = await Contact.find({
    userId: userId,
    status: 'subscribed',
    telegramChatId: { $exists: true, $ne: null }
  });

  const total = targets.length;
  const stats = { sent: 0, failed: 0 };

  const batches = [];
  for (let i = 0; i < targets.length; i += BATCH_SIZE) {
    batches.push(targets.slice(i, i + BATCH_SIZE));
  }

  for (let b = 0; b < batches.length; b++) {
    await sendBatch(batches[b], chunks, stats);
    if (b < batches.length - 1) {
      await new Promise(function(resolve) { setTimeout(resolve, BATCH_INTERVAL_MS); });
    }
  }

  let reportText = broadcastId ? '<b>Scheduled Broadcast Report</b>\n\n' : '<b>Broadcast Report</b>\n\n';
  reportText += 'Sent as: <b>' + senderName + '</b>\n\n';
  if (total === 0) {
    reportText += 'No subscribed contacts with Telegram connected.';
  } else {
    reportText += '<b>' + stats.sent + ' of ' + total + '</b> delivered.\n';
    if (stats.failed > 0) reportText += stats.failed + ' failed.';
  }
  reportText += '\n\nTime: ' + new Date().toLocaleString();

  if (user && user.isTelegramConnected && user.telegramChatId) {
    try {
      await botPool.authBot.telegram.sendMessage(user.telegramChatId, reportText, { parse_mode: 'HTML' });
    } catch (err) {
      console.error('Failed to send report to user ' + userId, err.message);
    }
  }

  if (broadcastId) {
    await ScheduledBroadcast.deleteOne({ broadcastId: broadcastId });
  }

  invalidateUserCache(userId, 'contacts');
  return stats;
}

const worker = new Worker('telegram-broadcasts', processBroadcast, { connection: redisConnection, concurrency: 4 });

worker.on('completed', function(job) {
  console.log('Broadcast job (' + (job.id || 'immediate') + ') completed for user ' + job.data.userId);
});

worker.on('failed', async function(job, err) {
  console.error('Broadcast job (' + (job.id || 'immediate') + ') failed permanently: ' + err.message);
  const data = job.data || {};
  const userId = data.userId;
  const broadcastId = data.broadcastId;
  if (broadcastId) {
    await ScheduledBroadcast.findOneAndUpdate({ broadcastId: broadcastId }, { status: 'failed' }).catch(function() {});
  }
  const user = await User.findOne({ id: userId });
  if (user && user.isTelegramConnected && user.telegramChatId) {
    const text = broadcastId
      ? '<b>Scheduled Broadcast Failed</b>\n\nFailed after retries.\nError: ' + err.message
      : '<b>Broadcast Failed</b>\n\nFailed after retries.\nError: ' + err.message;
    try {
      await botPool.authBot.telegram.sendMessage(user.telegramChatId, text, { parse_mode: 'HTML' });
    } catch (e) {}
  }
});

// ==================== ONE-TIME MIGRATION: backfill botIndex on legacy contacts ====================
// Run once at startup (safe to leave in - it's a no-op once everything has botIndex set).
// Assigns a botIndex to any existing contact that doesn't have one yet, using the
// CURRENT hash-based lookup as a best-effort match to whichever bot they're likely
// already talking to. After this runs once, sendToContact never needs the fallback.
async function backfillBotIndexes() {
  const contacts = await Contact.find({ botIndex: null, telegramChatId: { $ne: null } });
  if (contacts.length === 0) {
    console.log('No legacy contacts need botIndex backfill');
    return;
  }
  let updated = 0;
  for (const c of contacts) {
    const entry = botPool.getBotForContact(c.userId, c.contact);
    if (entry) {
      c.botIndex = entry.index;
      await c.save();
      updated++;
    }
  }
  console.log('Backfilled botIndex for ' + updated + '/' + contacts.length + ' legacy contact(s)');
}

// ==================== SCHEDULED BROADCAST RECOVERY AFTER RESTART ====================
async function recoverLostScheduledBroadcasts() {
  console.log('Starting recovery of scheduled broadcasts after server restart...');

  const now = new Date();
  const pendingFuture = await ScheduledBroadcast.find({
    status: 'pending',
    scheduledTime: { $gt: now }
  }).lean();

  if (pendingFuture.length === 0) {
    console.log('No pending future scheduled broadcasts need recovery');
    return;
  }

  console.log('Found ' + pendingFuture.length + ' scheduled broadcast(s) to recover');

  let recovered = 0;
  let alreadyExists = 0;

  for (const task of pendingFuture) {
    const jobId = task.broadcastId;
    const existing = await broadcastQueue.getJob(jobId);
    if (existing) { alreadyExists++; continue; }

    const delayMs = task.scheduledTime.getTime() - Date.now();

    await broadcastQueue.add(
      'send-broadcast',
      { userId: task.userId, message: task.message, broadcastId: task.broadcastId },
      {
        jobId: task.broadcastId,
        delay: delayMs > 1000 ? delayMs : 0,
        attempts: 4,
        backoff: { type: 'exponential', delay: 5000 }
      }
    );

    recovered++;
  }

  console.log('Recovery completed: ' + recovered + ' broadcast(s) re-queued, ' + alreadyExists + ' were already present in queue');
}

// ==================== MIDDLEWARE ====================
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static('public'));
app.use(cors());
// `verify` stashes the exact raw bytes Express received BEFORE JSON parsing/
// re-serialization touches them. Paystack signs those exact raw bytes, so
// re-deriving JSON.stringify(req.body) later can drift (key order, number
// formatting) and cause valid webhooks to fail signature checks. Only the
// webhook route uses req.rawBody; every other route is unaffected.
app.use(express.json({
  limit: '10mb',
  verify: function(req, res, buf) { req.rawBody = buf; }
}));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many attempts' }
});

const formSubmitLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many submissions to this form. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: function(req) { return req.ip + '::' + req.params.shortId; },
  skip: function(req) { return !req.params.shortId; }
});

// ==================== WEBHOOK ROUTES (one per bot) ====================
app.post('/webhook/auth/:secret', async function(req, res) {
  if (req.params.secret !== WEBHOOK_SECRET) return res.sendStatus(404);
  try {
    const update = Buffer.isBuffer(req.body) ? JSON.parse(req.body.toString('utf8')) : req.body;
    await botPool.authBot.handleUpdate(update);
  } catch (err) {
    console.error('Auth webhook handling error:', err.message);
  }
  res.sendStatus(200);
});

app.post('/webhook/broadcast/:botIndex/:secret', async function(req, res) {
  if (req.params.secret !== WEBHOOK_SECRET) return res.sendStatus(404);
  const idx = parseInt(req.params.botIndex, 10);
  const entry = botPool.getBroadcastBotByIndex(idx);
  if (!entry) {
    console.warn('Webhook hit for unknown broadcast bot index ' + idx);
    return res.sendStatus(404);
  }
  try {
    const update = Buffer.isBuffer(req.body) ? JSON.parse(req.body.toString('utf8')) : req.body;
    await entry.bot.handleUpdate(update);
  } catch (err) {
    console.error('Broadcast[' + idx + '] webhook handling error:', err.message);
  }
  res.sendStatus(200);
});

// ==================== JWT AUTH ====================
const authenticateToken = async function(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : req.query.token;

  if (!token) return res.status(401).json({ error: 'Access token required' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findOne({ id: decoded.userId });
    if (!user) return res.status(404).json({ error: 'User not found' });
    req.user = user;
    next();
  } catch (err) {
    res.status(403).json({ error: 'Invalid or expired token' });
  }
};

// ==================== AUTH ROUTES ====================
app.post('/api/auth/register', authLimiter, async function(req, res) {
  const nameCheck = validateName(req.body.fullName, 'Full name');
  if (!nameCheck.ok) return res.status(400).json({ error: nameCheck.error });

  const emailCheck = validateEmail(req.body.email);
  if (!emailCheck.ok) return res.status(400).json({ error: emailCheck.error });

  const passwordCheck = validatePasswordLength(req.body.password);
  if (!passwordCheck.ok) return res.status(400).json({ error: passwordCheck.error });

  const fullName = nameCheck.value;
  const email = emailCheck.value;
  const password = passwordCheck.value;

  const existing = await User.findOne({ email: email });
  if (existing) return res.status(409).json({ error: 'Email already exists' });

  const hashed = await bcrypt.hash(password, 12);
  const newUser = await User.create({
    id: uuidv4(),
    fullName: fullName,
    email: email,
    password: hashed,
  });

  const token = jwt.sign({ userId: newUser.id }, JWT_SECRET, { expiresIn: '7d' });
  res.status(201).json({
    success: true,
    token: token,
    user: { id: newUser.id, fullName: newUser.fullName, email: newUser.email, isTelegramConnected: false }
  });
});

app.post('/api/auth/login', authLimiter, async function(req, res) {
  const email = req.body.email;
  const password = req.body.password;
  if (!isNonEmptyString(email) || !isNonEmptyString(password)) {
    return res.status(400).json({ error: 'Email and password required' });
  }
  // Cap lengths BEFORE hitting bcrypt.compare (which hashes the input) so an
  // attacker can't force expensive hashing of a huge payload just by POSTing
  // a giant "password" string.
  if (email.length > EMAIL_MAX_LENGTH || password.length > PASSWORD_MAX_LENGTH) {
    return res.status(400).json({ error: 'Invalid credentials' });
  }

  const user = await User.findOne({ email: email.toLowerCase().trim() });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
  res.json({
    success: true,
    token: token,
    user: { id: user.id, fullName: user.fullName, email: user.email, isTelegramConnected: user.isTelegramConnected }
  });
});

app.get('/api/auth/me', authenticateToken, function(req, res) {
  res.json({
    user: {
      id: req.user.id,
      fullName: req.user.fullName,
      email: req.user.email,
      isTelegramConnected: req.user.isTelegramConnected
    }
  });
});

// Connect 2FA: deep link into the SHARED auth bot.
// Route: /api/telegram/connect - grouped under its own "telegram"
// namespace since this is about linking a Telegram account, not
// authenticating a request. Checks authBotReady (not serverReady) so a
// slow/broken broadcast pool can never block login/2FA linking.
app.get('/api/telegram/connect', authenticateToken, function(req, res) {
  const bot = botPool.authBot;
  if (!bot || !bot.username) {
    console.warn(
      '[telegram/connect] 503 - auth bot not ready. userId=' + req.user.id +
      ' authBotReady=' + authBotReady +
      ' botPool.authBot=' + (bot ? 'set' : 'null') +
      ' username=' + (bot && bot.username ? bot.username : 'none')
    );
    return res.status(503).json({ error: 'Auth bot not ready yet, try again shortly.' });
  }
  console.log('[telegram/connect] 200 - link issued for userId=' + req.user.id + ' bot=@' + bot.username);
  return res.json({
    success: true,
    startLink: 'https://t.me/' + bot.username + '?start=' + req.user.id,
    botUsername: '@' + bot.username
  });
});

app.post('/api/auth/disconnect-telegram', authenticateToken, async function(req, res) {
  req.user.telegramChatId = null;
  req.user.isTelegramConnected = false;
  await req.user.save();
  res.json({ success: true, message: 'Telegram 2FA disconnected.' });
});

app.get('/api/auth/bot-status', authenticateToken, function(req, res) {
  res.json({ activated: req.user.isTelegramConnected, chatId: req.user.telegramChatId || null });
});

app.post('/api/auth/forgot-password', async function(req, res) {
  const email = req.body.email;
  if (!isNonEmptyString(email) || email.length > EMAIL_MAX_LENGTH) {
    return res.status(400).json({ error: 'Email required' });
  }

  const user = await User.findOne({ email: email.toLowerCase().trim() });
  if (!user) return res.json({ success: true, message: 'If account exists, code was sent.' });
  if (!user.isTelegramConnected) return res.status(400).json({ error: 'Telegram 2FA not connected' });

  const code = generate2FACode();
  const resetToken = uuidv4();
  resetTokens.set(resetToken, { userId: user.id, code: code, expiresAt: Date.now() + 10 * 60 * 1000 });

  const sent = await send2FACodeViaBot(user, code);
  if (!sent) return res.status(500).json({ error: 'Failed to send code' });

  res.json({ success: true, message: 'Code sent!', resetToken: resetToken });
});

app.post('/api/auth/verify-reset-code', function(req, res) {
  const resetToken = req.body.resetToken;
  const code = req.body.code;
  if (!isNonEmptyString(resetToken) || !isNonEmptyString(code)) {
    return res.status(400).json({ error: 'Token and code required' });
  }
  if (resetToken.length > 200 || code.length > 20) {
    return res.status(400).json({ error: 'Invalid or expired code' });
  }

  const entry = resetTokens.get(resetToken);
  if (!entry || Date.now() > entry.expiresAt) {
    resetTokens.delete(resetToken);
    return res.status(400).json({ error: 'Invalid or expired code' });
  }
  if (entry.code !== code.trim()) return res.status(400).json({ error: 'Wrong code' });

  res.json({ success: true, message: 'Verified', userId: entry.userId });
});

app.post('/api/auth/reset-password', async function(req, res) {
  const resetToken = req.body.resetToken;
  if (!isNonEmptyString(resetToken) || resetToken.length > 200) {
    return res.status(400).json({ error: 'Valid token and password required' });
  }

  const passwordCheck = validatePasswordLength(req.body.newPassword);
  if (!passwordCheck.ok) return res.status(400).json({ error: passwordCheck.error });
  const newPassword = passwordCheck.value;

  const entry = resetTokens.get(resetToken);
  if (!entry || Date.now() > entry.expiresAt) {
    resetTokens.delete(resetToken);
    return res.status(400).json({ error: 'Invalid session' });
  }

  const user = await User.findOne({ id: entry.userId });
  if (!user) return res.status(404).json({ error: 'User not found' });

  user.password = await bcrypt.hash(newPassword, 12);
  await user.save();
  resetTokens.delete(resetToken);

  res.json({ success: true, message: 'Password reset successful' });
});

// ==================== SUBSCRIPTION ROUTES (Paystack) ====================
app.get('/api/subscription/status', authenticateToken, async function(req, res) {
  const subscribed = hasActiveSubscription(req.user);
  res.json({
    subscribed: subscribed,
    plan: subscribed ? 'premium-monthly' : 'free',
    endDate: req.user.subscriptionEndDate || null,
    daysLeft: subscribed
      ? Math.ceil((new Date(req.user.subscriptionEndDate) - new Date()) / (1000 * 60 * 60 * 24))
      : 0
  });
});

app.post('/api/subscription/initiate', authenticateToken, async function(req, res) {
  if (hasActiveSubscription(req.user)) {
    return res.status(400).json({ error: 'You already have an active subscription' });
  }

  try {
    const response = await axios.post(
      'https://api.paystack.co/transaction/initialize',
      {
        email: req.user.email,
        amount: MONTHLY_PRICE_KOBO,
        currency: 'NGN',
        callback_url: req.protocol + '://' + req.get('host') + '/subscription-success',
        // app tag lets the shared webhook endpoint tell this product's
        // payments apart from any other SaaS sharing the same Paystack account.
        metadata: { userId: req.user.id, plan: 'premium-monthly', app: PAYSTACK_APP_TAG }
      },
      { headers: { Authorization: 'Bearer ' + PAYSTACK_SECRET_KEY, 'Content-Type': 'application/json' } }
    );

    const authorization_url = response.data.data.authorization_url;
    const reference = response.data.data.reference;

    req.user.pendingPaymentReference = reference;
    await req.user.save();

    res.json({ success: true, authorizationUrl: authorization_url, reference: reference });
  } catch (error) {
    console.error('Paystack init error:', error.response ? error.response.data : error.message);
    res.status(500).json({ error: 'Failed to initialize payment' });
  }
});

// Forwards a webhook we don't own to the other SaaS, unmodified. We pass the
// exact raw bytes Paystack sent (not a re-serialized copy) plus the original
// signature header, so the downstream app can independently verify it against
// its own copy of the shared Paystack secret exactly as if Paystack had hit
// it directly. Best-effort: Paystack only cares that WE return 200 quickly,
// so a forwarding failure is logged, not surfaced back to Paystack (which
// would just trigger pointless retries against us).
async function forwardWebhookToOtherSaas(rawBody, signatureHeader) {
  if (!OTHER_SAAS_WEBHOOK_URL) {
    console.warn('[webhook] Received an event not tagged for this app, but OTHER_SAAS_WEBHOOK_URL is not set - dropping it.');
    return;
  }
  try {
    await axios.post(OTHER_SAAS_WEBHOOK_URL, rawBody, {
      headers: {
        'Content-Type': 'application/json',
        'x-paystack-signature': signatureHeader
      },
      timeout: 10000
    });
    console.log('[webhook] Forwarded untagged event to other SaaS');
  } catch (err) {
    console.error('[webhook] Failed to forward event to other SaaS:', err.message);
  }
}

app.post('/api/subscription/webhook', async function(req, res) {
  try {
    // req.rawBody is the exact byte stream Paystack sent (see the verify()
    // hook on express.json() above). Signing THAT, not a re-serialized
    // JSON.stringify(req.body), is what makes this check reliable.
    const rawBody = req.rawBody || Buffer.from(JSON.stringify(req.body));
    const signatureHeader = req.headers['x-paystack-signature'];

    const hash = crypto.createHmac('sha512', PAYSTACK_SECRET_KEY)
      .update(rawBody)
      .digest('hex');

    if (!signatureHeader || hash !== signatureHeader) {
      return res.status(401).send('Invalid signature');
    }

    const event = req.body;
    const eventAppTag = event && event.data && event.data.metadata && event.data.metadata.app;

    // Not ours - hand it off to whichever other SaaS is sharing this
    // Paystack account and ack Paystack immediately so it doesn't retry.
    if (eventAppTag !== PAYSTACK_APP_TAG) {
      res.status(200).send('OK');
      await forwardWebhookToOtherSaas(rawBody, signatureHeader);
      return;
    }

    if (event.event === 'charge.success') {
      const reference = event.data.reference;
      const userId = event.data.metadata && event.data.metadata.userId;

      if (!userId) return res.status(200).send('OK');

      const user = await User.findOne({ id: userId });
      if (!user || user.pendingPaymentReference !== reference) {
        return res.status(200).send('OK');
      }

      const endDate = new Date();
      endDate.setDate(endDate.getDate() + 30);

      user.isSubscribed = true;
      user.subscriptionEndDate = endDate;
      user.subscriptionPlan = 'premium-monthly';
      user.pendingPaymentReference = undefined;
      await user.save();

      console.log('Subscription activated for ' + user.email + ' (ref: ' + reference + ')');
    }

    res.status(200).send('OK');
  } catch (err) {
    console.error('Webhook error:', err);
    res.status(200).send('OK');
  }
});

app.get('/subscription-success', function(req, res) {
  res.send('<!DOCTYPE html>\n<html lang="en">\n<head>\n  <meta charset="UTF-8">\n  <title>Payment Successful</title>\n  <style>\n    body{font-family:system-ui,sans-serif;background:#0a0a0a;color:#00ff41;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;}\n    .box{background:#111;padding:60px;border-radius:20px;text-align:center;box-shadow:0 0 30px rgba(0,255,65,0.2);}\n    h1{margin:0 0 20px;font-size:3em;color:#00ff41;}\n    p{font-size:1.3em;margin:20px 0;line-height:1.6;}\n    a{display:inline-block;margin-top:30px;padding:14px 32px;background:#00ff41;color:#000;font-weight:bold;text-decoration:none;border-radius:8px;font-size:1.1em;}\n    a:hover{background:#00cc33;}\n  </style>\n</head>\n<body>\n  <div class="box">\n    <h1>Payment Successful!</h1>\n    <p>Your subscription is now <strong>active</strong>.</p>\n    <p>You have unlimited broadcasts, landing pages, and forms.</p>\n    <p><a href="https://sendi.onrender.com">Return to Dashboard</a></p>\n  </div>\n</body>\n</html>');
});

// ==================== CACHED HIGH-READ ENDPOINTS ====================
app.get('/p/:shortId', async function(req, res) {
  const key = 'landing:' + req.params.shortId;
  const cached = publicCache.get(key);

  if (cached && Date.now() - cached.timestamp < TTL.public) {
    return res.render('landing', cached.data);
  }

  const page = await LandingPage.findOne({ shortId: req.params.shortId });
  if (!page) return res.status(404).render('404');

  const processedBlocks = page.config.blocks.map(function(block) {
    if (block.type === 'text') {
      return Object.assign({}, block, { htmlContent: textToHtmlForDisplay(block.content) });
    }
    return block;
  });

  const data = { title: page.title, blocks: processedBlocks };

  publicCache.set(key, { data: data, timestamp: Date.now() });
  res.render('landing', data);
});

app.get('/f/:shortId', async function(req, res) {
  const key = 'form:' + req.params.shortId;
  const cached = publicCache.get(key);

  if (cached && Date.now() - cached.timestamp < TTL.public) {
    return res.render('form', cached.data);
  }

  const form = await FormPage.findOne({ shortId: req.params.shortId });
  if (!form) return res.status(404).render('404');

  const data = { title: form.title, state: form.state };
  publicCache.set(key, { data: data, timestamp: Date.now() });
  res.render('form', data);
});

app.get('/api/pages', authenticateToken, async function(req, res) {
  const bucket = getUserCache(req.user.id);
  const now = Date.now();

  if (bucket.pages && now - bucket.pagesTs < TTL.pages) {
    return res.json({ pages: bucket.pages });
  }

  const pages = await LandingPage.find({ userId: req.user.id }).sort({ updatedAt: -1 });
  const host = req.get('host');
  const protocol = req.protocol;
  const formatted = pages.map(function(p) {
    return {
      shortId: p.shortId,
      title: p.title,
      createdAt: p.createdAt,
      updatedAt: p.updatedAt,
      url: protocol + '://' + host + '/p/' + p.shortId
    };
  });

  bucket.pages = formatted;
  bucket.pagesTs = now;
  res.json({ pages: formatted });
});

app.get('/api/forms', authenticateToken, async function(req, res) {
  const bucket = getUserCache(req.user.id);
  const now = Date.now();

  if (bucket.forms && now - bucket.formsTs < TTL.forms) {
    return res.json({ forms: bucket.forms });
  }

  const forms = await FormPage.find({ userId: req.user.id }).sort({ updatedAt: -1 });
  const host = req.get('host');
  const protocol = req.protocol;
  const formatted = forms.map(function(f) {
    return {
      shortId: f.shortId,
      title: f.title,
      createdAt: f.createdAt,
      updatedAt: f.updatedAt,
      url: protocol + '://' + host + '/f/' + f.shortId
    };
  });

  bucket.forms = formatted;
  bucket.formsTs = now;
  res.json({ forms: formatted });
});

app.get('/api/contacts', authenticateToken, async function(req, res) {
  const bucket = getUserCache(req.user.id);
  const now = Date.now();

  if (bucket.contacts && now - bucket.contactsTs < TTL.contacts) {
    return res.json({ success: true, contacts: bucket.contacts });
  }

  const contacts = await Contact.find({ userId: req.user.id }).sort({ submittedAt: -1 });
  const formatted = contacts.map(function(c) {
    return {
      name: c.name,
      contact: c.contact,
      status: c.status,
      telegramChatId: c.telegramChatId || null,
      telegramUsername: c.telegramUsername || null,
      pageId: c.shortId,
      submittedAt: new Date(c.submittedAt).toLocaleString(),
      subscribedAt: c.subscribedAt ? new Date(c.subscribedAt).toLocaleString() : null
    };
  });

  bucket.contacts = formatted;
  bucket.contactsTs = now;
  res.json({ success: true, contacts: formatted });
});

app.get('/api/page/:shortId', async function(req, res) {
  const key = 'apiPage:' + req.params.shortId;
  const cached = publicCache.get(key);
  if (cached && Date.now() - cached.timestamp < TTL.public) {
    return res.json(cached.data);
  }

  const page = await LandingPage.findOne({ shortId: req.params.shortId });
  if (!page) return res.status(404).json({ error: 'Page not found' });

  const data = { shortId: page.shortId, title: page.title, config: page.config };
  publicCache.set(key, { data: data, timestamp: Date.now() });
  res.json(data);
});

app.get('/api/form/:shortId', async function(req, res) {
  const key = 'apiForm:' + req.params.shortId;
  const cached = publicCache.get(key);
  if (cached && Date.now() - cached.timestamp < TTL.public) {
    return res.json(cached.data);
  }

  const form = await FormPage.findOne({ shortId: req.params.shortId });
  if (!form) return res.status(404).json({ error: 'Form not found' });

  const data = { shortId: form.shortId, title: form.title, state: form.state, welcomeMessage: form.welcomeMessage };
  publicCache.set(key, { data: data, timestamp: Date.now() });
  res.json(data);
});

// ==================== LANDING PAGES WRITE ROUTES ====================
app.post('/api/pages/save', authenticateToken, async function(req, res) {
  const shortId = req.body.shortId;
  const config = req.body.config;
  if (!config || !Array.isArray(config.blocks)) return res.status(400).json({ error: 'Title and config.blocks required' });

  const titleCheck = validateTitle(req.body.title);
  if (!titleCheck.ok) return res.status(400).json({ error: titleCheck.error });
  const title = titleCheck.value;

  const limits = getUserLimits(req.user);

  if (!shortId) {
    const currentCount = await LandingPage.countDocuments({ userId: req.user.id });
    if (currentCount >= limits.maxLandingPages && limits.maxLandingPages !== Infinity) {
      return res.status(403).json({ error: 'Maximum landing pages limit reached.' });
    }
  }

  const finalShortId = shortId || uuidv4().slice(0, 8);
  const now = new Date();

  const cleanBlocks = config.blocks.map(function(b) {
    if (!b || b.isEditor || (b.id && (b.id.includes('editor-') || b.id.includes('control-')))) return null;
    if (b.type === 'text') return { type: 'text', tag: b.tag || 'p', content: (b.content || '').trim() };
    if (b.type === 'image') return b.src ? { type: 'image', src: b.src.trim() } : null;
    if (b.type === 'button') return b.text ? { type: 'button', text: b.text.trim(), href: b.href || '' } : null;
    if (b.type === 'form') return b.html ? { type: 'form', html: sanitizeLandingPageFormHtml(b.html) } : null;
    return null;
  }).filter(Boolean);

  if (cleanBlocks.length === 0) return res.status(400).json({ error: 'No valid blocks' });

  const updateDoc = { userId: req.user.id, title: title, config: { blocks: cleanBlocks }, updatedAt: now };
  if (!shortId) updateDoc.createdAt = now;

  await LandingPage.findOneAndUpdate(
    { shortId: finalShortId },
    updateDoc,
    { upsert: true }
  );

  invalidateUserCache(req.user.id, 'pages');
  invalidatePublicCache('landing:' + finalShortId);
  invalidatePublicCache('apiPage:' + finalShortId);

  const url = req.protocol + '://' + req.get('host') + '/p/' + finalShortId;
  res.json({ success: true, shortId: finalShortId, url: url });
});

app.post('/api/pages/delete', authenticateToken, async function(req, res) {
  const shortId = req.body.shortId;
  const page = await LandingPage.findOne({ shortId: shortId, userId: req.user.id });
  if (!page) return res.status(404).json({ error: 'Page not found' });
  await LandingPage.deleteOne({ shortId: shortId });

  invalidateUserCache(req.user.id, 'pages');
  invalidatePublicCache('landing:' + shortId);
  invalidatePublicCache('apiPage:' + shortId);

  res.json({ success: true });
});

// ==================== FORMS WRITE ROUTES ====================
app.post('/api/forms/save', authenticateToken, async function(req, res) {
  const shortId = req.body.shortId;
  const state = req.body.state;
  const welcomeMessage = req.body.welcomeMessage;
  if (!state) return res.status(400).json({ error: 'Title and state required' });

  const titleCheck = validateTitle(req.body.title);
  if (!titleCheck.ok) return res.status(400).json({ error: titleCheck.error });
  const title = titleCheck.value;

  if (welcomeMessage && typeof welcomeMessage === 'string' && welcomeMessage.trim().length > WELCOME_MESSAGE_MAX_LENGTH) {
    return res.status(400).json({ error: 'Welcome message must be ' + WELCOME_MESSAGE_MAX_LENGTH + ' characters or fewer' });
  }

  const limits = getUserLimits(req.user);

  if (!shortId) {
    const currentCount = await FormPage.countDocuments({ userId: req.user.id });
    if (currentCount >= limits.maxForms && limits.maxForms !== Infinity) {
      return res.status(403).json({ error: 'Maximum forms limit reached.' });
    }
  }

  const sanitizedState = JSON.parse(JSON.stringify(state));
  if (sanitizedState.headerText) sanitizedState.headerText = sanitizedState.headerText.replace(/<script.*?<\/script>/gi, '');
  if (sanitizedState.subheaderText) sanitizedState.subheaderText = sanitizedState.subheaderText.replace(/<script.*?<\/script>/gi, '');
  if (sanitizedState.buttonText) sanitizedState.buttonText = sanitizedState.buttonText.replace(/<script.*?<\/script>/gi, '');

  const sanitizedWelcome = welcomeMessage && typeof welcomeMessage === 'string'
    ? sanitizeTelegramHtml(welcomeMessage.trim())
    : '';

  const finalShortId = shortId || uuidv4().slice(0, 8);
  const now = new Date();

  const updateDoc = { userId: req.user.id, title: title, state: sanitizedState, welcomeMessage: sanitizedWelcome, updatedAt: now };
  if (!shortId) updateDoc.createdAt = now;

  await FormPage.findOneAndUpdate(
    { shortId: finalShortId },
    updateDoc,
    { upsert: true }
  );

  invalidateUserCache(req.user.id, 'forms');
  invalidatePublicCache('form:' + finalShortId);
  invalidatePublicCache('apiForm:' + finalShortId);

  const url = req.protocol + '://' + req.get('host') + '/f/' + finalShortId;
  res.json({ success: true, shortId: finalShortId, url: url });
});

app.post('/api/forms/delete', authenticateToken, async function(req, res) {
  const shortId = req.body.shortId;
  const form = await FormPage.findOne({ shortId: shortId, userId: req.user.id });
  if (!form) return res.status(404).json({ error: 'Form not found' });
  await FormPage.deleteOne({ shortId: shortId });
  await Contact.deleteMany({ shortId: shortId, userId: req.user.id });

  invalidateUserCache(req.user.id, 'forms');
  invalidatePublicCache('form:' + shortId);
  invalidatePublicCache('apiForm:' + shortId);

  res.json({ success: true });
});

// ==================== SUBSCRIBE & CONTACTS ====================
app.post('/api/subscribe/:shortId', formSubmitLimiter, async function(req, res) {
  if (!serverReady || botPool.poolSize === 0) {
    return res.status(503).json({ error: 'Server is still starting up. Please try again in a few seconds.' });
  }

  try {
    const shortId = req.params.shortId;

    const nameCheck = validateName(req.body.name, 'Name');
    if (!nameCheck.ok) return res.status(400).json({ error: nameCheck.error });
    const name = nameCheck.value;

    const rawContact = req.body.email;
    if (!isNonEmptyString(rawContact)) return res.status(400).json({ error: 'Contact is required' });

    const contactValue = rawContact.trim();

    if (!CONTACT_REGEX.test(contactValue)) {
      return res.status(400).json({ error: 'Contact must be a valid email address or phone number' });
    }

    const form = await FormPage.findOne({ shortId: shortId });
    if (!form) return res.status(404).json({ error: 'Form not found' });

    const owner = await User.findOne({ id: form.userId });
    if (!owner) return res.status(400).json({ error: 'Form owner not found' });

    // Compute the bot assignment ONCE here. This is the only place a fresh
    // hash-based assignment should ever happen. Once stored (below), it's locked.
    // Keyed by owner.id + contactValue - see getBotForContact for why.
    const broadcastBotEntry = botPool.getBotForContact(owner.id, contactValue);
    if (!broadcastBotEntry) {
      console.error('No broadcast bot available (pool empty) for contact ' + contactValue + ' (owner ' + owner.id + ')');
      return res.status(503).json({ error: 'Unable to assign a broadcast bot right now. Please try again shortly.' });
    }
    const freshAssignedIndex = broadcastBotEntry.index;

    const payload = 'sub_' + shortId + '_' + uuidv4().slice(0, 12);

    let contact = await Contact.findOne({ userId: owner.id, contact: contactValue });

    if (contact) {
      if (contact.status === 'subscribed') {
        // Already subscribed elsewhere - keep their EXISTING bot assignment if they
        // have one, don't silently move them to whatever the hash says today.
        const lockedIndex = contact.botIndex != null ? contact.botIndex : freshAssignedIndex;

        contact.name = name;
        contact.shortId = shortId;
        contact.submittedAt = new Date();
        if (contact.botIndex == null) contact.botIndex = lockedIndex;
        await contact.save();

        await PendingSubscriber.create({
          payload: payload, userId: owner.id, shortId: shortId,
          name: name, contact: contactValue, botIndex: lockedIndex
        });

        const botForLink = botPool.getBroadcastBotByIndex(lockedIndex) || broadcastBotEntry;
        const deepLink = 'https://t.me/' + botForLink.username + '?start=' + payload;
        return res.json({ success: true, deepLink: deepLink, alreadySubscribed: true });
      }

      // Not currently subscribed (pending/unsubscribed) - fresh assignment is fine.
      contact.name = name;
      contact.shortId = shortId;
      contact.submittedAt = new Date();
      contact.botIndex = freshAssignedIndex;
    } else {
      contact = new Contact({
        userId: owner.id,
        shortId: shortId,
        name: name,
        contact: contactValue,
        status: 'pending',
        botIndex: freshAssignedIndex,
        submittedAt: new Date()
      });
    }
    await contact.save();

    await PendingSubscriber.create({
      payload: payload, userId: owner.id, shortId: shortId,
      name: name, contact: contactValue, botIndex: freshAssignedIndex
    });

    const deepLink = 'https://t.me/' + broadcastBotEntry.username + '?start=' + payload;
    res.json({ success: true, deepLink: deepLink });

    invalidateUserCache(owner.id, 'contacts');
  } catch (err) {
    console.error('Subscribe error for shortId ' + req.params.shortId + ': ' + err.message);
    res.status(500).json({ error: 'Something went wrong while subscribing. Please try again.' });
  }
});

app.post('/api/contacts/delete', authenticateToken, async function(req, res) {
  const contacts = req.body.contacts;
  if (!Array.isArray(contacts) || contacts.length === 0) return res.status(400).json({ error: 'Provide contact array' });
  if (contacts.length > CONTACTS_DELETE_MAX) {
    return res.status(400).json({ error: 'Cannot delete more than ' + CONTACTS_DELETE_MAX + ' contacts at once' });
  }
  if (!contacts.every(function(c) { return typeof c === 'string' && c.length <= EMAIL_MAX_LENGTH; })) {
    return res.status(400).json({ error: 'Invalid contact value in list' });
  }

  const result = await Contact.deleteMany({ userId: req.user.id, contact: { $in: contacts } });

  invalidateUserCache(req.user.id, 'contacts');

  res.json({ success: true, deletedCount: result.deletedCount });
});

// ==================== BROADCASTING ====================
app.post('/api/broadcast/now', authenticateToken, async function(req, res) {
  if (!serverReady || botPool.poolSize === 0) {
    return res.status(503).json({ error: 'Server is still starting up. Please try again in a few seconds.' });
  }

  const message = req.body.message;
  if (!message || !message.trim()) return res.status(400).json({ error: 'Message required' });

  const processed = message.trim();
  if (processed.length > MAX_MSG_LENGTH * 10) {
    return res.status(400).json({ error: 'Message too long' });
  }

  const todayCount = await incrementDailyBroadcast(req.user.id);
  const limits = getUserLimits(req.user);
  if (todayCount > limits.dailyBroadcasts && limits.dailyBroadcasts !== Infinity) {
    return res.status(403).json({ error: 'Daily broadcast limit reached.' });
  }

  const readyMessage = prepareTelegramMessage(processed);

  if (readyMessage.length === 0) {
    return res.status(400).json({ error: 'Message empty after processing' });
  }

  await broadcastQueue.add('send-broadcast', {
    userId: req.user.id,
    message: readyMessage
  }, {
    attempts: 4,
    backoff: { type: 'exponential', delay: 5000 }
  });

  res.json({
    success: true,
    message: 'Broadcast queued and sending in background. You will receive a delivery report via Telegram shortly.'
  });
});

app.post('/api/broadcast/schedule', authenticateToken, async function(req, res) {
  if (!serverReady || botPool.poolSize === 0) {
    return res.status(503).json({ error: 'Server is still starting up. Please try again in a few seconds.' });
  }

  const message = req.body.message;
  const scheduledTime = req.body.scheduledTime;
  const recipients = req.body.recipients || 'all';
  if (!message || !message.trim()) return res.status(400).json({ error: 'Message required' });

  const processed = message.trim();
  if (processed.length > MAX_MSG_LENGTH * 10) {
    return res.status(400).json({ error: 'Message too long' });
  }

  const todayCount = await incrementDailyBroadcast(req.user.id);
  const limits = getUserLimits(req.user);
  if (todayCount > limits.dailyBroadcasts && limits.dailyBroadcasts !== Infinity) {
    return res.status(403).json({ error: 'Daily broadcast limit reached.' });
  }

  const time = new Date(scheduledTime);
  if (isNaN(time.getTime()) || time <= new Date()) {
    return res.status(400).json({ error: 'Invalid future time' });
  }

  const readyMessage = prepareTelegramMessage(processed);
  const broadcastId = uuidv4();

  await ScheduledBroadcast.create({
    broadcastId: broadcastId,
    userId: req.user.id,
    message: readyMessage,
    recipients: recipients,
    scheduledTime: time,
    status: 'pending'
  });

  const delay = time.getTime() - Date.now();

  await broadcastQueue.add('send-broadcast', {
    userId: req.user.id,
    message: readyMessage,
    broadcastId: broadcastId
  }, {
    jobId: broadcastId,
    delay: delay,
    attempts: 4,
    backoff: { type: 'exponential', delay: 5000 }
  });

  res.json({ success: true, broadcastId: broadcastId, scheduledTime: time.toISOString() });
});

app.get('/api/broadcast/scheduled', authenticateToken, async function(req, res) {
  const scheduled = await ScheduledBroadcast.find({ userId: req.user.id, status: 'pending' }).sort({ scheduledTime: 1 });
  const formatted = scheduled.map(function(s) {
    return {
      broadcastId: s.broadcastId,
      message: s.message.substring(0, 100) + (s.message.length > 100 ? '...' : ''),
      scheduledTime: s.scheduledTime.toISOString(),
      status: s.status,
      recipients: s.recipients
    };
  });
  res.json({ success: true, scheduled: formatted });
});

app.delete('/api/broadcast/scheduled/:broadcastId', authenticateToken, async function(req, res) {
  const broadcastId = req.params.broadcastId;
  const task = await ScheduledBroadcast.findOne({ broadcastId: broadcastId, userId: req.user.id });
  if (!task) return res.status(404).json({ error: 'Not found' });

  const job = await broadcastQueue.getJob(broadcastId);
  if (job) await job.remove();

  await task.deleteOne();

  res.json({ success: true });
});

app.patch('/api/broadcast/scheduled/:broadcastId', authenticateToken, async function(req, res) {
  const message = req.body.message;
  const scheduledTime = req.body.scheduledTime;
  const recipients = req.body.recipients;
  const task = await ScheduledBroadcast.findOne({ broadcastId: req.params.broadcastId, userId: req.user.id, status: 'pending' });

  if (!task) return res.status(400).json({ error: 'Cannot edit this broadcast' });

  const oldJob = await broadcastQueue.getJob(task.broadcastId);
  if (oldJob) await oldJob.remove();

  let needsUpdate = false;

  if (message && message.trim()) {
    const processed = message.trim();
    if (processed.length > MAX_MSG_LENGTH * 10) {
      return res.status(400).json({ error: 'Message too long' });
    }
    task.message = prepareTelegramMessage(processed);
    needsUpdate = true;
  }
  if (recipients) {
    task.recipients = recipients;
    needsUpdate = true;
  }
  if (scheduledTime) {
    const newTime = new Date(scheduledTime);
    if (isNaN(newTime.getTime()) || newTime <= new Date()) return res.status(400).json({ error: 'Invalid future time' });
    task.scheduledTime = newTime;
    needsUpdate = true;
  }

  if (needsUpdate) {
    await task.save();

    const delay = task.scheduledTime.getTime() - Date.now();

    await broadcastQueue.add('send-broadcast', {
      userId: task.userId,
      message: task.message,
      broadcastId: task.broadcastId
    }, {
      jobId: task.broadcastId,
      delay: delay > 0 ? delay : 0,
      attempts: 4,
      backoff: { type: 'exponential', delay: 5000 }
    });
  }

  res.json({ success: true, broadcastId: task.broadcastId, scheduledTime: task.scheduledTime.toISOString() });
});

app.get('/api/broadcast/scheduled/:broadcastId/details', authenticateToken, async function(req, res) {
  const task = await ScheduledBroadcast.findOne({ broadcastId: req.params.broadcastId, userId: req.user.id });

  if (!task || task.status !== 'pending') {
    return res.status(404).json({ error: 'Broadcast not found or not editable' });
  }

  const scheduledDate = new Date(task.scheduledTime);
  const offsetMs = scheduledDate.getTimezoneOffset() * 60000;
  const localDate = new Date(scheduledDate.getTime() + offsetMs);
  const localIsoString = localDate.toISOString().slice(0, 16);

  res.json({
    success: true,
    message: task.message,
    scheduledTime: localIsoString,
    recipients: task.recipients || 'all'
  });
});

// ==================== ADMIN LIMITS PANEL ====================
app.get('/admin-limits', async function(req, res) {
  const totalUsers = await User.countDocuments({});
  const payingUsers = await User.countDocuments({ isSubscribed: true, subscriptionEndDate: { $gt: new Date() } });

  const html = '<!DOCTYPE html>\n' +
    '<html lang="en">\n' +
    '<head>\n' +
    '  <meta charset="UTF-8">\n' +
    '  <meta name="viewport" content="width=device-width, initial-scale=1.0">\n' +
    '  <title>Server Admin Panel</title>\n' +
    '  <style>\n' +
    '    body { font-family: \'Segoe UI\', sans-serif; background: #121212; color: #e0e0e0; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }\n' +
    '    .container { background: #1e1e1e; padding: 40px; border-radius: 12px; box-shadow: 0 8px 32px rgba(0,0,0,0.6); width: 90%; max-width: 600px; }\n' +
    '    h1 { text-align: center; color: #ffd700; margin-bottom: 30px; }\n' +
    '    .stats { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin-bottom: 30px; }\n' +
    '    .stat-box { background: #2d2d2d; padding: 20px; border-radius: 10px; text-align: center; }\n' +
    '    .stat-number { font-size: 2.5em; font-weight: bold; color: #00ff41; margin: 10px 0; }\n' +
    '    .stat-label { font-size: 1.1em; color: #aaa; }\n' +
    '    .pool { text-align: center; margin: 15px 0; padding: 12px; background: #2d2d2d; border-radius: 8px; font-size: 0.95em; color: #8fd; }\n' +
    '    label { display: block; margin: 20px 0 8px; font-size: 1.1em; }\n' +
    '    input[type="number"], input[type="password"] { width: 100%; padding: 12px; background: #2d2d2d; border: none; border-radius: 6px; color: white; font-size: 1em; margin-bottom: 15px; box-sizing: border-box; }\n' +
    '    button { width: 100%; padding: 14px; background: #ffd700; color: black; font-weight: bold; border: none; border-radius: 6px; cursor: pointer; font-size: 1.1em; margin-top: 20px; }\n' +
    '    button:hover { background: #e6c200; }\n' +
    '    .current { text-align: center; margin: 25px 0; padding: 15px; background: #2d2d2d; border-radius: 8px; font-size: 1.1em; }\n' +
    '  </style>\n' +
    '</head>\n' +
    '<body>\n' +
    '  <div class="container">\n' +
    '    <h1>Server Admin Panel</h1>\n' +
    '    <div class="pool">Bot pool: 1 auth bot (' + (authBotReady ? 'ready' : 'starting') + ') + ' + botPool.poolSize + ' broadcast bots</div>\n' +
    '    <div class="stats">\n' +
    '      <div class="stat-box">\n' +
    '        <div class="stat-number">' + totalUsers + '</div>\n' +
    '        <div class="stat-label">Total Users</div>\n' +
    '      </div>\n' +
    '      <div class="stat-box">\n' +
    '        <div class="stat-number">' + payingUsers + '</div>\n' +
    '        <div class="stat-label">Paying Users</div>\n' +
    '      </div>\n' +
    '    </div>\n' +
    '    <form method="POST">\n' +
    '      <label>Owner Password</label>\n' +
    '      <input type="password" name="password" required placeholder="Enter admin password">\n' +
    '      <label>Daily Broadcasts per User (Free)</label>\n' +
    '      <input type="number" name="daily_broadcast" min="1" value="' + adminSettingsCache.dailyBroadcastLimit + '" required>\n' +
    '      <label>Max Landing Pages per User (Free)</label>\n' +
    '      <input type="number" name="max_pages" min="1" value="' + adminSettingsCache.maxLandingPages + '" required>\n' +
    '      <label>Max Forms per User (Free)</label>\n' +
    '      <input type="number" name="max_forms" min="1" value="' + adminSettingsCache.maxForms + '" required>\n' +
    '      <div class="current">\n' +
    '        <strong>Current Free Tier Limits:</strong><br>\n' +
    '        Broadcasts/day: ' + adminSettingsCache.dailyBroadcastLimit + ' | Pages: ' + adminSettingsCache.maxLandingPages + ' | Forms: ' + adminSettingsCache.maxForms + '\n' +
    '      </div>\n' +
    '      <button type="submit">Update Limits</button>\n' +
    '    </form>\n' +
    '  </div>\n' +
    '</body>\n' +
    '</html>';
  res.send(html);
});

app.post('/admin-limits', async function(req, res) {
  const password = req.body.password;
  const daily_broadcast = req.body.daily_broadcast;
  const max_pages = req.body.max_pages;
  const max_forms = req.body.max_forms;

  if (typeof password !== 'string' || password.length > 200 || password !== ADMIN_PASSWORD) {
    return res.send('<html><body style="background:#121212;color:#f44336;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;font-family:sans-serif;text-align:center;"><h1>Access Denied<br>Wrong Password</h1></body></html>');
  }

  const newDaily = parseInt(daily_broadcast);
  const newPages = parseInt(max_pages);
  const newForms = parseInt(max_forms);

  if (isNaN(newDaily) || isNaN(newPages) || isNaN(newForms) || newDaily < 1 || newPages < 1 || newForms < 1) {
    return res.send('<html><body style="background:#121212;color:#f44336;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;font-family:sans-serif;text-align:center;"><h1>Invalid Values<br>All limits must be >= 1</h1></body></html>');
  }

  try {
    await AdminSettings.updateSettings({
      dailyBroadcastLimit: newDaily,
      maxLandingPages: newPages,
      maxForms: newForms
    });

    adminSettingsCache = { dailyBroadcastLimit: newDaily, maxLandingPages: newPages, maxForms: newForms };

    console.log('Admin limits updated and saved to DB:', adminSettingsCache);

    res.send('<!DOCTYPE html>\n' +
      '<html lang="en">\n' +
      '<head>\n' +
      '  <meta charset="UTF-8">\n' +
      '  <title>Limits Updated</title>\n' +
      '  <style>\n' +
      '    body { font-family: \'Segoe UI\', sans-serif; background: #121212; color: #e0e0e0; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }\n' +
      '    .container { background: #1e1e1e; padding: 40px; border-radius: 12px; text-align: center; }\n' +
      '    h1 { color: #4caf50; }\n' +
      '    .success { font-size: 1.2em; margin: 20px 0; }\n' +
      '    a { color: #ffd700; text-decoration: none; font-weight: bold; }\n' +
      '    a:hover { text-decoration: underline; }\n' +
      '  </style>\n' +
      '</head>\n' +
      '<body>\n' +
      '  <div class="container">\n' +
      '    <h1>Success!</h1>\n' +
      '    <p class="success">Server limits updated and <strong>saved permanently</strong>:</p>\n' +
      '    <p><strong>Daily Broadcasts:</strong> ' + newDaily + '<br>\n' +
      '       <strong>Max Pages:</strong> ' + newPages + '<br>\n' +
      '       <strong>Max Forms:</strong> ' + newForms + '</p>\n' +
      '    <p><a href="/admin-limits">Back to Control Panel</a></p>\n' +
      '  </div>\n' +
      '</body>\n' +
      '</html>');
  } catch (err) {
    console.error('Failed to save admin settings:', err);
    res.status(500).send('Failed to save settings');
  }
});

// ==================== STARTUP ====================
async function loadAdminSettings() {
  try {
    const settings = await AdminSettings.getSettings();
    adminSettingsCache = {
      dailyBroadcastLimit: settings.dailyBroadcastLimit,
      maxLandingPages: settings.maxLandingPages,
      maxForms: settings.maxForms
    };
    console.log('Admin settings loaded from DB:', adminSettingsCache);
  } catch (err) {
    console.error('Failed to load admin settings:', err);
  }
}

mongoose.connection.once('open', async function() {
  try {
    await loadAdminSettings();

    // ---- Phase 1: Auth bot. Independent lifecycle, own readiness flag.
    await initAuthBot();
    registerAuthBotHandlers(botPool.authBot);
    await setupAuthWebhook();
    authBotReady = true;
    console.log('Auth bot fully ready - login/2FA is live.');

    // ---- Phase 2: Broadcast pool. Separate lifecycle.
    await initBroadcastPool();
    botPool.broadcastBots.forEach(function(entry) {
      registerBroadcastBotHandlers(entry.bot, entry.index);
    });
    await setupBroadcastWebhooks();

    // Backfill botIndex on any legacy contacts before anything else touches them.
    await backfillBotIndexes();

    await recoverLostScheduledBroadcasts();

    serverReady = true;
    console.log('Startup sequence completed - server is now accepting all bot-dependent requests');
  } catch (err) {
    console.error('FATAL: startup sequence failed, exiting:', err.message);
    process.exit(1);
  }
});

process.on('SIGTERM', async function() {
  console.log('Shutting down gracefully...');
  await worker.close();
  await broadcastQueue.close();
  process.exit(0);
});

process.on('SIGINT', async function() {
  console.log('Shutting down gracefully...');
  await worker.close();
  await broadcastQueue.close();
  process.exit(0);
});

// Render (and any uptime monitor) pings bare GET/HEAD / by default.
// Without an explicit route here it falls through to the 404 catch-all
// and spams the deploy logs every few seconds - this is just a cheap,
// no-DB-touching health response so that noise stops.
app.get('/', function(req, res) {
  res.status(200).type('text/plain').send('Sendm is running [' + BUILD_TAG + ']');
});

app.get('/ping', function(req, res) {
  if (!authBotReady) return res.status(503).type('text/plain').send('auth bot starting up [' + BUILD_TAG + ']');
  if (!serverReady) return res.status(200).type('text/plain').send('auth ok, broadcast pool starting [' + BUILD_TAG + ']');
  res.status(200).type('text/plain').send('ok [' + BUILD_TAG + ']');
});

app.use(function(req, res) {
  console.warn('[404] No route matched: ' + req.method + ' ' + req.originalUrl);
  res.status(404).render('404');
});

app.listen(PORT, function() {
  console.log('\nSENDM SERVER - SHARED BOT-POOL MODEL (auth bot + broadcast pool)');
  console.log('Server running on port ' + PORT + ' | Domain: https://' + DOMAIN + '\n');
});
