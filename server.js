require('dotenv').config();

const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { Telegraf } = require('telegraf');
const mongoose = require('mongoose');
const axios = require('axios');
const IORedis = require('ioredis');
const { Queue, Worker } = require('bullmq');

const fastifyCors = require('@fastify/cors');
const fastifyStatic = require('@fastify/static');
const fastifyFormbody = require('@fastify/formbody');
const fastifyView = require('@fastify/view');
const fastifyRateLimit = require('@fastify/rate-limit');
const ejs = require('ejs');

const PORT = process.env.PORT || 3000;

const fastify = require('fastify')({
  trustProxy: 3,           // same hop-count semantics as app.set('trust proxy', 3)
  bodyLimit: 10 * 1024 * 1024, // 10mb, matches express.json({ limit: '10mb' })
  ignoreTrailingSlash: true
});

// ==================== CONFIG & SECRETS ====================
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_weak_secret_change_me_immediately';
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY || 'sk_test_fallback_change_me';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'midas';
const DOMAIN = process.env.DOMAIN;
let WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;

if (!DOMAIN) {
  console.error('ERROR: DOMAIN environment variable is required for webhooks!');
  process.exit(1);
}

if (!WEBHOOK_SECRET || WEBHOOK_SECRET.trim() === '') {
  WEBHOOK_SECRET = crypto.randomBytes(32).toString('hex');
  console.warn('⚠️  WARNING: WEBHOOK_SECRET not set in .env! Generated temporary one:');
  console.warn('     ' + WEBHOOK_SECRET);
  console.warn('     Add it to your .env file to keep it permanent across restarts:');
  console.warn('     WEBHOOK_SECRET=' + WEBHOOK_SECRET + '\n');
} else {
  console.log('Webhook secret loaded from .env');
}

if (JWT_SECRET.includes('fallback')) {
  console.warn('⚠️  WARNING: JWT_SECRET not set in .env! Using insecure fallback.');
}
if (PAYSTACK_SECRET_KEY.startsWith('sk_test_fallback')) {
  console.warn('⚠️  WARNING: PAYSTACK_SECRET_KEY not set in .env!');
}

const MONTHLY_PRICE_KOBO = 150000;

// Batching config
const BATCH_SIZE = 25;
const BATCH_DELAY_MS = 1000;
const MAX_MSG_LENGTH = 4000;

// ==================== REDIS CONNECTIONS ====================
// BullMQ requires separate IORedis instances for Queue and Worker.
// The Worker uses BLPOP (blocking pop) internally, which ties up the
// connection. If Queue and Worker share one connection, published jobs
// can never be delivered. Two connections pointing to the same URL fixes this.
function createRedisConnection() {
  if (process.env.REDIS_URL) {
    return new IORedis(process.env.REDIS_URL, {
      maxRetriesPerRequest: null,
      enableReadyCheck: false
    });
  }
  console.warn('⚠️ WARNING: REDIS_URL not set in .env, falling back to localhost:6379');
  return new IORedis({
    host: 'localhost',
    port: 6379,
    maxRetriesPerRequest: null,
    enableReadyCheck: false
  });
}

const redisConnection = createRedisConnection();       // used by Queue (publisher)
const workerRedisConnection = createRedisConnection(); // used by Worker (consumer)

// ==================== REDIS DIAGNOSTICS ====================
redisConnection.on('connect', function() {
  console.log('✅ Redis (queue) connected');
});
redisConnection.on('ready', function() {
  console.log('✅ Redis (queue) ready');
});
redisConnection.on('error', function(err) {
  console.error('❌ Redis (queue) error:', err.message);
});
redisConnection.on('close', function() {
  console.warn('⚠️ Redis (queue) connection closed');
});
redisConnection.on('reconnecting', function() {
  console.warn('🔄 Redis (queue) reconnecting...');
});

workerRedisConnection.on('connect', function() {
  console.log('✅ Redis (worker) connected');
});
workerRedisConnection.on('ready', function() {
  console.log('✅ Redis (worker) ready');
});
workerRedisConnection.on('error', function(err) {
  console.error('❌ Redis (worker) error:', err.message);
});
workerRedisConnection.on('close', function() {
  console.warn('⚠️ Redis (worker) connection closed');
});
workerRedisConnection.on('reconnecting', function() {
  console.warn('🔄 Redis (worker) reconnecting...');
});

const broadcastQueue = new Queue('telegram-broadcasts', { connection: redisConnection });

broadcastQueue.on('error', function(err) {
  console.error('❌ BullMQ Queue error:', err.message);
});

// ==================== CONTACT VALIDATION REGEX ====================
const CONTACT_REGEX = /^(\+?[0-9\s\-\(\)]{7,20}|[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$/;

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
    bucket = {
      pages: null,
      forms: null,
      contacts: null,
      pagesTs: 0,
      formsTs: 0,
      contactsTs: 0,
      lastAccess: Date.now()
    };
    userCache.set(userId, bucket);
  } else {
    bucket.lastAccess = Date.now();
  }
  return bucket;
}

function invalidateUserCache(userId, type) {
  type = type || 'all';
  const bucket = userCache.get(userId);
  if (!bucket) return;

  if (type === 'pages' || type === 'all') {
    bucket.pages = null;
    bucket.pagesTs = 0;
  }
  if (type === 'forms' || type === 'all') {
    bucket.forms = null;
    bucket.formsTs = 0;
  }
  if (type === 'contacts' || type === 'all') {
    bucket.contacts = null;
    bucket.contactsTs = 0;
  }
  bucket.lastAccess = Date.now();
}

function invalidatePublicCache(key) {
  publicCache.delete(key);
}

setInterval(function() {
  const now = Date.now();
  const INACTIVE_THRESHOLD = 30 * 60 * 1000;

  for (const [key, val] of publicCache.entries()) {
    if (now - val.timestamp > TTL.public) {
      publicCache.delete(key);
    }
  }

  for (const [userId, bucket] of userCache.entries()) {
    if (now - bucket.lastAccess > INACTIVE_THRESHOLD) {
      userCache.delete(userId);
      console.log('🧹 Cleaned cache for inactive user: ' + userId);
    }
  }
}, 10 * 60 * 1000);

// ==================== ADMIN SETTINGS CACHE ====================
let adminSettingsCache = {
  dailyBroadcastLimit: 3,
  maxLandingPages: 5,
  maxForms: 5
};

// ==================== MONGODB CONNECTION ====================
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/sendm';
console.log('Connecting to MongoDB:', MONGODB_URI.replace(/:([^:@]+)@/, ':****@'));

mongoose.connect(MONGODB_URI, {
  serverSelectionTimeoutMS: 30000,
  socketTimeoutMS: 45000,
  connectTimeoutMS: 30000,
}).then(function() {
  console.log('✅ MongoDB connected');
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
  telegramBotToken: String,
  telegramChatId: String,
  isTelegramConnected: { type: Boolean, default: false },
  botUsername: String,
  isSubscribed: { type: Boolean, default: false },
  subscriptionEndDate: Date,
  subscriptionPlan: String,
  pendingPaymentReference: String,
  createdAt: { type: Date, default: Date.now },
}, { timestamps: true });

userSchema.index({ telegramBotToken: 1 });

const landingPageSchema = new mongoose.Schema({
  shortId: { type: String, required: true, unique: true },
  userId: { type: String, required: true },
  title: String,
  config: Object,
  createdAt: Date,
  updatedAt: Date,
}, { timestamps: true });

landingPageSchema.index({ userId: 1 });

const formPageSchema = new mongoose.Schema({
  shortId: { type: String, required: true, unique: true },
  userId: { type: String, required: true },
  title: String,
  state: Object,
  welcomeMessage: String,
  createdAt: Date,
  updatedAt: Date,
}, { timestamps: true });

formPageSchema.index({ userId: 1 });

const contactSchema = new mongoose.Schema({
  userId: { type: String, required: true },
  shortId: String,
  name: String,
  contact: { type: String, required: true },
  telegramChatId: String,
  status: { type: String, default: 'pending' },
  submittedAt: Date,
  subscribedAt: Date,
  unsubscribedAt: Date,
}, { timestamps: true });

contactSchema.index({ userId: 1 });
contactSchema.index({ userId: 1, contact: 1 });
contactSchema.index({ userId: 1, telegramChatId: 1 });
contactSchema.index({ userId: 1, status: 1 });

const scheduledBroadcastSchema = new mongoose.Schema({
  broadcastId: { type: String, required: true, unique: true },
  userId: { type: String, required: true },
  currentJobId: { type: String },
  message: String,
  recipients: { type: String, default: 'all' },
  scheduledTime: Date,
  // FIX: stores "userId::YYYY-MM-DDTHH:MM" to enforce one broadcast per minute per user
  minuteBucket: { type: String },
  status: { type: String, default: 'pending' },
  createdAt: Date,
}, { timestamps: true });

scheduledBroadcastSchema.index({ userId: 1 });
scheduledBroadcastSchema.index({ status: 1 });
scheduledBroadcastSchema.index({ scheduledTime: 1 });
// FIX: unique constraint — one pending broadcast per user per minute
scheduledBroadcastSchema.index(
  { userId: 1, minuteBucket: 1 },
  { unique: true, partialFilterExpression: { status: 'pending', minuteBucket: { $exists: true } } }
);

const broadcastDailySchema = new mongoose.Schema({
  userId: { type: String, required: true },
  date: { type: String, required: true },
  count: { type: Number, default: 1 },
}, { timestamps: true });

broadcastDailySchema.index({ userId: 1, date: 1 }, { unique: true });

const adminSettingsSchema = new mongoose.Schema({
  dailyBroadcastLimit: { type: Number, default: 3, min: 1 },
  maxLandingPages: { type: Number, default: 5, min: 1 },
  maxForms: { type: Number, default: 5, min: 1 },
}, { timestamps: true });

adminSettingsSchema.statics.getSettings = async function() {
  let settings = await this.findOne();
  if (!settings) {
    settings = await this.create({
      dailyBroadcastLimit: 3,
      maxLandingPages: 5,
      maxForms: 5
    });
  }
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
const ScheduledBroadcast = mongoose.model('ScheduledBroadcast', scheduledBroadcastSchema);
const BroadcastDaily = mongoose.model('BroadcastDaily', broadcastDailySchema);

// In-memory helpers
const activeBots = new Map();
const resetTokens = new Map();
const pendingSubscribers = new Map();

// ==================== TELEGRAM BOT MANAGEMENT ====================
function registerBotHandlers(user, bot) {
  bot.webhookReply = false;
  bot.options.webhookReply = false;

  bot.catch(function(err) {
    if (err.message && err.message.includes('Bot is not running')) {
      console.warn('Ignored expected "Bot is not running" warning in webhook mode for ' + user.email);
    } else {
      console.error('Bot error for ' + user.email + ':', err);
    }
  });

  bot.start(async function(ctx) {
    const payload = ctx.startPayload || '';
    const chatId = ctx.chat.id.toString();

    if (payload.startsWith('sub_') && pendingSubscribers.has(payload)) {
      const sub = pendingSubscribers.get(payload);
      if (sub.userId === user.id) {
        let targetContact = await Contact.findOne({
          userId: user.id,
          telegramChatId: chatId
        });

        const contactsByEmail = await Contact.find({ userId: user.id, contact: sub.contact });

        if (!targetContact) {
          targetContact = contactsByEmail.find(function(c) { return c.status === 'subscribed'; }) ||
                          contactsByEmail.find(function(c) { return c.shortId === sub.shortId; }) ||
                          contactsByEmail[0];
        }

        if (!targetContact) {
          targetContact = new Contact({
            userId: user.id,
            shortId: sub.shortId,
            name: sub.name,
            contact: sub.contact,
            telegramChatId: chatId,
            status: 'subscribed',
            submittedAt: new Date(),
            subscribedAt: new Date()
          });
        } else {
          targetContact.name = sub.name;
          targetContact.contact = sub.contact;
          targetContact.shortId = sub.shortId;
          targetContact.telegramChatId = chatId;
          targetContact.status = 'subscribed';
          targetContact.subscribedAt = targetContact.subscribedAt || new Date();
          targetContact.submittedAt = new Date();
        }

        await targetContact.save();

        await Contact.deleteMany({
          userId: user.id,
          $or: [
            { contact: sub.contact, _id: { $ne: targetContact._id } },
            { telegramChatId: chatId, _id: { $ne: targetContact._id } }
          ]
        });

        pendingSubscribers.delete(payload);

        const form = await FormPage.findOne({ shortId: sub.shortId });
        let welcomeText = '<b>Subscription Confirmed!</b>\n\nHi <b>' + escapeHtml(sub.name) + '</b>!\n\nYou\'re now subscribed.\n\nThank you';

        if (form && form.welcomeMessage && form.welcomeMessage.trim()) {
          welcomeText = form.welcomeMessage
            .replace(/\{name\}/gi, '<b>' + escapeHtml(sub.name) + '</b>')
            .replace(/\{contact\}/gi, escapeHtml(sub.contact));
        }

        await ctx.replyWithHTML(welcomeText);
        return;
      }
    }

    if (payload === user.id) {
      user.telegramChatId = chatId;
      user.isTelegramConnected = true;
      await user.save();
      await ctx.replyWithHTML('<b>Sendm 2FA Connected Successfully!</b>\n\nYou will receive login codes here.');
      return;
    }

    await ctx.replyWithHTML('<b>Welcome!</b>\n\nSubscribe from the page to get updates.');
  });

  bot.command('status', async function(ctx) {
    await ctx.replyWithHTML('<b>Sendm 2FA Status</b>\nAccount: <code>' + user.email + '</code>\nStatus: <b>' + (user.isTelegramConnected ? 'Connected' : 'Not Connected') + '</b>');
  });

  activeBots.set(user.id, bot);
}

async function setupBotWebhook(user) {
  if (!user.telegramBotToken) return;

  const webhookPath = '/webhook/' + WEBHOOK_SECRET + '/' + user.id;
  const webhookUrl = 'https://' + DOMAIN + webhookPath;

  const bot = activeBots.get(user.id);
  if (!bot) {
    console.error('setupBotWebhook called but no bot instance found for ' + user.email);
    return;
  }

  try {
    await bot.telegram.deleteWebhook({ drop_pending_updates: true });
    console.log('Webhook cleaned for ' + user.email);

    await new Promise(function(resolve) { setTimeout(resolve, 4000); });
    await new Promise(function(resolve) { setTimeout(resolve, 2500); });

    let attempts = 0;
    const maxAttempts = 5;

    while (attempts < maxAttempts) {
      try {
        const success = await bot.telegram.setWebhook(webhookUrl, {
          allowed_updates: ['message', 'callback_query', 'my_chat_member']
        });

        if (success) {
          console.log('Webhook SUCCESSFULLY set for @' + (user.botUsername || 'unknown') + ' → ' + webhookUrl);
          return;
        }
      } catch (err) {
        attempts++;
        if (err.response && err.response.error_code === 429) {
          const retryAfter = (err.response.parameters && err.response.parameters.retry_after) || 30;
          console.warn('Rate limit hit for ' + user.email + ' - waiting ' + (retryAfter + 5) + 's (attempt ' + attempts + '/' + maxAttempts + ')');
          await new Promise(function(r) { setTimeout(r, (retryAfter + 5) * 1000); });
        } else {
          console.error('Webhook set FAILED for ' + user.email + ': ' + err.message);
          if (attempts >= maxAttempts) throw err;
          await new Promise(function(r) { setTimeout(r, 5000); });
        }
      }
    }

    console.error('Gave up setting webhook for ' + user.email + ' after ' + maxAttempts + ' attempts');
  } catch (err) {
    console.error('Webhook setup completely failed for ' + user.email + ': ' + err.message);
  }
}

function registerBot(user) {
  if (!user.telegramBotToken) return;

  if (activeBots.has(user.id)) {
    activeBots.delete(user.id);
  }

  const bot = new Telegraf(user.telegramBotToken);
  registerBotHandlers(user, bot);
  console.log('Bot handlers registered for ' + user.email + ' (lazy webhook mode)');
}

// ==================== UTILITIES ====================
function sanitizeTelegramHtml(unsafe) {
  if (!unsafe || typeof unsafe !== 'string') return '';
  const allowedTags = new Set(['b','strong','i','em','u','ins','s','strike','del','span','tg-spoiler','a','code','pre','tg-emoji','blockquote']);
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

function escapeHtml(unsafe) {
  if (!unsafe) unsafe = '';
  return unsafe.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}

function textToHtmlForDisplay(text) {
  if (!text) return '';
  return text
    .replace(/\n{2,}/g, '</p><p>')
    .replace(/\n/g, '<br>');
}

// FIX: returns "userId::YYYY-MM-DDTHH:MM" — used as the per-minute uniqueness key
function getMinuteBucket(userId, date) {
  return userId + '::' + date.toISOString().slice(0, 16); // "YYYY-MM-DDTHH:MM"
}

function prepareTelegramMessage(raw) {
  if (!raw || typeof raw !== 'string') return '';

  let msg = raw.trim();

  // FIX: normalise block-level HTML → newlines before sanitising.
  // Order matters: closing+opening pairs first so we get a blank line between
  // paragraphs, then strip the remaining lone open/close tags.
  // FIX: use [\s]* so a literal newline between </p> and <p> is also matched.
  msg = msg
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/p>[\s]*<p[^>]*>/gi, '\n\n')
    .replace(/<p[^>]*>/gi, '')
    .replace(/<\/p>/gi, '\n')
    .replace(/<div[^>]*>/gi, '\n')
    .replace(/<\/div>/gi, '\n')
    .replace(/&nbsp;/gi, ' ')         // FIX: decode &nbsp; so it isn't sent as literal entity
    .replace(/\n{3,}/g, '\n\n')
    .trim();

  // FIX: if the entire message was HTML structure with no text content, return ''
  // rather than letting sanitizeTelegramHtml return an empty/whitespace string
  // that slips through the caller's length === 0 guard.
  const stripped = msg.replace(/<[^>]+>/g, '').trim();
  if (!stripped) return '';

  return sanitizeTelegramHtml(msg);
}

function splitTelegramMessage(text) {
  if (!text) return [];
  const chunks = [];
  let current = '';
  const lines = text.split(/\r?\n/);

  for (let i = 0; i < lines.length; i++) {
    let line = lines[i];
    while (line.length > MAX_MSG_LENGTH) {
      if (current) {
        chunks.push(current.trim());
        current = '';
      }
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
  if (hasActiveSubscription(user)) {
    return { dailyBroadcasts: Infinity, maxLandingPages: Infinity, maxForms: Infinity };
  }
  return {
    dailyBroadcasts: adminSettingsCache.dailyBroadcastLimit,
    maxLandingPages: adminSettingsCache.maxLandingPages,
    maxForms: adminSettingsCache.maxForms
  };
}

async function incrementDailyBroadcast(userId) {
  const today = getTodayDateString();
  try {
    const record = await BroadcastDaily.findOneAndUpdate(
      { userId: userId, date: today },
      { $inc: { count: 1 } },
      { upsert: true, new: true }
    );
    return record.count;
  } catch (err) {
    if (err.code === 11000) {
      try {
        const record = await BroadcastDaily.findOneAndUpdate(
          { userId: userId, date: today },
          { $inc: { count: 1 } },
          { new: true }
        );
        return record ? record.count : 1;
      } catch (retryErr) {
        console.error('incrementDailyBroadcast retry failed for ' + userId + ':', retryErr.message);
        throw retryErr;
      }
    }
    console.error('incrementDailyBroadcast failed for ' + userId + ':', err.message);
    throw err;
  }
}

async function getDailyBroadcastCount(userId) {
  const today = getTodayDateString();
  try {
    const record = await BroadcastDaily.findOne({ userId: userId, date: today });
    return record ? record.count : 0;
  } catch (err) {
    console.error('getDailyBroadcastCount failed for ' + userId + ':', err.message);
    return 0;
  }
}

// ==================== BullMQ Worker ====================
async function processBroadcast(job) {
  const { userId, message, broadcastId } = job.data;

  console.log('📤 Processing broadcast job ' + job.id + ' for user ' + userId + (broadcastId ? ' (scheduled: ' + broadcastId + ')' : ' (immediate)'));

  if (!activeBots.has(userId)) {
    const userForBot = await User.findOne({ id: userId });
    if (userForBot && userForBot.telegramBotToken) {
      registerBot(userForBot);
      console.log('Lazily hydrated bot for user ' + userId + ' inside broadcast worker');
    }
  }

  const bot = activeBots.get(userId);
  if (!bot) {
    throw new Error('Telegram bot not connected for user ' + userId);
  }

  // FIX: verify the bot token is still valid before attempting to send to
  // potentially thousands of subscribers. A 401 here is fast-fail; without
  // this check every sendMessage() below would fail and we'd only find out
  // after burning through the entire contact list.
  try {
    await bot.telegram.getMe();
  } catch (tokenErr) {
    throw new Error('Bot token invalid or revoked for user ' + userId + ': ' + tokenErr.message);
  }

  const chunks = splitTelegramMessage(message);

  const targets = await Contact.find({
    userId: userId,
    status: 'subscribed',
    telegramChatId: { $exists: true, $ne: null }
  }).lean();

  const total = targets.length;
  let sent = 0;
  let failed = 0;

  console.log('📋 Broadcast job ' + job.id + ': sending to ' + total + ' subscribers');

  const batches = [];
  for (let i = 0; i < targets.length; i += BATCH_SIZE) {
    batches.push(targets.slice(i, i + BATCH_SIZE));
  }

  const unsubscribedIds = [];

  for (let b = 0; b < batches.length; b++) {
    const batch = batches[b];

    await Promise.all(batch.map(async function(target) {
      try {
        for (const chunk of chunks) {
          await bot.telegram.sendMessage(target.telegramChatId, chunk, { parse_mode: 'HTML' });
        }
        sent++;
      } catch (err) {
        failed++;
        const isBlocked = (err.response && err.response.error_code === 403) ||
          /blocked|forbidden|chat not found|deactivated/i.test(err.message || '');
        if (isBlocked) {
          unsubscribedIds.push(target._id);
        } else {
          console.warn('Send failed for chatId ' + target.telegramChatId + ': ' + err.message);
        }
      }
    }));

    if (b < batches.length - 1) {
      await new Promise(function(resolve) { setTimeout(resolve, BATCH_DELAY_MS); });
    }
  }

  if (unsubscribedIds.length > 0) {
    await Contact.updateMany(
      { _id: { $in: unsubscribedIds } },
      { status: 'unsubscribed', unsubscribedAt: new Date(), telegramChatId: null }
    );
  }

  const user = await User.findOne({ id: userId });
  let reportText = broadcastId ? '<b>Scheduled Broadcast Report</b>\n\n' : '<b>Broadcast Report</b>\n\n';
  if (total === 0) {
    reportText += 'No subscribed contacts with Telegram connected.';
  } else {
    const emoji = failed === 0 ? '🎉' : '⚠️';
    reportText += emoji + ' <b>' + sent + ' of ' + total + '</b> delivered.';
    if (failed > 0) reportText += '\n' + failed + ' failed (blocked/deactivated accounts removed).';
  }
  reportText += '\n\nTime: ' + new Date().toLocaleString();

  if (user && user.isTelegramConnected && user.telegramChatId && activeBots.has(userId)) {
    try {
      await bot.telegram.sendMessage(user.telegramChatId, reportText, { parse_mode: 'HTML' });
    } catch (err) {
      console.error('Failed to send report to user ' + userId + ':', err.message);
    }
  }

  if (broadcastId) {
    await ScheduledBroadcast.deleteOne({ broadcastId: broadcastId });
    console.log('✅ Scheduled broadcast ' + broadcastId + ' completed and removed from DB');
  }

  invalidateUserCache(userId, 'contacts');

  console.log('✅ Broadcast job ' + job.id + ' done: ' + sent + ' sent, ' + failed + ' failed out of ' + total);
}

// Worker uses its own dedicated Redis connection to avoid blocking the Queue's connection
const worker = new Worker('telegram-broadcasts', processBroadcast, {
  connection: workerRedisConnection,
  concurrency: 4
});

// ==================== BULLMQ WORKER DIAGNOSTICS ====================
worker.on('ready', function() {
  console.log('✅ BullMQ Worker ready and listening for jobs');
});

worker.on('error', function(err) {
  console.error('❌ BullMQ Worker error:', err.message);
});

worker.on('active', function(job) {
  console.log('▶️  Broadcast job ' + job.id + ' started for user ' + (job.data && job.data.userId));
});

worker.on('completed', function(job) {
  console.log('✅ Broadcast job ' + job.id + ' completed for user ' + (job.data && job.data.userId));
});

worker.on('failed', async function(job, err) {
  try {
    console.error('❌ Broadcast job ' + (job && job.id) + ' failed permanently: ' + err.message);
    console.error('   Job data:', job && job.data);

    const data = (job && job.data) || {};
    const userId = data.userId;
    const broadcastId = data.broadcastId;

    if (!userId) {
      console.error('   Cannot recover — no userId in job data');
      return;
    }

    if (broadcastId) {
      await ScheduledBroadcast.findOneAndUpdate(
        { broadcastId: broadcastId },
        { status: 'failed' }
      ).catch(function(dbErr) {
        console.error('   Failed to mark broadcast as failed in DB:', dbErr.message);
      });
    }

    if (!activeBots.has(userId)) {
      const userForBot = await User.findOne({ id: userId });
      if (userForBot && userForBot.telegramBotToken) {
        registerBot(userForBot);
      }
    }

    const user = await User.findOne({ id: userId });
    if (user && user.isTelegramConnected && user.telegramChatId && activeBots.has(userId)) {
      const bot = activeBots.get(userId);
      const text = broadcastId
        ? '<b>Scheduled Broadcast Failed</b>\n\nFailed after all retries.\nError: ' + escapeHtml(err.message)
        : '<b>Broadcast Failed</b>\n\nFailed after all retries.\nError: ' + escapeHtml(err.message);
      try {
        await bot.telegram.sendMessage(user.telegramChatId, text, { parse_mode: 'HTML' });
      } catch (notifyErr) {
        console.error('   Also failed to notify user via Telegram:', notifyErr.message);
      }
    }
  } catch (handlerErr) {
    console.error('❌ Error inside worker "failed" handler:', handlerErr.message);
  }
});

worker.on('stalled', function(jobId) {
  console.warn('⚠️ Broadcast job ' + jobId + ' stalled and will be retried');
});

// ==================== SCHEDULED BROADCAST RECOVERY ====================
async function recoverLostScheduledBroadcasts() {
  console.log('🔄 Starting recovery of scheduled broadcasts after server restart...');

  const now = new Date();

  const pendingFuture = await ScheduledBroadcast.find({
    status: 'pending',
    scheduledTime: { $gt: now }
  }).lean();

  if (pendingFuture.length === 0) {
    console.log('✔ No pending future scheduled broadcasts need recovery');
    return;
  }

  console.log('Found ' + pendingFuture.length + ' scheduled broadcast(s) to recover');

  let recovered = 0;
  let alreadyExists = 0;

  for (const task of pendingFuture) {
    const jobId = task.currentJobId || task.broadcastId;

    try {
      const existing = await broadcastQueue.getJob(jobId);
      if (existing) {
        const state = await existing.getState();
        if (state === 'waiting' || state === 'delayed' || state === 'active') {
          alreadyExists++;
          console.log('  ↩ Job ' + jobId + ' already in queue with state: ' + state);
          continue;
        }
        await existing.remove();
        console.log('  🗑 Removed stale job ' + jobId + ' with state: ' + state);
      }

      const delayMs = task.scheduledTime.getTime() - Date.now();
      const newJobId = task.broadcastId + '_v' + Date.now();

      const addedJob = await broadcastQueue.add(
        'send-broadcast',
        {
          userId: task.userId,
          message: task.message,
          broadcastId: task.broadcastId
        },
        {
          jobId: newJobId,
          delay: delayMs > 1000 ? delayMs : 0,
          attempts: 4,
          backoff: { type: 'exponential', delay: 5000 }
        }
      );

      await ScheduledBroadcast.updateOne(
        { broadcastId: task.broadcastId },
        { currentJobId: addedJob.id }
      );

      recovered++;
      console.log('  ✅ Re-queued broadcast ' + task.broadcastId + ' as job ' + addedJob.id + ' with delay ' + Math.round(delayMs / 1000) + 's');
    } catch (err) {
      console.error('  ❌ Failed to recover broadcast ' + task.broadcastId + ': ' + err.message);
    }
  }

  console.log(
    '✔ Recovery completed: ' + recovered + ' broadcast(s) re-queued, ' +
    alreadyExists + ' were already present in queue'
  );
}

// ==================== JWT AUTH (Fastify preHandler) ====================
async function authenticateToken(request, reply) {
  const authHeader = request.headers.authorization;
  const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : request.query.token;

  if (!token) {
    reply.code(401).send({ error: 'Access token required' });
    return;
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findOne({ id: decoded.userId });
    if (!user) {
      reply.code(404).send({ error: 'User not found' });
      return;
    }
    request.user = user;
  } catch (err) {
    reply.code(403).send({ error: 'Invalid or expired token' });
  }
}

function generate2FACode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

async function send2FACodeViaBot(user, code) {
  if (!user.isTelegramConnected || !user.telegramChatId || !activeBots.has(user.id)) return false;
  try {
    await activeBots.get(user.id).telegram.sendMessage(
      user.telegramChatId,
      'Security Alert — Password Reset\n\nYour 6-digit code:\n\n<b>' + code + '</b>\n\nValid for 10 minutes.',
      { parse_mode: 'HTML' }
    );
    return true;
  } catch (err) {
    console.error('Failed to send 2FA code:', err.message);
    return false;
  }
}

// ==================== APP BUILD ====================
async function main() {
  // ---- plugins ----
  await fastify.register(fastifyCors, {});
  await fastify.register(fastifyStatic, { root: path.join(__dirname, 'public') });
  await fastify.register(fastifyFormbody); // parses application/x-www-form-urlencoded (admin-limits form)
  await fastify.register(fastifyView, {
    engine: { ejs },
    root: path.join(__dirname, 'views')
  });
  await fastify.register(fastifyRateLimit, { global: false }); // opt-in per-route via config.rateLimit

  const authLimiterConfig = {
    rateLimit: {
      max: 10,
      timeWindow: '15 minutes',
      errorResponseBuilder: function() { return { error: 'Too many attempts' }; }
    }
  };

  const formSubmitLimiterConfig = {
    rateLimit: {
      max: 10,
      timeWindow: '15 minutes',
      keyGenerator: function(request) {
        return request.ip + '::' + request.params.shortId;
      },
      errorResponseBuilder: function() { return { error: 'Too many submissions to this form. Please try again later.' }; }
    }
  };

  // ==================== WEBHOOK ENDPOINT ====================
  fastify.post('/webhook/' + WEBHOOK_SECRET + '/:userId', async function(request, reply) {
    const userId = request.params.userId;
    let bot = activeBots.get(userId);

    if (!bot) {
      try {
        const user = await User.findOne({ id: userId });
        if (user && user.telegramBotToken) {
          registerBot(user);
          bot = activeBots.get(userId);
          console.log('Lazily hydrated bot for user ' + user.email + ' on incoming webhook');
        }
      } catch (err) {
        console.error('Failed to lazily hydrate bot for user ' + userId + ':', err.message);
      }
    }

    let update;
    try {
      if (Buffer.isBuffer(request.body)) {
        update = JSON.parse(request.body.toString('utf8'));
      } else if (request.body && typeof request.body === 'object') {
        update = request.body;
      } else {
        throw new Error('Invalid body format');
      }
    } catch (err) {
      console.error('Failed to parse webhook body for user ' + userId + ':', err);
      reply.code(400).send();
      return;
    }

    if (bot) {
      try {
        await bot.handleUpdate(update);
      } catch (err) {
        console.error('Webhook handle error for user ' + userId + ':', err);
      }
    }

    reply.code(200).send();
  });

  // ==================== AUTH ROUTES ====================
  fastify.post('/api/auth/register', { config: authLimiterConfig }, async function(request, reply) {
    const { fullName, email, password } = request.body;
    if (!fullName || !email || !password) return reply.code(400).send({ error: 'All fields required' });

    const existing = await User.findOne({ email: email.toLowerCase() });
    if (existing) return reply.code(409).send({ error: 'Email already exists' });

    const hashed = await bcrypt.hash(password, 12);
    const newUser = await User.create({
      id: uuidv4(),
      fullName: fullName.trim(),
      email: email.toLowerCase(),
      password: hashed,
    });

    const token = jwt.sign({ userId: newUser.id }, JWT_SECRET, { expiresIn: '7d' });
    reply.code(201).send({
      success: true,
      token: token,
      user: { id: newUser.id, fullName: newUser.fullName, email: newUser.email, isTelegramConnected: false }
    });
  });

  fastify.post('/api/auth/login', { config: authLimiterConfig }, async function(request, reply) {
    const { email, password } = request.body;
    if (!email || !password) return reply.code(400).send({ error: 'Email and password required' });

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return reply.code(401).send({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
    reply.send({
      success: true,
      token: token,
      user: { id: user.id, fullName: user.fullName, email: user.email, isTelegramConnected: user.isTelegramConnected }
    });
  });

  fastify.get('/api/auth/me', { preHandler: authenticateToken }, async function(request, reply) {
    reply.send({
      user: {
        id: request.user.id,
        fullName: request.user.fullName,
        email: request.user.email,
        isTelegramConnected: request.user.isTelegramConnected
      }
    });
  });

  fastify.post('/api/auth/connect-telegram', { preHandler: authenticateToken }, async function(request, reply) {
    const { botToken } = request.body;
    if (!botToken || !botToken.trim()) return reply.code(400).send({ error: 'Bot token required' });

    const token = botToken.trim();

    const existingUser = await User.findOne({ telegramBotToken: token });
    if (existingUser && existingUser.id !== request.user.id) {
      return reply.code(400).send({ error: 'This bot is already linked to another account.' });
    }

    let botInfo;
    let attempts = 0;
    const maxAttempts = 7;
    while (attempts < maxAttempts) {
      attempts++;
      try {
        const response = await axios.get('https://api.telegram.org/bot' + token + '/getMe', {
          timeout: 20000
        });
        if (!response.data.ok) {
          return reply.code(400).send({
            error: 'Invalid bot token — Telegram rejected it: ' + (response.data.description || 'Unauthorized')
          });
        }
        botInfo = response.data.result;
        if (!botInfo || !botInfo.username) {
          return reply.code(400).send({ error: 'Invalid response — missing bot username' });
        }
        break;
      } catch (err) {
        console.warn('Bot token validation attempt ' + attempts + '/' + maxAttempts + ' failed: ' + (err.message || err.code));
        if (attempts >= maxAttempts) {
          return reply.code(500).send({ error: 'Network error validating bot token. Please try again later.' });
        }
        await new Promise(function(r) { setTimeout(r, 8000); });
      }
    }

    const botUsername = botInfo.username.replace(/^@/, '');

    if (request.user.telegramBotToken && request.user.telegramBotToken !== token) {
      try {
        await axios.post('https://api.telegram.org/bot' + request.user.telegramBotToken + '/deleteWebhook', {
          drop_pending_updates: true
        }, { timeout: 20000 });
        console.log('Old webhook cleared before connecting new bot for user ' + request.user.id);
      } catch (err) {
        console.warn('Failed to clear old webhook (may be invalid token): ' + err.message);
      }
    }

    request.user.telegramBotToken = token;
    request.user.botUsername = botUsername;
    request.user.isTelegramConnected = false;
    request.user.telegramChatId = null;
    await request.user.save();

    registerBot(request.user);
    await setupBotWebhook(request.user);

    const startLink = 'https://t.me/' + botUsername + '?start=' + request.user.id;

    reply.send({
      success: true,
      message: 'Bot connected!',
      botUsername: '@' + botUsername,
      startLink: startLink
    });
  });

  fastify.post('/api/auth/change-bot-token', { preHandler: authenticateToken }, async function(request, reply) {
    const { newBotToken } = request.body;
    if (!newBotToken || !newBotToken.trim()) return reply.code(400).send({ error: 'New bot token required' });

    const token = newBotToken.trim();

    const existingUser = await User.findOne({ telegramBotToken: token });
    if (existingUser && existingUser.id !== request.user.id) {
      return reply.code(400).send({ error: 'This bot is already linked to another account.' });
    }

    let botInfo;
    let attempts = 0;
    const maxAttempts = 7;
    while (attempts < maxAttempts) {
      attempts++;
      try {
        const response = await axios.get('https://api.telegram.org/bot' + token + '/getMe', {
          timeout: 20000
        });
        if (!response.data.ok) {
          return reply.code(400).send({
            error: 'Invalid new token — Telegram rejected it: ' + (response.data.description || 'Unauthorized')
          });
        }
        botInfo = response.data.result;
        if (!botInfo || !botInfo.username) {
          return reply.code(400).send({ error: 'Invalid response — missing bot username' });
        }
        break;
      } catch (err) {
        console.warn('New bot token validation attempt ' + attempts + '/' + maxAttempts + ' failed: ' + (err.message || err.code));
        if (attempts >= maxAttempts) {
          return reply.code(500).send({ error: 'Network error validating new bot token. Please try again later.' });
        }
        await new Promise(function(r) { setTimeout(r, 8000); });
      }
    }

    const botUsername = botInfo.username.replace(/^@/, '');

    if (request.user.telegramBotToken) {
      try {
        await axios.post('https://api.telegram.org/bot' + request.user.telegramBotToken + '/deleteWebhook', {
          drop_pending_updates: true
        }, { timeout: 20000 });
        console.log('Old webhook cleared on bot token change for user ' + request.user.id);
      } catch (err) {
        console.warn('Failed to clear old webhook on token change: ' + err.message);
      }
    }

    request.user.telegramBotToken = token;
    request.user.botUsername = botUsername;
    request.user.isTelegramConnected = false;
    request.user.telegramChatId = null;
    await request.user.save();

    registerBot(request.user);
    await setupBotWebhook(request.user);

    const startLink = 'https://t.me/' + botUsername + '?start=' + request.user.id;

    reply.send({
      success: true,
      message: 'Bot token updated! Please send /start to the new bot to reconnect 2FA.',
      botUsername: '@' + botUsername,
      startLink: startLink
    });
  });

  fastify.post('/api/auth/disconnect-telegram', { preHandler: authenticateToken }, async function(request, reply) {
    if (request.user.telegramBotToken) {
      try {
        await axios.post('https://api.telegram.org/bot' + request.user.telegramBotToken + '/deleteWebhook', {
          drop_pending_updates: true
        }, { timeout: 20000 });
        console.log('Webhook cleared on disconnect for user ' + request.user.id);
      } catch (err) {
        console.warn('Failed to clear webhook on disconnect: ' + err.message);
      }
    }

    if (activeBots.has(request.user.id)) {
      activeBots.delete(request.user.id);
    }

    request.user.telegramBotToken = null;
    request.user.botUsername = null;
    request.user.telegramChatId = null;
    request.user.isTelegramConnected = false;
    await request.user.save();

    reply.send({ success: true, message: 'Telegram disconnected successfully. You can now connect a fresh bot without any blockage.' });
  });

  fastify.get('/api/auth/bot-status', { preHandler: authenticateToken }, async function(request, reply) {
    reply.send({
      activated: request.user.isTelegramConnected,
      chatId: request.user.telegramChatId || null
    });
  });

  fastify.post('/api/auth/forgot-password', async function(request, reply) {
    const { email } = request.body;
    if (!email) return reply.code(400).send({ error: 'Email required' });

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return reply.send({ success: true, message: 'If account exists, code was sent.' });
    if (!user.isTelegramConnected) return reply.code(400).send({ error: 'Telegram 2FA not connected' });

    if (!activeBots.has(user.id) && user.telegramBotToken) {
      registerBot(user);
    }

    const code = generate2FACode();
    const resetToken = uuidv4();
    resetTokens.set(resetToken, { userId: user.id, code: code, expiresAt: Date.now() + 10 * 60 * 1000 });

    const sent = await send2FACodeViaBot(user, code);
    if (!sent) return reply.code(500).send({ error: 'Failed to send code' });

    reply.send({ success: true, message: 'Code sent!', resetToken: resetToken });
  });

  fastify.post('/api/auth/verify-reset-code', async function(request, reply) {
    const { resetToken, code } = request.body;
    if (!resetToken || !code) return reply.code(400).send({ error: 'Token and code required' });

    const entry = resetTokens.get(resetToken);
    if (!entry || Date.now() > entry.expiresAt) {
      resetTokens.delete(resetToken);
      return reply.code(400).send({ error: 'Invalid or expired code' });
    }
    if (entry.code !== code.trim()) return reply.code(400).send({ error: 'Wrong code' });

    reply.send({ success: true, message: 'Verified', userId: entry.userId });
  });

  fastify.post('/api/auth/reset-password', async function(request, reply) {
    const { resetToken, newPassword } = request.body;
    if (!resetToken || !newPassword || newPassword.length < 6) return reply.code(400).send({ error: 'Valid token and password required' });

    const entry = resetTokens.get(resetToken);
    if (!entry || Date.now() > entry.expiresAt) {
      resetTokens.delete(resetToken);
      return reply.code(400).send({ error: 'Invalid session' });
    }

    const user = await User.findOne({ id: entry.userId });
    if (!user) return reply.code(404).send({ error: 'User not found' });

    user.password = await bcrypt.hash(newPassword, 12);
    await user.save();
    resetTokens.delete(resetToken);

    reply.send({ success: true, message: 'Password reset successful' });
  });

  // ==================== SUBSCRIPTION ROUTES ====================
  fastify.get('/api/subscription/status', { preHandler: authenticateToken }, async function(request, reply) {
    const subscribed = hasActiveSubscription(request.user);
    reply.send({
      subscribed: subscribed,
      plan: subscribed ? 'premium-monthly' : 'free',
      endDate: request.user.subscriptionEndDate || null,
      daysLeft: subscribed
        ? Math.ceil((new Date(request.user.subscriptionEndDate) - new Date()) / (1000 * 60 * 60 * 24))
        : 0
    });
  });

  fastify.post('/api/subscription/initiate', { preHandler: authenticateToken }, async function(request, reply) {
    if (hasActiveSubscription(request.user)) {
      return reply.code(400).send({ error: 'You already have an active subscription' });
    }

    try {
      const response = await axios.post(
        'https://api.paystack.co/transaction/initialize',
        {
          email: request.user.email,
          amount: MONTHLY_PRICE_KOBO,
          currency: 'NGN',
          callback_url: request.protocol + '://' + request.headers.host + '/subscription-success',
          metadata: { userId: request.user.id, plan: 'premium-monthly' }
        },
        {
          headers: {
            Authorization: 'Bearer ' + PAYSTACK_SECRET_KEY,
            'Content-Type': 'application/json'
          }
        }
      );

      const authorization_url = response.data.data.authorization_url;
      const reference = response.data.data.reference;

      request.user.pendingPaymentReference = reference;
      await request.user.save();

      reply.send({ success: true, authorizationUrl: authorization_url, reference: reference });
    } catch (error) {
      console.error('Paystack init error:', error.response ? error.response.data : error.message);
      reply.code(500).send({ error: 'Failed to initialize payment' });
    }
  });

  fastify.post('/api/subscription/webhook', async function(request, reply) {
    try {
      const hash = crypto.createHmac('sha512', PAYSTACK_SECRET_KEY)
        .update(JSON.stringify(request.body))
        .digest('hex');

      if (hash !== request.headers['x-paystack-signature']) {
        return reply.code(401).send('Invalid signature');
      }

      const event = request.body;

      if (event.event === 'charge.success') {
        const reference = event.data.reference;
        const userId = event.data.metadata && event.data.metadata.userId;

        if (!userId) return reply.code(200).send('OK');

        const user = await User.findOne({ id: userId });
        if (!user || user.pendingPaymentReference !== reference) {
          return reply.code(200).send('OK');
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

      reply.code(200).send('OK');
    } catch (err) {
      console.error('Webhook error:', err);
      reply.code(200).send('OK');
    }
  });

  fastify.get('/subscription-success', async function(request, reply) {
    reply.type('text/html').send('<!DOCTYPE html>\n<html lang="en">\n<head>\n  <meta charset="UTF-8">\n  <title>Payment Successful</title>\n  <style>\n    body{font-family:system-ui,sans-serif;background:#0a0a0a;color:#00ff41;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;}\n    .box{background:#111;padding:60px;border-radius:20px;text-align:center;box-shadow:0 0 30px rgba(0,255,65,0.2);}\n    h1{margin:0 0 20px;font-size:3em;color:#00ff41;}\n    p{font-size:1.3em;margin:20px 0;line-height:1.6;}\n    a{display:inline-block;margin-top:30px;padding:14px 32px;background:#00ff41;color:#000;font-weight:bold;text-decoration:none;border-radius:8px;font-size:1.1em;}\n    a:hover{background:#00cc33;}\n  </style>\n</head>\n<body>\n  <div class="box">\n    <h1>✔ Payment Successful!</h1>\n    <p>Your subscription is now <strong>active</strong>.</p>\n    <p>You have unlimited broadcasts, landing pages, and forms.</p>\n    <p><a href="https://sendmi.onrender.com">← Return to Dashboard</a></p>\n  </div>\n</body>\n</html>');
  });

  // ==================== CACHED HIGH-READ ENDPOINTS ====================
  fastify.get('/p/:shortId', async function(request, reply) {
    const key = 'landing:' + request.params.shortId;
    const cached = publicCache.get(key);

    if (cached && Date.now() - cached.timestamp < TTL.public) {
      return reply.view('landing', cached.data);
    }

    const page = await LandingPage.findOne({ shortId: request.params.shortId });
    if (!page) { reply.code(404); return reply.view('404'); }

    const processedBlocks = page.config.blocks.map(function(block) {
      if (block.type === 'text') {
        return Object.assign({}, block, { htmlContent: textToHtmlForDisplay(block.content) });
      }
      return block;
    });

    const data = {
      title: page.title,
      blocks: processedBlocks
    };

    publicCache.set(key, { data: data, timestamp: Date.now() });
    return reply.view('landing', data);
  });

  fastify.get('/f/:shortId', async function(request, reply) {
    const key = 'form:' + request.params.shortId;
    const cached = publicCache.get(key);

    if (cached && Date.now() - cached.timestamp < TTL.public) {
      return reply.view('form', cached.data);
    }

    const form = await FormPage.findOne({ shortId: request.params.shortId });
    if (!form) { reply.code(404); return reply.view('404'); }

    const data = { title: form.title, state: form.state };
    publicCache.set(key, { data: data, timestamp: Date.now() });
    return reply.view('form', data);
  });

  fastify.get('/api/pages', { preHandler: authenticateToken }, async function(request, reply) {
    const bucket = getUserCache(request.user.id);
    const now = Date.now();

    if (bucket.pages && now - bucket.pagesTs < TTL.pages) {
      return reply.send({ pages: bucket.pages });
    }

    const pages = await LandingPage.find({ userId: request.user.id }).sort({ updatedAt: -1 });
    const host = request.headers.host;
    const protocol = request.protocol;
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
    reply.send({ pages: formatted });
  });

  fastify.get('/api/forms', { preHandler: authenticateToken }, async function(request, reply) {
    const bucket = getUserCache(request.user.id);
    const now = Date.now();

    if (bucket.forms && now - bucket.formsTs < TTL.forms) {
      return reply.send({ forms: bucket.forms });
    }

    const forms = await FormPage.find({ userId: request.user.id }).sort({ updatedAt: -1 });
    const host = request.headers.host;
    const protocol = request.protocol;
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
    reply.send({ forms: formatted });
  });

  fastify.get('/api/contacts', { preHandler: authenticateToken }, async function(request, reply) {
    const bucket = getUserCache(request.user.id);
    const now = Date.now();

    if (bucket.contacts && now - bucket.contactsTs < TTL.contacts) {
      return reply.send({ success: true, contacts: bucket.contacts });
    }

    const contacts = await Contact.find({ userId: request.user.id }).sort({ submittedAt: -1 });
    const formatted = contacts.map(function(c) {
      return {
        name: c.name,
        contact: c.contact,
        status: c.status,
        telegramChatId: c.telegramChatId || null,
        pageId: c.shortId,
        submittedAt: new Date(c.submittedAt).toLocaleString(),
        subscribedAt: c.subscribedAt ? new Date(c.subscribedAt).toLocaleString() : null
      };
    });

    bucket.contacts = formatted;
    bucket.contactsTs = now;
    reply.send({ success: true, contacts: formatted });
  });

  fastify.get('/api/page/:shortId', async function(request, reply) {
    const key = 'apiPage:' + request.params.shortId;
    const cached = publicCache.get(key);
    if (cached && Date.now() - cached.timestamp < TTL.public) {
      return reply.send(cached.data);
    }

    const page = await LandingPage.findOne({ shortId: request.params.shortId });
    if (!page) return reply.code(404).send({ error: 'Page not found' });

    const data = { shortId: page.shortId, title: page.title, config: page.config };
    publicCache.set(key, { data: data, timestamp: Date.now() });
    reply.send(data);
  });

  fastify.get('/api/form/:shortId', async function(request, reply) {
    const key = 'apiForm:' + request.params.shortId;
    const cached = publicCache.get(key);
    if (cached && Date.now() - cached.timestamp < TTL.public) {
      return reply.send(cached.data);
    }

    const form = await FormPage.findOne({ shortId: request.params.shortId });
    if (!form) return reply.code(404).send({ error: 'Form not found' });

    const data = {
      shortId: form.shortId,
      title: form.title,
      state: form.state,
      welcomeMessage: form.welcomeMessage
    };
    publicCache.set(key, { data: data, timestamp: Date.now() });
    reply.send(data);
  });

  // ==================== LANDING PAGES WRITE ROUTES ====================
  fastify.post('/api/pages/save', { preHandler: authenticateToken }, async function(request, reply) {
    const { shortId, title, config } = request.body;
    if (!title || !config || !Array.isArray(config.blocks)) return reply.code(400).send({ error: 'Title and config.blocks required' });

    const limits = getUserLimits(request.user);

    if (!shortId) {
      const currentCount = await LandingPage.countDocuments({ userId: request.user.id });
      if (currentCount >= limits.maxLandingPages && limits.maxLandingPages !== Infinity) {
        return reply.code(403).send({ error: 'Maximum landing pages limit reached.' });
      }
    }

    const finalShortId = shortId || uuidv4().slice(0, 8);
    const now = new Date();

    const cleanBlocks = config.blocks.map(function(b) {
      if (!b || b.isEditor || (b.id && (b.id.includes('editor-') || b.id.includes('control-')))) return null;
      if (b.type === 'text') return { type: 'text', tag: b.tag || 'p', content: (b.content || '').trim() };
      if (b.type === 'image') return b.src ? { type: 'image', src: b.src.trim() } : null;
      if (b.type === 'button') return b.text ? { type: 'button', text: b.text.trim(), href: b.href || '' } : null;
      if (b.type === 'form') return b.html ? { type: 'form', html: b.html.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '') } : null;
      return null;
    }).filter(Boolean);

    if (cleanBlocks.length === 0) return reply.code(400).send({ error: 'No valid blocks' });

    await LandingPage.findOneAndUpdate(
      { shortId: finalShortId },
      {
        userId: request.user.id,
        title: title.trim(),
        config: { blocks: cleanBlocks },
        updatedAt: now,
        createdAt: shortId ? undefined : now
      },
      { upsert: true }
    );

    invalidateUserCache(request.user.id, 'pages');
    invalidatePublicCache('landing:' + finalShortId);
    invalidatePublicCache('apiPage:' + finalShortId);

    const url = request.protocol + '://' + request.headers.host + '/p/' + finalShortId;
    reply.send({ success: true, shortId: finalShortId, url: url });
  });

  fastify.post('/api/pages/delete', { preHandler: authenticateToken }, async function(request, reply) {
    const { shortId } = request.body;
    const page = await LandingPage.findOne({ shortId: shortId, userId: request.user.id });
    if (!page) return reply.code(404).send({ error: 'Page not found' });
    await LandingPage.deleteOne({ shortId: shortId });

    invalidateUserCache(request.user.id, 'pages');
    invalidatePublicCache('landing:' + shortId);
    invalidatePublicCache('apiPage:' + shortId);

    reply.send({ success: true });
  });

  // ==================== FORMS WRITE ROUTES ====================
  fastify.post('/api/forms/save', { preHandler: authenticateToken }, async function(request, reply) {
    const { shortId, title, state, welcomeMessage } = request.body;
    if (!title || !state) return reply.code(400).send({ error: 'Title and state required' });

    const limits = getUserLimits(request.user);

    if (!shortId) {
      const currentCount = await FormPage.countDocuments({ userId: request.user.id });
      if (currentCount >= limits.maxForms && limits.maxForms !== Infinity) {
        return reply.code(403).send({ error: 'Maximum forms limit reached.' });
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

    await FormPage.findOneAndUpdate(
      { shortId: finalShortId },
      {
        userId: request.user.id,
        title: title.trim(),
        state: sanitizedState,
        welcomeMessage: sanitizedWelcome,
        updatedAt: now,
        createdAt: shortId ? undefined : now
      },
      { upsert: true }
    );

    invalidateUserCache(request.user.id, 'forms');
    invalidatePublicCache('form:' + finalShortId);
    invalidatePublicCache('apiForm:' + finalShortId);

    const url = request.protocol + '://' + request.headers.host + '/f/' + finalShortId;
    reply.send({ success: true, shortId: finalShortId, url: url });
  });

  fastify.post('/api/forms/delete', { preHandler: authenticateToken }, async function(request, reply) {
    const { shortId } = request.body;
    const form = await FormPage.findOne({ shortId: shortId, userId: request.user.id });
    if (!form) return reply.code(404).send({ error: 'Form not found' });
    await FormPage.deleteOne({ shortId: shortId });
    await Contact.deleteMany({ shortId: shortId, userId: request.user.id });

    invalidateUserCache(request.user.id, 'forms');
    invalidatePublicCache('form:' + shortId);
    invalidatePublicCache('apiForm:' + shortId);

    reply.send({ success: true });
  });

  // ==================== SUBSCRIBE & CONTACTS ====================
  fastify.post('/api/subscribe/:shortId', { config: formSubmitLimiterConfig }, async function(request, reply) {
    const shortId = request.params.shortId;
    const { name, email } = request.body;

    if (!name || !name.trim()) return reply.code(400).send({ error: 'Name is required' });
    if (!email || !email.trim()) return reply.code(400).send({ error: 'Contact is required' });

    const contactValue = email.trim();

    if (!CONTACT_REGEX.test(contactValue)) {
      return reply.code(400).send({ error: 'Contact must be a valid email address or phone number' });
    }

    const form = await FormPage.findOne({ shortId: shortId });
    if (!form) return reply.code(404).send({ error: 'Form not found' });

    const owner = await User.findOne({ id: form.userId });
    if (!owner || !owner.telegramBotToken || !owner.botUsername) return reply.code(400).send({ error: 'Bot not connected' });

    const payload = 'sub_' + shortId + '_' + uuidv4().slice(0, 12);

    let contact = await Contact.findOne({ userId: owner.id, contact: contactValue });

    if (contact) {
      if (contact.status === 'subscribed') {
        contact.name = name.trim();
        contact.shortId = shortId;
        contact.submittedAt = new Date();
        await contact.save();

        pendingSubscribers.set(payload, {
          userId: owner.id,
          shortId: shortId,
          name: name.trim(),
          contact: contactValue,
          createdAt: Date.now()
        });

        const deepLink = 'https://t.me/' + owner.botUsername + '?start=' + payload;
        return reply.send({ success: true, deepLink: deepLink, alreadySubscribed: true });
      }

      contact.name = name.trim();
      contact.shortId = shortId;
      contact.submittedAt = new Date();
      await contact.save();
    } else {
      contact = new Contact({
        userId: owner.id,
        shortId: shortId,
        name: name.trim(),
        contact: contactValue,
        status: 'pending',
        submittedAt: new Date()
      });
      await contact.save();
    }

    pendingSubscribers.set(payload, {
      userId: owner.id,
      shortId: shortId,
      name: name.trim(),
      contact: contactValue,
      createdAt: Date.now()
    });

    const deepLink = 'https://t.me/' + owner.botUsername + '?start=' + payload;
    reply.send({ success: true, deepLink: deepLink });

    invalidateUserCache(owner.id, 'contacts');
  });

  fastify.post('/api/contacts/delete', { preHandler: authenticateToken }, async function(request, reply) {
    const { contacts } = request.body;
    if (!Array.isArray(contacts) || contacts.length === 0) return reply.code(400).send({ error: 'Provide contact array' });

    const result = await Contact.deleteMany({
      userId: request.user.id,
      contact: { $in: contacts }
    });

    invalidateUserCache(request.user.id, 'contacts');

    reply.send({ success: true, deletedCount: result.deletedCount });
  });

  // ==================== BROADCASTING ====================
  fastify.post('/api/broadcast/now', { preHandler: authenticateToken }, async function(request, reply) {
    const { message } = request.body;
    if (!message || !message.trim()) return reply.code(400).send({ error: 'Message required' });

    const processed = message.trim();
    if (processed.length > MAX_MSG_LENGTH * 10) {
      return reply.code(400).send({ error: 'Message too long' });
    }

    const limits = getUserLimits(request.user);
    if (limits.dailyBroadcasts !== Infinity) {
      const currentCount = await getDailyBroadcastCount(request.user.id);
      if (currentCount >= limits.dailyBroadcasts) {
        return reply.code(403).send({ error: 'Daily broadcast limit reached.' });
      }
    }

    let todayCount;
    try {
      todayCount = await incrementDailyBroadcast(request.user.id);
    } catch (err) {
      console.error('Failed to increment daily broadcast count for ' + request.user.id + ':', err.message);
      return reply.code(500).send({ error: 'Internal error — please try again.' });
    }

    if (todayCount > limits.dailyBroadcasts && limits.dailyBroadcasts !== Infinity) {
      return reply.code(403).send({ error: 'Daily broadcast limit reached.' });
    }

    const readyMessage = prepareTelegramMessage(processed);

    // FIX: prepareTelegramMessage now returns '' for HTML-only messages with no text content
    if (!readyMessage) {
      return reply.code(400).send({ error: 'Message is empty after processing — check for unsupported HTML.' });
    }

    let job;
    try {
      job = await broadcastQueue.add('send-broadcast', {
        userId: request.user.id,
        message: readyMessage
      }, {
        attempts: 4,
        backoff: { type: 'exponential', delay: 5000 }
      });
    } catch (err) {
      console.error('Failed to queue immediate broadcast for ' + request.user.id + ':', err.message);
      return reply.code(500).send({ error: 'Failed to queue broadcast. Please try again.' });
    }

    console.log('📤 Immediate broadcast queued: job ' + job.id + ' for user ' + request.user.id);

    reply.send({
      success: true,
      message: 'Broadcast queued and sending in background. You will receive a delivery report via Telegram shortly.'
    });
  });

  fastify.post('/api/broadcast/schedule', { preHandler: authenticateToken }, async function(request, reply) {
    const { message, scheduledTime, recipients } = request.body;
    const recipientsList = recipients || 'all';

    if (!message || !message.trim()) return reply.code(400).send({ error: 'Message required' });

    const processed = message.trim();
    if (processed.length > MAX_MSG_LENGTH * 10) {
      return reply.code(400).send({ error: 'Message too long' });
    }

    const time = new Date(scheduledTime);
    if (isNaN(time.getTime()) || time <= new Date()) {
      return reply.code(400).send({ error: 'Invalid future time' });
    }

    const limits = getUserLimits(request.user);
    if (limits.dailyBroadcasts !== Infinity) {
      const currentCount = await getDailyBroadcastCount(request.user.id);
      if (currentCount >= limits.dailyBroadcasts) {
        return reply.code(403).send({ error: 'Daily broadcast limit reached.' });
      }
    }

    let todayCount;
    try {
      todayCount = await incrementDailyBroadcast(request.user.id);
    } catch (err) {
      console.error('Failed to increment daily broadcast count for ' + request.user.id + ':', err.message);
      return reply.code(500).send({ error: 'Internal error — please try again.' });
    }

    if (todayCount > limits.dailyBroadcasts && limits.dailyBroadcasts !== Infinity) {
      return reply.code(403).send({ error: 'Daily broadcast limit reached.' });
    }

    const readyMessage = prepareTelegramMessage(processed);

    // FIX: catch empty message early (e.g. HTML-only input with no visible text)
    if (!readyMessage) {
      return reply.code(400).send({ error: 'Message is empty after processing — check for unsupported HTML.' });
    }

    // FIX: enforce one broadcast per user per minute
    const bucket = getMinuteBucket(request.user.id, time);
    const conflict = await ScheduledBroadcast.findOne({
      userId: request.user.id,
      minuteBucket: bucket,
      status: 'pending'
    });
    if (conflict) {
      return reply.code(409).send({
        error: 'You already have a broadcast scheduled at that minute. Please choose a different time.'
      });
    }

    const broadcastId = uuidv4();
    const now = new Date();
    const delay = time.getTime() - Date.now();
    const jobId = broadcastId + '_v1';

    await ScheduledBroadcast.create({
      broadcastId: broadcastId,
      currentJobId: jobId,
      userId: request.user.id,
      message: readyMessage,
      recipients: recipientsList,
      scheduledTime: time,
      minuteBucket: bucket,   // FIX: stored for uniqueness enforcement
      status: 'pending',
      createdAt: now
    });

    let job;
    try {
      job = await broadcastQueue.add('send-broadcast', {
        userId: request.user.id,
        message: readyMessage,
        broadcastId: broadcastId
      }, {
        jobId: jobId,
        delay: delay,
        attempts: 4,
        backoff: { type: 'exponential', delay: 5000 }
      });
    } catch (err) {
      console.error('Failed to queue scheduled broadcast ' + broadcastId + ' for ' + request.user.id + ':', err.message);
      return reply.code(500).send({ error: 'Broadcast saved but failed to queue. It will be retried on next server restart.' });
    }

    console.log('⏰ Scheduled broadcast queued: job ' + job.id + ' for user ' + request.user.id + ' at ' + time.toISOString() + ' (delay: ' + Math.round(delay / 1000) + 's)');

    reply.send({ success: true, broadcastId: broadcastId, scheduledTime: time.toISOString() });
  });

  fastify.get('/api/broadcast/scheduled', { preHandler: authenticateToken }, async function(request, reply) {
    const scheduled = await ScheduledBroadcast.find({ userId: request.user.id, status: 'pending' }).sort({ scheduledTime: 1 });
    const formatted = scheduled.map(function(s) {
      return {
        broadcastId: s.broadcastId,
        message: s.message.substring(0, 100) + (s.message.length > 100 ? '...' : ''),
        scheduledTime: s.scheduledTime.toISOString(),
        status: s.status,
        recipients: s.recipients
      };
    });
    reply.send({ success: true, scheduled: formatted });
  });

  fastify.delete('/api/broadcast/scheduled/:broadcastId', { preHandler: authenticateToken }, async function(request, reply) {
    const broadcastId = request.params.broadcastId;
    const task = await ScheduledBroadcast.findOne({ broadcastId: broadcastId, userId: request.user.id });
    if (!task) return reply.code(404).send({ error: 'Not found' });

    const jobIdToRemove = task.currentJobId || broadcastId;
    try {
      const job = await broadcastQueue.getJob(jobIdToRemove);
      if (job) {
        await job.remove();
      }
    } catch (err) {
      console.warn('Failed to remove job ' + jobIdToRemove + ' from queue (may already be gone):', err.message);
    }

    await task.deleteOne();

    reply.send({ success: true });
  });

  fastify.patch('/api/broadcast/scheduled/:broadcastId', { preHandler: authenticateToken }, async function(request, reply) {
    const { message, scheduledTime, recipients } = request.body;
    const task = await ScheduledBroadcast.findOne({ broadcastId: request.params.broadcastId, userId: request.user.id, status: 'pending' });

    if (!task) return reply.code(400).send({ error: 'Cannot edit this broadcast' });

    const oldJobId = task.currentJobId || task.broadcastId;
    try {
      const oldJob = await broadcastQueue.getJob(oldJobId);
      if (oldJob) {
        await oldJob.remove();
      }
    } catch (err) {
      console.warn('Failed to remove old job ' + oldJobId + ' on edit:', err.message);
    }

    let needsUpdate = false;

    if (message && message.trim()) {
      const processed = message.trim();
      if (processed.length > MAX_MSG_LENGTH * 10) {
        return reply.code(400).send({ error: 'Message too long' });
      }
      const readyMessage = prepareTelegramMessage(processed);
      // FIX: guard against empty message after processing
      if (!readyMessage) {
        return reply.code(400).send({ error: 'Message is empty after processing — check for unsupported HTML.' });
      }
      task.message = readyMessage;
      needsUpdate = true;
    }
    if (recipients) {
      task.recipients = recipients;
      needsUpdate = true;
    }
    if (scheduledTime) {
      const newTime = new Date(scheduledTime);
      if (isNaN(newTime.getTime()) || newTime <= new Date()) return reply.code(400).send({ error: 'Invalid future time' });

      // FIX: check no other pending broadcast from this user occupies the new minute
      const newBucket = getMinuteBucket(task.userId, newTime);
      const conflict = await ScheduledBroadcast.findOne({
        userId: task.userId,
        minuteBucket: newBucket,
        status: 'pending',
        broadcastId: { $ne: task.broadcastId }  // exclude self
      });
      if (conflict) {
        return reply.code(409).send({
          error: 'You already have a broadcast scheduled at that minute. Please choose a different time.'
        });
      }

      task.scheduledTime = newTime;
      task.minuteBucket = newBucket;  // FIX: update the bucket when the time changes
      needsUpdate = true;
    }

    if (needsUpdate) {
      const delay = task.scheduledTime.getTime() - Date.now();
      const newJobId = task.broadcastId + '_v' + Date.now();
      task.currentJobId = newJobId;
      await task.save();

      let job;
      try {
        job = await broadcastQueue.add('send-broadcast', {
          userId: task.userId,
          message: task.message,
          broadcastId: task.broadcastId
        }, {
          jobId: newJobId,
          delay: delay > 0 ? delay : 0,
          attempts: 4,
          backoff: { type: 'exponential', delay: 5000 }
        });
      } catch (err) {
        console.error('Failed to re-queue broadcast ' + task.broadcastId + ' after edit:', err.message);
        return reply.code(500).send({ error: 'Broadcast updated in DB but failed to re-queue. It will be retried on next server restart.' });
      }

      console.log('✏️  Broadcast ' + task.broadcastId + ' updated and re-queued: job ' + job.id + ' delay ' + Math.round((delay > 0 ? delay : 0) / 1000) + 's');
    }

    reply.send({ success: true, broadcastId: task.broadcastId, scheduledTime: task.scheduledTime.toISOString() });
  });

  fastify.get('/api/broadcast/scheduled/:broadcastId/details', { preHandler: authenticateToken }, async function(request, reply) {
    const task = await ScheduledBroadcast.findOne({ broadcastId: request.params.broadcastId, userId: request.user.id });

    if (!task || task.status !== 'pending') {
      return reply.code(404).send({ error: 'Broadcast not found or not editable' });
    }

    const scheduledDate = new Date(task.scheduledTime);
    const offsetMs = scheduledDate.getTimezoneOffset() * 60000;
    const localDate = new Date(scheduledDate.getTime() + offsetMs);
    const localIsoString = localDate.toISOString().slice(0, 16);

    reply.send({
      success: true,
      message: task.message,
      scheduledTime: localIsoString,
      recipients: task.recipients || 'all'
    });
  });

  // ==================== DEBUG ENDPOINT (remove in production) ====================
  fastify.get('/api/debug/queue', { preHandler: authenticateToken }, async function(request, reply) {
    try {
      const waiting = await broadcastQueue.getWaiting();
      const delayed = await broadcastQueue.getDelayed();
      const active = await broadcastQueue.getActive();
      const failed = await broadcastQueue.getFailed();
      const completed = await broadcastQueue.getCompleted();

      reply.send({
        waiting: waiting.length,
        delayed: delayed.length,
        active: active.length,
        failed: failed.length,
        completed: completed.length,
        failedJobs: failed.map(function(j) {
          return { id: j.id, reason: j.failedReason, data: j.data };
        }),
        delayedJobs: delayed.map(function(j) {
          return { id: j.id, delay: j.opts && j.opts.delay, data: j.data };
        })
      });
    } catch (err) {
      reply.code(500).send({ error: err.message });
    }
  });

  // ==================== ADMIN LIMITS PANEL ====================
  fastify.get('/admin-limits', async function(request, reply) {
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
      '    label { display: block; margin: 20px 0 8px; font-size: 1.1em; }\n' +
      '    input[type="number"], input[type="password"] { width: 100%; padding: 12px; background: #2d2d2d; border: none; border-radius: 6px; color: white; font-size: 1em; margin-bottom: 15px; }\n' +
      '    button { width: 100%; padding: 14px; background: #ffd700; color: black; font-weight: bold; border: none; border-radius: 6px; cursor: pointer; font-size: 1.1em; margin-top: 20px; }\n' +
      '    button:hover { background: #e6c200; }\n' +
      '    .current { text-align: center; margin: 25px 0; padding: 15px; background: #2d2d2d; border-radius: 8px; font-size: 1.1em; }\n' +
      '  </style>\n' +
      '</head>\n' +
      '<body>\n' +
      '  <div class="container">\n' +
      '    <h1>Server Admin Panel</h1>\n' +
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
    reply.type('text/html').send(html);
  });

  fastify.post('/admin-limits', async function(request, reply) {
    const { password, daily_broadcast, max_pages, max_forms } = request.body;

    if (password !== ADMIN_PASSWORD) {
      return reply.type('text/html').send('<html><body style="background:#121212;color:#f44336;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;font-family:sans-serif;text-align:center;"><h1>Access Denied<br>Wrong Password</h1></body></html>');
    }

    const newDaily = parseInt(daily_broadcast);
    const newPages = parseInt(max_pages);
    const newForms = parseInt(max_forms);

    if (isNaN(newDaily) || isNaN(newPages) || isNaN(newForms) || newDaily < 1 || newPages < 1 || newForms < 1) {
      return reply.type('text/html').send('<html><body style="background:#121212;color:#f44336;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;font-family:sans-serif;text-align:center;"><h1>Invalid Values<br>All limits must be ≥ 1</h1></body></html>');
    }

    try {
      await AdminSettings.updateSettings({
        dailyBroadcastLimit: newDaily,
        maxLandingPages: newPages,
        maxForms: newForms
      });

      adminSettingsCache = {
        dailyBroadcastLimit: newDaily,
        maxLandingPages: newPages,
        maxForms: newForms
      };

      console.log('Admin limits updated and saved to DB:', adminSettingsCache);

      reply.type('text/html').send('<!DOCTYPE html>\n' +
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
        '    <p><a href="/admin-limits">← Back to Control Panel</a></p>\n' +
        '  </div>\n' +
        '</body>\n' +
        '</html>');
    } catch (err) {
      console.error('Failed to save admin settings:', err);
      reply.code(500).send('Failed to save settings');
    }
  });

  fastify.get('/ping', async function(request, reply) {
    reply.code(200).type('text/plain').send('ok');
  });

  // ==================== 404 ====================
  fastify.setNotFoundHandler(async function(request, reply) {
    reply.code(404);
    return reply.view('404');
  });

  // ==================== CLEANUP ====================
  setInterval(function() {
    const now = Date.now();
    const keys = Array.from(pendingSubscribers.keys());
    for (const key of keys) {
      const data = pendingSubscribers.get(key);
      if (now - data.createdAt > 30 * 60 * 1000) {
        pendingSubscribers.delete(key);
      }
    }
  }, 60 * 60 * 1000);

  // ==================== STARTUP ====================
  async function loadAdminSettings() {
    try {
      const settings = await AdminSettings.getSettings();
      adminSettingsCache = {
        dailyBroadcastLimit: settings.dailyBroadcastLimit,
        maxLandingPages: settings.maxLandingPages,
        maxForms: settings.maxForms
      };
      console.log('✅ Admin settings loaded from DB:', adminSettingsCache);
    } catch (err) {
      console.error('Failed to load admin settings:', err);
    }
  }

  mongoose.connection.once('open', async function() {
    await loadAdminSettings();
    console.log('✅ Startup complete — bots will hydrate lazily on first use');
    await recoverLostScheduledBroadcasts();
    console.log('Startup sequence completed');
  });

  process.on('SIGTERM', async function() {
    console.log('Shutting down gracefully...');
    await worker.close();
    await broadcastQueue.close();
    redisConnection.disconnect();
    workerRedisConnection.disconnect();
    await fastify.close();
    process.exit(0);
  });

  process.on('SIGINT', async function() {
    console.log('Shutting down gracefully...');
    await worker.close();
    await broadcastQueue.close();
    redisConnection.disconnect();
    workerRedisConnection.disconnect();
    await fastify.close();
    process.exit(0);
  });

  await fastify.listen({ port: PORT, host: '0.0.0.0' });

  console.log('\nSENDEM SERVER (Fastify) — FULL VERSION WITH BullMQ + Redis BROADCAST QUEUE');
  console.log('Server running on port ' + PORT + ' | Domain: https://' + DOMAIN + '\n');
}

main().catch(function(err) {
  console.error('Fatal startup error:', err);
  process.exit(1);
});
