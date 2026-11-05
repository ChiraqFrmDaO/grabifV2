const express      = require('express');
const dotenv       = require('dotenv');
const uaParser     = require('ua-parser-js');
const session      = require('express-session');
const pgSession    = require('connect-pg-simple')(session);
const helmet       = require('helmet');
const rateLimit    = require('express-rate-limit');
const compression  = require('compression');
const fsp          = require('fs').promises;
const fs           = require('fs');
const https        = require('https');
const crypto       = require('crypto');
const path         = require('path');
const { Pool }     = require('pg');
const Database     = require('better-sqlite3');
const cors         = require('cors');
const Joi          = require('joi');
const bcrypt       = require('bcrypt');

dotenv.config();

const app = express();
app.set('trust proxy', 1);

// ── Database Configuration ────────────────────────────────────────────────────
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'database.sqlite');
const DATABASE_URL = process.env.DATABASE_URL;

let db = null;
let pool = null;
let useDb = false;
let usePostgres = false;
let sessionStore = null;

// ── Custom Error Classes ──────────────────────────────────────────────────────────
class AppError extends Error {
  constructor(message, statusCode, code = 'INTERNAL_ERROR') {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
    this.isOperational = true;
    Error.captureStackTrace(this, this.constructor);
  }
}

class ValidationError extends AppError {
  constructor(message, details = []) {
    super(message, 400, 'VALIDATION_ERROR');
    this.details = details;
  }
}

class AuthenticationError extends AppError {
  constructor(message = 'Authentication failed') {
    super(message, 401, 'AUTH_ERROR');
  }
}

class NotFoundError extends AppError {
  constructor(message = 'Resource not found') {
    super(message, 404, 'NOT_FOUND');
  }
}

// ── Validation Schemas ───────────────────────────────────────────────────────────
const trackerSchema = Joi.object({
  tracker_id: Joi.string().alphanum().min(1).max(32).optional(),
  name: Joi.string().min(1).max(100).required(),
  destination_url: Joi.string().uri({ scheme: ['https'] }).required()
}).options({
  allowUnknown: false,
  stripUnknown: true
});

const loginSchema = Joi.object({
  username: Joi.string().min(1).max(100).required(),
  password: Joi.string().min(1).max(200).required()
}).options({
  allowUnknown: false,
  stripUnknown: true
});

const geoLogSchema = Joi.object({
  tracker_id: Joi.string().required(),
  ip: Joi.string().ip().optional(),
  country: Joi.string().optional(),
  city: Joi.string().optional(),
  isp: Joi.string().optional(),
  lat: Joi.number().min(-90).max(90).optional(),
  lon: Joi.number().min(-180).max(180).optional()
}).options({
  allowUnknown: false,
  stripUnknown: true
});

// ── Response Helpers ─────────────────────────────────────────────────────────────
function successResponse(res, data, message = 'Success') {
  res.json({
    success: true,
    message,
    data,
    timestamp: new Date().toISOString()
  });
}

function errorResponse(res, error) {
  if (error instanceof AppError) {
    return res.status(error.statusCode).json({
      success: false,
      error: error.message,
      code: error.code,
      details: error.details || undefined,
      timestamp: new Date().toISOString()
    });
  }

  console.error('Unexpected error:', error);
  return res.status(500).json({
    success: false,
    error: 'Internal server error',
    code: 'INTERNAL_ERROR',
    timestamp: new Date().toISOString()
  });
}

// ── Request ID middleware (custom to avoid vulnerable uuid dependency) ─────
app.use((req, res, next) => {
  req.id = crypto.randomBytes(16).toString('hex');
  res.setHeader('X-Request-ID', req.id);
  next();
});


app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:  ["'self'"],
      scriptSrc:   ["'self'", "'unsafe-inline'", 'cdnjs.cloudflare.com'],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc:    ["'self'", "'unsafe-inline'", 'fonts.googleapis.com', 'cdnjs.cloudflare.com'],
      styleSrcAttr: ["'unsafe-inline'"],
      fontSrc:     ["'self'", 'fonts.gstatic.com'],
      imgSrc:      ["'self'", 'data:', '*.tile.openstreetmap.org', '*.opentopomap.org', 'https://cdnjs.cloudflare.com'],
      connectSrc:  ["'self'", 'ipapi.co', 'ipwhois.app'],
      frameSrc:    ["'none'"],
      objectSrc:   ["'none'"],
      formAction:  ["'self'"],
      frameAncestors: ["'none'"],
      upgradeInsecureRequests: [],
    }
  },
  crossOriginEmbedderPolicy: false,
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  noSniff: true,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  xssFilter: true,
}));

app.use(compression());

// CORS configuration
app.use(cors({
  origin: '*',
  credentials: true,
  methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  maxAge: 86400
}));

// ── Session management ────────────────────────────────────────────────────────
const sessionSecret = process.env.SESSION_SECRET;
if (!sessionSecret && process.env.NODE_ENV === 'production') {
  console.error('❌ ERROR: SESSION_SECRET is required in production. Set it in your .env file.');
  process.exit(1);
}
if (!sessionSecret) {
  console.warn('⚠️  WARNING: No SESSION_SECRET set. Using random secret (sessions will be lost on restart).');
}

// Session store init based on DATABASE_URL
if (DATABASE_URL) {
  sessionStore = new pgSession({
    conObject: {
      connectionString: DATABASE_URL,
      ssl: { rejectUnauthorized: false }
    },
    tableName: 'session',
    createTableIfMissing: true
  });
} else {
  try {
    const SQLiteStore = require('better-sqlite3-session-store')(session);
    sessionStore = new SQLiteStore({
      db: new Database(DB_PATH),
      expired: { clear: true, intervalMs: 900000 }
    });
  } catch (err) {
    console.warn('SQLite session store init failed, using memory store');
  }
}

app.use(session({
  store: sessionStore,
  secret: sessionSecret || crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  name: 'sid',
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
    maxAge: 24 * 60 * 60 * 1000
  }
}));

// Request logging middleware
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    const logLevel = res.statusCode >= 500 ? 'error' : res.statusCode >= 400 ? 'warn' : 'info';
    console.log(`[${logLevel.toUpperCase()}] ${req.method} ${req.path} ${res.statusCode} ${duration}ms - ${req.id}`);
  });
  next();
});

app.use(express.static('public', {
  maxAge: '1d',
  etag: true,
  lastModified: true
}));
app.use(express.json({ limit: '16kb' }));
app.use(express.urlencoded({ extended: true, limit: '16kb' }));



// Session store zal later worden geïnitialiseerd na database init
let sessionStore = null;

// ── Authenticatie middleware ──────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (req.session && req.session.authenticated) {
    return next();
  }

  if (req.path.startsWith('/api/')) {
    return res.status(401).json({ error: 'Niet ingelogd. Log opnieuw in.' });
  }

  res.redirect('/login');
}

// Apply API rate limiter to all /api routes except login/logout
app.use('/api', (req, res, next) => {
  if (req.path === '/login' || req.path === '/logout') {
    return next();
  }
  apiLimiter(req, res, next);
});

// ── Admin credentials ─────────────────────────────────────────────────────────
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'change_me';
const ADMIN_PASS_HASH = process.env.ADMIN_PASS_HASH;

// Hash password if not already hashed
async function hashPassword(password) {
  return await bcrypt.hash(password, 12);
}

async function verifyPassword(password, hash) {
  // If no hash is set (legacy), compare plain text and warn
  if (!hash && ADMIN_PASS === password) {
    console.warn('⚠️  WARNING: Using plain text password. Set ADMIN_PASS_HASH in .env for security.');
    return true;
  }
  if (!hash) return false;
  return await bcrypt.compare(password, hash);
}

// Generate invite token
function generateInviteToken() {
  return crypto.randomBytes(32).toString('hex');
}

if (process.env.NODE_ENV === 'production' && (ADMIN_USER === 'admin' || ADMIN_PASS === 'change_me')) {
  console.warn('⚠️  WARNING: Using default admin credentials in production!');
}

// ── Rate limiting ─────────────────────────────────────────────────────────────
const geoLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Te veel verzoeken. Probeer later opnieuw.' },
  skip: (req) => isBotUserAgent(req.headers['user-agent']),
  keyGenerator: (req) => getClientIp(req)
});

const pixelLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => isBotUserAgent(req.headers['user-agent']),
  keyGenerator: (req) => getClientIp(req)
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Te veel login pogingen. Probeer over 15 minuten.' },
  skipSuccessfulRequests: true
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Te veel API verzoeken. Probeer later opnieuw.' },
  skip: (req) => req.session.authenticated
});

// ── Constanten ────────────────────────────────────────────────────────────────
const TRACKERS_FILE       = path.join(__dirname, 'trackers.json');
const LOG_FILE            = path.join(__dirname, 'logs.txt');
const DEFAULT_REDIRECT_URL = process.env.DEFAULT_REDIRECT_URL || 'https://youtube.com';
const MAX_LOG_ROWS        = 500;

// ── Simple cache ──────────────────────────────────────────────────────────────
const cache = new Map();
const CACHE_TTL = 30 * 1000; // 30 seconds

function getCached(key) {
  const entry = cache.get(key);
  if (!entry) return null;
  if (Date.now() > entry.expires) {
    cache.delete(key);
    return null;
  }
  return entry.data;
}

function setCached(key, data, ttl = CACHE_TTL) {
  cache.set(key, {
    data,
    expires: Date.now() + ttl
  });
}

function invalidateCache(pattern) {
  for (const key of cache.keys()) {
    if (key.includes(pattern)) {
      cache.delete(key);
    }
  }
}

// Alle paden die nooit een tracker-ID mogen zijn
const RESERVED_IDS = new Set([
  'api', 'admin', 'favicon.ico', 'pixel', 'track',
  'static', 'public', 'health', 'robots.txt', 'sitemap.xml', 'debug-headers'
]);

// ── Hulpfuncties ──────────────────────────────────────────────────────────────

/** Escaped een string zodat hij veilig in een HTML-attribuut of JS-string kan. */
function escapeHtml(str) {
  return String(str)
    .replace(/&/g,  '&amp;')
    .replace(/</g,  '&lt;')
    .replace(/>/g,  '&gt;')
    .replace(/"/g,  '&quot;')
    .replace(/'/g,  '&#039;')
    .replace(/\//g, '&#x2F;');
}

/** Veilig voor gebruik binnen een JS-string-literal in een <script>-blok. */
function escapeJs(str) {
  return JSON.stringify(String(str));
}

function getClientIp(req) {
  // Try to get real IP from various headers
  const headers = [
    req.headers['forwarded'], // Wasmer uses this: for="[::ffff:IP]"
    req.headers['x-forwarded-for'],
    req.headers['x-real-ip'], 
    req.headers['cf-connecting-ip'],
    req.headers['x-client-ip'],
    req.socket.remoteAddress
  ];

  for (const header of headers) {
    if (header) {
      let ip;
      
      // Parse Wasmer's forwarded header: for="[::ffff:185.182.194.243]"
      if (typeof header === 'string' && header.includes('for=')) {
        const match = header.match(/for="([^"]+)"/);
        if (match) {
          ip = match[1].replace(/^\[::ffff:/, '').replace(/\]$/, '');
        }
      }
      
      // Handle comma-separated IPs (x-forwarded-for can have multiple)
      if (!ip) {
        const ips = String(header).split(',').map(ip => ip.trim());
        ip = ips[0];
      }
      
      if (ip) {
        const cleanIp = ip.replace(/^::ffff:/, '').replace(/^::1$/, '127.0.0.1');
        
        // Filter out private/local IPs to get the real client IP
        if (cleanIp && 
            cleanIp !== 'Unknown' && 
            !cleanIp.startsWith('127.') && 
            !cleanIp.startsWith('192.168.') && 
            !cleanIp.startsWith('10.') &&
            !cleanIp.startsWith('172.16.') &&
            !cleanIp.startsWith('172.17.') &&
            !cleanIp.startsWith('172.18.') &&
            !cleanIp.startsWith('172.19.') &&
            !cleanIp.startsWith('172.20.') &&
            !cleanIp.startsWith('172.21.') &&
            !cleanIp.startsWith('172.22.') &&
            !cleanIp.startsWith('172.23.') &&
            !cleanIp.startsWith('172.24.') &&
            !cleanIp.startsWith('172.25.') &&
            !cleanIp.startsWith('172.26.') &&
            !cleanIp.startsWith('172.27.') &&
            !cleanIp.startsWith('172.28.') &&
            !cleanIp.startsWith('172.29.') &&
            !cleanIp.startsWith('172.30.') &&
            !cleanIp.startsWith('172.31.') &&
            cleanIp !== 'localhost') {
          return cleanIp;
        }
      }
    }
  }
  
  // If no public IP found, return the first available IP (even if local)
  const fallbackIp = (headers[0] || headers[1] || headers[2] || headers[3] || headers[4] || '');
  return fallbackIp.split(',')[0].trim().replace(/^::ffff:/, '') || 'Unknown';
}

function fetchJson(url) {
  return new Promise((resolve, reject) => {
    https.get(url, res => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch (err) { reject(err); }
      });
    }).on('error', reject);
  });
}

async function getGeoInfoForIp(ip) {
  if (!ip || ip === 'Unknown') return null;
  const endpoints = [
    `https://ipwhois.app/json/${encodeURIComponent(ip)}`,
    `https://ipapi.co/${encodeURIComponent(ip)}/json/`
  ];

  for (const url of endpoints) {
    try {
      const data = await fetchJson(url);
      if (!data || !data.ip) continue;
      return {
        ip:      data.ip,
        country: data.country_name || data.country || 'Unknown',
        city:    data.city || 'Unknown',
        isp:     data.org || data.isp || 'Unknown',
        lat:     data.latitude ?? data.lat ?? null,
        lon:     data.longitude ?? data.lon ?? null
      };
    } catch (err) {
      console.warn('Server-side geo lookup failed for', url, err.message);
    }
  }
  return null;
}

function isBotUserAgent(userAgent) {
  const ua = (userAgent || '').toLowerCase();
  if (!ua || ua === 'unknown') return true;
  const botKeywords = [
    'bot', 'crawl', 'spider', 'slurp', 'fetch', 'scanner', 'monitor',
    'python-requests', 'libwww-perl', 'curl', 'wget', 'httpclient', 'okhttp',
    'facebookexternalhit', 'facebot', 'discordbot', 'slackbot', 'telegrambot',
    'ahrefsbot', 'semrushbot', 'mj12bot', 'rogerbot', 'yandex', 'bingpreview',
    'googlebot', 'bingbot', 'baiduspider', 'pinterest', 'preview',
    'twitterbot', 'linkedinbot', 'whatsapp', 'instagram', 'facebook',
    'dotbot', 'exabot', 'nutch', 'sogou', 'soso', 'yacy',
    'seznambot', 'ltx71', 'gigabot', 'searchmetrics', 'linkdex',
    'crawler', 'scout', 'scraper', 'harvest', 'extractor',
    'headlesschrome', 'phantom', 'selenium', 'puppeteer', 'playwright',
    'bot-', '-bot', '_bot', 'crawl-', '-crawl', 'spider-', '-spider'
  ];
  return botKeywords.some(kw => ua.includes(kw));
}

function isBotLog(log) {
  // SQLite stores booleans as 0/1, convert to boolean
  if (log.is_pixel !== undefined) {
    log.is_pixel = Boolean(log.is_pixel);
  }
  return isBotUserAgent(log.useragent) || isBotUserAgent(log.browser) || isBotUserAgent(log.os);
}

/** Valideert dat een URL met https:// begint en een geldig hostname heeft. */
function isValidHttpsUrl(raw) {
  try {
    const u = new URL(raw);
    return u.protocol === 'https:' && u.hostname.length > 0;
  } catch {
    return false;
  }
}

/** Genereert een cryptografisch veilig tracker-ID (8 hex-tekens). */
function generateTrackerId() {
  return crypto.randomBytes(4).toString('hex');
}

// ── Database-initialisatie ────────────────────────────────────────────────────
async function initDatabase() {
  // Use PostgreSQL if DATABASE_URL is set, otherwise SQLite
  if (DATABASE_URL) {
    try {
      pool = new Pool({
        connectionString: DATABASE_URL,
        ssl: { rejectUnauthorized: false },
        max: 20,
        idleTimeoutMillis: 30000,
        connectionTimeoutMillis: 10000,
      });

      pool.on('error', (err) => {
        console.error('Unexpected error on idle client', err);
      });

      await pool.query('SELECT 1');

      // Create trackers table
      await pool.query(`
        CREATE TABLE IF NOT EXISTS trackers (
          tracker_id TEXT PRIMARY KEY,
          name TEXT NOT NULL,
          destination_url TEXT NOT NULL,
          management_key TEXT UNIQUE,
          created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
          updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
      `);

      // Add updated_at column if it doesn't exist
      try {
        await pool.query(`ALTER TABLE trackers ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT now();`);
      } catch (err) {}

      // Add management_key column if it doesn't exist
      try {
        await pool.query(`ALTER TABLE trackers ADD COLUMN IF NOT EXISTS management_key TEXT UNIQUE;`);
      } catch (err) {}

      // Create users table
      await pool.query(`
        CREATE TABLE IF NOT EXISTS users (
          id SERIAL PRIMARY KEY,
          username TEXT UNIQUE NOT NULL,
          email TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL,
          role TEXT NOT NULL DEFAULT 'user',
          invite_token TEXT UNIQUE,
          created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
      `);

      // Create logs table
      await pool.query(`
        CREATE TABLE IF NOT EXISTS logs (
          id SERIAL PRIMARY KEY,
          tracker_id TEXT NOT NULL,
          tracker_name TEXT,
          timestamp TIMESTAMPTZ NOT NULL DEFAULT now(),
          ip TEXT,
          country TEXT,
          city TEXT,
          isp TEXT,
          browser TEXT,
          os TEXT,
          device TEXT,
          useragent TEXT,
          referer TEXT,
          latitude NUMERIC,
          longitude NUMERIC,
          is_pixel BOOLEAN DEFAULT false
        );
      `);

      // Add columns if they don't exist
      try {
        await pool.query(`ALTER TABLE logs ADD COLUMN IF NOT EXISTS latitude NUMERIC;`);
      } catch (err) {}
      try {
        await pool.query(`ALTER TABLE logs ADD COLUMN IF NOT EXISTS longitude NUMERIC;`);
      } catch (err) {}
      try {
        await pool.query(`ALTER TABLE logs ADD COLUMN IF NOT EXISTS is_pixel BOOLEAN DEFAULT false;`);
      } catch (err) {}

      // Create indexes
      await pool.query(`CREATE INDEX IF NOT EXISTS idx_logs_tracker_id ON logs(tracker_id)`);
      await pool.query(`CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp DESC)`);
      await pool.query(`CREATE INDEX IF NOT EXISTS idx_logs_ip ON logs(ip)`);

      useDb = true;
      usePostgres = true;
      console.log('✅ PostgreSQL database actief. Opslag via database.');
    } catch (error) {
      console.error('❌ PostgreSQL connectie mislukt. Probeer SQLite...');
      console.error(error);
      pool = null;
    }
  }

  // Fallback to SQLite
  if (!useDb) {
    try {
      db = new Database(DB_PATH);
      db.pragma('journal_mode = WAL');

      // Create trackers table
      db.exec(`
        CREATE TABLE IF NOT EXISTS trackers (
          tracker_id TEXT PRIMARY KEY,
          name TEXT NOT NULL,
          destination_url TEXT NOT NULL,
          management_key TEXT UNIQUE,
          created_at TEXT NOT NULL DEFAULT (datetime('now')),
          updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
      `);

      // Add updated_at column if it doesn't exist
      try {
        db.exec(`ALTER TABLE trackers ADD COLUMN updated_at TEXT DEFAULT (datetime('now'));`);
      } catch (err) {}

      // Add management_key column if it doesn't exist
      try {
        db.exec(`ALTER TABLE trackers ADD COLUMN management_key TEXT UNIQUE;`);
      } catch (err) {}

      // Create users table
      db.exec(`
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT UNIQUE NOT NULL,
          email TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL,
          role TEXT NOT NULL DEFAULT 'user',
          invite_token TEXT UNIQUE,
          created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
      `);

      // Create logs table
      db.exec(`
        CREATE TABLE IF NOT EXISTS logs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          tracker_id TEXT NOT NULL,
          tracker_name TEXT,
          timestamp TEXT NOT NULL DEFAULT (datetime('now')),
          ip TEXT,
          country TEXT,
          city TEXT,
          isp TEXT,
          browser TEXT,
          os TEXT,
          device TEXT,
          useragent TEXT,
          referer TEXT,
          latitude REAL,
          longitude REAL,
          is_pixel INTEGER DEFAULT 0
        );
      `);

      // Add columns if they don't exist
      try {
        db.exec(`ALTER TABLE logs ADD COLUMN latitude REAL;`);
      } catch (err) {}
      try {
        db.exec(`ALTER TABLE logs ADD COLUMN longitude REAL;`);
      } catch (err) {}
      try {
        db.exec(`ALTER TABLE logs ADD COLUMN is_pixel INTEGER DEFAULT 0;`);
      } catch (err) {}

      // Create indexes
      db.exec(`CREATE INDEX IF NOT EXISTS idx_logs_tracker_id ON logs(tracker_id);`);
      db.exec(`CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp DESC);`);
      db.exec(`CREATE INDEX IF NOT EXISTS idx_logs_ip ON logs(ip);`);

      useDb = true;
      console.log('✅ SQLite database actief. Opslag via database.');
    } catch (error) {
      console.error('❌ Database connectie mislukt. Gebruik fallback file storage.');
      console.error(error);
      db = null;
      useDb = false;
    }
  }
}

// ── File-storage helpers (async) ──────────────────────────────────────────────
async function readTrackersFile() {
  try {
    const data = await fsp.readFile(TRACKERS_FILE, 'utf8');
    return JSON.parse(data);
  } catch {
    return [];
  }
}

async function writeTrackersFile(trackers) {
  await fsp.writeFile(TRACKERS_FILE, JSON.stringify(trackers, null, 2));
}

// ── Data-toegang ──────────────────────────────────────────────────────────────
async function loadTrackers() {
  const cacheKey = 'trackers';
  const cached = getCached(cacheKey);
  if (cached) return cached;

  let result;
  if (useDb) {
    if (usePostgres) {
      const { rows } = await pool.query('SELECT tracker_id, name, destination_url, created_at FROM trackers ORDER BY created_at DESC');
      result = rows;
    } else {
      const stmt = db.prepare('SELECT tracker_id, name, destination_url, created_at FROM trackers ORDER BY created_at DESC');
      result = stmt.all();
    }
  } else {
    result = await readTrackersFile();
  }

  setCached(cacheKey, result);
  return result;
}

async function loadTrackerById(trackerId) {
  if (useDb) {
    if (usePostgres) {
      const { rows } = await pool.query('SELECT tracker_id, name, destination_url FROM trackers WHERE tracker_id = $1', [trackerId]);
      return rows[0];
    } else {
      const stmt = db.prepare('SELECT tracker_id, name, destination_url FROM trackers WHERE tracker_id = ?');
      return stmt.get(trackerId);
    }
  }
  const trackers = await readTrackersFile();
  return trackers.find(t => t.tracker_id === trackerId);
}

async function saveTracker({ tracker_id, name, destination_url }) {
  const management_key = crypto.randomBytes(32).toString('hex');

  if (useDb) {
    if (usePostgres) {
      await pool.query(`
        INSERT INTO trackers (tracker_id, name, destination_url, management_key, created_at, updated_at)
        VALUES ($1, $2, $3, $4, now(), now())
        ON CONFLICT (tracker_id) DO UPDATE SET
          name = EXCLUDED.name,
          destination_url = EXCLUDED.destination_url,
          updated_at = now()
      `, [tracker_id, name, destination_url, management_key]);
    } else {
      const now = new Date().toISOString();
      const stmt = db.prepare(`
        INSERT INTO trackers (tracker_id, name, destination_url, management_key, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(tracker_id) DO UPDATE SET
          name = excluded.name,
          destination_url = excluded.destination_url,
          updated_at = excluded.updated_at
      `);
      stmt.run(tracker_id, name, destination_url, management_key, now, now);
    }
    invalidateCache('summary');
    invalidateCache('trackers');
    return;
  }

  const trackers    = await readTrackersFile();
  const existingIdx = trackers.findIndex(t => t.tracker_id === tracker_id);
  const now         = new Date().toISOString();

  if (existingIdx >= 0) {
    trackers[existingIdx] = {
      ...trackers[existingIdx],
      name,
      destination_url,
      updated_at: now
    };
  } else {
    trackers.push({ tracker_id, name, destination_url, management_key, created_at: now, updated_at: now });
  }
  await writeTrackersFile(trackers);
  invalidateCache('summary');
  invalidateCache('trackers');
}

async function deleteTrackerById(trackerId) {
  if (useDb) {
    if (usePostgres) {
      await pool.query('DELETE FROM logs WHERE tracker_id = $1', [trackerId]);
      await pool.query('DELETE FROM trackers WHERE tracker_id = $1', [trackerId]);
    } else {
      const deleteLogs = db.prepare('DELETE FROM logs WHERE tracker_id = ?');
      const deleteTracker = db.prepare('DELETE FROM trackers WHERE tracker_id = ?');
      deleteLogs.run(trackerId);
      deleteTracker.run(trackerId);
    }
    invalidateCache('summary');
    invalidateCache('trackers');
    invalidateCache('logs');
    return;
  }

  const trackers         = await readTrackersFile();
  const filteredTrackers = trackers.filter(t => t.tracker_id !== trackerId);
  if (filteredTrackers.length !== trackers.length) {
    await writeTrackersFile(filteredTrackers);
  }

  try {
    const rawLogs = (await fsp.readFile(LOG_FILE, 'utf8'))
      .trim().split('\n').filter(Boolean)
      .map(line => { try { return JSON.parse(line); } catch { return null; } })
      .filter(Boolean)
      .filter(log => log.tracker_id !== trackerId);
    await fsp.writeFile(
      LOG_FILE,
      rawLogs.map(l => JSON.stringify(l)).join('\n') + (rawLogs.length ? '\n' : '')
    );
  } catch {
    // LOG_FILE bestaat nog niet — geen probleem
  }
  invalidateCache('summary');
  invalidateCache('trackers');
  invalidateCache('logs');
}

async function appendLog(log) {
  if (useDb) {
    if (usePostgres) {
      await pool.query(`
        INSERT INTO logs
          (tracker_id, tracker_name, timestamp, ip, country, city, isp,
           browser, os, device, useragent, referer, latitude, longitude, is_pixel)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
      `, [
        log.tracker_id, log.tracker_name, log.timestamp,
        log.ip, log.country, log.city, log.isp,
        log.browser, log.os, log.device, log.useragent, log.referer,
        log.latitude, log.longitude, log.is_pixel ?? false
      ]);
    } else {
      const stmt = db.prepare(`
        INSERT INTO logs
          (tracker_id, tracker_name, timestamp, ip, country, city, isp,
           browser, os, device, useragent, referer, latitude, longitude, is_pixel)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      stmt.run(
        log.tracker_id, log.tracker_name, log.timestamp,
        log.ip, log.country, log.city, log.isp,
        log.browser, log.os, log.device, log.useragent, log.referer,
        log.latitude, log.longitude, log.is_pixel ? 1 : 0
      );
    }
    invalidateCache('summary');
    invalidateCache('logs');
    return;
  }
  await fsp.appendFile(LOG_FILE, JSON.stringify(log) + '\n');
  invalidateCache('summary');
  invalidateCache('logs');
}

async function getLogs(limit = MAX_LOG_ROWS, offset = 0) {
  if (useDb) {
    if (usePostgres) {
      const { rows } = await pool.query('SELECT * FROM logs ORDER BY timestamp DESC LIMIT $1 OFFSET $2', [limit, offset]);
      return rows.filter(row => !isBotLog(row));
    } else {
      const stmt = db.prepare('SELECT * FROM logs ORDER BY timestamp DESC LIMIT ? OFFSET ?');
      const rows = stmt.all(limit, offset);
      return rows.filter(row => !isBotLog(row));
    }
  }

  try {
    const rawLogs = (await fsp.readFile(LOG_FILE, 'utf8'))
      .trim().split('\n').filter(Boolean)
      .map(line => { try { return JSON.parse(line); } catch { return null; } })
      .filter(Boolean)
      .filter(log => !isBotLog(log));
    const reversed = rawLogs.reverse();
    return limit > 0 ? reversed.slice(offset, offset + limit) : reversed;
  } catch {
    return [];
  }
}

async function getSummary() {
  const cacheKey = 'summary';
  const cached = getCached(cacheKey);
  if (cached) return cached;

  let result;
  if (useDb) {
    if (usePostgres) {
      const [trackerRes, visitsRes, uniqueRes] = await Promise.all([
        pool.query(`SELECT COUNT(*) FROM trackers`),
        pool.query(`SELECT COUNT(*) FROM logs WHERE useragent NOT ILIKE '%bot%' AND useragent NOT ILIKE '%crawl%'`),
        pool.query(`SELECT COUNT(DISTINCT ip) FROM logs WHERE useragent NOT ILIKE '%bot%' AND useragent NOT ILIKE '%crawl%'`),
      ]);
      result = {
        totalTrackers: parseInt(trackerRes.rows[0].count, 10),
        totalVisits:   parseInt(visitsRes.rows[0].count,   10),
        uniqueVisits:  parseInt(uniqueRes.rows[0].count,   10),
      };
    } else {
      const trackerCount = db.prepare('SELECT COUNT(*) as count FROM trackers').get();
      const visitCount = db.prepare("SELECT COUNT(*) as count FROM logs WHERE useragent NOT LIKE '%bot%' AND useragent NOT LIKE '%crawl%'").get();
      const uniqueCount = db.prepare("SELECT COUNT(DISTINCT ip) as count FROM logs WHERE useragent NOT LIKE '%bot%' AND useragent NOT LIKE '%crawl%'").get();

      result = {
        totalTrackers: trackerCount.count,
        totalVisits:   visitCount.count,
        uniqueVisits:  uniqueCount.count,
      };
    }
  } else {
    const trackers   = await readTrackersFile();
    const logs       = await getLogs(0);
    const uniqueIps  = new Set(logs.map(l => l.ip).filter(Boolean));
    result = {
      totalTrackers: trackers.length,
      totalVisits:   logs.length,
      uniqueVisits:  uniqueIps.size
    };
  }

  setCached(cacheKey, result);
  return result;
}

// ── Routes ────────────────────────────────────────────────────────────────────

// Homepagina uit views/index.html
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'index.html'));
});

// Redirect-handler met HTML-escaping
async function handleTrackerRedirect(trackerId, res) {
  let destinationUrl = DEFAULT_REDIRECT_URL;
  try {
    const tracker = await loadTrackerById(trackerId);
    if (tracker?.destination_url) {
      destinationUrl = tracker.destination_url;
    }
  } catch (error) {
    console.error('Fout bij ophalen tracker:', error);
  }

  let html = await fsp.readFile(path.join(__dirname, 'views', 'redirect.html'), 'utf8');

  // Veilige injectie in HTML data-attributen
  html = html
    .replace('{{DESTINATION_URL}}', escapeHtml(destinationUrl))
    .replace('{{TRACKER_ID}}',      escapeHtml(trackerId));

  res.send(html);
}

app.get('/track/:id', async (req, res) => {
  await handleTrackerRedirect(req.params.id, res);
});

// Tracking pixel
app.get('/pixel/:trackerId.png', pixelLimiter, async (req, res) => {
  try {
    const userAgent = req.headers['user-agent'] || 'Unknown';
    if (!isBotUserAgent(userAgent)) {
      const tracker = await loadTrackerById(req.params.trackerId);
      const parser  = uaParser(userAgent);
      await appendLog({
        timestamp:    new Date().toISOString(),
        tracker_id:   req.params.trackerId,
        tracker_name: tracker?.name || 'Onbekend',
        ip:           getClientIp(req),
        country:      'Unknown',
        city:         'Unknown',
        isp:          'Unknown',
        browser:      parser.browser.name || 'Unknown',
        os:           parser.os.name      || 'Unknown',
        device:       parser.device.type  || 'desktop',
        useragent:    userAgent,
        referer:      req.headers.referer || 'None',
        latitude:     null,
        longitude:    null,
        is_pixel:     true
      });
    }
  } catch (error) {
    console.error('Pixel logging error:', error);
  }

  const pixel = Buffer.from(
    'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/w8AAn8B9q7xVQAAAABJRU5ErkJggg==',
    'base64'
  );
  res.setHeader('Content-Type', 'image/png');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.send(pixel);
});

// Geo-log (client-side geo → server)
app.post('/api/log-geo', geoLimiter, async (req, res) => {
  const { error, value } = geoLogSchema.validate(req.body);
  if (error) {
    return res.status(400).json({ error: 'Invalid geo data' });
  }

  const { tracker_id, ip: clientIp, country, city, isp, lat, lon } = value;
  if (!tracker_id) return res.status(400).json({ error: 'No tracker_id' });

  try {
    const userAgent = req.headers['user-agent'] || 'Unknown';
    if (isBotUserAgent(userAgent)) return res.json({ success: true });

    const parser = uaParser(userAgent);
    const tracker = await loadTrackerById(tracker_id);

    const serverIp = getClientIp(req);
    const ip = clientIp && clientIp !== 'Unknown' ? clientIp : serverIp;
    let finalCountry = country && country !== 'Unknown' ? country : null;
    let finalCity = city && city !== 'Unknown' ? city : null;
    let finalIsp = isp && isp !== 'Unknown' ? isp : null;
    let finalLat = lat ?? null;
    let finalLon = lon ?? null;

    if (!finalCountry || !finalCity || !finalIsp) {
      const geoInfo = await getGeoInfoForIp(ip);
      if (geoInfo) {
        finalCountry = finalCountry || geoInfo.country;
        finalCity    = finalCity    || geoInfo.city;
        finalIsp     = finalIsp     || geoInfo.isp;
        finalLat     = finalLat     || geoInfo.lat;
        finalLon     = finalLon     || geoInfo.lon;
      }
    }

    await appendLog({
      timestamp:    new Date().toISOString(),
      tracker_id,
      tracker_name: tracker?.name || 'Onbekend',
      ip,
      country:      finalCountry || 'Unknown',
      city:         finalCity    || 'Unknown',
      isp:          finalIsp     || 'Unknown',
      browser:      parser.browser.name || 'Unknown',
      os:           parser.os.name      || 'Unknown',
      device:       parser.device.type  || 'desktop',
      useragent:    userAgent,
      referer:      req.headers.referer || 'Direct',
      latitude:     finalLat,
      longitude:    finalLon,
      is_pixel:     false
    });

    res.json({ success: true });
  } catch (error) {
        console.error("========== GEO ERROR ==========");
        console.error(error);
        console.error(error.stack);

        res.status(500).json({
            message: error.message,
            stack: error.stack
         });
    }
});

// Tracker opslaan (met Joi validatie)
app.post('/api/save-tracker', requireAuth, async (req, res) => {
  try {
    const { error, value } = trackerSchema.validate(req.body);
    if (error) {
      throw new ValidationError('Invalid input', error.details);
    }

    let { tracker_id, name, destination_url } = value;

    // Genereer een ID als er geen is opgegeven
    if (!tracker_id) tracker_id = generateTrackerId();

    // Blokkeer reserved IDs
    if (RESERVED_IDS.has(tracker_id.toLowerCase())) {
      throw new ValidationError('Dit tracker-ID is gereserveerd.');
    }

    await saveTracker({ tracker_id, name, destination_url });
    successResponse(res, { tracker_id, link: `/${tracker_id}` }, 'Tracker created successfully');
  } catch (error) {
    errorResponse(res, error);
  }
});

app.get('/api/trackers', requireAuth, async (req, res) => {
  try {
    successResponse(res, await loadTrackers());
  } catch (error) {
    errorResponse(res, error);
  }
});

app.post('/api/delete-tracker', requireAuth, async (req, res) => {
  const { tracker_id } = req.body;
  if (!tracker_id) return res.status(400).json({ error: 'Missing tracker_id' });

  try {
    await deleteTrackerById(tracker_id);
    res.json({ success: true });
  } catch (error) {
    console.error('Delete tracker error:', error);
    res.status(500).json({ error: 'Delete failed' });
  }
});

app.get('/api/summary', requireAuth, async (req, res) => {
  try {
    res.json(await getSummary());
  } catch (error) {
    console.error('Summary error:', error);
    res.status(500).json({ error: 'Summary failed' });
  }
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'views/login.html'));
});

app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'views/register.html'));
});

app.post('/api/login', authLimiter, async (req, res) => {
  const { error, value } = loginSchema.validate(req.body);
  if (error) {
    return res.status(400).json({ error: 'Invalid credentials format' });
  }

  const { username, password } = value;
  const isJson = req.headers.accept?.includes('application/json') || req.headers['content-type']?.includes('application/json');

  // Check admin credentials first (legacy support)
  if (username === ADMIN_USER && await verifyPassword(password, ADMIN_PASS_HASH)) {
    req.session.authenticated = true;
    req.session.user = username;
    req.session.role = 'admin';
    if (isJson) {
      return res.json({ success: true });
    }
    return res.redirect('/admin');
  }

  // Check users table
  let user = null;
  if (useDb) {
    if (usePostgres) {
      const { rows } = await pool.query(`SELECT * FROM users WHERE username = $1`, [username]);
      user = rows[0];
    } else {
      const stmt = db.prepare(`SELECT * FROM users WHERE username = ?`);
      user = stmt.get(username);
    }
  }

  if (user && await verifyPassword(password, user.password_hash)) {
    req.session.authenticated = true;
    req.session.user = username;
    req.session.role = user.role;
    if (isJson) {
      return res.json({ success: true });
    }
    return res.redirect('/admin');
  }

  if (isJson) {
    return res.status(401).json({ error: 'Ongeldige gebruikersnaam of wachtwoord.' });
  }

  res.redirect('/login');
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

app.get('/admin', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'admin.html'));
});

app.get('/api/logs', requireAuth, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || MAX_LOG_ROWS;
    const offset = parseInt(req.query.offset) || 0;

    if (limit > 1000) {
      return res.status(400).json({ error: 'Limit mag maximaal 1000 zijn.' });
    }

    const logs     = await getLogs(limit, offset);
    const trackers = useDb ? [] : await readTrackersFile();
    const tMap     = trackers.reduce((acc, t) => { acc[t.tracker_id] = t; return acc; }, {});

    res.json({
      data: logs.map(log => ({
        ...log,
        name: log.tracker_name || tMap[log.tracker_id]?.name || 'Onbekend'
      })),
      pagination: {
        limit,
        offset,
        hasMore: logs.length === limit
      }
    });
  } catch (error) {
    console.error('Load logs error:', error);
    res.status(500).json({ error: 'Load failed' });
  }
});

// Wildcard tracker-redirect (reserved-check ook hier)
app.get('/:trackerId', async (req, res, next) => {
  const trackerId = req.params.trackerId;
  if (RESERVED_IDS.has(trackerId.toLowerCase())) return next();
  await handleTrackerRedirect(trackerId, res);
});

// Management link - access tracker settings via management key
app.get('/manage/:managementKey', async (req, res) => {
  const { managementKey } = req.params;

  try {
    let tracker;
    if (useDb) {
      if (usePostgres) {
        const { rows } = await pool.query('SELECT * FROM trackers WHERE management_key = $1', [managementKey]);
        tracker = rows[0];
      } else {
        const stmt = db.prepare('SELECT * FROM trackers WHERE management_key = ?');
        tracker = stmt.get(managementKey);
      }
    } else {
      const trackers = await readTrackersFile();
      tracker = trackers.find(t => t.management_key === managementKey);
    }

    if (!tracker) {
      return res.status(404).send('Ongeldige management link');
    }

    // Return management page
    const html = await fsp.readFile(path.join(__dirname, 'views', 'manage.html'), 'utf8');
    const safeHtml = html
      .replace('{{TRACKER_ID}}', escapeHtml(tracker.tracker_id))
      .replace('{{TRACKER_NAME}}', escapeHtml(tracker.name))
      .replace('{{DESTINATION_URL}}', escapeHtml(tracker.destination_url))
      .replace('{{MANAGEMENT_KEY}}', escapeHtml(managementKey));
    res.send(safeHtml);
  } catch (error) {
    console.error('Management link error:', error);
    res.status(500).send('Fout bij laden tracker');
  }
});

// API endpoint to update tracker via management key
app.post('/api/manage/:managementKey', async (req, res) => {
  const { managementKey } = req.params;
  const { name, destination_url } = req.body;

  try {
    const { error, value } = trackerSchema.validate({ name, destination_url });
    if (error) {
      return res.status(400).json({ error: 'Invalid input' });
    }

    let tracker;
    if (useDb) {
      if (usePostgres) {
        await pool.query(`
          UPDATE trackers
          SET name = $1, destination_url = $2, updated_at = now()
          WHERE management_key = $3
        `, [value.name, value.destination_url, managementKey]);
        const { rows } = await pool.query('SELECT * FROM trackers WHERE management_key = $1', [managementKey]);
        tracker = rows[0];
      } else {
        const stmt = db.prepare(`
          UPDATE trackers
          SET name = ?, destination_url = ?, updated_at = datetime('now')
          WHERE management_key = ?
        `);
        stmt.run(value.name, value.destination_url, managementKey);
        const getStmt = db.prepare('SELECT * FROM trackers WHERE management_key = ?');
        tracker = getStmt.get(managementKey);
      }
    } else {
      const trackers = await readTrackersFile();
      const idx = trackers.findIndex(t => t.management_key === managementKey);
      if (idx >= 0) {
        trackers[idx] = {
          ...trackers[idx],
          name: value.name,
          destination_url: value.destination_url,
          updated_at: new Date().toISOString()
        };
        await writeTrackersFile(trackers);
        tracker = trackers[idx];
      }
    }

    invalidateCache('summary');
    invalidateCache('trackers');

    res.json({ success: true, tracker });
  } catch (error) {
    console.error('Management update error:', error);
    res.status(500).json({ error: 'Update failed' });
  }
});

// ── User Management ─────────────────────────────────────────────────────────
// Generate invite token
app.post('/api/invites', requireAuth, async (req, res) => {
  try {
    const inviteToken = generateInviteToken();
    
    if (useDb) {
      if (usePostgres) {
        await pool.query(`INSERT INTO users (username, email, password_hash, role, invite_token) VALUES ($1, $2, $3, $4, $5)`, 
          ['pending', inviteToken, '', 'user', inviteToken]);
      } else {
        const stmt = db.prepare(`INSERT INTO users (username, email, password_hash, role, invite_token) VALUES (?, ?, ?, ?, ?)`);
        stmt.run('pending', inviteToken, '', 'user', inviteToken);
      }
    }
    
    const inviteUrl = `${req.protocol}://${req.get('host')}/register?token=${inviteToken}`;
    res.json({ success: true, inviteToken, inviteUrl });
  } catch (error) {
    console.error('Invite generation error:', error);
    res.status(500).json({ error: 'Invite generation failed' });
  }
});

// List invites
app.get('/api/invites', requireAuth, async (req, res) => {
  try {
    let invites = [];
    if (useDb) {
      if (usePostgres) {
        const { rows } = await pool.query(`SELECT invite_token, created_at FROM users WHERE username = 'pending'`);
        invites = rows;
      } else {
        const stmt = db.prepare(`SELECT invite_token, created_at FROM users WHERE username = 'pending'`);
        invites = stmt.all();
      }
    }
    res.json(invites);
  } catch (error) {
    console.error('List invites error:', error);
    res.status(500).json({ error: 'Failed to list invites' });
  }
});

// Registration with invite token
app.post('/api/register', async (req, res) => {
  const { username, email, password, inviteToken } = req.body;
  
  try {
    // Validate invite token
    let validInvite = false;
    if (useDb) {
      if (usePostgres) {
        const { rows } = await pool.query(`SELECT * FROM users WHERE invite_token = $1 AND username = 'pending'`, [inviteToken]);
        validInvite = rows.length > 0;
      } else {
        const stmt = db.prepare(`SELECT * FROM users WHERE invite_token = ? AND username = 'pending'`);
        validInvite = stmt.get(inviteToken);
      }
    }
    
    if (!validInvite) {
      return res.status(400).json({ error: 'Ongeldige invite token' });
    }
    
    // Hash password
    const passwordHash = await hashPassword(password);
    
    // Update user
    if (useDb) {
      if (usePostgres) {
        await pool.query(`
          UPDATE users 
          SET username = $1, email = $2, password_hash = $3, invite_token = NULL 
          WHERE invite_token = $4
        `, [username, email, passwordHash, inviteToken]);
      } else {
        const stmt = db.prepare(`
          UPDATE users 
          SET username = ?, email = ?, password_hash = ?, invite_token = NULL 
          WHERE invite_token = ?
        `);
        stmt.run(username, email, passwordHash, inviteToken);
      }
    }
    
    res.json({ success: true, message: 'Account aangemaakt. Je kunt nu inloggen.' });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registratie mislukt' });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    database: useDb ? 'connected' : 'fallback',
    timestamp: new Date().toISOString()
  });
});

// Debug endpoint to see all headers
app.get('/debug-headers', (req, res) => {
  const forwarded = req.headers['forwarded'];
  const xForwardedFor = req.headers['x-forwarded-for'];
  
  res.json({
    headers: req.headers,
    forwarded: forwarded,
    xForwardedFor: xForwardedFor,
    parsedForwarded: forwarded ? forwarded.match(/for="([^"]+)"/) : null,
    ip: getClientIp(req),
    socketAddress: req.socket.remoteAddress
  });
});

// Metrics endpoint (for monitoring)
app.get('/metrics', requireAuth, async (req, res) => {
  try {
    const summary = await getSummary();
    const uptime = process.uptime();
    const memory = process.memoryUsage();
    
    successResponse(res, {
      uptime: {
        seconds: uptime,
        human: `${Math.floor(uptime / 3600)}h ${Math.floor((uptime % 3600) / 60)}m ${Math.floor(uptime % 60)}s`
      },
      memory: {
        rss: Math.round(memory.rss / 1024 / 1024) + ' MB',
        heapTotal: Math.round(memory.heapTotal / 1024 / 1024) + ' MB',
        heapUsed: Math.round(memory.heapUsed / 1024 / 1024) + ' MB',
        external: Math.round(memory.external / 1024 / 1024) + ' MB'
      },
      database: {
        connected: useDb,
        type: useDb ? 'postgresql' : 'file'
      },
      statistics: summary,
      node: process.version,
      platform: process.platform,
      arch: process.arch
    });
  } catch (error) {
    errorResponse(res, error);
  }
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ── Graceful shutdown ───────────────────────────────────────────────────────────
const gracefulShutdown = async (signal) => {
  console.log(`\n${signal} received. Starting graceful shutdown...`);

  if (pool) {
    console.log('Closing PostgreSQL pool...');
    await pool.end();
  }

  if (db) {
    console.log('Closing SQLite connection...');
    db.close();
  }

  process.exit(0);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// ── Opstarten ─────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
initDatabase().then(() => {
  const server = app.listen(PORT, () => {
    console.log(`🚀 𝐑𝟑𝐃𝐈𝐑𝟑𝐂𝐓 draait op poort ${PORT}`);
  });

  server.on('error', (error) => {
    if (error.code === 'EADDRINUSE') {
      console.error(`❌ Poort ${PORT} is al in gebruik.`);
    } else {
      console.error('❌ Server error:', error);
    }
    process.exit(1);
  });
}).catch(err => {
  console.error('❌ Failed to initialize:', err);
  process.exit(1);
});
