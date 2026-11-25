// CEASER WEB PAIR RELAY
// This service never stores WhatsApp credentials. It queues short-lived pairing
// requests and accepts only signed, verified WebPay events.
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '64kb', verify: (req, _res, buf) => { req.rawBody = Buffer.from(buf); } }));
app.use(express.urlencoded({ extended: false, limit: '64kb' }));
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));

// ---- secrets: bot and bug are fully separate ----
const POLL_SECRET = process.env.WEBPAIR_SECRET || 'change-me';          // bot host -> relay
const BUG_POLL_SECRET = process.env.BUG_POLL_SECRET || '';              // bug host -> relay
const ADMIN_CODE = process.env.ADMIN_CODE || process.env.ADMIN_PASSCODE || '';   // username "admin" + this code = see everyone
const BUG_PIN = process.env.BUG_PIN || '';                              // bug login PIN (server side only)
const TOKEN_SECRET = {
  bot: process.env.BOT_TOKEN_SECRET || crypto.createHash('sha256').update('bot:' + POLL_SECRET).digest('hex'),
  bug: process.env.BUG_TOKEN_SECRET || crypto.createHash('sha256').update('bug:' + (BUG_POLL_SECRET || POLL_SECRET)).digest('hex')
};
const WEBPAY_SECRET = process.env.WEBPAY_WEBHOOK_SECRET || '';
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || process.env.BOT_TOKEN || '';
const OWNER_TG_ID = process.env.OWNER_TG_ID || process.env.ADMIN_TG_ID || '';
const TELEGRAM_BOT_USERNAME = process.env.TELEGRAM_BOT_USERNAME || 'your_bot';
const DEV_TELEGRAM_USERNAME = process.env.DEV_TELEGRAM_USERNAME || 'your_username';
const JOB_TTL_MS = 5 * 60 * 1000;
const jobs = new Map();
const payments = new Map();

function cleanup() {
  const now = Date.now();
  for (const [id, j] of jobs) if (now - j.createdAt > JOB_TTL_MS) jobs.delete(id);
  for (const [id, p] of payments) if (now - p.createdAt > 90 * 24 * 60 * 60 * 1000) payments.delete(id);
}
setInterval(cleanup, 30000).unref?.();

function safeEqual(a, b) {
  const x = Buffer.from(String(a || ''));
  const y = Buffer.from(String(b || ''));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
function verifyWebPay(req) {
  if (!WEBPAY_SECRET) return false;
  const supplied = req.get('x-webpay-signature') || req.get('x-webpay-secret');
  if (req.get('x-webpay-secret')) return safeEqual(supplied, WEBPAY_SECRET);
  const expected = crypto.createHmac('sha256', WEBPAY_SECRET).update(req.rawBody || Buffer.from(JSON.stringify(req.body || {}))).digest('hex');
  return safeEqual(supplied?.replace(/^sha256=/i, ''), expected);
}
function riskFor(body) {
  let score = 0;
  const sessions = Number(body.sessions ?? body.sessionCount ?? body.quantity ?? 0);
  const amount = Number(body.amount ?? body.total ?? 0);
  if (!body.paymentId && !body.id && !body.reference) score += 30;
  if (sessions > 3) score += Math.min(35, (sessions - 3) * 10);
  if (sessions > 10) score += 20;
  if (!Number.isFinite(amount) || amount <= 0) score += 20;
  if (body.email && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(String(body.email))) score += 10;
  if (body.verified !== true && body.status !== 'paid' && body.status !== 'success') score += 25;
  score = Math.min(100, score);
  return { score, level: score >= 70 ? 'high' : score >= 35 ? 'medium' : 'low', sessions: Number.isFinite(sessions) ? sessions : 0 };
}
async function alertOwner(data) {
  if (!TELEGRAM_BOT_TOKEN || !OWNER_TG_ID || typeof fetch !== 'function') return;
  const text = `<b>💳 WEBPAY EVENT</b>\n<blockquote>🧾 Payment <code>${esc(data.paymentId)}</code>\n👤 Customer <code>${esc(data.customerId)}</code>\n📱 Sessions <b>${data.sessions}</b>\n🛡 Risk <b>${data.riskLevel}</b> (${data.riskScore}/100)\n✅ Verified <b>${data.verified ? 'yes' : 'no'}</b></blockquote>`;
  try {
    await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ chat_id: OWNER_TG_ID, text, parse_mode: 'HTML' })
    });
  } catch (e) { console.log('[webpay->owner]', e.message); }
}
function esc(value) { return String(value ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }

// ================= accounts, sessions, relay =================
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');   // mount a Render disk here to keep accounts
try { fs.mkdirSync(DATA_DIR, { recursive: true }); } catch (_) {}
function store(file, def) {
  const p = path.join(DATA_DIR, file); let d = def;
  try { d = JSON.parse(fs.readFileSync(p, 'utf8')); } catch (_) {}
  let t;
  return { d, save() { clearTimeout(t); t = setTimeout(() => { try { fs.writeFileSync(p + '.tmp', JSON.stringify(this.d)); fs.renameSync(p + '.tmp', p); } catch (e) { console.log('[store]', e.message); } }, 200); } };
}
const users  = { bot: store('users_bot.json', {}),  bug: store('users_bug.json', {}) };    // separate username databases
const owners = { bot: store('owners_bot.json', {}), bug: store('owners_bug.json', {}) };  // sessionName -> {user,phone,createdAt,seen}
const snaps = { bot: null, bug: null };           // latest session snapshot reported by each host
const commands = { bot: [], bug: [] };            // delete commands waiting for each host
const tombs = { bot: new Map(), bug: new Map() }; // deleted names -> last re-queue time
const SNAP_FRESH_MS = 45 * 1000, UNSEEN_GRACE_MS = 10 * 60 * 1000;

const b64 = s => Buffer.from(s).toString('base64url');
function sign(kind, username, admin) {
  const p = b64(JSON.stringify({ u: username, k: kind, a: admin ? 1 : 0, exp: Date.now() + 30 * 24 * 3600 * 1000 }));
  return p + '.' + crypto.createHmac('sha256', TOKEN_SECRET[kind]).update(p).digest('base64url');
}
function readToken(tok) {
  try {
    const [p, sig] = String(tok || '').split('.');
    const k = JSON.parse(Buffer.from(p, 'base64url').toString()).k;
    if (k !== 'bot' && k !== 'bug') return null;
    if (!safeEqual(sig, crypto.createHmac('sha256', TOKEN_SECRET[k]).update(p).digest('base64url'))) return null;
    const d = JSON.parse(Buffer.from(p, 'base64url').toString());
    if (!d.exp || d.exp < Date.now()) return null;
    if (d.a) { if (!ADMIN_CODE) return null; return { name: 'admin', kind: k, admin: true }; }
    if (!users[k].d[d.u]) return null;
    return { name: d.u, kind: k, admin: false };
  } catch (_) { return null; }
}
function requireUser(req, res, next) {
  const u = readToken((req.get('authorization') || '').replace(/^Bearer\s+/i, ''));
  if (!u) return res.status(401).json({ error: 'please log in' });
  req.user = u; next();
}
function requireAdmin(req, res, next) { if (!req.user.admin) return res.status(403).json({ error: 'admin only' }); next(); }
function requireHost(req, res, next) {
  const s = req.get('x-poll-secret') || '';
  if (POLL_SECRET && safeEqual(s, POLL_SECRET)) req.kind = 'bot';
  else if (BUG_POLL_SECRET && safeEqual(s, BUG_POLL_SECRET)) req.kind = 'bug';
  else return res.status(401).json({ error: 'bad secret' });
  next();
}
const tries = new Map();
function limited(req, res) {
  const now = Date.now(), t = tries.get(req.ip) || { n: 0, reset: now + 10 * 60 * 1000 };
  if (now > t.reset) { t.n = 0; t.reset = now + 10 * 60 * 1000; }
  tries.set(req.ip, t);
  if (t.n >= 10) { res.status(429).json({ error: 'Too many attempts. Try again in a few minutes.' }); return true; }
  return false;
}
const fail = req => { const t = tries.get(req.ip); if (t) t.n++; };
const hashPw = (pw, salt) => crypto.scryptSync(pw, salt, 32).toString('hex');
const validName = u => /^[a-z0-9_]{3,20}$/.test(u);
const cleanName = v => String(v || '').trim().toLowerCase();

app.get('/health', (_req, res) => res.json({ ok: true, service: 'ceaser-web-pair', jobs: jobs.size }));

app.post('/api/auth/register', (req, res) => {
  if (limited(req, res)) return;
  const u = cleanName(req.body.username), pw = String(req.body.password || '');
  if (!validName(u)) return res.status(400).json({ error: 'Username: 3-20 letters, numbers or _' });
  if (pw.length < 6 || pw.length > 64) return res.status(400).json({ error: 'Password must be 6-64 characters.' });
  if (u === 'admin' || users.bot.d[u]) return res.status(409).json({ error: 'Username already taken.' });
  const salt = crypto.randomBytes(16).toString('hex');
  users.bot.d[u] = { salt, hash: hashPw(pw, salt), createdAt: Date.now() }; users.bot.save();
  res.json({ token: sign('bot', u), username: u });
});
app.post('/api/auth/login', (req, res) => {
  if (limited(req, res)) return;
  const u = cleanName(req.body.username), pw = String(req.body.password || ''), rec = users.bot.d[u];
  if (u === 'admin') {
    if (ADMIN_CODE && safeEqual(pw, ADMIN_CODE)) return res.json({ token: sign('bot', 'admin', true), username: 'admin', admin: true });
    fail(req); return res.status(401).json({ error: 'Wrong username or password.' });
  }
  if (!rec || !safeEqual(hashPw(pw, rec.salt), rec.hash)) { fail(req); return res.status(401).json({ error: 'Wrong username or password.' }); }
  res.json({ token: sign('bot', u), username: u });
});
app.post('/api/bug/login', (req, res) => {
  if (limited(req, res)) return;
  const u = cleanName(req.body.username);
  if (!validName(u)) return res.status(400).json({ error: 'Username: 3-20 letters, numbers or _' });
  if (u === 'admin') {
    if (ADMIN_CODE && safeEqual(String(req.body.pin || ''), ADMIN_CODE)) return res.json({ token: sign('bug', 'admin', true), username: 'admin', admin: true });
    fail(req); return res.status(401).json({ error: 'Unauthorized. Wrong code.' });
  }
  if (!BUG_PIN) return res.status(503).json({ error: 'Bug access is not configured.' });
  if (!safeEqual(String(req.body.pin || ''), BUG_PIN)) { fail(req); return res.status(401).json({ error: 'Unauthorized. Wrong PIN.' }); }
  if (!users.bug.d[u]) { users.bug.d[u] = { createdAt: Date.now() }; users.bug.save(); }
  res.json({ token: sign('bug', u), username: u });
});
app.post('/api/auth/logout', (_req, res) => res.json({ ok: true }));

app.post('/api/request-pair', requireUser, (req, res) => {
  if (req.user.admin) return res.status(403).json({ error: 'Admin accounts are view-only.' });
  const { name, kind } = req.user;
  const phone = String(req.body.phone || '').replace(/\D/g, '');
  if (!/^\d{10,15}$/.test(phone)) return res.status(400).json({ error: 'Enter a valid number with country code, digits only.' });
  if (kind === 'bug') {   // exactly 1 bug bot per account
    const owned = Object.values(owners.bug.d).filter(o => o.user === name).length;
    const active = [...jobs.values()].filter(j => j.kind === 'bug' && j.user === name && (j.status === 'pending' || j.status === 'sent')).length;
    if (owned + active >= 1) return res.status(400).json({ error: 'Bug accounts can pair only 1 bot. Delete the current session first.' });
  }
  const id = crypto.randomBytes(12).toString('hex');
  jobs.set(id, { phone, kind, user: name, status: 'pending', createdAt: Date.now() });
  res.json({ id, expiresIn: JOB_TTL_MS });
});
app.get('/api/job/:id', requireUser, (req, res) => {
  const j = jobs.get(req.params.id);
  if (!j || j.user !== req.user.name || j.kind !== req.user.kind) return res.status(404).json({ error: 'expired, please try again' });
  res.json({ status: j.status, displayCode: j.displayCode || null, error: j.error || null, sessionName: j.sessionName || null });
});

// ---- host side (WhatsApp process polls these with its secret) ----
app.get('/api/pending-jobs', requireHost, (req, res) => {
  const out = [];
  for (const [id, j] of jobs) if (j.status === 'pending' && j.kind === req.kind) { j.status = 'sent'; j.sentAt = Date.now(); out.push({ id, type: 'pair', phone: j.phone }); }
  for (const c of commands[req.kind].splice(0)) out.push(c);
  res.json(out);
});
app.post('/api/job/:id/result', requireHost, (req, res) => {
  const j = jobs.get(req.params.id);
  if (!j || j.kind !== req.kind) return res.status(404).json({ error: 'job gone' });
  if (req.body.error) { j.status = 'error'; j.error = String(req.body.error).slice(0, 200); }
  else {
    j.status = 'done'; j.displayCode = String(req.body.displayCode || ''); j.sessionName = String(req.body.sessionName || '');
    if (j.sessionName) { owners[j.kind].d[j.sessionName] = { user: j.user, phone: j.phone, createdAt: Date.now(), seen: false }; owners[j.kind].save(); }
  }
  j.updatedAt = Date.now();
  res.json({ ok: true });
});
// Host reports the sessions it really has. Anything missing here (folder deleted) disappears from the website.
app.post('/api/host/sessions', requireHost, (req, res) => {
  const kind = req.kind, now = Date.now(), list = Array.isArray(req.body.sessions) ? req.body.sessions : [];
  const map = new Map(list.map(s => [String(s.name), s.status === 'online' ? 'online' : s.status === 'connecting' ? 'connecting' : 'offline']));
  snaps[kind] = { at: now, map };
  const o = owners[kind].d; let dirty = false;
  for (const [name, rec] of Object.entries(o)) {
    if (map.has(name)) { if (!rec.seen) { rec.seen = true; dirty = true; } }
    else if (rec.seen || now - rec.createdAt > UNSEEN_GRACE_MS) { delete o[name]; dirty = true; }
  }
  for (const [name, last] of tombs[kind]) {            // make sure deletes really happen
    if (!map.has(name)) tombs[kind].delete(name);
    else if (now - last > 10000) { tombs[kind].set(name, now); commands[kind].push({ id: crypto.randomBytes(6).toString('hex'), type: 'delete', sessionName: name }); }
  }
  if (dirty) owners[kind].save();
  res.json({ ok: true });
});

// ---- admin: see every user + session for this side (bot or bug) ----
app.get('/api/admin/overview', requireUser, requireAdmin, (req, res) => {
  const kind = req.user.kind, snap = snaps[kind], fresh = !!(snap && Date.now() - snap.at < SNAP_FRESH_MS), by = {};
  for (const [name, r] of Object.entries(users[kind].d)) by[name] = { username: name, createdAt: r.createdAt, sessions: [] };
  for (const [id, r] of Object.entries(owners[kind].d)) {
    (by[r.user] || (by[r.user] = { username: r.user, createdAt: r.createdAt, sessions: [] })).sessions.push({
      id, phone: r.phone, createdAt: r.createdAt, status: fresh ? (snap.map.get(id) || 'connecting') : 'offline' });
  }
  const list = Object.values(by).sort((a, b) => b.sessions.length - a.sessions.length || b.createdAt - a.createdAt);
  res.json({ users: list, hostOnline: fresh, kind });
});
app.delete('/api/admin/sessions/:id', requireUser, requireAdmin, (req, res) => {
  const kind = req.user.kind, id = req.params.id;
  if (!owners[kind].d[id]) return res.status(404).json({ error: 'Session not found.' });
  delete owners[kind].d[id]; owners[kind].save();
  tombs[kind].set(id, Date.now());
  commands[kind].push({ id: crypto.randomBytes(6).toString('hex'), type: 'delete', sessionName: id });
  res.json({ ok: true });
});

// ---- user side ----
app.get('/api/sessions', requireUser, (req, res) => {
  const { name, kind } = req.user, snap = snaps[kind], fresh = snap && Date.now() - snap.at < SNAP_FRESH_MS;
  const sessions = Object.entries(owners[kind].d).filter(([, r]) => r.user === name).map(([id, r]) => ({
    id, phone: r.phone, createdAt: r.createdAt, status: fresh ? (snap.map.get(id) || 'connecting') : 'offline'
  })).sort((x, y) => y.createdAt - x.createdAt);
  res.json({ sessions, limit: kind === 'bug' ? 1 : null, hostOnline: !!fresh });
});
app.delete('/api/sessions/:id', requireUser, (req, res) => {
  const { name, kind } = req.user, id = req.params.id, rec = owners[kind].d[id];
  if (!rec || rec.user !== name) return res.status(404).json({ error: 'Session not found.' });
  delete owners[kind].d[id]; owners[kind].save();
  tombs[kind].set(id, Date.now());
  commands[kind].push({ id: crypto.randomBytes(6).toString('hex'), type: 'delete', sessionName: id });
  res.json({ ok: true });
});

// Provider-neutral WebPay webhook. Configure WEBPAY_WEBHOOK_SECRET and send
// either X-WebPay-Signature: sha256=<HMAC> or X-WebPay-Secret.
app.post('/api/webpay/webhook', (req, res) => {
  if (!verifyWebPay(req)) return res.status(401).json({ error: 'invalid webhook signature' });
  const paymentId = String(req.body.paymentId || req.body.id || req.body.reference || '').trim();
  if (!paymentId) return res.status(400).json({ error: 'payment id is required' });
  if (payments.has(paymentId)) return res.status(200).json({ ok: true, duplicate: true, payment: payments.get(paymentId) });
  const risk = riskFor(req.body);
  const verified = req.body.verified === true || ['paid', 'success', 'completed'].includes(String(req.body.status || '').toLowerCase());
  const record = { paymentId, customerId: String(req.body.customerId || req.body.customer || req.body.email || 'unknown'), sessions: risk.sessions, riskScore: risk.score, riskLevel: risk.level, verified, createdAt: Date.now() };
  payments.set(paymentId, record);
  alertOwner(record).catch(() => {});
  res.status(202).json({ ok: true, payment: record });
});
app.get('/api/config', (_req, res) => res.json({ telegramBot: TELEGRAM_BOT_USERNAME, devHandle: DEV_TELEGRAM_USERNAME }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Web pair server listening on ${PORT}`));
