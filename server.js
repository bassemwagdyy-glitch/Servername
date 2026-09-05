require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');

const db = require('./db');
const { generateLicenseToken, verifyLicenseTokenSignature, computeExpiry, genId } = require('./license');

const app = express();
const PORT = process.env.PORT || 3000;

// ============ إعدادات الأدمن (غيّريها في ملف .env قبل النشر) ============
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || bcrypt.hashSync('change-me-now', 10);
const JWT_SECRET = process.env.JWT_SECRET || 'CHANGE-THIS-SESSION-SECRET-BEFORE-DEPLOY';

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const UPDATES_DIR = path.join(__dirname, 'updates');
if (!fs.existsSync(UPDATES_DIR)) fs.mkdirSync(UPDATES_DIR, { recursive: true });
app.use('/updates', express.static(UPDATES_DIR));

const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPDATES_DIR),
    filename: (req, file, cb) => {
      // بنحافظ على الاسم الأصلي بس بنمنع أي حاجة غريبة فيه (path traversal etc.)
      const safe = file.originalname.replace(/[^\w.\-\u0600-\u06FF ]/g, '_');
      cb(null, Date.now() + '__' + safe);
    }
  }),
  limits: { fileSize: 500 * 1024 * 1024 } // حد أقصى 500MB للملف (كفاية لـ exe أو apk)
});

// ============ Rate limiting (حماية بسيطة من هجمات التخمين والإغراق) ============
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false });
const verifyLimiter = rateLimit({ windowMs: 60 * 1000, max: 60, standardHeaders: true, legacyHeaders: false });

// ============ Middleware: تحقق جلسة الأدمن ============
function requireAdmin(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'unauthorized' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.role !== 'admin') throw new Error('bad-role');
    req.admin = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'unauthorized' });
  }
}

function logEvent(type, detail) {
  try {
    db.prepare('INSERT INTO admin_events (event_type, detail) VALUES (?, ?)').run(type, detail ? JSON.stringify(detail) : null);
  } catch (e) { /* تجاهل فشل تسجيل الحدث نفسه */ }
}

// ============================================================
// تسجيل دخول الأدمن
// ============================================================
app.post('/api/admin/login', loginLimiter, (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'missing-fields' });
  if (username !== ADMIN_USERNAME || !bcrypt.compareSync(password, ADMIN_PASSWORD_HASH)) {
    logEvent('login_failed', { username });
    return res.status(401).json({ error: 'invalid-credentials' });
  }
  const token = jwt.sign({ role: 'admin', username }, JWT_SECRET, { expiresIn: '7d' });
  logEvent('login_success', { username });
  res.json({ token });
});

// ============================================================
// إدارة التراخيص (محمية بجلسة أدمن)
// ============================================================
app.post('/api/admin/licenses', requireAdmin, (req, res) => {
  const { customerName, storeName, phone, note, duration, customDate } = req.body || {};
  if (!customerName || !storeName) return res.status(400).json({ error: 'missing-fields' });

  const expires = computeExpiry(duration, customDate);
  if (!expires || isNaN(expires.getTime())) return res.status(400).json({ error: 'bad-duration' });

  const id = genId();
  const issuedAt = new Date().toISOString();
  const expiresAt = expires.toISOString();
  const token = generateLicenseToken({ id, customerName, storeName, phone: phone || '', note: note || '', issuedAt, expiresAt });

  db.prepare(`INSERT INTO licenses (id, token, customer_name, store_name, phone, note, issued_at, expires_at, status)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active')`)
    .run(id, token, customerName, storeName, phone || '', note || '', issuedAt, expiresAt);

  logEvent('license_created', { id, customerName, storeName });
  res.json({ id, token, issuedAt, expiresAt });
});

app.get('/api/admin/licenses', requireAdmin, (req, res) => {
  const q = (req.query.q || '').trim();
  let rows;
  if (q) {
    const like = `%${q}%`;
    rows = db.prepare(`SELECT * FROM licenses WHERE customer_name LIKE ? OR store_name LIKE ? OR id LIKE ? ORDER BY created_at DESC LIMIT 500`)
      .all(like, like, like);
  } else {
    rows = db.prepare(`SELECT * FROM licenses ORDER BY created_at DESC LIMIT 500`).all();
  }
  res.json({ licenses: rows });
});

app.post('/api/admin/licenses/:id/revoke', requireAdmin, (req, res) => {
  const info = db.prepare(`UPDATE licenses SET status = 'revoked' WHERE id = ?`).run(req.params.id);
  if (info.changes === 0) return res.status(404).json({ error: 'not-found' });
  logEvent('license_revoked', { id: req.params.id });
  res.json({ ok: true });
});

app.post('/api/admin/licenses/:id/restore', requireAdmin, (req, res) => {
  const info = db.prepare(`UPDATE licenses SET status = 'active' WHERE id = ?`).run(req.params.id);
  if (info.changes === 0) return res.status(404).json({ error: 'not-found' });
  logEvent('license_restored', { id: req.params.id });
  res.json({ ok: true });
});

app.delete('/api/admin/licenses/:id', requireAdmin, (req, res) => {
  const info = db.prepare(`DELETE FROM licenses WHERE id = ?`).run(req.params.id);
  if (info.changes === 0) return res.status(404).json({ error: 'not-found' });
  logEvent('license_deleted', { id: req.params.id });
  res.json({ ok: true });
});

app.get('/api/admin/stats', requireAdmin, (req, res) => {
  const total = db.prepare(`SELECT COUNT(*) c FROM licenses`).get().c;
  const active = db.prepare(`SELECT COUNT(*) c FROM licenses WHERE status = 'active' AND expires_at > datetime('now')`).get().c;
  const expired = db.prepare(`SELECT COUNT(*) c FROM licenses WHERE expires_at <= datetime('now') AND status = 'active'`).get().c;
  const revoked = db.prepare(`SELECT COUNT(*) c FROM licenses WHERE status = 'revoked'`).get().c;
  const expiringSoon = db.prepare(`SELECT COUNT(*) c FROM licenses WHERE status='active' AND expires_at > datetime('now') AND expires_at <= datetime('now', '+5 days')`).get().c;
  res.json({ total, active, expired, revoked, expiringSoon });
});

// ============================================================
// تحقق الترخيص أونلاين (بينداها شاشة الأسعار/تطبيق ويندوز/أندرويد)
// نقطة عامة (من غير تسجيل دخول أدمن) لأن التطبيقات المرخّصة هي اللي بتناديها
// ============================================================
app.post('/api/license/verify', verifyLimiter, (req, res) => {
  const { key, deviceLabel } = req.body || {};
  const sigCheck = verifyLicenseTokenSignature(key);

  if (!sigCheck.valid && sigCheck.reason !== 'expired') {
    // توقيع غلط خالص (اتعدل يدوي أو مزوّر) — مرفوض فورًا من غير حتى نبص على قاعدة البيانات
    return res.json({ valid: false, reason: sigCheck.reason });
  }

  const row = db.prepare(`SELECT * FROM licenses WHERE id = ?`).get(sigCheck.payload.id);
  if (!row) {
    // مفتاح موقّع بشكل صحيح لكن مش موجود في قاعدة البيانات (مثلاً اتعمل بالأداة المحلية القديمة مش بالسيرفر)
    return res.json({ valid: sigCheck.valid, reason: sigCheck.valid ? null : sigCheck.reason, payload: sigCheck.payload, serverKnown: false });
  }

  db.prepare(`UPDATE licenses SET last_check_at = datetime('now'), last_check_ip = ?, check_count = check_count + 1, device_label = COALESCE(?, device_label) WHERE id = ?`)
    .run(req.ip, deviceLabel || null, row.id);

  if (deviceLabel) {
    db.prepare(`INSERT INTO device_sightings (license_id, device_id, last_seen, last_ip) VALUES (?, ?, datetime('now'), ?)
                ON CONFLICT(license_id, device_id) DO UPDATE SET last_seen = datetime('now'), last_ip = excluded.last_ip`)
      .run(row.id, deviceLabel, req.ip);
  }

  if (row.status === 'revoked') {
    return res.json({ valid: false, reason: 'revoked', payload: sigCheck.payload, serverKnown: true });
  }
  if (new Date(row.expires_at) < new Date()) {
    return res.json({ valid: false, reason: 'expired', payload: sigCheck.payload, serverKnown: true });
  }
  res.json({ valid: true, payload: sigCheck.payload, serverKnown: true });
});

// ============================================================
// سحب الإعدادات/المنتجات اللي الأدمن ضبطها عن بُعد (بينداها التطبيق نفسه دوريًا)
// الأولوية: إعدادات خاصة بالجهاز ده تحديدًا، وإلا إعدادات عامة لكل الترخيص
// ============================================================
app.post('/api/device/pull-config', verifyLimiter, (req, res) => {
  const { key, deviceId } = req.body || {};
  const sigCheck = verifyLicenseTokenSignature(key);
  if (!sigCheck.payload || !sigCheck.payload.id) {
    return res.status(400).json({ error: 'invalid-key' });
  }
  const licenseId = sigCheck.payload.id;

  let row = null;
  if (deviceId) {
    row = db.prepare(`SELECT * FROM remote_configs WHERE scope_type = 'device' AND scope_key = ?`).get(deviceId);
  }
  if (!row) {
    row = db.prepare(`SELECT * FROM remote_configs WHERE scope_type = 'license' AND scope_key = ?`).get(licenseId);
  }
  if (!row) return res.json({ hasConfig: false });

  res.json({
    hasConfig: true,
    updatedAt: row.updated_at,
    settings: row.settings_json ? JSON.parse(row.settings_json) : null,
    products: row.products_json ? JSON.parse(row.products_json) : null
  });
});

// ============================================================
// إدارة الأجهزة والإعدادات عن بُعد (تاب "الأجهزة" في لوحة التحكم)
// ============================================================
app.get('/api/admin/devices', requireAdmin, (req, res) => {
  const rows = db.prepare(`
    SELECT d.device_id, d.license_id, d.last_seen, d.last_ip,
           l.customer_name, l.store_name, l.status, l.expires_at
    FROM device_sightings d
    JOIN licenses l ON l.id = d.license_id
    ORDER BY d.last_seen DESC LIMIT 500
  `).all();
  res.json({ devices: rows });
});

app.get('/api/admin/config/:scopeType/:scopeKey', requireAdmin, (req, res) => {
  const { scopeType, scopeKey } = req.params;
  if (!['license', 'device'].includes(scopeType)) return res.status(400).json({ error: 'bad-scope' });
  const row = db.prepare(`SELECT * FROM remote_configs WHERE scope_type = ? AND scope_key = ?`).get(scopeType, scopeKey);
  if (!row) return res.json({ hasConfig: false });
  res.json({
    hasConfig: true,
    updatedAt: row.updated_at,
    settings: row.settings_json ? JSON.parse(row.settings_json) : null,
    products: row.products_json ? JSON.parse(row.products_json) : null
  });
});

app.put('/api/admin/config/:scopeType/:scopeKey', requireAdmin, (req, res) => {
  const { scopeType, scopeKey } = req.params;
  const { settings, products } = req.body || {};
  if (!['license', 'device'].includes(scopeType)) return res.status(400).json({ error: 'bad-scope' });
  if (!settings && !products) return res.status(400).json({ error: 'nothing-to-save' });

  db.prepare(`
    INSERT INTO remote_configs (scope_type, scope_key, settings_json, products_json, updated_at)
    VALUES (?, ?, ?, ?, datetime('now'))
    ON CONFLICT(scope_type, scope_key) DO UPDATE SET
      settings_json = COALESCE(excluded.settings_json, remote_configs.settings_json),
      products_json = COALESCE(excluded.products_json, remote_configs.products_json),
      updated_at = datetime('now')
  `).run(scopeType, scopeKey, settings ? JSON.stringify(settings) : null, products ? JSON.stringify(products) : null);

  logEvent('remote_config_set', { scopeType, scopeKey });
  res.json({ ok: true });
});

app.delete('/api/admin/config/:scopeType/:scopeKey', requireAdmin, (req, res) => {
  const { scopeType, scopeKey } = req.params;
  db.prepare(`DELETE FROM remote_configs WHERE scope_type = ? AND scope_key = ?`).run(scopeType, scopeKey);
  logEvent('remote_config_cleared', { scopeType, scopeKey });
  res.json({ ok: true });
});

// ============================================================
// التحديثات التلقائية (electron-updater بيقرا من هنا)
// ============================================================
app.get('/api/updates/:platform/latest', (req, res) => {
  const platform = req.params.platform;
  const row = db.prepare(`SELECT * FROM app_versions WHERE platform = ? AND is_active = 1 ORDER BY id DESC LIMIT 1`).get(platform);
  if (!row) return res.status(404).json({ error: 'no-version-published' });
  res.json({ version: row.version, notes: row.notes, url: `/updates/${encodeURIComponent(row.file_path)}`, publishedAt: row.published_at });
});

app.post('/api/admin/versions', requireAdmin, (req, res) => {
  const { platform, version, filePath, notes } = req.body || {};
  if (!platform || !version || !filePath) return res.status(400).json({ error: 'missing-fields' });
  db.prepare(`UPDATE app_versions SET is_active = 0 WHERE platform = ?`).run(platform);
  db.prepare(`INSERT INTO app_versions (platform, version, file_path, notes) VALUES (?, ?, ?, ?)`).run(platform, version, filePath, notes || '');
  logEvent('version_published', { platform, version });
  res.json({ ok: true });
});

// رفع ملف تحديث (exe / apk) مباشرة من لوحة التحكم وتسجيله كأحدث نسخة لمنصة معيّنة
app.post('/api/admin/versions/upload', requireAdmin, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'no-file' });
  const { platform, version, notes } = req.body || {};
  if (!platform || !version) {
    fs.unlink(req.file.path, () => {});
    return res.status(400).json({ error: 'missing-fields' });
  }
  db.prepare(`UPDATE app_versions SET is_active = 0 WHERE platform = ?`).run(platform);
  db.prepare(`INSERT INTO app_versions (platform, version, file_path, notes) VALUES (?, ?, ?, ?)`)
    .run(platform, version, req.file.filename, notes || '');
  logEvent('version_uploaded', { platform, version, file: req.file.filename });
  res.json({ ok: true, file: req.file.filename });
});

app.get('/api/admin/versions', requireAdmin, (req, res) => {
  res.json({ versions: db.prepare(`SELECT * FROM app_versions ORDER BY id DESC LIMIT 100`).all() });
});

// ============================================================
app.get('/api/health', (req, res) => res.json({ ok: true, time: new Date().toISOString() }));

app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'not-found' });
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// معالج أخطاء عام (زي ملف أكبر من المسموح في الرفع) — بيرجع JSON مفهوم بدل صفحة خطأ خام
app.use((err, req, res, next) => {
  console.error(err);
  if (err.code === 'LIMIT_FILE_SIZE') return res.status(413).json({ error: 'file-too-large' });
  res.status(500).json({ error: 'server-error' });
});

app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
  if (!process.env.ADMIN_PASSWORD_HASH) {
    console.log(`⚠️  Warning: You are using a default admin password which is not secure (change-me-now). You should set the environment variables before deploying — check the .env.example file`);
  }
});
