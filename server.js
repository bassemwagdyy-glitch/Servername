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

const store = require('./store');
const { data } = store;
const { generateLicenseToken, verifyLicenseTokenSignature, computeExpiry, genId } = require('./license');
const { sendSms } = require('./sms');

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
      const safe = file.originalname.replace(/[^\w.\-\u0600-\u06FF ]/g, '_');
      cb(null, Date.now() + '__' + safe);
    }
  }),
  limits: { fileSize: 500 * 1024 * 1024 }
});

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false });
const verifyLimiter = rateLimit({ windowMs: 60 * 1000, max: 60, standardHeaders: true, legacyHeaders: false });
const otpLimiter = rateLimit({ windowMs: 10 * 60 * 1000, max: 5, standardHeaders: true, legacyHeaders: false }); // يمنع إغراق الأرقام برسائل OTP

function normalizePhone(phone) {
  return String(phone || '').replace(/[\s\-()]/g, '');
}
function genOtpCode() {
  return String(Math.floor(100000 + Math.random() * 900000)); // 6 أرقام
}
function createAndSendOtp(phone) {
  const code = genOtpCode();
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString(); // صالح 5 دقايق
  data.otpCodes = data.otpCodes.filter(o => o.phone !== phone); // أي كود قديم لنفس الرقم يتلغي
  data.otpCodes.push({ phone, code, expiresAt, attempts: 0, createdAt: store.now() });
  store.save();
  sendSms(phone, `كود التفعيل بتاعك في Scanit هو: ${code} (صالح لمدة 5 دقايق)`);
}

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

function requireCustomer(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'unauthorized' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.role !== 'customer') throw new Error('bad-role');
    const customer = data.customers.find(c => c.id === decoded.customerId);
    if (!customer) throw new Error('not-found');
    req.customer = customer;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'unauthorized' });
  }
}

// بتعمل أو تجدد الترخيص المرتبط بعميل معيّن — نفس الدالة دي بتتنادى سواء الأدمن منح المدة يدويًا
// (مثلاً بعد تأكيد تحويل بنكي بالتليفون) أو بعد ما يوافق على طلب دفع من بوابة العميل
function grantSubscriptionPeriod(customerId, duration, customDate) {
  const customer = data.customers.find(c => c.id === customerId);
  if (!customer) return null;

  let sub = data.subscriptions.find(s => s.customerId === customerId);
  const now = new Date();
  let existingLicense = sub && sub.licenseId ? data.licenses.find(l => l.id === sub.licenseId) : null;

  // لو لسه في فترة سارية، بنمدد من تاريخ انتهائها (مش من دلوقتي) عشان الدفع المبكر يضيف فوق الفترة الحالية
  const baseDate = (existingLicense && new Date(existingLicense.expires_at) > now) ? new Date(existingLicense.expires_at) : now;
  const newExpiry = computeExpiry(duration, customDate, baseDate);
  if (!newExpiry || isNaN(newExpiry.getTime())) return null;

  if (existingLicense) {
    existingLicense.expires_at = newExpiry.toISOString();
    existingLicense.token = generateLicenseToken({
      id: existingLicense.id,
      customerName: customer.name, storeName: customer.storeName, phone: customer.phone || '',
      issuedAt: existingLicense.issued_at, expiresAt: existingLicense.expires_at
    });
    existingLicense.status = 'active';
  } else {
    const id = genId();
    const issuedAt = now.toISOString();
    const token = generateLicenseToken({
      id, customerName: customer.name, storeName: customer.storeName, phone: customer.phone || '',
      issuedAt, expiresAt: newExpiry.toISOString()
    });
    existingLicense = {
      id, token, customer_name: customer.name, store_name: customer.storeName, phone: customer.phone || '', note: 'subscription',
      issued_at: issuedAt, expires_at: newExpiry.toISOString(), status: 'active', device_label: null, max_devices: 1,
      last_check_at: null, last_check_ip: null, check_count: 0, created_at: store.now()
    };
    data.licenses.push(existingLicense);
  }

  if (!sub) {
    sub = { id: data.nextSubscriptionId++, customerId, licenseId: existingLicense.id, plan: duration, status: 'active', createdAt: store.now() };
    data.subscriptions.push(sub);
  } else {
    sub.licenseId = existingLicense.id;
    sub.plan = duration;
    sub.status = 'active';
  }
  store.save();
  return { license: existingLicense, subscription: sub };
}

function logEvent(type, detail) {
  try {
    data.adminEvents.push({
      id: data.nextEventId++,
      event_type: type,
      detail: detail ? JSON.stringify(detail) : null,
      created_at: store.now()
    });
    if (data.adminEvents.length > 2000) data.adminEvents = data.adminEvents.slice(-2000);
    store.save();
  } catch (e) { /* تجاهل فشل تسجيل الحدث نفسه */ }
}

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

app.post('/api/admin/licenses', requireAdmin, (req, res) => {
  const { customerName, storeName, phone, note, duration, customDate, maxDevices } = req.body || {};
  if (!customerName || !storeName) return res.status(400).json({ error: 'missing-fields' });

  const expires = computeExpiry(duration, customDate);
  if (!expires || isNaN(expires.getTime())) return res.status(400).json({ error: 'bad-duration' });

  const maxDev = Number.isInteger(maxDevices) && maxDevices > 0 ? maxDevices : 1;

  const id = genId();
  const issuedAt = new Date().toISOString();
  const expiresAt = expires.toISOString();
  const token = generateLicenseToken({ id, customerName, storeName, phone: phone || '', note: note || '', issuedAt, expiresAt });

  data.licenses.push({
    id, token,
    customer_name: customerName, store_name: storeName,
    phone: phone || '', note: note || '',
    issued_at: issuedAt, expires_at: expiresAt,
    status: 'active', device_label: null, max_devices: maxDev,
    last_check_at: null, last_check_ip: null, check_count: 0,
    created_at: store.now()
  });
  store.save();

  logEvent('license_created', { id, customerName, storeName, maxDevices: maxDev });
  res.json({ id, token, issuedAt, expiresAt, maxDevices: maxDev });
});

app.post('/api/admin/licenses/:id/max-devices', requireAdmin, (req, res) => {
  const maxDevices = parseInt(req.body && req.body.maxDevices);
  if (!Number.isInteger(maxDevices) || maxDevices < 1) return res.status(400).json({ error: 'bad-value' });
  const lic = data.licenses.find(l => l.id === req.params.id);
  if (!lic) return res.status(404).json({ error: 'not-found' });
  lic.max_devices = maxDevices;
  store.save();
  logEvent('license_max_devices_updated', { id: req.params.id, maxDevices });
  res.json({ ok: true });
});

app.get('/api/admin/licenses', requireAdmin, (req, res) => {
  const q = (req.query.q || '').trim().toLowerCase();
  let rows = data.licenses;
  if (q) {
    rows = rows.filter(l =>
      l.customer_name.toLowerCase().includes(q) ||
      l.store_name.toLowerCase().includes(q) ||
      l.id.toLowerCase().includes(q)
    );
  }
  rows = [...rows]
    .sort((a, b) => b.created_at.localeCompare(a.created_at))
    .slice(0, 500)
    .map(l => ({ ...l, device_count: data.deviceSightings.filter(d => d.license_id === l.id).length }));
  res.json({ licenses: rows });
});

app.post('/api/admin/licenses/:id/revoke', requireAdmin, (req, res) => {
  const lic = data.licenses.find(l => l.id === req.params.id);
  if (!lic) return res.status(404).json({ error: 'not-found' });
  lic.status = 'revoked';
  store.save();
  logEvent('license_revoked', { id: req.params.id });
  res.json({ ok: true });
});

app.post('/api/admin/licenses/:id/restore', requireAdmin, (req, res) => {
  const lic = data.licenses.find(l => l.id === req.params.id);
  if (!lic) return res.status(404).json({ error: 'not-found' });
  lic.status = 'active';
  store.save();
  logEvent('license_restored', { id: req.params.id });
  res.json({ ok: true });
});

app.delete('/api/admin/licenses/:id', requireAdmin, (req, res) => {
  const before = data.licenses.length;
  data.licenses = data.licenses.filter(l => l.id !== req.params.id);
  if (data.licenses.length === before) return res.status(404).json({ error: 'not-found' });
  store.save();
  logEvent('license_deleted', { id: req.params.id });
  res.json({ ok: true });
});

app.get('/api/admin/stats', requireAdmin, (req, res) => {
  const now = new Date();
  const in5Days = new Date(Date.now() + 5 * 24 * 60 * 60 * 1000);
  const total = data.licenses.length;
  const active = data.licenses.filter(l => l.status === 'active' && new Date(l.expires_at) > now).length;
  const expired = data.licenses.filter(l => l.status === 'active' && new Date(l.expires_at) <= now).length;
  const revoked = data.licenses.filter(l => l.status === 'revoked').length;
  const expiringSoon = data.licenses.filter(l => l.status === 'active' && new Date(l.expires_at) > now && new Date(l.expires_at) <= in5Days).length;
  res.json({ total, active, expired, revoked, expiringSoon });
});

// ============================================================
// إعدادات طرق الدفع (بيانات التحويل البنكي / فودافون كاش / إنستاباي)
// GET عامة (بيحتاجها بوابة العميل تعرض تعليمات الدفع)، والتعديل للأدمن بس
// ============================================================
app.get('/api/payment-settings', (req, res) => {
  res.json(data.paymentSettings);
});
app.put('/api/admin/payment-settings', requireAdmin, (req, res) => {
  const { bankDetails, vodafoneCash, instapay } = req.body || {};
  data.paymentSettings = {
    bankDetails: bankDetails || '',
    vodafoneCash: vodafoneCash || '',
    instapay: instapay || ''
  };
  store.save();
  logEvent('payment_settings_updated', {});
  res.json({ ok: true });
});

// ============================================================
// إدارة العملاء والاشتراكات (الأدمن)
// ============================================================
app.post('/api/admin/customers', requireAdmin, (req, res) => {
  const { name, storeName, phone, email, password } = req.body || {};
  if (!name || !storeName || !phone || !password) return res.status(400).json({ error: 'missing-fields' });
  const normPhone = normalizePhone(phone);
  if (data.customers.some(c => c.phone === normPhone)) return res.status(400).json({ error: 'phone-taken' });

  const customer = {
    id: data.nextCustomerId++,
    name, storeName, phone: normPhone, email: email || '',
    passwordHash: bcrypt.hashSync(password, 10),
    phoneVerified: true, // الأدمن هو اللي بيضيفه يدويًا، فبيتحسب موثّق تلقائيًا من غير OTP
    createdAt: store.now()
  };
  data.customers.push(customer);
  store.save();
  logEvent('customer_created', { id: customer.id, name, storeName, by: 'admin' });
  res.json({ id: customer.id });
});

app.get('/api/admin/customers', requireAdmin, (req, res) => {
  const q = (req.query.q || '').trim().toLowerCase();
  let rows = data.customers;
  if (q) {
    rows = rows.filter(c => c.name.toLowerCase().includes(q) || c.storeName.toLowerCase().includes(q) || c.phone.includes(q));
  }
  const out = [...rows].sort((a, b) => b.createdAt.localeCompare(a.createdAt)).map(c => {
    const sub = data.subscriptions.find(s => s.customerId === c.id);
    const lic = sub && sub.licenseId ? data.licenses.find(l => l.id === sub.licenseId) : null;
    return {
      id: c.id, name: c.name, storeName: c.storeName, phone: c.phone, email: c.email,
      phoneVerified: c.phoneVerified, createdAt: c.createdAt,
      subscriptionStatus: lic ? (lic.status === 'revoked' ? 'revoked' : (new Date(lic.expires_at) > new Date() ? 'active' : 'expired')) : 'none',
      expiresAt: lic ? lic.expires_at : null,
      licenseId: lic ? lic.id : null
    };
  });
  res.json({ customers: out });
});

app.delete('/api/admin/customers/:id', requireAdmin, (req, res) => {
  const id = parseInt(req.params.id);
  const before = data.customers.length;
  data.customers = data.customers.filter(c => c.id !== id);
  data.subscriptions = data.subscriptions.filter(s => s.customerId !== id);
  if (data.customers.length === before) return res.status(404).json({ error: 'not-found' });
  store.save();
  logEvent('customer_deleted', { id });
  res.json({ ok: true });
});

// منح فترة اشتراك يدويًا (مثلاً بعد تأكيد تحويل بنكي عن طريق التليفون، من غير ما العميل يبعت طلب دفع)
app.post('/api/admin/customers/:id/grant', requireAdmin, (req, res) => {
  const id = parseInt(req.params.id);
  const { duration, customDate } = req.body || {};
  const result = grantSubscriptionPeriod(id, duration, customDate);
  if (!result) return res.status(400).json({ error: 'grant-failed' });
  logEvent('subscription_granted_manually', { customerId: id, duration });
  res.json({ ok: true, expiresAt: result.license.expires_at, token: result.license.token });
});

// ============================================================
// تسجيل عميل جديد بنفسه + تفعيل برقم الموبايل (OTP)
// ============================================================
app.post('/api/customer/register', otpLimiter, (req, res) => {
  const { name, storeName, phone, email, password } = req.body || {};
  if (!name || !storeName || !phone || !password) return res.status(400).json({ error: 'missing-fields' });
  if (password.length < 6) return res.status(400).json({ error: 'weak-password' });
  const normPhone = normalizePhone(phone);
  if (!/^\d{8,15}$/.test(normPhone.replace(/^\+/, ''))) return res.status(400).json({ error: 'bad-phone' });

  const existing = data.customers.find(c => c.phone === normPhone);
  if (existing && existing.phoneVerified) return res.status(400).json({ error: 'phone-taken' });

  if (existing) {
    // رقم سجّل قبل كده بس ما فعّلش — نحدّث بياناته ونبعتله كود جديد بدل ما نرفضه
    existing.name = name; existing.storeName = storeName; existing.email = email || '';
    existing.passwordHash = bcrypt.hashSync(password, 10);
  } else {
    data.customers.push({
      id: data.nextCustomerId++,
      name, storeName, phone: normPhone, email: email || '',
      passwordHash: bcrypt.hashSync(password, 10),
      phoneVerified: false,
      createdAt: store.now()
    });
  }
  store.save();
  createAndSendOtp(normPhone);
  logEvent('customer_registered', { phone: normPhone, name, storeName });
  res.json({ ok: true });
});

app.post('/api/customer/verify-otp', otpLimiter, (req, res) => {
  const { phone, code } = req.body || {};
  if (!phone || !code) return res.status(400).json({ error: 'missing-fields' });
  const normPhone = normalizePhone(phone);
  const otp = data.otpCodes.find(o => o.phone === normPhone);
  if (!otp) return res.status(400).json({ error: 'no-otp-requested' });
  if (new Date(otp.expiresAt) < new Date()) return res.status(400).json({ error: 'otp-expired' });
  otp.attempts = (otp.attempts || 0) + 1;
  if (otp.attempts > 5) { store.save(); return res.status(400).json({ error: 'too-many-attempts' }); }
  if (otp.code !== String(code).trim()) { store.save(); return res.status(400).json({ error: 'wrong-code' }); }

  const customer = data.customers.find(c => c.phone === normPhone);
  if (!customer) return res.status(404).json({ error: 'not-found' });
  customer.phoneVerified = true;
  data.otpCodes = data.otpCodes.filter(o => o.phone !== normPhone);
  store.save();

  const token = jwt.sign({ role: 'customer', customerId: customer.id }, JWT_SECRET, { expiresIn: '30d' });
  logEvent('customer_verified', { customerId: customer.id });
  res.json({ token });
});

app.post('/api/customer/resend-otp', otpLimiter, (req, res) => {
  const { phone } = req.body || {};
  if (!phone) return res.status(400).json({ error: 'missing-fields' });
  const normPhone = normalizePhone(phone);
  const customer = data.customers.find(c => c.phone === normPhone);
  if (!customer) return res.status(404).json({ error: 'not-found' });
  if (customer.phoneVerified) return res.status(400).json({ error: 'already-verified' });
  createAndSendOtp(normPhone);
  res.json({ ok: true });
});

// ============================================================
// بوابة العميل (تسجيل دخول ومتابعة الاشتراك وإرسال إثبات الدفع)
// ============================================================
app.post('/api/customer/login', loginLimiter, (req, res) => {
  const { phone, password } = req.body || {};
  if (!phone || !password) return res.status(400).json({ error: 'missing-fields' });
  const normPhone = normalizePhone(phone);
  const customer = data.customers.find(c => c.phone === normPhone);
  if (!customer || !bcrypt.compareSync(password, customer.passwordHash)) {
    return res.status(401).json({ error: 'invalid-credentials' });
  }
  if (!customer.phoneVerified) {
    return res.status(403).json({ error: 'phone-not-verified' });
  }
  const token = jwt.sign({ role: 'customer', customerId: customer.id }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token });
});

app.get('/api/customer/me', requireCustomer, (req, res) => {
  const sub = data.subscriptions.find(s => s.customerId === req.customer.id);
  const lic = sub && sub.licenseId ? data.licenses.find(l => l.id === sub.licenseId) : null;
  res.json({
    name: req.customer.name, storeName: req.customer.storeName, phone: req.customer.phone,
    subscription: lic ? {
      status: lic.status === 'revoked' ? 'revoked' : (new Date(lic.expires_at) > new Date() ? 'active' : 'expired'),
      expiresAt: lic.expires_at,
      licenseKey: lic.token
    } : null
  });
});

app.post('/api/customer/payment-claims', requireCustomer, (req, res) => {
  const { method, amount, reference, duration } = req.body || {};
  if (!method || !duration) return res.status(400).json({ error: 'missing-fields' });
  if (!['bank_transfer', 'vodafone_cash', 'instapay'].includes(method)) return res.status(400).json({ error: 'bad-method' });

  const claim = {
    id: data.nextClaimId++,
    customerId: req.customer.id,
    method, amount: amount || '', reference: reference || '', duration,
    status: 'pending',
    submittedAt: store.now(),
    reviewedAt: null, reviewNote: ''
  };
  data.paymentClaims.push(claim);
  store.save();
  logEvent('payment_claim_submitted', { customerId: req.customer.id, method, duration });
  res.json({ ok: true, claimId: claim.id });
});

app.get('/api/customer/payment-claims', requireCustomer, (req, res) => {
  const rows = data.paymentClaims
    .filter(c => c.customerId === req.customer.id)
    .sort((a, b) => b.submittedAt.localeCompare(a.submittedAt));
  res.json({ claims: rows });
});

// ============================================================
// مراجعة طلبات الدفع (الأدمن)
// ============================================================
app.get('/api/admin/payment-claims', requireAdmin, (req, res) => {
  const status = req.query.status; // 'pending' | 'approved' | 'rejected' | undefined (الكل)
  let rows = data.paymentClaims;
  if (status) rows = rows.filter(c => c.status === status);
  const out = [...rows].sort((a, b) => b.submittedAt.localeCompare(a.submittedAt)).map(c => {
    const customer = data.customers.find(cu => cu.id === c.customerId);
    return { ...c, customerName: customer ? customer.name : '—', storeName: customer ? customer.storeName : '—' };
  });
  res.json({ claims: out });
});

app.post('/api/admin/payment-claims/:id/approve', requireAdmin, (req, res) => {
  const id = parseInt(req.params.id);
  const claim = data.paymentClaims.find(c => c.id === id);
  if (!claim) return res.status(404).json({ error: 'not-found' });
  if (claim.status !== 'pending') return res.status(400).json({ error: 'already-reviewed' });

  const result = grantSubscriptionPeriod(claim.customerId, claim.duration, null);
  if (!result) return res.status(400).json({ error: 'grant-failed' });

  claim.status = 'approved';
  claim.reviewedAt = store.now();
  store.save();
  logEvent('payment_claim_approved', { claimId: id, customerId: claim.customerId });
  res.json({ ok: true, expiresAt: result.license.expires_at });
});

app.post('/api/admin/payment-claims/:id/reject', requireAdmin, (req, res) => {
  const id = parseInt(req.params.id);
  const { reviewNote } = req.body || {};
  const claim = data.paymentClaims.find(c => c.id === id);
  if (!claim) return res.status(404).json({ error: 'not-found' });
  if (claim.status !== 'pending') return res.status(400).json({ error: 'already-reviewed' });

  claim.status = 'rejected';
  claim.reviewedAt = store.now();
  claim.reviewNote = reviewNote || '';
  store.save();
  logEvent('payment_claim_rejected', { claimId: id, customerId: claim.customerId });
  res.json({ ok: true });
});

app.post('/api/license/verify', verifyLimiter, (req, res) => {
  const { key, deviceLabel } = req.body || {};
  const sigCheck = verifyLicenseTokenSignature(key);

  if (!sigCheck.valid && sigCheck.reason !== 'expired') {
    return res.json({ valid: false, reason: sigCheck.reason });
  }

  const row = data.licenses.find(l => l.id === sigCheck.payload.id);
  if (!row) {
    return res.json({ valid: sigCheck.valid, reason: sigCheck.valid ? null : sigCheck.reason, payload: sigCheck.payload, serverKnown: false });
  }

  if (deviceLabel) {
    const alreadyKnown = data.deviceSightings.some(d => d.license_id === row.id && d.device_id === deviceLabel);
    if (!alreadyKnown) {
      const currentCount = data.deviceSightings.filter(d => d.license_id === row.id).length;
      if (currentCount >= row.max_devices) {
        return res.json({ valid: false, reason: 'device-limit-reached', payload: sigCheck.payload, serverKnown: true, maxDevices: row.max_devices });
      }
    }
  }

  row.last_check_at = store.now();
  row.last_check_ip = req.ip;
  row.check_count = (row.check_count || 0) + 1;
  if (deviceLabel) row.device_label = deviceLabel;

  if (deviceLabel) {
    let sight = data.deviceSightings.find(d => d.license_id === row.id && d.device_id === deviceLabel);
    if (sight) { sight.last_seen = store.now(); sight.last_ip = req.ip; }
    else { data.deviceSightings.push({ license_id: row.id, device_id: deviceLabel, last_seen: store.now(), last_ip: req.ip }); }
  }
  store.save();

  if (row.status === 'revoked') {
    return res.json({ valid: false, reason: 'revoked', payload: sigCheck.payload, serverKnown: true });
  }
  if (new Date(row.expires_at) < new Date()) {
    return res.json({ valid: false, reason: 'expired', payload: sigCheck.payload, serverKnown: true });
  }
  // currentToken بيرجع دايمًا التوكن الرسمي الحالي — لو الاشتراك اتجدد وطول ميعاد الانتهاء، التوكن ده بيبقى مختلف
  // عن المفتاح اللي التطبيق باعته، والتطبيق بيحدّث نسخته المحفوظة بيه تلقائيًا عشان يعرف يشتغل أوفلاين للمدة الجديدة
  res.json({ valid: true, payload: sigCheck.payload, serverKnown: true, currentToken: row.token });
});

app.post('/api/device/pull-config', verifyLimiter, (req, res) => {
  const { key, deviceId } = req.body || {};
  const sigCheck = verifyLicenseTokenSignature(key);
  if (!sigCheck.payload || !sigCheck.payload.id) {
    return res.status(400).json({ error: 'invalid-key' });
  }
  const licenseId = sigCheck.payload.id;

  let row = null;
  if (deviceId) {
    row = data.remoteConfigs.find(r => r.scope_type === 'device' && r.scope_key === deviceId);
  }
  if (!row) {
    row = data.remoteConfigs.find(r => r.scope_type === 'license' && r.scope_key === licenseId);
  }
  if (!row) return res.json({ hasConfig: false });

  res.json({
    hasConfig: true,
    updatedAt: row.updated_at,
    settings: row.settings_json ? JSON.parse(row.settings_json) : null,
    products: row.products_json ? JSON.parse(row.products_json) : null
  });
});

app.get('/api/admin/devices', requireAdmin, (req, res) => {
  const rows = data.deviceSightings
    .map(d => {
      const lic = data.licenses.find(l => l.id === d.license_id);
      if (!lic) return null;
      return {
        device_id: d.device_id, license_id: d.license_id, last_seen: d.last_seen, last_ip: d.last_ip,
        customer_name: lic.customer_name, store_name: lic.store_name, status: lic.status,
        expires_at: lic.expires_at, max_devices: lic.max_devices
      };
    })
    .filter(Boolean)
    .sort((a, b) => b.last_seen.localeCompare(a.last_seen))
    .slice(0, 500);
  res.json({ devices: rows });
});

app.delete('/api/admin/devices/:licenseId/:deviceId', requireAdmin, (req, res) => {
  const before = data.deviceSightings.length;
  data.deviceSightings = data.deviceSightings.filter(
    d => !(d.license_id === req.params.licenseId && d.device_id === req.params.deviceId)
  );
  if (data.deviceSightings.length === before) return res.status(404).json({ error: 'not-found' });
  store.save();
  logEvent('device_forgotten', { licenseId: req.params.licenseId, deviceId: req.params.deviceId });
  res.json({ ok: true });
});

app.get('/api/admin/config/:scopeType/:scopeKey', requireAdmin, (req, res) => {
  const { scopeType, scopeKey } = req.params;
  if (!['license', 'device'].includes(scopeType)) return res.status(400).json({ error: 'bad-scope' });
  const row = data.remoteConfigs.find(r => r.scope_type === scopeType && r.scope_key === scopeKey);
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

  let row = data.remoteConfigs.find(r => r.scope_type === scopeType && r.scope_key === scopeKey);
  if (!row) {
    row = { scope_type: scopeType, scope_key: scopeKey, settings_json: null, products_json: null, updated_at: store.now() };
    data.remoteConfigs.push(row);
  }
  if (settings) row.settings_json = JSON.stringify(settings);
  if (products) row.products_json = JSON.stringify(products);
  row.updated_at = store.now();
  store.save();

  logEvent('remote_config_set', { scopeType, scopeKey });
  res.json({ ok: true });
});

app.delete('/api/admin/config/:scopeType/:scopeKey', requireAdmin, (req, res) => {
  const { scopeType, scopeKey } = req.params;
  data.remoteConfigs = data.remoteConfigs.filter(r => !(r.scope_type === scopeType && r.scope_key === scopeKey));
  store.save();
  logEvent('remote_config_cleared', { scopeType, scopeKey });
  res.json({ ok: true });
});

app.get('/api/updates/:platform/latest', (req, res) => {
  const platform = req.params.platform;
  const versions = data.appVersions.filter(v => v.platform === platform && v.is_active);
  const row = versions.sort((a, b) => b.id - a.id)[0];
  if (!row) return res.status(404).json({ error: 'no-version-published' });
  res.json({ version: row.version, notes: row.notes, url: `/updates/${encodeURIComponent(row.file_path)}`, publishedAt: row.published_at });
});

app.post('/api/admin/versions', requireAdmin, (req, res) => {
  const { platform, version, filePath, notes } = req.body || {};
  if (!platform || !version || !filePath) return res.status(400).json({ error: 'missing-fields' });
  data.appVersions.forEach(v => { if (v.platform === platform) v.is_active = 0; });
  data.appVersions.push({ id: data.nextVersionId++, platform, version, file_path: filePath, notes: notes || '', published_at: store.now(), is_active: 1 });
  store.save();
  logEvent('version_published', { platform, version });
  res.json({ ok: true });
});

app.post('/api/admin/versions/upload', requireAdmin, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'no-file' });
  const { platform, version, notes } = req.body || {};
  if (!platform || !version) {
    fs.unlink(req.file.path, () => {});
    return res.status(400).json({ error: 'missing-fields' });
  }
  data.appVersions.forEach(v => { if (v.platform === platform) v.is_active = 0; });
  data.appVersions.push({ id: data.nextVersionId++, platform, version, file_path: req.file.filename, notes: notes || '', published_at: store.now(), is_active: 1 });
  store.save();
  logEvent('version_uploaded', { platform, version, file: req.file.filename });
  res.json({ ok: true, file: req.file.filename });
});

app.get('/api/admin/versions', requireAdmin, (req, res) => {
  const rows = [...data.appVersions].sort((a, b) => b.id - a.id).slice(0, 100);
  res.json({ versions: rows });
});

app.get('/api/health', (req, res) => res.json({ ok: true, time: new Date().toISOString() }));

app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'not-found' });
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.use((err, req, res, next) => {
  console.error(err);
  if (err.code === 'LIMIT_FILE_SIZE') return res.status(413).json({ error: 'file-too-large' });
  res.status(500).json({ error: 'server-error' });
});

app.listen(PORT, () => {
  console.log(`✅ سيرفر التحكم شغال على المنفذ ${PORT}`);
  if (!process.env.ADMIN_PASSWORD_HASH) {
    console.log(`⚠️  تحذير: بتستخدم كلمة سر أدمن افتراضية غير آمنة (change-me-now). لازم تظبطي متغيرات البيئة قبل النشر الحقيقي — شوفي ملف .env.example`);
  }
});
