// license.js — نفس نظام التوقيع الموجود في أداة مولّد التراخيص وفي شاشة الأسعار (Electron)
// لازم LICENSE_SECRET يكون مطابق تمامًا في التلاتة أماكن عشان المفاتيح تفضل شغالة مع بعض
const crypto = require('crypto');

const LICENSE_SECRET = process.env.LICENSE_SECRET || 'SHARQAWY-FX-LICENSE-2026-K7m9Qx2Lp4Rt8Vb';

function b64urlFromBuffer(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlFromString(str) {
  return b64urlFromBuffer(Buffer.from(str, 'utf-8'));
}
function stringFromB64url(b64) {
  b64 = b64.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) b64 += '=';
  return Buffer.from(b64, 'base64').toString('utf-8');
}
function hmacSign(message) {
  return b64urlFromBuffer(crypto.createHmac('sha256', LICENSE_SECRET).update(message).digest());
}

function generateLicenseToken(payload) {
  const payloadB64 = b64urlFromString(JSON.stringify(payload));
  const sig = hmacSign(payloadB64);
  return `${payloadB64}.${sig}`;
}

function verifyLicenseTokenSignature(token) {
  if (!token || typeof token !== 'string' || token.indexOf('.') === -1) {
    return { valid: false, reason: 'missing' };
  }
  const parts = token.trim().split('.');
  if (parts.length !== 2) return { valid: false, reason: 'format' };
  const [payloadB64, sig] = parts;
  const expectedSig = hmacSign(payloadB64);
  if (expectedSig !== sig) return { valid: false, reason: 'signature' };
  let payload;
  try {
    payload = JSON.parse(stringFromB64url(payloadB64));
  } catch (e) {
    return { valid: false, reason: 'parse' };
  }
  if (!payload.expiresAt) return { valid: false, reason: 'no-expiry', payload };
  const expires = new Date(payload.expiresAt);
  if (isNaN(expires.getTime())) return { valid: false, reason: 'bad-expiry', payload };
  if (new Date() > expires) return { valid: false, reason: 'expired', payload };
  return { valid: true, payload };
}

function computeExpiry(durationKey, customDateStr) {
  const d = new Date();
  switch (durationKey) {
    case 'day': d.setDate(d.getDate() + 1); break;
    case '3days': d.setDate(d.getDate() + 3); break;
    case 'week': d.setDate(d.getDate() + 7); break;
    case 'month': d.setMonth(d.getMonth() + 1); break;
    case '3months': d.setMonth(d.getMonth() + 3); break;
    case '6months': d.setMonth(d.getMonth() + 6); break;
    case 'year': d.setFullYear(d.getFullYear() + 1); break;
    case 'custom':
      if (!customDateStr) return null;
      return new Date(customDateStr + 'T23:59:59');
    default: return null;
  }
  return d;
}

function genId() {
  return 'LIC-' + Date.now().toString(36).toUpperCase() + '-' + crypto.randomBytes(3).toString('hex').toUpperCase();
}

module.exports = { generateLicenseToken, verifyLicenseTokenSignature, computeExpiry, genId, LICENSE_SECRET };
