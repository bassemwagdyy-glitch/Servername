// db.js — قاعدة بيانات SQLite بسيطة (ملف واحد، مفيش سيرفر قاعدة بيانات منفصل مطلوب)
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, 'licenses.db'));
db.pragma('journal_mode = WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS licenses (
  id TEXT PRIMARY KEY,
  token TEXT NOT NULL,
  customer_name TEXT NOT NULL,
  store_name TEXT NOT NULL,
  phone TEXT,
  note TEXT,
  issued_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active', -- active | revoked
  device_label TEXT,
  last_check_at TEXT,
  last_check_ip TEXT,
  check_count INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS app_versions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  platform TEXT NOT NULL, -- win | android
  version TEXT NOT NULL,
  file_path TEXT NOT NULL,
  notes TEXT,
  published_at TEXT NOT NULL DEFAULT (datetime('now')),
  is_active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS admin_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type TEXT NOT NULL,
  detail TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- إعدادات ومنتجات يتم التحكم فيها عن بُعد — إما لكل التراخيص (scope_type='license')
-- أو لجهاز واحد بعينه (scope_type='device'، والمفتاح بيبقى الـ deviceId)
CREATE TABLE IF NOT EXISTS remote_configs (
  scope_type TEXT NOT NULL, -- 'license' | 'device'
  scope_key TEXT NOT NULL,  -- license id أو device id
  settings_json TEXT,
  products_json TEXT,
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (scope_type, scope_key)
);

-- كل جهاز شغّل التطبيق وعمل تحقق ترخيص أونلاين، بنسجله هنا عشان تبان في تاب "الأجهزة"
CREATE TABLE IF NOT EXISTS device_sightings (
  license_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  last_seen TEXT NOT NULL DEFAULT (datetime('now')),
  last_ip TEXT,
  PRIMARY KEY (license_id, device_id)
);
`);

module.exports = db;
