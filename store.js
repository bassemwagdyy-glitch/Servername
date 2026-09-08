// store.js — تخزين بسيط في ملف JSON واحد على القرص، من غير أي مكتبات تحتاج بناء (compilation)
// السبب: better-sqlite3 (اللي كان مستخدم قبل كده) مكتبة "native" لازم تتبني خصيصى لسيرفر النشر،
// وده بيفشل بصمت على منصات زي Railway أحيانًا. الحجم هنا (تراخيص + أجهزة + نسخ) صغير جدًا
// (كام مية سطر على الأكتر)، فملف JSON عادي أبسط وأضمن وأسرع في النشر من غير أي مفاجآت.
const fs = require('fs');
const path = require('path');

const DATA_DIR = path.join(__dirname, 'data');
const FILE = path.join(DATA_DIR, 'store.json');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

function defaultData() {
  return {
    licenses: [],
    deviceSightings: [],
    remoteConfigs: [],
    appVersions: [],
    adminEvents: [],
    nextVersionId: 1,
    nextEventId: 1
  };
}

function load() {
  try {
    const raw = fs.readFileSync(FILE, 'utf-8');
    const parsed = JSON.parse(raw);
    return { ...defaultData(), ...parsed };
  } catch (e) {
    return defaultData();
  }
}

const data = load();

function save() {
  // كتابة الملف كله كل مرة — الحجم صغير أوي (نص JSON بسيط) فده مش مكلف أداءً في الاستخدام ده
  const tmp = FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
  fs.renameSync(tmp, FILE); // إعادة تسمية ذرية تمنع تلف الملف لو السيرفر اتقفل في نص الكتابة
}

function now() {
  return new Date().toISOString();
}

module.exports = { data, save, now };
