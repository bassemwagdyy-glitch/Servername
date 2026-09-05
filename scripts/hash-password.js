// استخدمي الأمر ده لتوليد هاش كلمة سر الأدمن قبل النشر:
//   node scripts/hash-password.js "كلمة-السر-اللي-عايزاها"
const bcrypt = require('bcryptjs');

const password = process.argv[2];
if (!password) {
  console.log('استخدمي: node scripts/hash-password.js "كلمة السر"');
  process.exit(1);
}
const hash = bcrypt.hashSync(password, 10);
console.log('\nحطي السطر ده في ملف .env:\n');
console.log(`ADMIN_PASSWORD_HASH=${hash}\n`);
