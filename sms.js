// sms.js — إرسال رسائل SMS (حاليًا لأكواد OTP)
//
// لو حطيتي بيانات Twilio في متغيرات البيئة (.env)، الرسائل هتتبعت حقيقي:
//   TWILIO_ACCOUNT_SID=...
//   TWILIO_AUTH_TOKEN=...
//   TWILIO_FROM_NUMBER=+1xxxxxxxxxx   (رقم Twilio بتاعك)
//
// من غير الإعدادات دي، الكود بيتطبع في سجل السيرفر بس (وضع تجريبي) عشان تقدري تجربي
// النظام كامل قبل ما تعملي حساب SMS حقيقي. أي مزوّد تاني (Msegat, Vonage, إلخ) ممكن
// نستبدل بيه Twilio هنا بنفس الطريقة — استدعاء HTTP بسيط، من غير أي مكتبة إضافية.

async function sendSms(phone, message) {
  const sid = process.env.TWILIO_ACCOUNT_SID;
  const token = process.env.TWILIO_AUTH_TOKEN;
  const from = process.env.TWILIO_FROM_NUMBER;

  if (!sid || !token || !from) {
    console.log(`📱 [SMS - وضع تجريبي، لسه مفيش مزوّد SMS حقيقي متظبط في .env] إلى ${phone}: ${message}`);
    return { sent: false, mode: 'console' };
  }

  try {
    const auth = Buffer.from(`${sid}:${token}`).toString('base64');
    const body = new URLSearchParams({ To: phone, From: from, Body: message });
    const res = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${sid}/Messages.json`, {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${auth}`,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: body.toString()
    });
    if (!res.ok) {
      const errText = await res.text();
      console.error('فشل إرسال SMS عبر Twilio:', errText);
      return { sent: false, mode: 'twilio-error' };
    }
    return { sent: true, mode: 'twilio' };
  } catch (e) {
    console.error('خطأ في الاتصال بـ Twilio:', e.message);
    return { sent: false, mode: 'twilio-error' };
  }
}

module.exports = { sendSms };
