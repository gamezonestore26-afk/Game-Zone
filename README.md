# GameZone — Backend حقيقي

## التشغيل
1. ثبّت Node.js 20+.
2. نفّذ `npm install`.
3. انسخ `.env.example` إلى `.env` وعدّل `JWT_SECRET` وبيانات المدير.
4. شغّل `npm start`.
5. افتح `http://localhost:3000`.

## حساب المدير
يُنشأ أول حساب مدير تلقائيًا من `ADMIN_EMAIL`, `ADMIN_PHONE`, `ADMIN_PASSWORD` عند أول تشغيل. لا تضع كلمة مرور حقيقية في مستودع Git.

## الأمان
- كلمات السر تُخزن كـ bcrypt hashes.
- جلسة الدخول في HttpOnly cookie.
- لوحة الإدارة محمية على السيرفر بدور `admin`، وليست مجرد إخفاء زر في الواجهة.
- OTP صالح لمدة محددة ويُخزن كـ hash ويُستخدم مرة واحدة.
- تغيير كلمة السر يتطلب كلمة السر الحالية ثم OTP ثم كلمة السر الجديدة.
- استعادة كلمة السر تستخدم OTP.
- للـOTP عبر البريد اضبط SMTP في `.env`. في التطوير فقط يظهر OTP في console إذا لم تُضبط SMTP.

## الصور
المدير يرفع صورة المنتج عبر `multipart/form-data` إلى `/api/admin/products`. الملفات تُحفظ في `uploads/`.

## مهم قبل النشر
استخدم HTTPS، وغيّر `JWT_SECRET` وكلمة مرور المدير، واضبط SMTP حقيقي، وأضف SMS provider إذا أردت OTP للهاتف. يمكن نقل SQLite إلى PostgreSQL عند التوسع.


## Real OTP setup

### SMS OTP (Twilio Verify)
The backend now uses Twilio Verify for phone OTP. Twilio's Node/Express flow uses an Account SID, Auth Token, and Verify Service SID; the verification is started with `channel: sms` and checked with the submitted code. citeturn0search4turn0search10

Add these to `.env` (never commit `.env`):
- `TWILIO_ACCOUNT_SID`
- `TWILIO_AUTH_TOKEN`
- `TWILIO_VERIFY_SERVICE_SID`

For production SMS delivery, configure the Twilio account and comply with recipient consent/opt-in requirements. Trial accounts can only send to verified recipients. citeturn0search2turn0search6

### Email OTP (SMTP)
Email OTP uses Nodemailer SMTP. Set `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, and `SMTP_FROM`. Nodemailer supports standard SMTP with STARTTLS on port 587 or TLS on 465, as well as provider presets such as Gmail. citeturn0search0turn0search7

For Gmail, use an app password/OAuth-supported authentication rather than putting your normal Gmail password in the project.
