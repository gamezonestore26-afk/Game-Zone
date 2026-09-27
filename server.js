import 'dotenv/config';
import express from 'express';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcryptjs';
import Database from 'better-sqlite3';
import jwt from 'jsonwebtoken';
import rateLimit from 'express-rate-limit';
import multer from 'multer';
import nodemailer from 'nodemailer';
import twilio from 'twilio';
import crypto from 'crypto';
import path from 'path';
import {fileURLToPath} from 'url';

const __dirname=path.dirname(fileURLToPath(import.meta.url));
const app=express();
const PORT=Number(process.env.PORT||3000);
const JWT_SECRET = JWT_SECRET || 'GAMEZONE-DEV-ONLY-CHANGE-ME';
if(!process.env.JWT_SECRET) console.warn('WARNING: JWT_SECRET is not set. Using temporary development secret; set JWT_SECRET in production.');
const db=new Database(path.join(__dirname,'data.sqlite'));
db.pragma('journal_mode = WAL');
db.exec(`CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,email TEXT UNIQUE,phone TEXT UNIQUE,password_hash TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'customer',verified INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP); CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,category TEXT NOT NULL,price INTEGER NOT NULL,image TEXT,description TEXT,active INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP); CREATE TABLE IF NOT EXISTS otp_codes(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,code_hash TEXT NOT NULL,purpose TEXT NOT NULL,expires_at INTEGER NOT NULL,used INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);`);

function seed(){
 const adminEmail=process.env.ADMIN_EMAIL, adminPhone=process.env.ADMIN_PHONE, adminPass=process.env.ADMIN_PASSWORD;
 if(!adminEmail||!adminPass) return;
 const existing=db.prepare('SELECT id FROM users WHERE role="admin" LIMIT 1').get();
 if(!existing){const hash=bcrypt.hashSync(adminPass,12);db.prepare('INSERT INTO users(email,phone,password_hash,role,verified) VALUES(?,?,?,?,1)').run(adminEmail,adminPhone||null,hash,'admin');}
 const count=db.prepare('SELECT COUNT(*) c FROM products').get().c;
 if(!count){const ins=db.prepare('INSERT INTO products(name,category,price,image,description) VALUES(?,?,?,?,?)');[['مبرد هاتف RGB Gaming','coolers',450,'','تبريد قوي مع إضاءة RGB'],['مبرد مغناطيسي Pro','coolers',650,'','تثبيت مغناطيسي وأداء هادئ'],['سماعة Gaming Stereo','headsets',550,'','صوت واضح وميكروفون للألعاب'],['سماعة RGB Pro','headsets',850,'','إضاءة RGB وصوت محيطي'],['صوابع PUBG Touch','triggers',120,'','استجابة سريعة وتحكم أفضل'],['صوابع PUBG Pro','triggers',180,'','زوج احترافي للألعاب']].forEach(x=>ins.run(...x));}
}
seed();
app.use(express.json({limit:'1mb'})); app.use(express.urlencoded({extended:true})); app.use(cookieParser());
app.use('/uploads',express.static(path.join(__dirname,'uploads')));
app.use(express.static(path.join(__dirname,'public')));
const authLimiter=rateLimit({windowMs:15*60*1000,max:30,standardHeaders:true,legacyHeaders:false});
const otpLimiter=rateLimit({windowMs:15*60*1000,max:8,standardHeaders:true,legacyHeaders:false});
const upload=multer({dest:path.join(__dirname,'uploads'),limits:{fileSize:5*1024*1024},fileFilter:(req,file,cb)=>cb(null,/^image\/(jpeg|png|webp|gif)$/.test(file.mimetype))});

function tokenFor(user){return jwt.sign({sub:user.id,role:user.role},JWT_SECRET,{expiresIn:'7d'});}
function auth(req,res,next){try{const t=req.cookies.gztoken;if(!t)return res.status(401).json({error:'غير مسجل الدخول'});req.user=jwt.verify(t,JWT_SECRET);next();}catch{return res.status(401).json({error:'جلسة غير صالحة'});}}
function admin(req,res,next){if(req.user?.role!=='admin')return res.status(403).json({error:'غير مصرح'});next();}
function findUser(identifier){return identifier.includes('@')?db.prepare('SELECT * FROM users WHERE email=?').get(identifier.toLowerCase()):db.prepare('SELECT * FROM users WHERE phone=?').get(identifier);}
function twilioClient(){if(!process.env.TWILIO_ACCOUNT_SID||!process.env.TWILIO_AUTH_TOKEN||!process.env.TWILIO_VERIFY_SERVICE_SID) return null; return twilio(process.env.TWILIO_ACCOUNT_SID,process.env.TWILIO_AUTH_TOKEN);}
function normalizePhone(phone){return String(phone||'').trim().replace(/\s+/g,'');}
async function sendPhoneOtp(user){const client=twilioClient(); if(!client) throw new Error('Twilio SMS is not configured'); await client.verify.v2.services(process.env.TWILIO_VERIFY_SERVICE_SID).verifications.create({to:normalizePhone(user.phone),channel:'sms'}); return 'sms';}
async function checkPhoneOtp(user,code){const client=twilioClient(); if(!client) return false; const r=await client.verify.v2.services(process.env.TWILIO_VERIFY_SERVICE_SID).verificationChecks.create({to:normalizePhone(user.phone),code:String(code||'').trim()}); return r.status==='approved';}
async function sendOtp(user,code){
 if(process.env.SMTP_HOST&&process.env.SMTP_USER&&process.env.SMTP_PASS&&user.email){const tr=nodemailer.createTransport({host:process.env.SMTP_HOST,port:Number(process.env.SMTP_PORT||587),secure:Number(process.env.SMTP_PORT||587)===465,auth:{user:process.env.SMTP_USER,pass:process.env.SMTP_PASS}});await tr.sendMail({from:process.env.SMTP_FROM||process.env.SMTP_USER,to:user.email,subject:'GameZone - رمز التحقق',text:`رمز التحقق الخاص بك: ${code}\nينتهي خلال ${process.env.OTP_EXPIRES_MINUTES||10} دقائق.`});return 'email';}
 console.log(`[GAMEZONE OTP] user=${user.id} code=${code}`); return 'console';
}
function issueOtp(user,purpose){const code=String(crypto.randomInt(100000,1000000));const hash=bcrypt.hashSync(code,10);const expires=Date.now()+Number(process.env.OTP_EXPIRES_MINUTES||10)*60000;db.prepare('UPDATE otp_codes SET used=1 WHERE user_id=? AND purpose=? AND used=0').run(user.id,purpose);db.prepare('INSERT INTO otp_codes(user_id,code_hash,purpose,expires_at) VALUES(?,?,?,?,?)').run(user.id,hash,purpose,expires);return {code,expires};}

app.post('/api/auth/register',authLimiter,async(req,res)=>{try{const {email,phone,password}=req.body;if(!email&&!phone||!password||password.length<8)return res.status(400).json({error:'بيانات التسجيل غير صحيحة'});if(findUser(email||phone))return res.status(409).json({error:'الحساب موجود بالفعل'});const hash=await bcrypt.hash(password,12);const info=db.prepare('INSERT INTO users(email,phone,password_hash,role,verified) VALUES(?,?,?,?,0)').run(email?.toLowerCase()||null,phone||null,hash,'customer');const user=db.prepare('SELECT * FROM users WHERE id=?').get(info.lastInsertRowid);if(user.phone){await sendPhoneOtp(user);}else{const {code}=issueOtp(user,'verify');await sendOtp(user,code);}res.json({ok:true,message:'تم إنشاء الحساب. تم إرسال رمز التحقق.'});}catch(e){res.status(400).json({error:'تعذر إنشاء الحساب'});}});
app.post('/api/auth/login',authLimiter,async(req,res)=>{const {identifier,password}=req.body;const u=findUser(identifier||'');if(!u||!(await bcrypt.compare(password||'',u.password_hash)))return res.status(401).json({error:'بيانات الدخول غير صحيحة'});if(u.role==='customer'&&!u.verified)return res.status(403).json({error:'يجب تأكيد الحساب أولاً'});res.cookie('gztoken',tokenFor(u),{httpOnly:true,sameSite:'lax',secure:process.env.NODE_ENV==='production',maxAge:7*24*60*60*1000});res.json({ok:true,user:{id:u.id,email:u.email,phone:u.phone,role:u.role}});});
app.post('/api/auth/verify',otpLimiter,async(req,res)=>{try{const {identifier,code}=req.body;const u=findUser(identifier||'');if(!u)return res.status(400).json({error:'الحساب غير موجود'});let valid=false;if(u.phone) valid=await checkPhoneOtp(u,code);else{const row=db.prepare('SELECT * FROM otp_codes WHERE user_id=? AND purpose="verify" AND used=0 ORDER BY id DESC LIMIT 1').get(u.id);valid=!!row&&row.expires_at>=Date.now()&&await bcrypt.compare(code||'',row.code_hash);if(valid)db.prepare('UPDATE otp_codes SET used=1 WHERE id=?').run(row.id);}if(!valid)return res.status(400).json({error:'رمز التحقق غير صحيح أو منتهي'});db.prepare('UPDATE users SET verified=1 WHERE id=?').run(u.id);res.json({ok:true,message:'تم تأكيد الحساب'});}catch(e){res.status(500).json({error:'تعذر التحقق الآن'});}});
app.post('/api/auth/forgot/request',otpLimiter,async(req,res)=>{const {identifier}=req.body;const u=findUser(identifier||'');if(!u)return res.json({ok:true,message:'إذا كان الحساب موجودًا سيتم إرسال رمز تحقق.'});if(u.phone){await sendPhoneOtp(u);}else{const {code}=issueOtp(u,'reset');await sendOtp(u,code);}res.json({ok:true,message:'تم إرسال رمز التحقق.'});});
app.post('/api/auth/forgot/reset',otpLimiter,async(req,res)=>{const {identifier,code,newPassword}=req.body;const u=findUser(identifier||'');if(!u||!newPassword||newPassword.length<8)return res.status(400).json({error:'بيانات غير صحيحة'});let valid=false;let row=null;if(u.phone) valid=await checkPhoneOtp(u,code);else{row=db.prepare('SELECT * FROM otp_codes WHERE user_id=? AND purpose="reset" AND used=0 ORDER BY id DESC LIMIT 1').get(u.id);valid=!!row&&row.expires_at>=Date.now()&&await bcrypt.compare(code||'',row.code_hash);}if(!valid)return res.status(400).json({error:'رمز التحقق غير صحيح أو منتهي'});if(row)db.prepare('UPDATE otp_codes SET used=1 WHERE id=?').run(row.id);db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(await bcrypt.hash(newPassword,12),u.id);res.json({ok:true,message:'تم تغيير كلمة السر'});});
app.post('/api/auth/change-password',auth,otpLimiter,async(req,res)=>{const {currentPassword,newPassword}=req.body;const u=db.prepare('SELECT * FROM users WHERE id=?').get(req.user.sub);if(!u||!(await bcrypt.compare(currentPassword||'',u.password_hash))||!newPassword||newPassword.length<8)return res.status(400).json({error:'بيانات تغيير كلمة السر غير صحيحة'});if(u.phone){await sendPhoneOtp(u);}else{const {code}=issueOtp(u,'change');await sendOtp(u,code);}res.json({ok:true,message:'تم إرسال رمز تحقق لإكمال تغيير كلمة السر.'});});
app.post('/api/auth/change-password/confirm',auth,otpLimiter,async(req,res)=>{const {code,newPassword}=req.body;const u=db.prepare('SELECT * FROM users WHERE id=?').get(req.user.sub);let valid=false;let row=null;if(u.phone) valid=await checkPhoneOtp(u,code);else{row=db.prepare('SELECT * FROM otp_codes WHERE user_id=? AND purpose="change" AND used=0 ORDER BY id DESC LIMIT 1').get(u.id);valid=!!row&&row.expires_at>=Date.now()&&await bcrypt.compare(code||'',row.code_hash);}if(!valid||!newPassword||newPassword.length<8)return res.status(400).json({error:'رمز التحقق أو كلمة السر غير صحيح'});if(row)db.prepare('UPDATE otp_codes SET used=1 WHERE id=?').run(row.id);db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(await bcrypt.hash(newPassword,12),u.id);res.json({ok:true,message:'تم تغيير كلمة السر بنجاح'});});
app.post('/api/auth/logout',(req,res)=>{res.clearCookie('gztoken');res.json({ok:true});});

app.get('/api/products',(req,res)=>res.json(db.prepare('SELECT id,name,category,price,image,description FROM products WHERE active=1 ORDER BY id DESC').all()));
app.get('/api/me',auth,(req,res)=>{const u=db.prepare('SELECT id,email,phone,role,verified FROM users WHERE id=?').get(req.user.sub);res.json(u);});
app.get('/api/admin/products',auth,admin,(req,res)=>res.json(db.prepare('SELECT * FROM products ORDER BY id DESC').all()));
app.post('/api/admin/products',auth,admin,upload.single('image'),(req,res)=>{const {name,category,price,description}=req.body;if(!name||!category||!Number(price))return res.status(400).json({error:'بيانات المنتج ناقصة'});const image=req.file?`/uploads/${req.file.filename}`:'';const info=db.prepare('INSERT INTO products(name,category,price,image,description) VALUES(?,?,?,?,?)').run(name,category,Number(price),image,description||'');res.json({ok:true,id:info.lastInsertRowid});});
app.put('/api/admin/products/:id',auth,admin,upload.single('image'),(req,res)=>{const p=db.prepare('SELECT * FROM products WHERE id=?').get(req.params.id);if(!p)return res.status(404).json({error:'المنتج غير موجود'});const {name,category,price,description,active}=req.body;const image=req.file?`/uploads/${req.file.filename}`:(req.body.image??p.image);db.prepare('UPDATE products SET name=?,category=?,price=?,image=?,description=?,active=? WHERE id=?').run(name||p.name,category||p.category,Number(price||p.price),image,description??p.description,active===undefined?p.active:Number(active),p.id);res.json({ok:true});});
app.delete('/api/admin/products/:id',auth,admin,(req,res)=>{db.prepare('DELETE FROM products WHERE id=?').run(req.params.id);res.json({ok:true});});
app.get('/api/admin/users',auth,admin,(req,res)=>res.json(db.prepare('SELECT id,email,phone,role,verified,created_at FROM users ORDER BY id DESC').all()));

app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
app.listen(PORT,'0.0.0.0',()=>console.log(`GameZone backend running on port ${PORT}`));
