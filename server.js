const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const path = require('path');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const dbPath = process.env.DATABASE_PATH || (process.env.VERCEL ? '/tmp/school.db' : path.join(__dirname, 'school.db'));
const db = new Database(dbPath);
const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || 'development-only-change-this-secret';
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT, full_name TEXT NOT NULL, username TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('student','teacher','admin','deputy')),
 grade INTEGER, class_name TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS admin_login_codes (
 id INTEGER PRIMARY KEY AUTOINCREMENT, code_hash TEXT NOT NULL, admin_name TEXT NOT NULL,
 expires_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS announcements (
 id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, body TEXT NOT NULL,
 author_id INTEGER, created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS assignments (
 id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, description TEXT DEFAULT '',
 grade INTEGER, due_date TEXT, teacher_id INTEGER, created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS grades (
 id INTEGER PRIMARY KEY AUTOINCREMENT, student_id INTEGER NOT NULL, subject TEXT NOT NULL,
 score REAL NOT NULL, note TEXT DEFAULT '', teacher_id INTEGER, created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS attendance (
 id INTEGER PRIMARY KEY AUTOINCREMENT, student_id INTEGER NOT NULL, day TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('present','absent','late')), teacher_id INTEGER,
 UNIQUE(student_id,day)
);
CREATE TABLE IF NOT EXISTS submissions (
 id INTEGER PRIMARY KEY AUTOINCREMENT, assignment_id INTEGER NOT NULL, student_id INTEGER NOT NULL,
 answer TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(assignment_id,student_id)
);
`);
// Safe schema upgrade for existing installations.
const userColumns = db.prepare('PRAGMA table_info(users)').all().map(c => c.name);
if (!userColumns.includes('approved')) db.exec('ALTER TABLE users ADD COLUMN approved INTEGER NOT NULL DEFAULT 1');
const count = db.prepare('SELECT COUNT(*) n FROM users').get().n;
if (!count) {
 const hash = bcrypt.hashSync('Admin12345!', 12);
 db.prepare('INSERT INTO users(full_name,username,password_hash,role) VALUES(?,?,?,?)')
   .run('مدیر سامانه','admin',hash,'admin');
 const t = bcrypt.hashSync('Teacher123!',12);
 db.prepare('INSERT INTO users(full_name,username,password_hash,role,grade,class_name) VALUES(?,?,?,?,?,?)')
   .run('معلم نمونه','teacher',t,'teacher',4,'چهارم الف');
 const s = bcrypt.hashSync('Student123!',12);
 db.prepare('INSERT INTO users(full_name,username,password_hash,role,grade,class_name) VALUES(?,?,?,?,?,?)')
   .run('دانش‌آموز نمونه','student',s,'student',4,'چهارم الف');
 db.prepare('INSERT INTO announcements(title,body) VALUES(?,?)')
   .run('به سامانه مدرسه هوشمند خوش آمدید','اطلاعیه‌ها و تکالیف مدرسه را از این بخش دنبال کنید.');
 db.prepare('INSERT INTO assignments(title,description,grade,due_date) VALUES(?,?,?,?)')
   .run('تمرین ریاضی','تمرین‌های صفحه امروز کتاب را حل کنید.',4,'2026-11-25');
}
function auth(req,res,next) {
 const token = req.cookies.school_token || (req.headers.authorization||'').replace('Bearer ','');
 try { req.user = jwt.verify(token, SECRET); next(); }
 catch { res.status(401).json({error:'برای ادامه وارد حساب شوید.'}); }
}
function roles(...allowed){ return (req,res,next)=> allowed.includes(req.user.role) ? next() : res.status(403).json({error:'دسترسی مجاز نیست.'}); }
app.post('/api/register',(req,res)=>{
 const {fullName,username,password,role='student',grade,className} = req.body||{};
 if(!fullName||!username||!password||password.length<8) return res.status(400).json({error:'نام، نام کاربری و رمز حداقل ۸ کاراکتری لازم است.'});
 if(role!=='student') return res.status(403).json({error:'ثبت‌نام عمومی فقط برای دانش‌آموز فعال است.'});
 try {
  const info=db.prepare('INSERT INTO users(full_name,username,password_hash,role,grade,class_name,approved) VALUES(?,?,?,?,?,?,0)')
   .run(fullName.trim(),username.trim(),bcrypt.hashSync(password,12),'student',Number(grade)||null,className||'');
  res.status(201).json({ok:true,id:info.lastInsertRowid});
 } catch(e){ res.status(409).json({error:'این نام کاربری قبلاً ثبت شده است.'}); }
});
const adminEmail = 'amotopiok@gmail.com';
const adminCodeRequests = new Map();
function hashAdminCode(code){return crypto.createHmac('sha256',SECRET).update(code).digest('hex');}
app.post('/api/admin/request-code',async(req,res)=>{
 const name=String(req.body?.name||'').trim().slice(0,60);
 if(name.length<2)return res.status(400).json({error:'نام مدیر را وارد کنید.'});
 const ip=req.ip||'unknown', now=Date.now(), last=adminCodeRequests.get(ip)||0;
 if(now-last<60_000)return res.status(429).json({error:'برای دریافت کد جدید کمی صبر کنید.'});
 if(!process.env.RESEND_API_KEY||!process.env.MAIL_FROM)return res.status(503).json({error:'ارسال ایمیل هنوز تنظیم نشده است. مدیر فنی باید RESEND_API_KEY و MAIL_FROM را در تنظیمات امن Vercel وارد کند.'});
 adminCodeRequests.set(ip,now);
 const code=String(crypto.randomInt(100000,1000000));
 db.prepare('DELETE FROM admin_login_codes').run();
 db.prepare('INSERT INTO admin_login_codes(code_hash,admin_name,expires_at,created_at) VALUES(?,?,?,?)').run(hashAdminCode(code),name,now+10*60*1000,now);
 try{
  const mail=await fetch('https://api.resend.com/emails',{method:'POST',headers:{Authorization:'Bearer '+process.env.RESEND_API_KEY,'Content-Type':'application/json'},body:JSON.stringify({from:process.env.MAIL_FROM,to:[adminEmail],subject:'کد ورود مدیر سامانه مدرسه قاضی‌زاده',text:'کد ورود شما: '+code+'\nاین کد تا ۱۰ دقیقه معتبر است. اگر شما درخواست نداده‌اید، این پیام را نادیده بگیرید.',html:'<div dir="rtl" style="font-family:Arial,sans-serif"><h2>ورود مدیر سامانه مدرسه قاضی‌زاده</h2><p>کد یک‌بارمصرف شما:</p><div style="font-size:30px;font-weight:bold;letter-spacing:8px">'+code+'</div><p>این کد تا ۱۰ دقیقه معتبر است.</p></div>'})});
  const result=await mail.json().catch(()=>({}));
  if(!mail.ok){db.prepare('DELETE FROM admin_login_codes').run();return res.status(502).json({error:'ارسال ایمیل ناموفق بود. تنظیمات فرستنده را بررسی کنید.'});}
  res.json({ok:true,message:'کد ورود به ایمیل ثابت مدیر ارسال شد.'});
 }catch(e){db.prepare('DELETE FROM admin_login_codes').run();res.status(502).json({error:'ارتباط با سرویس ایمیل برقرار نشد.'});}
});
app.post('/api/admin/verify-code',(req,res)=>{
 const code=String(req.body?.code||'').trim(), now=Date.now();
 const row=db.prepare('SELECT * FROM admin_login_codes ORDER BY id DESC LIMIT 1').get();
 if(!row||row.expires_at<now||row.attempts>=5)return res.status(401).json({error:'کد منقضی شده یا معتبر نیست. دوباره کد بگیرید.'});
 const expected=Buffer.from(row.code_hash), actual=Buffer.from(hashAdminCode(code));
 if(expected.length!==actual.length||!crypto.timingSafeEqual(expected,actual)){
  db.prepare('UPDATE admin_login_codes SET attempts=attempts+1 WHERE id=?').run(row.id);
  return res.status(401).json({error:'کد واردشده درست نیست.'});
 }
 db.prepare('DELETE FROM admin_login_codes WHERE id=?').run(row.id);
 const admin=db.prepare("SELECT id,full_name,grade,class_name FROM users WHERE role='admin' ORDER BY id LIMIT 1").get();
 if(!admin)return res.status(403).json({error:'حساب مدیر در سامانه تعریف نشده است.'});
 const name=row.admin_name;
 const token=jwt.sign({id:admin.id,name,role:'admin',grade:admin.grade,className:admin.class_name},SECRET,{expiresIn:'8h'});
 res.cookie('school_token',token,{httpOnly:true,sameSite:'lax',secure:process.env.NODE_ENV==='production',maxAge:8*60*60*1000});
 res.json({user:{id:admin.id,name,role:'admin',grade:admin.grade,className:admin.class_name}});
});
app.post('/api/login',(req,res)=>{
 const {username,password,role}=req.body||{};
 if(!['student','teacher','deputy'].includes(role))return res.status(403).json({error:'برای این نقش از روش ورود مخصوص خودش استفاده کنید.'});
 const user=db.prepare('SELECT * FROM users WHERE username=? AND role=?').get(username||'',role);
 if(!user||!bcrypt.compareSync(password||'',user.password_hash)) return res.status(401).json({error:'نام کاربری یا رمز عبور نادرست است.'});
 if(!user.approved) return res.status(403).json({error:'حساب شما هنوز توسط مدرسه تأیید نشده است.'});
 const token=jwt.sign({id:user.id,name:user.full_name,role:user.role,grade:user.grade,className:user.class_name},SECRET,{expiresIn:'8h'});
 res.cookie('school_token',token,{httpOnly:true,sameSite:'lax',secure:process.env.NODE_ENV==='production',maxAge:8*60*60*1000});
 res.json({user:{id:user.id,name:user.full_name,role:user.role,grade:user.grade,className:user.class_name}});
});
app.post('/api/logout',(req,res)=>{res.clearCookie('school_token');res.json({ok:true});});
app.get('/api/me',auth,(req,res)=>res.json({user:req.user}));
app.get('/api/dashboard',auth,(req,res)=>{
 const announcements=db.prepare('SELECT id,title,body,created_at FROM announcements ORDER BY id DESC LIMIT 8').all();
 const assignments=db.prepare('SELECT id,title,description,grade,due_date FROM assignments WHERE grade IS NULL OR grade=? ORDER BY id DESC LIMIT 8').all(req.user.grade||0);
 const stats={students:db.prepare("SELECT COUNT(*) n FROM users WHERE role='student'").get().n,teachers:db.prepare("SELECT COUNT(*) n FROM users WHERE role='teacher'").get().n,assignments:db.prepare('SELECT COUNT(*) n FROM assignments').get().n};
 const grades=req.user.role==='student'?db.prepare('SELECT subject,score,note,created_at FROM grades WHERE student_id=? ORDER BY id DESC').all(req.user.id):[];
 res.json({announcements,assignments,stats,grades});
});
app.get('/api/users',auth,roles('admin','deputy','teacher'),(req,res)=>{
 const rows=db.prepare('SELECT id,full_name,username,role,grade,class_name,approved,created_at FROM users ORDER BY approved,role,full_name').all();res.json({users:rows});
});
app.post('/api/users',auth,roles('admin','deputy'),(req,res)=>{
 const {fullName,username,password,role,grade,className}=req.body||{};
 if(!fullName||!username||!password||password.length<8||!['student','teacher','deputy','admin'].includes(role)) return res.status(400).json({error:'اطلاعات کاربر کامل یا معتبر نیست.'});
 try{db.prepare('INSERT INTO users(full_name,username,password_hash,role,grade,class_name) VALUES(?,?,?,?,?,?)').run(fullName,username,bcrypt.hashSync(password,12),role,Number(grade)||null,className||'');res.json({ok:true});}
 catch{res.status(409).json({error:'نام کاربری تکراری است.'});}
});
app.post('/api/users/:id/approve',auth,roles('admin','deputy'),(req,res)=>{
 const result=db.prepare("UPDATE users SET approved=1 WHERE id=? AND role='student'").run(Number(req.params.id));
 if(!result.changes)return res.status(404).json({error:'درخواست دانش‌آموز پیدا نشد.'});
 res.json({ok:true});
});
app.delete('/api/users/:id',auth,roles('admin'),(req,res)=>{if(Number(req.params.id)===req.user.id)return res.status(400).json({error:'حذف حساب واردشده ممکن نیست.'});db.prepare('DELETE FROM users WHERE id=?').run(req.params.id);res.json({ok:true});});
app.post('/api/announcements',auth,roles('admin','deputy','teacher'),(req,res)=>{
 const {title,body}=req.body||{};if(!title||!body)return res.status(400).json({error:'عنوان و متن لازم است.'});
 db.prepare('INSERT INTO announcements(title,body,author_id) VALUES(?,?,?)').run(title,body,req.user.id);res.json({ok:true});
});
app.post('/api/assignments',auth,roles('admin','deputy','teacher'),(req,res)=>{
 const {title,description,grade,dueDate}=req.body||{};if(!title)return res.status(400).json({error:'عنوان تکلیف لازم است.'});
 db.prepare('INSERT INTO assignments(title,description,grade,due_date,teacher_id) VALUES(?,?,?,?,?)').run(title,description||'',Number(grade)||null,dueDate||null,req.user.id);res.json({ok:true});
});
app.post('/api/grades',auth,roles('admin','deputy','teacher'),(req,res)=>{
 const {studentId,subject,score,note}=req.body||{};if(!studentId||!subject||score===''||Number(score)<0||Number(score)>20)return res.status(400).json({error:'نمره باید بین صفر تا ۲۰ باشد.'});
 db.prepare('INSERT INTO grades(student_id,subject,score,note,teacher_id) VALUES(?,?,?,?,?)').run(Number(studentId),subject,Number(score),note||'',req.user.id);res.json({ok:true});
});
app.get('/api/attendance',auth,roles('admin','deputy','teacher'),(req,res)=>{
 const day=/^\\d{4}-\\d{2}-\\d{2}$/.test(req.query.day||'')?req.query.day:new Date().toISOString().slice(0,10);
 const students=db.prepare("SELECT id,full_name,grade,class_name FROM users WHERE role='student' AND approved=1 ORDER BY grade,class_name,full_name").all();
 const rows=db.prepare("SELECT a.student_id,a.status,u.full_name,u.class_name FROM attendance a JOIN users u ON u.id=a.student_id WHERE a.day=? ORDER BY u.grade,u.class_name,u.full_name").all(day);
 res.json({day,students,rows});
});
app.post('/api/attendance',auth,roles('admin','deputy','teacher'),(req,res)=>{
 const {studentId,day,status}=req.body||{};if(!studentId||!day||!['present','absent','late'].includes(status))return res.status(400).json({error:'اطلاعات حضور و غیاب نامعتبر است.'});
 db.prepare(`INSERT INTO attendance(student_id,day,status,teacher_id) VALUES(?,?,?,?) ON CONFLICT(student_id,day) DO UPDATE SET status=excluded.status,teacher_id=excluded.teacher_id`).run(Number(studentId),day,status,req.user.id);res.json({ok:true});
});
app.post('/api/submissions',auth,roles('student'),(req,res)=>{
 const {assignmentId,answer}=req.body||{};if(!assignmentId||!answer)return res.status(400).json({error:'پاسخ تکلیف را وارد کنید.'});
 try{db.prepare('INSERT INTO submissions(assignment_id,student_id,answer) VALUES(?,?,?)').run(Number(assignmentId),req.user.id,answer);res.json({ok:true});}
 catch{res.status(409).json({error:'برای این تکلیف قبلاً پاسخی ارسال شده است.'});}
});
app.get('/api/reports',auth,roles('admin','deputy','teacher'),(req,res)=>{
 const data=db.prepare(`SELECT u.id,u.full_name,u.grade,u.class_name,g.subject,g.score,g.created_at FROM users u LEFT JOIN grades g ON g.student_id=u.id WHERE u.role='student' ORDER BY u.full_name,g.id DESC`).all();res.json({rows:data});
});
app.post('/api/ai',auth,async(req,res)=>{
 const {message}=req.body||{};if(!message||message.length>3000)return res.status(400).json({error:'پیام خالی یا بیش از حد طولانی است.'});
 if(!process.env.AI_API_KEY)return res.json({answer:'دستیار هوشمند آماده اتصال است. مدیر سامانه باید AI_API_KEY را در فایل محیطی تنظیم کند. فعلاً می‌توانم پیشنهاد کنم سؤال درسی‌ات را کوتاه و دقیق بنویسی.'});
 try{
  const response=await fetch('https://api.openai.com/v1/chat/completions',{method:'POST',headers:{'Content-Type':'application/json','Authorization':`Bearer ${process.env.AI_API_KEY}`},body:JSON.stringify({model:process.env.AI_MODEL||'gpt-4o-mini',messages:[{role:'system',content:`تو آموزگار مهربان و دقیق دبستان ایران هستی. به فارسی ساده و متناسب پایه ${req.user.grade||'ابتدایی'} پاسخ بده. ریاضی را مرحله‌ای توضیح بده و پاسخ را بدون سرزنش آموزش بده.`},{role:'user',content:message}],temperature:0.5})});
  const data=await response.json();if(!response.ok)throw new Error(data.error?.message||'AI request failed');res.json({answer:data.choices?.[0]?.message?.content||'پاسخی دریافت نشد.'});
 }catch(e){const detail=String(e.message||'');console.error('AI request failed:',detail);if(/no credits remaining|insufficient_quota|billing|quota/i.test(detail)){return res.status(503).json({error:'اعتبار سرویس هوش مصنوعی تمام شده است. مدیر سامانه باید از پنل رسمی OpenAI اعتبار API تهیه کند؛ پس از آن دستیار دوباره فعال می‌شود.'});}if(/invalid_api_key|incorrect api key|unauthorized/i.test(detail)){return res.status(503).json({error:'کلید API معتبر نیست. مدیر سامانه باید مقدار AI_API_KEY را در تنظیمات امن سرور بررسی کند.'});}res.status(502).json({error:'ارتباط با سرویس هوش مصنوعی برقرار نشد. مدیر سامانه گزارش خطای سرور را بررسی کند.'});}
});
app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
app.listen(PORT,()=>console.log(`School Smart running at http://localhost:${PORT}`));
