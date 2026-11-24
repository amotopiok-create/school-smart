const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const { createClient } = require('@supabase/supabase-js');
const path = require('path');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
app.set('trust proxy', 1);
const supabase = process.env.SUPABASE_URL && process.env.SUPABASE_ANON_KEY
  ? createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY, { auth: { persistSession: false, autoRefreshToken: false } })
  : null;
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
async function auth(req,res,next) {
 const token = req.cookies.school_token || (req.headers.authorization||'').replace('Bearer ','');
 if (!token) return res.status(401).json({error:'برای ادامه وارد حساب شوید.'});
 try { req.user = jwt.verify(token, SECRET); return next(); } catch {}
 if (!supabase) return res.status(401).json({error:'نشست معتبر نیست.'});
 try {
  const sb=createClient(process.env.SUPABASE_URL,process.env.SUPABASE_ANON_KEY,{global:{headers:{Authorization:'Bearer '+token}},auth:{persistSession:false,autoRefreshToken:false}});
  const {data:authData,error:authError}=await sb.auth.getUser(token);
  if(authError||!authData?.user) return res.status(401).json({error:'نشست منقضی شده است. دوباره وارد شوید.'});
  const {data:rows,error:profileError}=await sb.rpc('school_current_user_status');
  const profile=Array.isArray(rows)?rows[0]:rows;
  if(profileError||!profile) return res.status(403).json({error:'پروفایل کاربری پیدا نشد.'});
  if(!profile.approved) return res.status(403).json({error:'درخواست ثبت‌نام شما هنوز توسط مدیر تأیید نشده است.'});
  req.sb=sb;req.authUser=authData.user;
  req.user={id:profile.profile_id,name:profile.full_name,role:profile.role,grade:profile.grade,phone:profile.phone,avatarUrl:profile.avatar_url,authProvider:'supabase'};
  return next();
 } catch(e){return res.status(401).json({error:'اعتبارسنجی حساب انجام نشد.'});}
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
function setSchoolSession(res,session){
 res.cookie('school_token',session.access_token,{httpOnly:true,sameSite:'lax',secure:process.env.NODE_ENV==='production',maxAge:Math.min(Number(session.expires_in||3600),3600)*1000});
}
app.post('/api/auth/register',async(req,res)=>{
 const fullName=String(req.body?.fullName||'').trim().slice(0,100),email=String(req.body?.email||'').trim().toLowerCase(),password=String(req.body?.password||''),grade=Number(req.body?.grade)||null;
 if(!fullName||!/^\S+@\S+\.\S+$/.test(email)||password.length<8||!grade||grade<1||grade>6)return res.status(400).json({error:'نام، ایمیل معتبر، رمز حداقل ۸ کاراکتری و پایه را وارد کنید.'});
 if(email===adminEmail)return res.status(403).json({error:'این ایمیل فقط برای ورود مدیر رزرو شده است.'});
 if(!supabase)return res.status(503).json({error:'سرویس حساب کاربری تنظیم نشده است.'});
 try{
  const {data,error}=await supabase.auth.signUp({email,password,options:{data:{full_name:fullName,grade}}});
  if(error)throw error;
  res.status(201).json({ok:true,needsEmailConfirmation:!data.session,message:'درخواست ثبت‌نام ثبت شد. ایمیل خود را برای تأیید بررسی کنید؛ سپس مدیر حساب را تأیید می‌کند.'});
 }catch(e){res.status(400).json({error:e.message||'ثبت‌نام انجام نشد.'});}
});
app.post('/api/auth/login',async(req,res)=>{
 const email=String(req.body?.email||'').trim().toLowerCase(),password=String(req.body?.password||'');
 if(!email||!password)return res.status(400).json({error:'ایمیل و رمز عبور لازم است.'});
 if(email===adminEmail)return res.status(403).json({error:'مدیر باید فقط با کد یک‌بارمصرف ایمیل وارد شود.'});
 if(!supabase)return res.status(503).json({error:'سرویس حساب کاربری تنظیم نشده است.'});
 try{
  const {data,error}=await supabase.auth.signInWithPassword({email,password});
  if(error)throw error;
  const sb=createClient(process.env.SUPABASE_URL,process.env.SUPABASE_ANON_KEY,{global:{headers:{Authorization:'Bearer '+data.session.access_token}},auth:{persistSession:false,autoRefreshToken:false}});
  const {data:rows,error:pe}=await sb.rpc('school_current_user_status');
  const p=Array.isArray(rows)?rows[0]:rows;
  if(pe||!p)throw new Error('پروفایل حساب پیدا نشد.');
  if(p.role!=='student')throw new Error('این مسیر فقط برای حساب دانش‌آموز است.');
  if(!p.approved)return res.status(403).json({error:'حساب شما هنوز توسط مدیر تأیید نشده است.'});
  setSchoolSession(res,data.session);
  res.json({user:{id:p.profile_id,name:p.full_name,role:p.role,grade:p.grade,phone:p.phone,avatarUrl:p.avatar_url}});
 }catch(e){res.status(401).json({error:e.message||'ورود انجام نشد.'});}
});
app.post('/api/admin/request-code',async(req,res)=>{
 const email=String(req.body?.email||'').trim().toLowerCase();
 if(email!==adminEmail)return res.status(403).json({error:'فقط ایمیل مجاز مدیر پذیرفته می‌شود.'});
 if(!supabase)return res.status(503).json({error:'سرویس احراز هویت تنظیم نشده است.'});
 try{
  const {error}=await supabase.auth.signInWithOtp({email,options:{shouldCreateUser:false}});
  if(error)throw error;
  res.json({ok:true,message:'کد یک‌بارمصرف به ایمیل مدیر ارسال شد.'});
 }catch(e){res.status(502).json({error:e.message||'ارسال کد انجام نشد.'});}
});
app.post('/api/admin/verify-code',async(req,res)=>{
 const email=String(req.body?.email||'').trim().toLowerCase(),code=String(req.body?.code||'').trim();
 if(email!==adminEmail)return res.status(403).json({error:'ایمیل مدیر مجاز نیست.'});
 if(!/^\d{6}$/.test(code))return res.status(400).json({error:'کد باید ۶ رقم باشد.'});
 try{
  const {data,error}=await supabase.auth.verifyOtp({email,token:code,type:'email'});
  if(error)throw error;
  const sb=createClient(process.env.SUPABASE_URL,process.env.SUPABASE_ANON_KEY,{global:{headers:{Authorization:'Bearer '+data.session.access_token}},auth:{persistSession:false,autoRefreshToken:false}});
  const {data:rows,error:pe}=await sb.rpc('school_current_user_status');
  const p=Array.isArray(rows)?rows[0]:rows;
  if(pe||!p||p.role!=='admin'||data.user.email?.toLowerCase()!==adminEmail) return res.status(403).json({error:'این حساب، حساب مدیر مجاز مدرسه نیست.'});
  setSchoolSession(res,data.session);
  res.json({user:{id:p.profile_id,name:p.full_name,role:p.role,grade:p.grade,phone:p.phone,avatarUrl:p.avatar_url}});
 }catch(e){res.status(401).json({error:e.message||'کد ورود معتبر نیست.'});}
});

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
 const day=/^\d{4}-\\d{2}-\\d{2}$/.test(req.query.day||'')?req.query.day:new Date().toISOString().slice(0,10);
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
app.get('/api/platform/health', async (req,res) => {
  if (!supabase) return res.status(503).json({ ok:false, database:'not_configured' });
  try {
    const { error } = await supabase.from('school_settings').select('*').limit(1);
    if (error) throw error;
    res.set('Cache-Control','no-store');
    res.json({ ok:true, database:'connected', storage:'supabase-postgres', checkedAt:new Date().toISOString() });
  } catch (error) {
    console.error('Supabase health check failed:', error.message);
    res.status(503).json({ ok:false, database:'unavailable' });
  }
});

// Persistent student portal features backed by Supabase Auth + RLS-protected Postgres.
app.get('/api/portal/profile',auth,async(req,res)=>{
 if(!req.sb)return res.json({profile:{id:req.user.id,full_name:req.user.name,role:req.user.role,grade:req.user.grade,avatar_url:null,phone:null}});
 const {data,error}=await req.sb.from('profiles').select('id,full_name,role,phone,grade,avatar_url').eq('id',req.user.id).single();
 if(error)return res.status(400).json({error:error.message});
 res.json({profile:data});
});
app.patch('/api/portal/profile',auth,async(req,res)=>{
 if(!req.sb)return res.status(400).json({error:'این قابلیت برای حساب‌های قدیمی فعال نیست.'});
 const full_name=String(req.body?.fullName||'').trim().slice(0,100),phone=String(req.body?.phone||'').trim().slice(0,30);
 if(!full_name)return res.status(400).json({error:'نام نمایشی لازم است.'});
 const {data,error}=await req.sb.from('profiles').update({full_name,phone:phone||null,updated_at:new Date().toISOString()}).eq('id',req.user.id).select('id,full_name,role,phone,grade,avatar_url').single();
 if(error)return res.status(400).json({error:error.message});
 res.json({profile:data});
});
app.post('/api/portal/avatar',auth,async(req,res)=>{
 if(!req.sb)return res.status(400).json({error:'این قابلیت برای حساب‌های قدیمی فعال نیست.'});
 const raw=String(req.body?.data||''),match=raw.match(/^data:(image\/(?:jpeg|png|webp));base64,([A-Za-z0-9+/=]+)$/);
 if(!match)return res.status(400).json({error:'فقط تصویر JPG، PNG یا WEBP پذیرفته می‌شود.'});
 const buffer=Buffer.from(match[2],'base64');
 if(buffer.length>2*1024*1024)return res.status(413).json({error:'حجم عکس باید کمتر از ۲ مگابایت باشد.'});
 const ext=match[1].split('/')[1].replace('jpeg','jpg'),path=req.user.id+'/avatar.'+ext;
 const {error:uploadError}=await req.sb.storage.from('school-avatars').upload(path,buffer,{contentType:match[1],upsert:true});
 if(uploadError)return res.status(400).json({error:uploadError.message});
 const {data}=req.sb.storage.from('school-avatars').getPublicUrl(path);
 const {error:updateError}=await req.sb.from('profiles').update({avatar_url:data.publicUrl}).eq('id',req.user.id);
 if(updateError)return res.status(400).json({error:updateError.message});
 res.json({avatarUrl:data.publicUrl});
});
app.get('/api/portal/messages',auth,async(req,res)=>{
 if(!req.sb)return res.json({messages:[]});
 const {data,error}=await req.sb.from('messages').select('id,sender_id,recipient_id,subject,body,read_at,created_at,sender:profiles!messages_sender_id_fkey(full_name,avatar_url),recipient:profiles!messages_recipient_id_fkey(full_name,avatar_url)').or('sender_id.eq.'+req.user.id+',recipient_id.eq.'+req.user.id).order('created_at',{ascending:false}).limit(100);
 if(error)return res.status(400).json({error:error.message});
 res.json({messages:data||[]});
});
app.post('/api/portal/messages',auth,async(req,res)=>{
 if(!req.sb)return res.status(400).json({error:'پیام‌رسان برای این حساب فعال نیست.'});
 const recipientId=String(req.body?.recipientId||''),body=String(req.body?.body||'').trim().slice(0,4000),subject=String(req.body?.subject||'').trim().slice(0,120);
 if(!recipientId||!body)return res.status(400).json({error:'گیرنده و متن پیام لازم است.'});
 const {data,error}=await req.sb.from('messages').insert({sender_id:req.user.id,recipient_id:recipientId,subject:subject||null,body}).select('id').single();
 if(error)return res.status(400).json({error:error.message});
 await req.sb.from('notifications').insert({recipient_id:recipientId,title:'پیام جدید',body:'یک پیام جدید در پیام‌رسان مدرسه دریافت کردید.',category:'message'});
 res.json({ok:true,id:data.id});
});
app.get('/api/portal/contacts',auth,async(req,res)=>{
 if(!req.sb)return res.json({contacts:[]});
 const {data,error}=await req.sb.rpc('school_directory');
 if(error)return res.status(400).json({error:error.message});
 res.json({contacts:data||[]});
});
app.get('/api/portal/notifications',auth,async(req,res)=>{
 if(!req.sb)return res.json({notifications:[]});
 const {data,error}=await req.sb.from('notifications').select('id,recipient_id,title,body,category,target_url,read_at,created_at').or('recipient_id.eq.'+req.user.id+',recipient_id.is.null').order('created_at',{ascending:false}).limit(100);
 if(error)return res.status(400).json({error:error.message});
 res.json({notifications:data||[]});
});
app.post('/api/portal/notifications',auth,roles('admin'),async(req,res)=>{
 if(!req.sb)return res.status(400).json({error:'پایگاه داده پایدار در دسترس نیست.'});
 const title=String(req.body?.title||'').trim().slice(0,120),body=String(req.body?.body||'').trim().slice(0,2000);
 if(!title||!body)return res.status(400).json({error:'عنوان و متن خبر لازم است.'});
 const {error}=await req.sb.from('notifications').insert({recipient_id:null,title,body,category:'announcement'});
 if(error)return res.status(400).json({error:error.message});
 res.json({ok:true});
});
app.post('/api/portal/notifications/:id/read',auth,async(req,res)=>{
 if(!req.sb)return res.status(400).json({error:'پایگاه داده در دسترس نیست.'});
 const {error}=await req.sb.from('notifications').update({read_at:new Date().toISOString()}).eq('id',req.params.id).eq('recipient_id',req.user.id);
 if(error)return res.status(400).json({error:error.message});
 res.json({ok:true});
});
app.get('/api/portal/council',auth,async(req,res)=>{
 if(!req.sb)return res.json({members:[],students:[]});
 const {data,error}=await req.sb.rpc('school_council_list');
 if(error)return res.status(400).json({error:error.message});
 let students=[];
 if(req.user.role==='admin'){
  const result=await req.sb.from('profiles').select('id,full_name,grade').eq('role','student').order('full_name');
  students=result.data||[];
 }
 res.json({members:data||[],students});
});
app.post('/api/portal/council',auth,roles('admin'),async(req,res)=>{
 if(!req.sb)return res.status(400).json({error:'پایگاه داده در دسترس نیست.'});
 const userId=String(req.body?.userId||''),position=String(req.body?.position||'عضو شورا').trim().slice(0,80);
 if(!userId)return res.status(400).json({error:'دانش‌آموز را انتخاب کنید.'});
 const {data:student,error:studentError}=await req.sb.from('profiles').select('id,grade,role').eq('id',userId).single();
 if(studentError||!student||student.role!=='student')return res.status(400).json({error:'فقط دانش‌آموزان می‌توانند عضو شورا شوند.'});
 await req.sb.from('council_members').delete().eq('user_id',userId);
 const {error}=await req.sb.from('council_members').insert({user_id:userId,position,grade:student.grade,active:true});
 if(error)return res.status(400).json({error:error.message});
 res.json({ok:true});
});
app.delete('/api/portal/council/:id',auth,roles('admin'),async(req,res)=>{
 const {error}=await req.sb.from('council_members').delete().eq('id',req.params.id);
 if(error)return res.status(400).json({error:error.message});
 res.json({ok:true});
});
app.get('/api/portal/registrations',auth,roles('admin'),async(req,res)=>{
 const {data,error}=await req.sb.from('registration_requests').select('id,full_name,email,phone,requested_role,grade,note,status,created_at').order('created_at',{ascending:false});
 if(error)return res.status(400).json({error:error.message});
 res.json({requests:data||[]});
});
app.post('/api/portal/registrations/:id/:status',auth,roles('admin'),async(req,res)=>{
 const status=req.params.status;
 if(!['approved','rejected'].includes(status))return res.status(400).json({error:'وضعیت نامعتبر است.'});
 const {error}=await req.sb.rpc('school_admin_set_registration',{p_request_id:req.params.id,p_status:status});
 if(error)return res.status(400).json({error:error.message});
 res.json({ok:true});
});

app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
app.listen(PORT,()=>console.log(`School Smart running at http://localhost:${PORT}`));
