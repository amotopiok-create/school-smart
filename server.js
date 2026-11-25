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
// A server-only service-role client is used only after the private admin JWT is verified.
// Never expose this key to browser code or return it from an API route.
const supabaseAdmin = process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY
  ? createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false, autoRefreshToken: false } })
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
// No demo or hard-coded user accounts are created on deployment.

async function auth(req,res,next) {
 const token = req.cookies.school_token || (req.headers.authorization||'').replace('Bearer ','');
 if (!token) return res.status(401).json({error:'برای ادامه وارد حساب شوید.'});
 try {
  req.user = jwt.verify(token, SECRET);
  // Admin routes can use persistent Supabase storage when the server-side key is configured.
  if (req.user.role === 'admin' && supabaseAdmin) req.sb = supabaseAdmin;
  return next();
 } catch {}
 if (!supabase) return res.status(401).json({error:'نشست معتبر نیست.'});
 try {
  const sb=createClient(process.env.SUPABASE_URL,process.env.SUPABASE_ANON_KEY,{global:{headers:{Authorization:'Bearer '+token}},auth:{persistSession:false,autoRefreshToken:false}});
  const {data:authData,error:authError}=await sb.auth.getUser(token);
  if(authError||!authData?.user) return res.status(401).json({error:'نشست منقضی شده است. دوباره وارد شوید.'});
  const {data:rows,error:profileError}=await sb.rpc('school_current_user_status');
  const profile=Array.isArray(rows)?rows[0]:rows;
  if(profileError||!profile) return res.status(403).json({error:'پروفایل کاربری پیدا نشد.'});
  if(!profile.approved) return res.status(403).json({error:'درخواست ثبت‌نام شما هنوز توسط مدیر تأیید نشده است.'});
  req.sb=sb;req.authUser=authData.user;req.authToken=token;
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

const adminMagicAttempts = new Map();
app.post('/api/admin/magic-link',async(req,res)=>{
 const origin=req.get('origin');
 if(origin&&origin!=='https://school-smart-preview.vercel.app')return res.status(403).json({error:'درخواست ورود از مبدأ نامعتبر است.'});
 if(!supabase)return res.status(503).json({error:'سرویس ورود امن مدیر در دسترس نیست.'});
 const ip=String(req.ip||'unknown'),now=Date.now(),prior=adminMagicAttempts.get(ip);
 if(prior&&now-prior.startedAt<15*60*1000&&prior.count>=3)return res.status(429).json({error:'درخواست‌های ورود زیاد است. ۱۵ دقیقه دیگر تلاش کنید.'});
 try{
  const {error}=await supabase.auth.signInWithOtp({email:adminEmail,options:{shouldCreateUser:false,emailRedirectTo:'https://school-smart-preview.vercel.app/owner'}});
  if(error)throw error;
  if(!prior||now-prior.startedAt>=15*60*1000)adminMagicAttempts.set(ip,{startedAt:now,count:1});
  else adminMagicAttempts.set(ip,{...prior,count:prior.count+1});
  res.set('Cache-Control','no-store');
  res.json({ok:true,message:'لینک ورود مدیر به ایمیل ثبت‌شده ارسال شد. صندوق ورودی و پوشه هرزنامه را بررسی کنید.'});
 }catch(e){res.status(400).json({error:e.message||'ارسال لینک ورود انجام نشد.'});}
});
app.post('/api/auth/session',async(req,res)=>{
 const token=String(req.body?.accessToken||'').trim();
 if(!token||token.length>5000)return res.status(400).json({error:'نشست ورود معتبر نیست.'});
 try{
  const sb=createClient(process.env.SUPABASE_URL,process.env.SUPABASE_ANON_KEY,{global:{headers:{Authorization:'Bearer '+token}},auth:{persistSession:false,autoRefreshToken:false}});
  const {data:authData,error:authError}=await sb.auth.getUser(token);
  const user=authData?.user;
  if(authError||!user||String(user.email||'').toLowerCase()!==adminEmail||user.app_metadata?.role!=='admin')return res.status(403).json({error:'این لینک برای حساب مدیر معتبر نیست.'});
  const {data:rows,error}=await sb.rpc('school_current_user_status');
  const profile=Array.isArray(rows)?rows[0]:rows;
  if(error||!profile||profile.role!=='admin')return res.status(403).json({error:'دسترسی مدیر تأیید نشد.'});
  setSchoolSession(res,{access_token:token,expires_in:3600});
  res.set('Cache-Control','no-store');
  return res.json({user:{id:profile.profile_id,name:profile.full_name,role:profile.role,grade:profile.grade,phone:profile.phone,avatarUrl:profile.avatar_url}});
 }catch(e){return res.status(401).json({error:'اعتبارسنجی لینک ورود انجام نشد.'});}
});
app.post('/api/auth/register',async(req,res)=>{
 const fullName=String(req.body?.fullName||'').trim().slice(0,100),email=String(req.body?.email||'').trim().toLowerCase(),password=String(req.body?.password||''),grade=Number(req.body?.grade)||null,className=String(req.body?.className||'').trim().slice(0,80);
 if(!fullName||!/^\S+@\S+\.\S+$/.test(email)||password.length<8||!grade||grade<1||grade>6)return res.status(400).json({error:'نام، ایمیل معتبر، رمز حداقل ۸ کاراکتری و پایه را وارد کنید.'});
 if(email===adminEmail)return res.status(403).json({error:'این ایمیل فقط برای ورود مدیر رزرو شده است.'});
 if(!supabase)return res.status(503).json({error:'سرویس حساب کاربری تنظیم نشده است.'});
 try{
  const {data,error}=await supabase.auth.signUp({email,password,options:{data:{full_name:fullName,grade,class_name:className||null}}});
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
  if(p.role==='admin')throw new Error('مدیر باید فقط با کد یک‌بارمصرف ایمیل وارد شود.');
  if(!p.approved)return res.status(403).json({error:'حساب شما هنوز توسط مدیر تأیید نشده است.'});
  setSchoolSession(res,data.session);
  res.json({user:{id:p.profile_id,name:p.full_name,role:p.role,grade:p.grade,phone:p.phone,avatarUrl:p.avatar_url}});
 }catch(e){res.status(401).json({error:e.message||'ورود انجام نشد.'});}
});
const adminLoginAttempts = new Map();
app.post('/api/admin/login',(req,res)=>{
 const password=String(req.body?.password||'');
 const ip=String(req.ip||'unknown');
 const now=Date.now();
 const attempt=adminLoginAttempts.get(ip);
 if(attempt && now-attempt.startedAt<15*60*1000 && attempt.count>=6)
  return res.status(429).json({error:'تعداد تلاش‌ها زیاد است. ۱۵ دقیقه دیگر دوباره امتحان کنید.'});
 const expected=process.env.SCHOOL_ADMIN_PASSWORD;
 if(!expected || !process.env.JWT_SECRET)
  return res.status(503).json({error:'ورود مدیر هنوز به‌صورت امن پیکربندی نشده است.'});
 const supplied=Buffer.from(password,'utf8'), stored=Buffer.from(expected,'utf8');
 const valid=supplied.length===stored.length && crypto.timingSafeEqual(supplied,stored);
 if(!valid){
  if(!attempt || now-attempt.startedAt>=15*60*1000) adminLoginAttempts.set(ip,{startedAt:now,count:1});
  else adminLoginAttempts.set(ip,{...attempt,count:attempt.count+1});
  return res.status(401).json({error:'رمز عبور نادرست است.'});
 }
 adminLoginAttempts.delete(ip);
 const token=jwt.sign({id:'owner',name:'مدیر سامانه',role:'admin'},SECRET,{expiresIn:'4h'});
 res.cookie('school_token',token,{httpOnly:true,sameSite:'strict',secure:process.env.NODE_ENV==='production',maxAge:4*60*60*1000,path:'/'});
 res.set('Cache-Control','no-store');
 return res.json({user:{id:'owner',name:'مدیر سامانه',role:'admin'}});
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
app.get('/api/dashboard',auth,async(req,res)=>{
 if(req.sb){
  const students=await req.sb.from('profiles').select('id',{count:'exact',head:true}).eq('role','student');
  const teachers=await req.sb.from('profiles').select('id',{count:'exact',head:true}).in('role',['teacher','deputy']);
  const assignmentCount=await req.sb.from('assignments').select('id',{count:'exact',head:true});
  const announcements=await req.sb.from('notices').select('id,title,body,created_at').eq('published',true).order('created_at',{ascending:false}).limit(8);
  const assignments=await req.sb.from('assignments').select('id,title,description,due_at,classes(grade)').order('created_at',{ascending:false}).limit(8);
  const grades=req.user.role==='student'?await req.sb.from('grades').select('title,score,note,created_at').eq('student_id',req.user.id).order('created_at',{ascending:false}).limit(20):{data:[],error:null};
  if(students.error||teachers.error||assignmentCount.error||announcements.error||assignments.error||grades.error)return res.status(503).json({error:'دریافت اطلاعات داشبورد انجام نشد.'});
  return res.json({announcements:announcements.data||[],assignments:(assignments.data||[]).map(a=>({...a,due_date:a.due_at,grade:a.classes?.grade||null})),stats:{students:students.count||0,teachers:teachers.count||0,assignments:assignmentCount.count||0},grades:(grades.data||[]).map(g=>({...g,subject:g.title}))});
 }
 const announcements=db.prepare('SELECT id,title,body,created_at FROM announcements ORDER BY id DESC LIMIT 8').all();
 const assignments=db.prepare('SELECT id,title,description,grade,due_date FROM assignments WHERE grade IS NULL OR grade=? ORDER BY id DESC LIMIT 8').all(req.user.grade||0);
 const stats={students:db.prepare('SELECT COUNT(*) n FROM users WHERE role=?').get('student').n,teachers:db.prepare('SELECT COUNT(*) n FROM users WHERE role=?').get('teacher').n,assignments:db.prepare('SELECT COUNT(*) n FROM assignments').get().n};
 const grades=req.user.role==='student'?db.prepare('SELECT subject,score,note,created_at FROM grades WHERE student_id=? ORDER BY id DESC').all(req.user.id):[];
 res.json({announcements,assignments,stats,grades});
});

async function callSchoolAdmin(req,payload){
 if(!req.authToken||!process.env.SUPABASE_URL||!process.env.SUPABASE_ANON_KEY)throw new Error('نشست امن مدیر در دسترس نیست.');
 const response=await fetch(process.env.SUPABASE_URL+'/functions/v1/school-admin',{
  method:'POST',
  headers:{'Content-Type':'application/json','apikey':process.env.SUPABASE_ANON_KEY,'Authorization':'Bearer '+req.authToken},
  body:JSON.stringify(payload)
 });
 const data=await response.json().catch(()=>({}));
 if(!response.ok)throw new Error(data.error||'عملیات مدیریت انجام نشد.');
 return data;
}
app.get('/api/admin/registration-requests',auth,roles('admin'),async(req,res)=>{
 try{const data=await callSchoolAdmin(req,{action:'list_registration_requests'});res.set('Cache-Control','no-store');res.json({requests:data.requests||[]});}
 catch(e){res.status(503).json({error:e.message||'درخواست‌ها دریافت نشد.'});}
});
app.post('/api/admin/registration-requests/:id/reject',auth,roles('admin'),async(req,res)=>{
 try{await callSchoolAdmin(req,{action:'reject_request',request_id:req.params.id});res.json({ok:true});}
 catch(e){res.status(400).json({error:e.message||'رد درخواست انجام نشد.'});}
});
app.get('/api/users',auth,roles('admin','deputy','teacher'),async(req,res)=>{
 try{
  if(req.user.role==='admin'||req.user.role==='deputy'){
   const data=await callSchoolAdmin(req,{action:'list_users'});
   return res.json({users:data.users||[]});
  }
  const {data,error}=await req.sb.from('profiles').select('id,full_name,role,grade,phone,classes(name),created_at').order('full_name');
  if(error)throw error;
  return res.json({users:(data||[]).map(p=>({id:p.id,full_name:p.full_name,username:p.phone||'',role:p.role,grade:p.grade,class_name:p.classes?.name||'',approved:true,created_at:p.created_at}))});
 }catch(e){res.status(503).json({error:e.message||'فهرست کاربران دریافت نشد.'});}
});
app.post('/api/users',auth,roles('admin','deputy'),async(req,res)=>{
 const {fullName,username,password,role,grade,className}=req.body||{};
 if(!fullName||!username||!password||password.length<8||!['student','teacher','deputy'].includes(role))return res.status(400).json({error:'اطلاعات کاربر کامل یا معتبر نیست.'});
 try{
  const data=await callSchoolAdmin(req,{action:'create_user',full_name:fullName,email:username,password,role,grade,class_name:className});
  res.json({ok:true,id:data.id});
 }catch(e){res.status(400).json({error:e.message});}
});
app.post('/api/users/:id/approve',auth,roles('admin','deputy'),async(req,res)=>{
 try{await callSchoolAdmin(req,{action:'approve_request',request_id:req.params.id});res.json({ok:true});}
 catch(e){res.status(400).json({error:e.message});}
});
app.delete('/api/users/:id',auth,roles('admin'),async(req,res)=>{
 try{await callSchoolAdmin(req,{action:'delete_user',user_id:req.params.id});res.json({ok:true});}
 catch(e){res.status(400).json({error:e.message});}
});
app.post('/api/announcements',auth,roles('admin','deputy','teacher'),async(req,res)=>{
 const {title,body}=req.body||{};
 if(!title||!body)return res.status(400).json({error:'عنوان و متن لازم است.'});
 if(!req.sb)return res.status(503).json({error:'پایگاه داده پایدار در دسترس نیست.'});
 const {error}=await req.sb.from('notices').insert({title:String(title).slice(0,120),body:String(body).slice(0,3000),author_id:req.user.id,published:true});
 if(error)return res.status(400).json({error:'انتشار اطلاعیه انجام نشد.'});
 return res.json({ok:true});
});
app.get('/api/public/announcements',async(req,res)=>{
 res.set('Cache-Control','public, max-age=60, stale-while-revalidate=300');
 if(supabase){
  const {data,error}=await supabase.from('notices').select('id,title,body,created_at').eq('published',true).order('created_at',{ascending:false}).limit(10);
  if(error)return res.status(503).json({error:'اطلاعیه‌ها فعلاً در دسترس نیستند.'});
  return res.json({announcements:data||[]});
 }
 return res.json({announcements:[]});
});
app.post('/api/assignments',auth,roles('admin','deputy','teacher'),async(req,res)=>{
 const {title,description,grade,dueDate}=req.body||{};
 if(!title)return res.status(400).json({error:'عنوان تکلیف لازم است.'});
 if(!req.sb)return res.status(503).json({error:'پایگاه داده پایدار در دسترس نیست.'});
 let classIds=[null];
 if(Number(grade)){
  const {data:classes,error:classError}=await req.sb.from('classes').select('id').eq('grade',Number(grade)).order('name');
  if(classError)return res.status(400).json({error:'کلاس پایه انتخاب‌شده پیدا نشد.'});
  if(!classes?.length)return res.status(400).json({error:'ابتدا کلاس این پایه را در سامانه تعریف کنید.'});
  classIds=classes.map(c=>c.id);
 }
 const dueAt=dueDate?String(dueDate)+'T23:59:59.000Z':null;
 const rows=classIds.map(classId=>({title:String(title).slice(0,160),description:String(description||'').slice(0,5000),class_id:classId,teacher_id:req.user.id,due_at:dueAt}));
 const {error}=await req.sb.from('assignments').insert(rows);
 if(error)return res.status(400).json({error:'ثبت تکلیف انجام نشد.'});
 res.json({ok:true,created:rows.length});
});
app.post('/api/grades',auth,roles('admin','deputy','teacher'),async(req,res)=>{
 const {studentId,subject,score,note}=req.body||{};
 if(!studentId||!subject||score===''||Number(score)<0||Number(score)>20)return res.status(400).json({error:'نمره باید بین صفر تا ۲۰ باشد.'});
 if(!req.sb)return res.status(503).json({error:'پایگاه داده پایدار در دسترس نیست.'});
 const {data:student,error:studentError}=await req.sb.from('profiles').select('id,role,grade').eq('id',studentId).single();
 if(studentError||!student||student.role!=='student')return res.status(400).json({error:'دانش‌آموز انتخاب‌شده معتبر نیست.'});
 const {data:subjectRow}=await req.sb.from('subjects').select('id').eq('name',String(subject).trim()).or('grade.is.null,grade.eq.'+Number(student.grade||0)).limit(1).maybeSingle();
 const {error}=await req.sb.from('grades').insert({student_id:studentId,subject_id:subjectRow?.id||null,title:String(subject).trim().slice(0,100),score:Number(score),note:String(note||'').slice(0,1000),teacher_id:req.user.id});
 if(error)return res.status(400).json({error:'ذخیره نمره انجام نشد.'});
 res.json({ok:true});
});
app.get('/api/attendance',auth,roles('admin','deputy','teacher'),async(req,res)=>{
 const day=/^\d{4}-\d{2}-\d{2}$/.test(req.query.day||'')?req.query.day:new Date().toISOString().slice(0,10);
 if(!req.sb)return res.status(503).json({error:'پایگاه داده پایدار در دسترس نیست.'});
 const [studentsResult,rowsResult]=await Promise.all([
  req.sb.from('profiles').select('id,full_name,grade,classes(name)').eq('role','student').order('grade').order('full_name'),
  req.sb.from('attendance').select('student_id,status,profiles!attendance_student_id_fkey(full_name,classes(name))').eq('attendance_date',day)
 ]);
 if(studentsResult.error||rowsResult.error)return res.status(503).json({error:'دریافت اطلاعات حضور و غیاب انجام نشد.'});
 const students=(studentsResult.data||[]).map(p=>({id:p.id,full_name:p.full_name,grade:p.grade,class_name:p.classes?.name||''}));
 const rows=(rowsResult.data||[]).map(r=>({student_id:r.student_id,status:r.status,full_name:r.profiles?.full_name||'',class_name:r.profiles?.classes?.name||''}));
 res.json({day,students,rows});
});
app.post('/api/attendance',auth,roles('admin','deputy','teacher'),async(req,res)=>{
 const {studentId,day,status}=req.body||{};
 if(!studentId||!day||!/^\d{4}-\d{2}-\d{2}$/.test(String(day))||!['present','absent','late'].includes(status))return res.status(400).json({error:'اطلاعات حضور و غیاب نامعتبر است.'});
 if(!req.sb)return res.status(503).json({error:'پایگاه داده پایدار در دسترس نیست.'});
 const {data:student,error:studentError}=await req.sb.from('profiles').select('id,class_id,role').eq('id',studentId).single();
 if(studentError||!student||student.role!=='student')return res.status(400).json({error:'دانش‌آموز انتخاب‌شده معتبر نیست.'});
 const {error}=await req.sb.from('attendance').upsert({student_id:studentId,class_id:student.class_id,attendance_date:day,status,recorded_by:req.user.id},{onConflict:'student_id,attendance_date'});
 if(error)return res.status(400).json({error:'ثبت حضور و غیاب انجام نشد.'});
 res.json({ok:true});
});
app.post('/api/submissions',auth,roles('student'),async(req,res)=>{
 const {assignmentId,answer}=req.body||{};
 if(!assignmentId||!answer)return res.status(400).json({error:'پاسخ تکلیف را وارد کنید.'});
 if(!req.sb)return res.status(503).json({error:'پایگاه داده پایدار در دسترس نیست.'});
 const {error}=await req.sb.from('assignment_submissions').insert({assignment_id:assignmentId,student_id:req.user.id,answer:String(answer).slice(0,10000)});
 if(error)return res.status(error.code==='23505'?409:400).json({error:error.code==='23505'?'برای این تکلیف قبلاً پاسخی ارسال شده است.':'ارسال پاسخ تکلیف انجام نشد.'});
 res.json({ok:true});
});
app.get('/api/reports',auth,roles('admin','deputy','teacher'),async(req,res)=>{
 if(!req.sb)return res.status(503).json({error:'پایگاه داده پایدار در دسترس نیست.'});
 const {data,error}=await req.sb.from('grades').select('student_id,title,score,created_at,student:profiles!grades_student_id_fkey(full_name,grade,classes(name))').order('created_at',{ascending:false}).limit(2000);
 if(error)return res.status(503).json({error:'گزارش نمرات دریافت نشد.'});
 const rows=(data||[]).map(g=>({id:g.student_id,full_name:g.student?.full_name||'',grade:g.student?.grade||null,class_name:g.student?.classes?.name||'',subject:g.title,score:g.score,created_at:g.created_at}));
 res.json({rows});
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
 if(data.avatar_url){const signed=await req.sb.storage.from('school-avatars').createSignedUrl(data.avatar_url,3600);data.avatar_url=signed.data?.signedUrl||null;}
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
 const {error:updateError}=await req.sb.from('profiles').update({avatar_url:path}).eq('id',req.user.id);
 if(updateError)return res.status(400).json({error:updateError.message});
 const signed=await req.sb.storage.from('school-avatars').createSignedUrl(path,3600);
 res.json({avatarUrl:signed.data?.signedUrl||null});
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
app.post('/api/portal/registrations/:id/:status',auth,roles('admin','deputy'),async(req,res)=>{
 const status=req.params.status;
 if(!['approved','rejected'].includes(status))return res.status(400).json({error:'وضعیت نامعتبر است.'});
 try{await callSchoolAdmin(req,{action:status==='approved'?'approve_request':'reject_request',request_id:req.params.id});res.json({ok:true});}
 catch(e){res.status(400).json({error:e.message});}
});

app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
app.listen(PORT,()=>console.log(`School Smart running at http://localhost:${PORT}`));
