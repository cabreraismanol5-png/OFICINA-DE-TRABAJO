const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto'),Database=require('better-sqlite3');

const PORT=Number.parseInt(process.env.PORT||'10000',10);
const HOST=process.env.HOST||'0.0.0.0';
const PROD=process.env.NODE_ENV==='production';
if(!Number.isInteger(PORT)||PORT<1||PORT>65535) throw new Error('PORT inválido: '+process.env.PORT);
const DATA=path.join(__dirname,'data');fs.mkdirSync(DATA,{recursive:true});
const db=new Database(path.join(DATA,'oficina.sqlite'));
db.pragma('journal_mode = WAL');db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users(
 id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, vendor_hash TEXT NOT NULL,
 email TEXT UNIQUE NOT NULL, phone TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
 created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, last_seen INTEGER, failed_logins INTEGER DEFAULT 0, locked_until INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS user_sessions(
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 csrf TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, last_seen INTEGER NOT NULL, ip TEXT, user_agent TEXT
);
CREATE TABLE IF NOT EXISTS admin_users(
 id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
 email TEXT UNIQUE, active INTEGER NOT NULL DEFAULT 1, is_primary INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL,
 updated_at INTEGER NOT NULL, last_login INTEGER
);
CREATE TABLE IF NOT EXISTS admin_sessions(
 id TEXT PRIMARY KEY, admin_id TEXT NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
 csrf TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, ip TEXT, user_agent TEXT
);
CREATE TABLE IF NOT EXISTS otps(
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 code_hash TEXT NOT NULL, purpose TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, used_at INTEGER
);
CREATE TABLE IF NOT EXISTS audit(
 id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT NOT NULL, action TEXT NOT NULL, user_id TEXT,
 meta TEXT, created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON user_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit(created_at);
CREATE INDEX IF NOT EXISTS idx_admin_users_active ON admin_users(active);
`);

// v3 -> v4 migration: administrator sessions changed from a single shared key
// to named administrator accounts. Existing admin sessions are ephemeral, so
// safely discard them when upgrading.
const adminSessionCols=db.prepare("PRAGMA table_info(admin_sessions)").all().map(x=>x.name);
if(!adminSessionCols.includes('admin_id')){
 db.exec('DROP TABLE IF EXISTS admin_sessions');
 db.exec(`CREATE TABLE admin_sessions(
   id TEXT PRIMARY KEY, admin_id TEXT NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
   csrf TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, ip TEXT, user_agent TEXT
 )`);
}
const adminUserCols=db.prepare("PRAGMA table_info(admin_users)").all().map(x=>x.name);
if(!adminUserCols.includes('is_primary')) db.exec("ALTER TABLE admin_users ADD COLUMN is_primary INTEGER NOT NULL DEFAULT 0");


const clean=x=>String(x??'').trim(), now=()=>Date.now();
const tok=()=>crypto.randomBytes(32).toString('hex'), six=()=>String(crypto.randomInt(0,1000000)).padStart(6,'0');
const hash=x=>crypto.scryptSync(String(x),process.env.PASSWORD_PEPPER||'CHANGE_ME_LONG_RANDOM',32).toString('hex');
const safe=(a,b)=>{if(!a||!b)return false;const A=Buffer.from(String(a)),B=Buffer.from(String(b));return A.length===B.length&&crypto.timingSafeEqual(A,B)};
const emailOk=x=>/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(x);
const ip=req=>(req.headers['x-forwarded-for']||req.socket.remoteAddress||'').split(',')[0].trim();
const ua=req=>String(req.headers['user-agent']||'').slice(0,300);
const parseCookies=req=>Object.fromEntries((req.headers.cookie||'').split(';').filter(Boolean).map(x=>{const i=x.indexOf('=');return [x.slice(0,i).trim(),decodeURIComponent(x.slice(i+1))]}));
const setCookie=(name,value,maxAge)=>`${name}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${PROD?'; Secure':''}`;
function send(res,status,body,type='application/json',headers={}){res.writeHead(status,{'Content-Type':type,'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'same-origin',...headers});res.end(type==='application/json'?JSON.stringify(body):body)}
const json=(r,o,s=200,h={})=>send(r,s,o,'application/json',h);
function body(req){return new Promise((resolve,reject)=>{let b='';req.on('data',c=>{b+=c;if(b.length>1e6)req.destroy()});req.on('end',()=>{try{resolve(b?JSON.parse(b):{})}catch(e){reject(e)}})})}
function audit(actor,action,userId=null,meta={}){db.prepare('INSERT INTO audit(actor,action,user_id,meta,created_at) VALUES(?,?,?,?,?)').run(actor,action,userId,JSON.stringify(meta),now())}
function cleanup(){const t=now();db.prepare('DELETE FROM user_sessions WHERE expires_at<?').run(t);db.prepare('DELETE FROM admin_sessions WHERE expires_at<?').run(t);db.prepare('DELETE FROM otps WHERE expires_at<? AND used_at IS NOT NULL').run(t)}
setInterval(cleanup,60000).unref();

const buckets=new Map();
function rate(req,key,max,windowMs){const k=key+':'+ip(req),t=now(),a=buckets.get(k)||[];const fresh=a.filter(x=>x>t-windowMs);if(fresh.length>=max){buckets.set(k,fresh);return false}fresh.push(t);buckets.set(k,fresh);return true}

async function mail(to,subject,text){
 const key=process.env.RESEND_API_KEY,from=process.env.EMAIL_FROM;
 if(!key||!from)throw Error('Correo no configurado');
 const r=await fetch('https://api.resend.com/emails',{method:'POST',headers:{Authorization:`Bearer ${key}`,'Content-Type':'application/json'},body:JSON.stringify({from,to,subject,text})});
 if(!r.ok)throw Error(await r.text());
}
function userSession(req){const c=parseCookies(req),s=db.prepare('SELECT * FROM user_sessions WHERE id=? AND expires_at>?').get(c.session,now());if(!s)return null;const u=db.prepare('SELECT * FROM users WHERE id=?').get(s.user_id);if(!u||u.status!=='approved')return null;db.prepare('UPDATE user_sessions SET last_seen=? WHERE id=?').run(now(),s.id);db.prepare('UPDATE users SET last_seen=? WHERE id=?').run(now(),u.id);return {u,s}}
function adminSession(req){
 const c=parseCookies(req);
 const s=db.prepare(`SELECT s.*,a.username,a.email FROM admin_sessions s JOIN admin_users a ON a.id=s.admin_id WHERE s.id=? AND s.expires_at>? AND a.active=1`).get(c.admin,now());
 return s||null;
}
function admin(req,res){const s=adminSession(req);if(!s){json(res,{error:'Sesión administrativa no autorizada.'},401);return null}return s}
function adminCount(){return db.prepare('SELECT count(*) c FROM admin_users WHERE active=1').get().c}
function validAdminUsername(x){return /^[a-zA-Z0-9._-]{3,40}$/.test(x)}
function validPassword(x){return typeof x==='string'&&x.length>=10&&x.length<=200}

function pub(u){return {id:u.id,username:u.username,email:u.email,phone:u.phone,status:u.status,createdAt:u.created_at,lastSeen:u.last_seen,online:!!u.last_seen&&now()-u.last_seen<90000,locked:!!u.locked_until&&u.locked_until>now()}}
function sameOrigin(req){if(!PROD)return true;const origin=req.headers.origin;if(!origin)return true;return origin===`https://${req.headers.host}`}

async function route(req,res){
 const u=new URL(req.url,`http://${req.headers.host||'localhost'}`),p=u.pathname;
 if(!sameOrigin(req))return json(res,{error:'Origen no permitido.'},403);

 if(req.method==='GET'&&(p==='/health'||p==='/health/'))return json(res,{ok:true,service:'oficina-trabajo-virtual',version:'4.7.1',env:PROD?'production':'development',time:now()});
 if(req.method==='GET'&&p==='/ready')return json(res,{ready:true,service:'oficina-trabajo-virtual',version:'4.7.1',database:'ok',time:now()});
 if(req.method==='GET'&&p==='/_render')return json(res,{ok:true,service:'oficina-trabajo-virtual',version:'4.7.1',port:PORT,host:HOST,node:process.version,production:PROD,time:now()});

 if(req.method==='POST'&&p==='/api/register'){
  if(!rate(req,'register',5,60*60*1000))return json(res,{error:'Demasiados registros desde esta conexión. Intenta más tarde.'},429);
  const b=await body(req),username=clean(b.username).toLowerCase(),vendor=clean(b.vendorCode),email=clean(b.email).toLowerCase(),phone=clean(b.phone);
  if(!/^[a-z0-9._-]{3,40}$/.test(username)||!/^\d{4}$/.test(vendor)||!emailOk(email)||phone.length<7)return json(res,{error:'Completa todos los datos correctamente.'},400);
  if(db.prepare('SELECT 1 FROM users WHERE username=? OR email=?').get(username,email))return json(res,{error:'El usuario o correo ya está registrado.'},409);
  const id=tok(),t=now();db.prepare('INSERT INTO users(id,username,vendor_hash,email,phone,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)').run(id,username,hash(vendor),email,phone,'pending',t,t);
  audit('system','register',id,{username});return json(res,{ok:true,message:'Registro recibido. El administrador debe aprobarlo.'});
 }

 if(req.method==='POST'&&p==='/api/request-otp'){
  if(!rate(req,'otp',5,15*60*1000))return json(res,{error:'Demasiadas solicitudes de códigos. Espera unos minutos.'},429);
  const b=await body(req),username=clean(b.username).toLowerCase(),vendor=clean(b.vendorCode),u=db.prepare('SELECT * FROM users WHERE username=?').get(username);
  if(!u||u.vendor_hash!==hash(vendor))return json(res,{error:'Usuario o código incorrecto.'},401);
  if(u.status!=='approved')return json(res,{error:'Tu cuenta todavía no está aprobada.'},403);
  if(u.locked_until>now())return json(res,{error:'Cuenta temporalmente bloqueada por intentos fallidos.'},429);
  const active=db.prepare('SELECT 1 FROM otps WHERE user_id=? AND purpose=? AND used_at IS NULL AND expires_at>?').get(u.id,'login',now());
  if(active)return json(res,{error:'Ya existe un código vigente. Revisa tu correo.'},429);
  const c=six(),id=tok();db.prepare('INSERT INTO otps(id,user_id,code_hash,purpose,created_at,expires_at) VALUES(?,?,?,?,?,?)').run(id,u.id,hash(c),'login',now(),now()+10*60*1000);
  try{await mail(u.email,'Código de acceso - Oficina de Trabajo Virtual',`Hola ${u.username},\n\nTu código de verificación es: ${c}\n\nVence en 10 minutos.`);audit('user','otp_requested',u.id);return json(res,{ok:true,message:'Código enviado al correo autorizado.'})}
  catch(e){db.prepare('DELETE FROM otps WHERE id=?').run(id);return json(res,{error:'No se pudo enviar el correo. Revisa la configuración del servidor.'},500)}
 }

 if(req.method==='POST'&&p==='/api/login'){
  if(!rate(req,'login',10,15*60*1000))return json(res,{error:'Demasiados intentos. Espera unos minutos.'},429);
  const b=await body(req),username=clean(b.username).toLowerCase(),vendor=clean(b.vendorCode),otp=clean(b.otp),u=db.prepare('SELECT * FROM users WHERE username=?').get(username);
  if(!u||u.vendor_hash!==hash(vendor))return json(res,{error:'Usuario o código incorrecto.'},401);
  if(u.status!=='approved')return json(res,{error:'Tu cuenta no está aprobada.'},403);
  if(u.locked_until>now())return json(res,{error:'Cuenta temporalmente bloqueada.'},429);
  const o=db.prepare('SELECT * FROM otps WHERE user_id=? AND purpose=? AND used_at IS NULL AND expires_at>? ORDER BY created_at DESC LIMIT 1').get(u.id,'login',now());
  if(!o||!safe(o.code_hash,hash(otp))){const fails=u.failed_logins+1,lock=fails>=8?now()+15*60*1000:0;db.prepare('UPDATE users SET failed_logins=?,locked_until=? WHERE id=?').run(fails,lock,u.id);return json(res,{error:'Código de verificación incorrecto o vencido.'},401)}
  db.prepare('UPDATE otps SET used_at=? WHERE id=?').run(now(),o.id);db.prepare('UPDATE users SET failed_logins=0,locked_until=0,last_seen=? WHERE id=?').run(now(),u.id);
  db.prepare('DELETE FROM user_sessions WHERE user_id=?').run(u.id);const sid=tok(),csrf=tok();db.prepare('INSERT INTO user_sessions(id,user_id,csrf,created_at,expires_at,last_seen,ip,user_agent) VALUES(?,?,?,?,?,?,?,?)').run(sid,u.id,csrf,now(),now()+12*60*60*1000,now(),ip(req),ua(req));audit('user','login',u.id);
  return json(res,{ok:true,csrf},200,{'Set-Cookie':setCookie('session',sid,12*60*60)});
 }

 if(req.method==='GET'&&p==='/api/me'){const s=userSession(req);return json(res,s?{authenticated:true,user:{username:s.u.username,email:s.u.email,phone:s.u.phone},csrf:s.s.csrf}:{authenticated:false})}
 if(req.method==='POST'&&p==='/api/heartbeat'){const s=userSession(req);if(!s)return json(res,{authenticated:false},401);return json(res,{ok:true})}
 if(req.method==='POST'&&p==='/api/logout'){const c=parseCookies(req);db.prepare('DELETE FROM user_sessions WHERE id=?').run(c.session);return json(res,{ok:true},200,{'Set-Cookie':setCookie('session','',0)})}

 if(req.method==='GET'&&p==='/api/admin/status'){
  return json(res,{setupRequired:adminCount()===0});
 }
 if(req.method==='POST'&&p==='/api/admin/setup'){
  if(adminCount()>0)return json(res,{error:'La configuración inicial ya fue completada.'},409);
  if(!rate(req,'adminsetup',5,60*60*1000))return json(res,{error:'Demasiados intentos de configuración.'},429);
  const b=await body(req),username=clean(b.username).toLowerCase(),password=String(b.password||''),email=clean(b.email).toLowerCase();
  if(!validAdminUsername(username)||!validPassword(password)||!emailOk(email))return json(res,{error:'Usuario válido, correo válido y clave de al menos 10 caracteres.'},400);
  const id=tok(),t=now();
  try{
   db.prepare('INSERT INTO admin_users(id,username,password_hash,email,active,is_primary,created_at,updated_at) VALUES(?,?,?,?,1,1,?,?)').run(id,username,hash(password),email,t,t);
   // Crear la sesión administrativa inmediatamente: la configuración inicial
   // debe llevar al usuario directamente al panel, sin obligarlo a iniciar
   // sesión por segunda vez.
   const sid=tok(),csrf=tok();
   db.prepare('INSERT INTO admin_sessions(id,admin_id,csrf,created_at,expires_at,ip,user_agent) VALUES(?,?,?,?,?,?,?)').run(sid,id,csrf,t,t+8*60*60*1000,ip(req),ua(req));
   db.prepare('UPDATE admin_users SET last_login=?,updated_at=? WHERE id=?').run(t,t,id);
   audit('system','admin_first_setup',null,{username,email});
   audit('admin','login',null,{admin:username,via:'first_setup'});
   return json(res,{ok:true,message:'Administrador principal creado. Abriendo el panel de administración.',csrf,admin:{username,email}},200,{'Set-Cookie':setCookie('admin',sid,8*60*60)});
  }catch(e){return json(res,{error:'No se pudo crear el administrador. El usuario o correo quizá ya existe.'},409)}
 }
 if(req.method==='POST'&&p==='/api/admin/login'){
  if(adminCount()===0)return json(res,{error:'Debes completar la configuración inicial del administrador.'},428);
  if(!rate(req,'adminlogin',10,15*60*1000))return json(res,{error:'Demasiados intentos administrativos.'},429);
  const b=await body(req),username=clean(b.username).toLowerCase(),password=String(b.password||'');
  const a=db.prepare('SELECT * FROM admin_users WHERE username=? AND active=1').get(username);
  if(!a||!safe(hash(password),a.password_hash))return json(res,{error:'Usuario o clave administrativa incorrectos.'},401);
  const id=tok(),csrf=tok();db.prepare('INSERT INTO admin_sessions(id,admin_id,csrf,created_at,expires_at,ip,user_agent) VALUES(?,?,?,?,?,?,?)').run(id,a.id,csrf,now(),now()+8*60*60*1000,ip(req),ua(req));
  db.prepare('UPDATE admin_users SET last_login=?,updated_at=? WHERE id=?').run(now(),now(),a.id);audit('admin','login',null,{admin:a.username});
  return json(res,{ok:true,csrf,admin:{username:a.username,email:a.email}},200,{'Set-Cookie':setCookie('admin',id,8*60*60)});
 }
 if(req.method==='GET'&&p==='/api/admin/me'){
  const a=adminSession(req);
  if(!a)return json(res,{authenticated:false});
  return json(res,{authenticated:true,csrf:a.csrf,admin:{username:a.username,email:a.email}});
 }
 if(req.method==='POST'&&p==='/api/admin/logout'){const c=parseCookies(req);db.prepare('DELETE FROM admin_sessions WHERE id=?').run(c.admin);return json(res,{ok:true},200,{'Set-Cookie':setCookie('admin','',0)})}

 if(p.startsWith('/api/admin/')){
  const a=admin(req,res);if(!a)return;
  if(['POST','PUT','PATCH','DELETE'].includes(req.method)){
   const b=await body(req);if(!safe(clean(b.csrf),a.csrf))return json(res,{error:'Token de seguridad inválido. Recarga el panel.'},403);
  }
  if(req.method==='GET'&&p==='/api/admin/admins'){
   return json(res,{admins:db.prepare('SELECT id,username,email,active,is_primary,created_at,last_login FROM admin_users ORDER BY created_at ASC').all()});
  }
  if(req.method==='POST'&&p==='/api/admin/admins/create'){
   const b=await body(req),username=clean(b.username).toLowerCase(),password=String(b.password||''),email=clean(b.email).toLowerCase();
   if(!validAdminUsername(username)||!validPassword(password)||!emailOk(email))return json(res,{error:'Usuario válido, correo válido y clave de al menos 10 caracteres.'},400);
   if(db.prepare('SELECT 1 FROM admin_users WHERE username=? OR email=?').get(username,email))return json(res,{error:'Ese usuario o correo ya existe.'},409);
   const id=tok(),t=now();db.prepare('INSERT INTO admin_users(id,username,password_hash,email,active,is_primary,created_at,updated_at) VALUES(?,?,?,?,1,0,?,?)').run(id,username,hash(password),email,t,t);
   audit('admin','admin_created',null,{username,email,by:a.username});return json(res,{ok:true,message:'Administrador creado correctamente.'});
  }
  if(req.method==='POST'&&p==='/api/admin/admins/toggle'){
   const b=await body(req),target=db.prepare('SELECT * FROM admin_users WHERE id=?').get(b.id);
   if(!target)return json(res,{error:'Administrador no encontrado.'},404);
   if(target.id===a.admin_id)return json(res,{error:'No puedes desactivar tu propia cuenta.'},400);
   if(target.is_primary)return json(res,{error:'El administrador principal no puede ser revocado desde este panel.'},400);
   db.prepare('UPDATE admin_users SET active=?,updated_at=? WHERE id=?').run(target.active?0:1,now(),target.id);
   if(target.active)db.prepare('DELETE FROM admin_sessions WHERE admin_id=?').run(target.id);
   audit('admin',target.active?'admin_disabled':'admin_enabled',null,{target:target.username,by:a.username});
   return json(res,{ok:true,message:target.active?'Administrador desactivado.':'Administrador activado.'});
  }
  if(req.method==='GET'&&p==='/api/admin/users'){
   const q=clean(u.searchParams.get('q')).toLowerCase(),st=clean(u.searchParams.get('status'));let sql='SELECT * FROM users WHERE 1=1',args=[];
   if(q){sql+=' AND (lower(username) LIKE ? OR lower(email) LIKE ? OR phone LIKE ?)';const z='%'+q+'%';args.push(z,z,z)}
   if(st&&st!=='all'&&st!=='locked'){sql+=' AND status=?';args.push(st)} if(st==='locked')sql+=' AND locked_until>? AND locked_until>0',args.push(now()); sql+=' ORDER BY created_at DESC';
   return json(res,{users:db.prepare(sql).all(...args).map(pub)});
  }
  if(req.method==='GET'&&p==='/api/admin/stats'){const total=db.prepare('SELECT count(*) c FROM users').get().c,pending=db.prepare("SELECT count(*) c FROM users WHERE status='pending'").get().c,approved=db.prepare("SELECT count(*) c FROM users WHERE status='approved'").get().c,online=db.prepare("SELECT count(*) c FROM users WHERE status='approved' AND last_seen>?").get(now()-90000).c;return json(res,{total,pending,approved,online})}
  if(req.method==='POST'&&p==='/api/admin/approve'){
   const b=await body(req),u=db.prepare('SELECT * FROM users WHERE id=?').get(b.id);if(!u)return json(res,{error:'Usuario no encontrado.'},404);
   db.prepare("UPDATE users SET status='approved',updated_at=? WHERE id=?").run(now(),u.id);db.prepare('DELETE FROM user_sessions WHERE user_id=?').run(u.id);
   const c=six(),oid=tok();db.prepare('INSERT INTO otps(id,user_id,code_hash,purpose,created_at,expires_at) VALUES(?,?,?,?,?,?)').run(oid,u.id,hash(c),'login',now(),now()+10*60*1000);
   try{await mail(u.email,'Acceso aprobado - Oficina de Trabajo Virtual',`Hola ${u.username},\n\nTu acceso fue aprobado.\n\nTu código de verificación es: ${c}\n\nVence en 10 minutos.`);audit('admin','approve',u.id);return json(res,{ok:true,message:'Usuario aprobado y código enviado.'})}
   catch(e){return json(res,{error:'Usuario aprobado, pero el correo no pudo enviarse. Revisa la configuración.'},500)}
  }
  if(req.method==='POST'&&p==='/api/admin/revoke'){
   const b=await body(req),u=db.prepare('SELECT * FROM users WHERE id=?').get(b.id);if(!u)return json(res,{error:'Usuario no encontrado.'},404);
   db.prepare("UPDATE users SET status='revoked',updated_at=? WHERE id=?").run(now(),u.id);db.prepare('DELETE FROM user_sessions WHERE user_id=?').run(u.id);audit('admin','revoke',u.id);return json(res,{ok:true,message:'Acceso revocado.'})
  }
  if(req.method==='POST'&&p==='/api/admin/resend'){
   const b=await body(req),u=db.prepare('SELECT * FROM users WHERE id=?').get(b.id);if(!u||u.status!=='approved')return json(res,{error:'El usuario debe estar aprobado.'},400);
   const c=six(),oid=tok();db.prepare('UPDATE otps SET used_at=? WHERE user_id=? AND purpose=? AND used_at IS NULL').run(now(),u.id,'login');db.prepare('INSERT INTO otps(id,user_id,code_hash,purpose,created_at,expires_at) VALUES(?,?,?,?,?,?)').run(oid,u.id,hash(c),'login',now(),now()+10*60*1000);
   try{await mail(u.email,'Nuevo código de acceso - Oficina de Trabajo Virtual',`Hola ${u.username},\n\nTu nuevo código es: ${c}\n\nVence en 10 minutos.`);audit('admin','resend_otp',u.id);return json(res,{ok:true,message:'Código reenviado.'})}catch(e){db.prepare('DELETE FROM otps WHERE id=?').run(oid);return json(res,{error:'No se pudo enviar el correo.'},500)}
  }
  if(req.method==='GET'&&p==='/api/admin/audit'){
   return json(res,{items:db.prepare('SELECT a.*,u.username FROM audit a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.created_at DESC LIMIT 200').all().map(x=>({...x,meta:JSON.parse(x.meta||'{}')}))})
  }
  if(req.method==='GET'&&p==='/api/admin/email-config')return json(res,{provider:'Resend',configured:!!process.env.RESEND_API_KEY&&!!process.env.EMAIL_FROM,from:process.env.EMAIL_FROM||'',adminEmail:process.env.ADMIN_EMAIL||''});
  if(req.method==='POST'&&p==='/api/admin/test-email'){const b=await body(req),to=clean(b.to)||process.env.ADMIN_EMAIL;if(!emailOk(to))return json(res,{error:'Correo de prueba inválido.'},400);try{await mail(to,'Prueba de correo - Oficina de Trabajo Virtual','La configuración del correo funciona correctamente.');audit('admin','test_email',null,{to});return json(res,{ok:true,message:'Correo de prueba enviado.'})}catch(e){return json(res,{error:'No se pudo enviar el correo.'},500)}}
 }
 if(p==='/')return send(res,200,fs.readFileSync(path.join(__dirname,'public','index.html'),'utf8'),'text/html');
 if(p==='/admin'||p==='/admin/'||p==='/admin.html'||p==='/admin.html/')return send(res,200,fs.readFileSync(path.join(__dirname,'public','admin.html'),'utf8'),'text/html',{'Cache-Control':'no-store, max-age=0'});
 if(p.startsWith('/app')){
   const s=userSession(req);if(!s)return send(res,302,'','text/plain',{Location:'/'});
 }
 const file=path.join(__dirname,'public',p.replace(/^\/+/,'')||'index.html');
 if(fs.existsSync(file)&&fs.statSync(file).isFile()){const ext=path.extname(file),types={'.html':'text/html','.js':'text/javascript','.css':'text/css','.json':'application/json','.png':'image/png','.jpg':'image/jpeg','.svg':'image/svg+xml','.txt':'text/plain'};return send(res,200,fs.readFileSync(file),types[ext]||'application/octet-stream')}
 return send(res,404,'No encontrado','text/plain');
}
const server=http.createServer((req,res)=>route(req,res).catch(e=>{console.error('Request error:',e);if(!res.headersSent)json(res,{error:'Error interno del servidor.'},500);else res.end()}));
server.keepAliveTimeout=65000;
server.headersTimeout=66000;
server.requestTimeout=120000;
server.on('error',e=>{console.error('Server error:',e);process.exit(1)});
const shutdown=signal=>{console.log(`Recibido ${signal}; cerrando servidor...`);try{db.close()}catch{}server.close(()=>process.exit(0));setTimeout(()=>process.exit(1),10000).unref()};
process.on('SIGTERM',()=>shutdown('SIGTERM'));
process.on('SIGINT',()=>shutdown('SIGINT'));
process.on('uncaughtException',e=>{console.error('Uncaught exception:',e);shutdown('uncaughtException')});
process.on('unhandledRejection',e=>console.error('Unhandled rejection:',e));
server.listen(PORT,HOST,()=>console.log(`OTV 4.7.1 escuchando en http://${HOST}:${PORT} (Render PORT=${PORT})`));
