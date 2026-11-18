// ASMAR server: zero dependencies, Node 22+. Accounts, email verification, leaderboard, friends, price/news proxy.
import http from "node:http";import crypto from "node:crypto";import {DatabaseSync} from "node:sqlite";
const E=process.env,PORT=+E.PORT||8787,SECRET=E.SECRET||crypto.randomBytes(32).toString("hex"),ORIGIN=E.ALLOWED_ORIGIN||"*",BASE=E.PUBLIC_URL||`http://localhost:${PORT}`,DEV=E.DEV==="1";
const db=new DatabaseSync(E.DB||"data.db");
db.exec(`CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,email TEXT UNIQUE,nick TEXT UNIQUE,salt TEXT,hash TEXT,verified INTEGER DEFAULT 0,vtoken TEXT,created INTEGER);
CREATE TABLE IF NOT EXISTS scores(uid INTEGER,week TEXT,equity REAL,t INTEGER,PRIMARY KEY(uid,week));
CREATE TABLE IF NOT EXISTS friends(a INTEGER,b INTEGER,PRIMARY KEY(a,b));`);
const one=(s,...a)=>db.prepare(s).get(...a),all=(s,...a)=>db.prepare(s).all(...a),run=(s,...a)=>db.prepare(s).run(...a);
const J=(res,c,o)=>{res.writeHead(c,{"Content-Type":"application/json","Access-Control-Allow-Origin":ORIGIN,"Access-Control-Allow-Headers":"Content-Type,Authorization","Access-Control-Allow-Methods":"GET,POST,OPTIONS"});res.end(JSON.stringify(o))};
const bad=(res,c,m)=>J(res,c,{error:m});
const hits=new Map;const limited=(ip,k,max)=>{const n=Date.now(),a=(hits.get(ip+k)||[]).filter(t=>n-t<6e4);a.push(n);hits.set(ip+k,a);return a.length>max};
const body=req=>new Promise((ok,no)=>{let d="";req.on("data",c=>{d+=c;if(d.length>1e4){no(new Error("big"));req.destroy()}});req.on("end",()=>{try{ok(d?JSON.parse(d):{})}catch(e){no(e)}})});
const hashPw=(pw,salt)=>crypto.scryptSync(pw,salt,64).toString("hex");
const sign=id=>{const p=id+"."+(Date.now()+30*864e5);return p+"."+crypto.createHmac("sha256",SECRET).update(p).digest("hex")};
function auth(req){const t=(req.headers.authorization||"").slice(7).split(".");if(t.length!==3)return null;const sig=crypto.createHmac("sha256",SECRET).update(t[0]+"."+t[1]).digest("hex");
 if(sig.length!==t[2].length||!crypto.timingSafeEqual(Buffer.from(sig),Buffer.from(t[2]))||+t[1]<Date.now())return null;return one("SELECT id,email,nick,verified FROM users WHERE id=?",+t[0])||null}
const wk=()=>{const d=new Date(),t=new Date(Date.UTC(d.getUTCFullYear(),d.getUTCMonth(),d.getUTCDate())),day=t.getUTCDay()||7;t.setUTCDate(t.getUTCDate()+4-day);const y=new Date(Date.UTC(t.getUTCFullYear(),0,1));return t.getUTCFullYear()+"-W"+Math.ceil(((t-y)/864e5+1)/7)};
async function mail(to,subject,html){if(!E.RESEND_KEY){console.log("[mail:dev]",to,subject,html);return}
 const r=await fetch("https://api.resend.com/emails",{method:"POST",headers:{Authorization:"Bearer "+E.RESEND_KEY,"Content-Type":"application/json"},body:JSON.stringify({from:E.MAIL_FROM,to,subject,html})});if(!r.ok)throw new Error("mail failed")}
const cache=new Map;async function cached(key,ttl,fn){const c=cache.get(key);if(c&&Date.now()-c.t<ttl)return c.v;const v=await fn();cache.set(key,{t:Date.now(),v});return v}
const START=100000;
http.createServer(async(req,res)=>{
 try{
  if(req.method==="OPTIONS")return J(res,204,{});
  const u=new URL(req.url,BASE),p=u.pathname,ip=(req.headers["x-forwarded-for"]||"").split(",")[0]||req.socket.remoteAddress;
  if(limited(ip,"all",120))return bad(res,429,"too many requests");
  if(p==="/api/health")return J(res,200,{ok:true,prices:!!E.TWELVE_KEY,news:!!E.FINNHUB_KEY,mail:!!E.RESEND_KEY});
  if(p==="/api/signup"&&req.method==="POST"){
   if(limited(ip,"auth",10))return bad(res,429,"too many attempts");
   const b=await body(req),nick=String(b.nick||"").trim(),email=String(b.email||"").trim().toLowerCase(),pw=String(b.password||"");
   if(!/^[A-Za-z0-9_\u0600-\u06FF]{3,20}$/.test(nick))return bad(res,400,"nickname must be 3-20 letters/numbers");
   if(!/^\S+@\S+\.\S+$/.test(email)||email.length>120)return bad(res,400,"invalid email");
   if(pw.length<8||pw.length>100)return bad(res,400,"password must be at least 8 characters");
   const salt=crypto.randomBytes(16).toString("hex"),vt=crypto.randomBytes(24).toString("hex");
   try{run("INSERT INTO users(email,nick,salt,hash,vtoken,created) VALUES(?,?,?,?,?,?)",email,nick,salt,hashPw(pw,salt),vt,Date.now())}catch(e){return bad(res,409,"email or nickname already used")}
   const link=`${BASE}/api/verify?t=${vt}`;
   try{await mail(email,"ASMAR: confirm your email",`<p>Welcome to ASMAR. Confirm your email: <a href="${link}">${link}</a></p>`)}catch(e){console.error(e.message)}
   return J(res,200,{ok:true,...(DEV?{devVerify:link}:{})});
  }
  if(p==="/api/verify"){const r=run("UPDATE users SET verified=1,vtoken=NULL WHERE vtoken=?",u.searchParams.get("t")||"x");
   res.writeHead(r.changes?200:400,{"Content-Type":"text/html; charset=utf-8"});return res.end(r.changes?"<h2 dir=rtl>تم تأكيد إيميلك. ارجع لتطبيق ASMAR وسجّل دخول.</h2>":"<h2 dir=rtl>الرابط غير صالح أو منتهي.</h2>")}
  if(p==="/api/login"&&req.method==="POST"){
   if(limited(ip,"auth",10))return bad(res,429,"too many attempts");
   const b=await body(req),em=String(b.email||"").trim().toLowerCase(),r=one("SELECT * FROM users WHERE email=?",em),salt=r?r.salt:"00";
   const h=hashPw(String(b.password||""),salt);
   if(!r||h.length!==r.hash.length||!crypto.timingSafeEqual(Buffer.from(h),Buffer.from(r.hash)))return bad(res,401,"wrong email or password");
   return J(res,200,{token:sign(r.id),nick:r.nick,verified:!!r.verified});
  }
  if(p==="/api/prices"||p==="/api/news"){
   if(p==="/api/prices"){
    if(!E.TWELVE_KEY)return bad(res,503,"price provider not configured");
    const list=(u.searchParams.get("symbols")||"").split(",").filter(s=>/^[A-Z0-9.:\/-]{1,12}$/.test(s)).slice(0,20);if(!list.length)return bad(res,400,"no symbols");
    const v=await cached("p:"+list.join(),15e3,async()=>{const r=await fetch(`https://api.twelvedata.com/price?symbol=${list.join(",")}&apikey=${E.TWELVE_KEY}`);const j=await r.json(),o={};
     if(list.length===1)o[list[0]]=+j.price;else for(const s of list)o[s]=j[s]&&j[s].price?+j[s].price:null;return o});
    return J(res,200,{prices:v,source:"Twelve Data"});
   }
   if(!E.FINNHUB_KEY)return bad(res,503,"news provider not configured");
   const v=await cached("n",6e4,async()=>{const r=await fetch(`https://finnhub.io/api/v1/news?category=general&token=${E.FINNHUB_KEY}`);const j=await r.json();return(Array.isArray(j)?j:[]).slice(0,20).map(n=>({title:n.headline,source:n.source,url:n.url,t:n.datetime}))});
   return J(res,200,{news:v,source:"Finnhub"});
  }
  const me=auth(req);if(!me)return bad(res,401,"login required");
  if(p==="/api/me")return J(res,200,{nick:me.nick,email:me.email,verified:!!me.verified});
  if(p==="/api/score"&&req.method==="POST"){
   if(!me.verified)return bad(res,403,"verify your email first");
   const eq=+(await body(req)).equity;if(!Number.isFinite(eq)||eq<0||eq>START*50)return bad(res,400,"invalid score");
   run("INSERT INTO scores(uid,week,equity,t) VALUES(?,?,?,?) ON CONFLICT(uid,week) DO UPDATE SET equity=excluded.equity,t=excluded.t",me.id,wk(),eq,Date.now());return J(res,200,{ok:true});
  }
  if(p==="/api/leaderboard"){
   const fr=u.searchParams.get("scope")==="friends",w=wk();
   const rows=fr?all("SELECT u.nick,s.equity FROM scores s JOIN users u ON u.id=s.uid WHERE s.week=? AND u.verified=1 AND (u.id=? OR u.id IN (SELECT b FROM friends WHERE a=?)) ORDER BY s.equity DESC LIMIT 50",w,me.id,me.id)
    :all("SELECT u.nick,s.equity FROM scores s JOIN users u ON u.id=s.uid WHERE s.week=? AND u.verified=1 ORDER BY s.equity DESC LIMIT 50",w);
   return J(res,200,{week:w,rows:rows.map((r,i)=>({rank:i+1,nick:r.nick,pct:+((r.equity/START-1)*100).toFixed(2),me:r.nick===me.nick}))});
  }
  if(p==="/api/friends"&&req.method==="POST"){
   const nick=String((await body(req)).nick||"").trim(),f=one("SELECT id FROM users WHERE nick=?",nick);
   if(!f||f.id===me.id)return bad(res,404,"user not found");run("INSERT OR IGNORE INTO friends(a,b) VALUES(?,?)",me.id,f.id);return J(res,200,{ok:true});
  }
  if(p==="/api/friends")return J(res,200,{friends:all("SELECT u.nick FROM friends f JOIN users u ON u.id=f.b WHERE f.a=?",me.id).map(r=>r.nick)});
  return bad(res,404,"not found");
 }catch(e){console.error(e);return bad(res,500,"server error")}
}).listen(PORT,()=>console.log("ASMAR server on",PORT));
