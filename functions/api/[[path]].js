// Cloudflare Pages Functions + D1 (바인딩 이름: DB)
// 환경변수: RESEND_API_KEY, MAIL_FROM(비밀번호 초기화 메일용), (선택) ADMIN_ID, ADMIN_PW
const J=(o,s=200)=>new Response(JSON.stringify(o),{status:s,headers:{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'}});
const E=(m,s=400)=>Object.assign(new Error(m),{s});
const enc=new TextEncoder();
const hex=b=>[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('');
const unhex=h=>new Uint8Array(h.match(/../g).map(x=>parseInt(x,16)));
const sha=async s=>hex(await crypto.subtle.digest('SHA-256',enc.encode(s)));
const rnd=n=>crypto.getRandomValues(new Uint32Array(1))[0]%n;
async function pbk(pw,salt){const k=await crypto.subtle.importKey('raw',enc.encode(pw),'PBKDF2',false,['deriveBits']);return hex(await crypto.subtle.deriveBits({name:'PBKDF2',hash:'SHA-256',salt,iterations:100000},k,256))}
async function hashPw(pw){const s=crypto.getRandomValues(new Uint8Array(16));return hex(s)+':'+await pbk(pw,s)}
async function checkPw(pw,st){const [s,h]=String(st).split(':');return (await pbk(pw,unhex(s)))===h}
const EM=/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/, IDR=/^[a-z0-9_]{4,20}$/;
const adm=env=>({id:(env.ADMIN_ID||'zian1001').toLowerCase(),pw:env.ADMIN_PW||'zn048675!!'});

async function mail(env,to,subject,html){
  if(!env.RESEND_API_KEY)throw E('메일 발송 설정(RESEND_API_KEY)이 되어 있지 않습니다.',500);
  const r=await fetch('https://api.resend.com/emails',{method:'POST',headers:{Authorization:'Bearer '+env.RESEND_API_KEY,'Content-Type':'application/json'},body:JSON.stringify({from:env.MAIL_FROM||'onboarding@resend.dev',to:[to],subject,html})});
  if(!r.ok)throw E('메일 발송에 실패했습니다. 이메일 주소와 발송 설정을 확인해 주세요.',502);
}
async function auth(env,req){
  const t=(req.headers.get('Authorization')||'').slice(7);if(!t)return null;
  const s=await env.DB.prepare('SELECT uid,role,exp FROM sessions WHERE th=?').bind(await sha(t)).first();
  if(!s||s.exp<Date.now())return null;
  if(s.role==='admin')return {uid:s.uid,role:'admin'};
  const u=await env.DB.prepare('SELECT status,blocked FROM users WHERE uid=?').bind(s.uid).first();
  return u&&!u.blocked&&u.status==='approved'?{uid:s.uid,role:'user'}:null;
}
async function newSession(DB,uid,role){
  const t=crypto.randomUUID()+crypto.randomUUID(),now=Date.now();
  await DB.prepare('DELETE FROM sessions WHERE exp<?').bind(now).run();
  await DB.prepare('INSERT INTO sessions(th,uid,role,exp) VALUES(?,?,?,?)').bind(await sha(t),uid,role,now+12*3600e3).run();
  return t;
}
async function route(p,req,env,b){
  const DB=env.DB;if(!DB)throw E('D1 바인딩(DB)이 설정되지 않았습니다.',500);
  const now=Date.now(),str=k=>String(b[k]??'').trim(),A=adm(env);

  if(p==='check-id'){const id=str('id').toLowerCase();
    if(!IDR.test(id))throw E('아이디는 영문/숫자/_ 4~20자로 입력해 주세요.');
    if(id===A.id||await DB.prepare('SELECT 1 FROM users WHERE uid=?').bind(id).first())throw E('이미 사용 중인 아이디입니다.');
    return J({ok:1})}

  if(p==='signup'){const id=str('id').toLowerCase(),em=str('email').toLowerCase(),co=str('company'),pw=String(b.pw||'');
    if(!co||co.length>50)throw E('업체명을 확인해 주세요.');
    if(!IDR.test(id)||id===A.id)throw E('아이디를 확인해 주세요.');
    if(!EM.test(em))throw E('이메일 형식이 올바르지 않습니다.');
    if(pw.length<8||pw.length>64)throw E('비밀번호는 8~64자로 입력해 주세요.');
    try{await DB.prepare("INSERT INTO users(uid,company,email,pw,status,blocked,created_at) VALUES(?,?,?,?,'pending',0,?)").bind(id,co,em,await hashPw(pw),now).run()}
    catch(e){throw E('이미 사용 중인 아이디 또는 이메일입니다.')}
    return J({ok:1})}

  if(p==='login'){const id=str('id').toLowerCase(),pw=String(b.pw||''),bad='아이디 또는 비밀번호가 올바르지 않습니다.';
    if(id===A.id){if(pw!==A.pw)throw E(bad,401);return J({role:'admin',uid:id,token:await newSession(DB,id,'admin')})}
    const u=await DB.prepare('SELECT * FROM users WHERE uid=?').bind(id).first();
    if(!u||!await checkPw(pw,u.pw))throw E(bad,401);
    if(u.blocked)throw E('차단된 계정입니다. 관리자에게 문의해 주세요.',403);
    if(u.status!=='approved')throw E('승인 전입니다. 관리자 승인 후 로그인할 수 있습니다.',403);
    return J({role:'user',uid:id,token:await newSession(DB,id,'user')})}

  if(p==='find-id'){
    const u=await DB.prepare('SELECT uid FROM users WHERE company=? AND email=?').bind(str('company'),str('email').toLowerCase()).first();
    if(!u)throw E('일치하는 회원 정보가 없습니다.',404);return J({id:u.uid})}

  if(p==='reset-pw'){const id=str('id').toLowerCase(),em=str('email').toLowerCase();
    const u=await DB.prepare('SELECT uid FROM users WHERE uid=? AND email=?').bind(id,em).first();
    if(!u)throw E('일치하는 회원 정보가 없습니다.',404);
    const ch='ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789';let tmp='';for(let i=0;i<10;i++)tmp+=ch[rnd(ch.length)];
    await mail(env,em,'[푸드 상세페이지 스튜디오] 초기화된 비밀번호',`<p>초기화된 비밀번호: <b style="font-size:20px">${tmp}</b></p><p>로그인 후 비밀번호를 변경해 주세요.</p>`);
    await DB.prepare('UPDATE users SET pw=? WHERE uid=?').bind(await hashPw(tmp),id).run();
    await DB.prepare('DELETE FROM sessions WHERE uid=?').bind(id).run();
    return J({ok:1})}

  if(p==='change-pw'){const id=str('id').toLowerCase(),np=String(b.pw||'');
    const u=await DB.prepare('SELECT pw FROM users WHERE uid=?').bind(id).first();
    if(!u||!await checkPw(String(b.old||''),u.pw))throw E('아이디 또는 현재 비밀번호가 올바르지 않습니다.',401);
    if(np.length<8||np.length>64)throw E('새 비밀번호는 8~64자로 입력해 주세요.');
    await DB.prepare('UPDATE users SET pw=? WHERE uid=?').bind(await hashPw(np),id).run();
    await DB.prepare('DELETE FROM sessions WHERE uid=?').bind(id).run();
    return J({ok:1})}

  if(p==='logout'){const t=(req.headers.get('Authorization')||'').slice(7);
    if(t)await DB.prepare('DELETE FROM sessions WHERE th=?').bind(await sha(t)).run();return J({ok:1})}

  // ---- 이하 로그인 필요 ----
  const me=await auth(env,req);if(!me)throw E('로그인이 필요합니다.',401);
  const needAdmin=()=>{if(me.role!=='admin')throw E('권한이 없습니다.',403)};

  if(p==='me')return J({role:me.role,uid:me.uid});

  if(p==='admin/users'){needAdmin();
    const {results}=await DB.prepare('SELECT uid,company,email,status,blocked,created_at FROM users ORDER BY created_at DESC').all();return J({users:results})}
  const Q={'admin/approve':"UPDATE users SET status='approved' WHERE uid=?",'admin/block':'UPDATE users SET blocked=1 WHERE uid=?','admin/unblock':'UPDATE users SET blocked=0 WHERE uid=?'}[p];
  if(Q){needAdmin();await DB.prepare(Q).bind(str('uid')).run();return J({ok:1})}

  throw E('존재하지 않는 요청입니다.',404);
}
export async function onRequest({request,env,params}){
  try{
    const path=[].concat(params.path||[]).join('/');
    const body=request.method==='POST'?await request.json().catch(()=>({})):{};
    return await route(path,request,env,body);
  }catch(e){return J({error:e.s?e.message:'서버 오류가 발생했습니다.'},e.s||500)}
}
