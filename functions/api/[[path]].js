// Cloudflare Pages Functions + D1 (바인딩 이름: DB)
// 환경변수: RESEND_API_KEY, MAIL_FROM, (선택) ADMIN_ID, ADMIN_PW
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
const GL='https://generativelanguage.googleapis.com/v1beta/';
const badKey=c=>c===400||c===401||c===403;
async function pickModels(key){
  const r=await fetch(GL+'models?pageSize=100',{headers:{'x-goog-api-key':key}});
  if(!r.ok)throw E(badKey(r.status)?'제미나이 API 키가 올바르지 않거나 권한이 없습니다.':'모델 목록을 가져오지 못했습니다. ('+r.status+')',502);
  const l=((await r.json()).models||[]).filter(m=>(m.supportedGenerationMethods||[]).includes('generateContent')).map(m=>m.name.replace('models/',''));
  const ok=l.filter(n=>/^gemini-[\d.]+-flash$/.test(n)).sort((x,y)=>parseFloat(y.split('-')[1])-parseFloat(x.split('-')[1]));
  const m=ok.length?ok.slice(0,3):[l.find(n=>/flash/.test(n)&&!/lite|image|tts|live|audio/.test(n))||l[0]].filter(Boolean);
  if(!m.length)throw E('사용 가능한 제미나이 모델이 없습니다.',502);return m;
}
const pickModel=async k=>(await pickModels(k))[0];
async function gem(key,model,sys,user,max){
  let r;for(let i=0;i<3;i++){
    r=await fetch(GL+'models/'+model+':generateContent',{method:'POST',headers:{'Content-Type':'application/json','x-goog-api-key':key},
      body:JSON.stringify({systemInstruction:{parts:[{text:sys}]},contents:[{role:'user',parts:[{text:user}]}],generationConfig:{temperature:.7,maxOutputTokens:max}})});
    if(![429,500,503].includes(r.status))break;await new Promise(o=>setTimeout(o,1500*(i+1)));
  }
  if(!r.ok)throw E(badKey(r.status)?'제미나이 API 키가 올바르지 않거나 권한이 없습니다.':'제미나이 호출에 실패했습니다. ('+r.status+', 모델: '+model+')',502);
  const d=await r.json();return (d.candidates?.[0]?.content?.parts||[]).map(p=>p.text||'').join('').replace(/\*\*/g,'').replace(/^```\w*\n?|\n?```$/g,'').trim();
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
const SYS=`당신은 식품 이커머스 상세페이지 전문 카피라이터입니다. 입력된 상품 정보를 지정된 템플릿 구성에 맞게 정리하고, 부족한 부분은 상품에 어울리는 카피라이팅으로 보강합니다.
규칙:
1. 출력 형식: 첫 줄=상품명, 둘째 줄=고객의 마음을 끄는 한 줄 소개 카피, 빈 줄, 이후 지정된 섹션을 순서대로. 각 섹션은 "○ 섹션이름" 줄로 시작하고 내용을 그 아래에 씁니다. 섹션이름은 지정된 그대로 사용합니다.
2. 사용자가 제공한 사실(원산지, 성분, 중량, 알레르기, 포장, 유통기한 등)은 바꾸거나 빼지 말고 그대로 반영합니다. 제공되지 않은 사실은 지어내지 말고 "[확인 필요]"로 표기합니다.
3. 스토리, 장점, 먹는 방법, 보관, FAQ 등 마케팅 성격의 섹션은 정보가 부족하면 상품 특성에 맞게 자연스럽게 작성해 완성도를 높입니다.
4. 과장·허위 표현, 질병 예방·치료 등 의학적 효능 주장, 근거 없는 최상급 표현은 금지합니다.
5. 마크다운 기호(**, #, 코드블록)와 설명·인사말 없이 본문만 출력합니다.`;
const HINT={spec:'각 줄을 "※ 항목 : 내용" 형식으로',faq:'"Q. 질문" 줄 다음 "A. 답변" 줄, 질문끼리는 빈 줄로 구분 (4~6개)',points:'한 줄에 장점 하나씩 3~5줄',steps:'한 줄에 한 단계씩 3~5줄',notice:'한 줄에 안내 하나씩',origin:'원산지를 한 줄로',text:'자연스러운 문장 2~5줄'};

async function route(p,req,env,b){
  const DB=env.DB;if(!DB)throw E('D1 바인딩(DB)이 설정되지 않았습니다.',500);
  const now=Date.now(),str=k=>String(b[k]??'').trim(),A=adm(env);

  if(p==='check-id'){const id=str('id').toLowerCase();
    if(!IDR.test(id))throw E('아이디는 영문/숫자/_ 4~20자로 입력해 주세요.');
    if(id===A.id||await DB.prepare('SELECT 1 FROM users WHERE uid=?').bind(id).first())throw E('이미 사용 중인 아이디입니다.');
    return J({ok:1})}

  if(p==='send-code'){const em=str('email').toLowerCase();
    if(!EM.test(em))throw E('이메일 형식이 올바르지 않습니다.');
    if(await DB.prepare('SELECT 1 FROM users WHERE email=?').bind(em).first())throw E('이미 가입된 이메일입니다.');
    const o=await DB.prepare('SELECT exp FROM email_codes WHERE email=?').bind(em).first();
    if(o&&o.exp-now>540000)throw E('1분 후에 다시 요청해 주세요.',429);
    const code=String(100000+rnd(900000));
    await mail(env,em,'[푸드 상세페이지 스튜디오] 이메일 인증번호',`<p>인증번호: <b style="font-size:22px">${code}</b></p><p>10분 안에 입력해 주세요.</p>`);
    await DB.prepare('INSERT OR REPLACE INTO email_codes(email,code,exp,tries,verified) VALUES(?,?,?,0,0)').bind(em,code,now+600000).run();
    return J({ok:1})}

  if(p==='verify-code'){const em=str('email').toLowerCase();
    const r=await DB.prepare('SELECT * FROM email_codes WHERE email=?').bind(em).first();
    if(!r||r.exp<now)throw E('인증번호가 만료되었거나 요청 내역이 없습니다.');
    if(r.tries>=5)throw E('시도 횟수를 초과했습니다. 인증번호를 다시 받아 주세요.',429);
    if(r.code!==str('code')){await DB.prepare('UPDATE email_codes SET tries=tries+1 WHERE email=?').bind(em).run();throw E('인증번호가 일치하지 않습니다.')}
    await DB.prepare('UPDATE email_codes SET verified=1,exp=? WHERE email=?').bind(now+1800000,em).run();
    return J({ok:1})}

  if(p==='signup'){const id=str('id').toLowerCase(),em=str('email').toLowerCase(),co=str('company'),pw=String(b.pw||'');
    if(!co||co.length>50)throw E('업체명을 확인해 주세요.');
    if(!IDR.test(id)||id===A.id)throw E('아이디를 확인해 주세요.');
    if(!EM.test(em))throw E('이메일 형식이 올바르지 않습니다.');
    if(pw.length<8||pw.length>64)throw E('비밀번호는 8~64자로 입력해 주세요.');
    const r=await DB.prepare('SELECT verified,exp FROM email_codes WHERE email=?').bind(em).first();
    if(!r||!r.verified||r.exp<now)throw E('이메일 인증을 완료해 주세요.');
    try{await DB.prepare("INSERT INTO users(uid,company,email,pw,status,blocked,created_at) VALUES(?,?,?,?,'pending',0,?)").bind(id,co,em,await hashPw(pw),now).run()}
    catch(e){throw E('이미 사용 중인 아이디 또는 이메일입니다.')}
    await DB.prepare('DELETE FROM email_codes WHERE email=?').bind(em).run();
    return J({ok:1})}

  if(p==='login'){const id=str('id').toLowerCase(),pw=String(b.pw||''),bad='아이디 또는 비밀번호가 올바르지 않습니다.';
    if(id===A.id){if(pw!==A.pw)throw E(bad,401);return J({role:'admin',uid:id,token:await newSession(DB,id,'admin')})}
    const u=await DB.prepare('SELECT * FROM users WHERE uid=?').bind(id).first();
    if(!u||!await checkPw(pw,u.pw))throw E(bad,401);
    if(u.blocked)throw E('차단된 계정입니다. 관리자에게 문의해 주세요.',403);
    if(u.status!=='approved')throw E('관리자 승인 대기 중입니다. 승인 후 로그인할 수 있습니다.',403);
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
  const KEY=async()=>(await DB.prepare("SELECT v FROM settings WHERE k='gemini_key'").first())?.v||'';
  const needAdmin=()=>{if(me.role!=='admin')throw E('권한이 없습니다.',403)};

  if(p==='me')return J({role:me.role,uid:me.uid});

  if(p==='admin/users'){needAdmin();
    const {results}=await DB.prepare('SELECT uid,company,email,status,blocked,created_at FROM users ORDER BY created_at DESC').all();return J({users:results})}
  const Q={'admin/approve':"UPDATE users SET status='approved' WHERE uid=?",'admin/block':'UPDATE users SET blocked=1 WHERE uid=?','admin/unblock':'UPDATE users SET blocked=0 WHERE uid=?'}[p];
  if(Q){needAdmin();await DB.prepare(Q).bind(str('uid')).run();return J({ok:1})}

  if(p==='gemini/status')return J({connected:!!await KEY()});
  if(p==='gemini/save'){needAdmin();const key=str('key');
    if(key.length<20)throw E('API 키 형식이 올바르지 않습니다.');
    const model=await pickModel(key); // 모델 목록 조회가 성공하면 키가 유효함 (시험 호출 생략)
    await DB.prepare("INSERT OR REPLACE INTO settings(k,v) VALUES('gemini_key',?)").bind(key).run();
    await DB.prepare("INSERT OR REPLACE INTO settings(k,v) VALUES('gemini_model',?)").bind(model).run();return J({ok:1,model})}
  if(p==='gemini/remove'){needAdmin();await DB.prepare("DELETE FROM settings WHERE k='gemini_key'").run();return J({ok:1})}
  if(p==='gemini/generate'){const key=await KEY();if(!key)throw E('제미나이가 연결되어 있지 않습니다. 관리자에게 문의해 주세요.');
    const raw=str('raw');if(!raw||raw.length>20000)throw E('상품 정보를 확인해 주세요. (최대 2만자)');
    const secs=(Array.isArray(b.sections)?b.sections:[]).slice(0,20).map(s=>`○ ${String(s.label||'').slice(0,40)} — ${HINT[s.kind]||HINT.text}${s.req?' (필수)':''}`).join('\n');
    const model=(await DB.prepare("SELECT v FROM settings WHERE k='gemini_model'").first())?.v||await pickModel(key);
    const text=await gem(key,model,SYS,`상품 템플릿: ${String(b.tpl||'').slice(0,20)}\n\n[섹션 구성 — 이 순서와 이름 그대로 사용]\n${secs}\n\n[입력된 상품 정보]\n${raw}`,16384);
    if(!text)throw E('제미나이가 응답을 만들지 못했습니다. 다시 시도해 주세요.',502);return J({text})}

  throw E('존재하지 않는 요청입니다.',404);
}
export async function onRequest({request,env,params}){
  try{
    const path=[].concat(params.path||[]).join('/');
    const body=request.method==='POST'?await request.json().catch(()=>({})):{};
    return await route(path,request,env,body);
  }catch(e){return J({error:e.s?e.message:'서버 오류가 발생했습니다.'},e.s||500)}
}
