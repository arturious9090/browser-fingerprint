import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {once} from 'node:events';
import {mkdtemp,rm,chmod,readFile,stat} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import path from 'node:path';
import {DatabaseSync} from 'node:sqlite';
import {createServer} from '../server.mjs';
import {configuration,clientContext,rateIdentity,createLimiter,assertJSONComplexity} from '../security.mjs';
import {validateReport} from '../reports.mjs';
import {openStore,hashKey} from '../database.mjs';
import {CONSENT_VERSION} from '../public/consent.js';
import {createAuditLogger} from '../audit.mjs';
const ownerKey='test-only-owner-key-0123456789-abcdef';
const report=()=>({schemaVersion:1,rows:[{id:'navigator.userAgent',value:'Browser',status:'ok',source:'browser',category:'browser'}]});
async function production(t,opts={}){
  const dir=await mkdtemp('/tmp/fp-security-'),socketPath=path.join(dir,'app.sock');
  const server=await createServer({production:true,publicOrigin:'https://fingerprint.example',adminOrigin:'http://127.0.0.1:8080',proxySocketPath:socketPath,dbPath:':memory:',ownerKey,auditSink:()=>{},...opts});
  server.listen(socketPath);await once(server,'listening');
  t.after(async()=>{await new Promise(resolve=>{server.closeAllConnections();server.close(resolve);});await rm(dir,{recursive:true,force:true});});
  function call(route,{admin=false,method='GET',body,headers={},ip='203.0.113.7'}={}){
    const host=admin?'127.0.0.1:8080':'fingerprint.example',origin=admin?'http://127.0.0.1:8080':'https://fingerprint.example';
    return new Promise((resolve,reject)=>{const req=http.request({socketPath,path:route,method,headers:{Host:host,Origin:origin,'X-Real-IP':ip,'X-Forwarded-Proto':admin?'http':'https',...(body===undefined?{}:{'Content-Type':'application/json'}),...headers}},res=>{let data='';res.setEncoding('utf8');res.on('data',s=>data+=s);res.on('end',()=>{let parsed;try{parsed=JSON.parse(data);}catch{parsed=data;}resolve({status:res.statusCode,headers:res.headers,body:parsed});});});req.on('error',reject);req.end(body===undefined?undefined:JSON.stringify(body));});
  }
  return {server,call};
}
async function consent(call,opts={}){const r=await call('/api/consent',{method:'POST',body:{granted:true,version:CONSENT_VERSION},...opts});assert.equal(r.status,201);return r.body.uploadToken;}
const payload=token=>({consent:{granted:true,version:CONSENT_VERSION},uploadToken:token,report:report()});

test('production fails closed on missing origin/socket, non-HTTPS or remote admin origin',()=>{
  for(const opts of [{},{publicOrigin:'http://x.example',proxySocketPath:'/tmp/x'},{publicOrigin:'https://x.example'},{publicOrigin:'https://x.example',proxySocketPath:'/tmp/x',adminOrigin:'https://admin.example'}])assert.throws(()=>configuration({production:true,...opts},{}));
  for(const publicOrigin of ['https://u:p@x.example','https://x.example/path','https://x.example/?query','https://x.example/#hash'])assert.throws(()=>configuration({publicOrigin},{}));
});
test('forwarded headers require Unix socket; TCP cannot impersonate the production proxy',()=>{
  assert.throws(()=>clientContext({headers:{'x-real-ip':'1.2.3.4','x-forwarded-proto':'https'},socket:{remoteAddress:'127.0.0.1'}},{production:true,proxySocketPath:'/tmp/x'}),{status:403});
  assert.equal(clientContext({headers:{'x-real-ip':'1.2.3.4'},socket:{remoteAddress:'::ffff:127.0.0.1'}},{}).ip,'127.0.0.1');
  assert.throws(()=>clientContext({headers:{'x-real-ip':'1.2.3.4, 5.6.7.8','x-forwarded-proto':'https'},socket:{}},{proxySocketPath:'/tmp/x'}),{status:400});
});
test('IPv6 rotation shares /64 quota; IPv4-mapped addresses normalize before throttling',()=>{
  assert.equal(rateIdentity('2001:db8:1234:5678::1'),rateIdentity('2001:0db8:1234:5678:aaaa:bbbb:cccc:dddd'));
  assert.notEqual(rateIdentity('2001:db8:1234:5678::1'),rateIdentity('2001:db8:1234:5679::1'));
});
test('limiter has bounded cardinality, expiry and Retry-After',()=>{
  let now=0;const limit=createLimiter({maxKeys:2,now:()=>now});limit('a',1,1000);assert.throws(()=>limit('a',1,1000),e=>e.status===429&&e.retryAfter===1);limit('b',1,1000);assert.throws(()=>limit('c',1,1000),{status:503});now=1001;limit('c',1,1000);
});
test('public production origin denies every admin entry, including spoofed Origin',async t=>{
  const {call}=await production(t);
  for(const route of ['/admin','/admin/','/admin.html','/admin.js','/admin.css','/api/admin/session','/api/admin/reports','/api/admin/login'])assert.equal((await call(route)).status,404);
  assert.equal((await call('/api/admin/login',{method:'POST',body:{key:ownerKey},headers:{Origin:'http://127.0.0.1:8080'}})).status,404);
  assert.equal((await call('/api/config',{headers:{Host:'attacker.example'}})).status,421);
  assert.equal((await call('/api/config',{headers:{'X-Forwarded-Proto':'http'}})).status,400);
});
test('owner tunnel requires authentication and works independently of public host',async t=>{
  const {call}=await production(t);assert.equal((await call('/api/admin/reports',{admin:true})).status,401);
  const login=await call('/api/admin/login',{admin:true,method:'POST',body:{key:ownerKey}});assert.equal(login.status,200);
  const cookie=login.headers['set-cookie'][0].split(';')[0];assert.match(login.headers['set-cookie'][0],/HttpOnly/);assert.doesNotMatch(login.headers['set-cookie'][0],/Secure/);
  assert.equal((await call('/api/admin/reports',{admin:true,headers:{Cookie:cookie}})).status,200);
  assert.equal((await call('/api/admin/reports',{headers:{Cookie:cookie}})).status,404);
  assert.equal((await call('/api/admin/reports',{admin:true,headers:{Cookie:cookie,Origin:'https://fingerprint.example'}})).status,403);
});
test('proxy client IP is persisted separately; client XFF and CF headers cannot replace it',async t=>{
  const {call,server}=await production(t);const token=await consent(call);
  assert.equal((await call('/api/reports',{method:'POST',body:payload(token),headers:{'X-Forwarded-For':'1.2.3.4','CF-Connecting-IP':'5.6.7.8'}})).status,201);
  const record=server.store.get(server.store.list().reports[0].id);assert.equal(record.ip,'203.0.113.7');assert.equal(record.connection.observations.peerAddress,null);assert.equal(record.connection.observations.forwardedHeadersTrusted,true);assert.equal(record.connection.observations.clientScheme,'https');
  assert.ok(!('x-forwarded-for' in record.connection.observations.requestHeaders));
});
test('consent ticket cannot transfer across IP identity or origins and is single use',async t=>{
  const {call}=await production(t);const token=await consent(call);
  assert.equal((await call('/api/reports',{method:'POST',body:payload(token),ip:'203.0.113.8'})).status,403);
  assert.equal((await call('/api/reports',{admin:true,method:'POST',body:payload(token)})).status,403);
  assert.equal((await call('/api/reports',{method:'POST',body:payload(token)})).status,201);
  assert.equal((await call('/api/reports',{method:'POST',body:payload(token)})).status,403);
});
test('upload throttling applies before report parsing, globally and per client',async t=>{
  const {call}=await production(t,{uploadsPerHour:1,globalUploadsPerHour:2});
  assert.equal((await call('/api/reports',{method:'POST',body:{}})).status,400);
  const blocked=await call('/api/reports',{method:'POST',body:{}});assert.equal(blocked.status,429);assert.ok(Number(blocked.headers['retry-after'])>0);
  assert.equal((await call('/api/reports',{method:'POST',body:{},ip:'203.0.113.8'})).status,400);
  assert.equal((await call('/api/reports',{method:'POST',body:{},ip:'203.0.113.9'})).status,429);
});
test('JSON nesting, dangerous object keys, compressed bodies and attacker marker types are bounded',async t=>{
  const {call}=await production(t);
  let deep={};for(let i=0;i<25;i++)deep={a:deep};assert.throws(()=>assertJSONComplexity(deep),{status:400});assert.throws(()=>assertJSONComplexity(JSON.parse('{"__proto__":{}}')),{status:400});
  assert.equal((await call('/api/consent',{method:'POST',body:deep})).status,400);
  assert.equal((await call('/api/consent',{method:'POST',body:{},headers:{'Content-Encoding':'gzip'}})).status,415);
  const r=report();r.rows=[{...r.rows[0],id:'canvas.pixelHash',value:{toString:1}},{...r.rows[0],id:'canvas.repeatPixelHash',value:2},{...r.rows[0],id:'webgl.unmaskedRenderer',value:{toString:1}},{...r.rows[0],id:'automation.seleniumGlobals',value:[{toString:1}]}];assert.doesNotThrow(()=>validateReport(r));
});
test('report count quota rejects writes; retention uses server creation time and frees capacity',async t=>{
  const {call,server}=await production(t,{maxReports:1});const first=await consent(call);assert.equal((await call('/api/reports',{method:'POST',body:payload(first)})).status,201);
  const second=await consent(call);assert.equal((await call('/api/reports',{method:'POST',body:payload(second)})).status,507);
  assert.equal(server.store.prune('2000-01-01T00:00:00.000Z'),0);assert.equal(server.store.prune('2999-01-01T00:00:00.000Z'),1);
  assert.equal((await call('/api/reports',{method:'POST',body:payload(second)})).status,201);
});
test('production headers protect HTML and API; path normalization cannot expose files',async t=>{
  const {call}=await production(t);for(const route of ['/','/api/config']){const r=await call(route);assert.equal(r.status,200);assert.match(r.headers['strict-transport-security'],/max-age/);assert.match(r.headers['content-security-policy'],/frame-ancestors 'none'/);assert.equal(r.headers['cross-origin-resource-policy'],'same-origin');assert.match(r.headers['cache-control'],/no-store/);}
  for(const route of ['/.data/owner-key.txt','/../server.mjs','/%2e%2e/server.mjs','//admin','/api%2fadmin/reports'])assert.ok([400,404].includes((await call(route)).status));
});
test('online SQLite backup includes uncheckpointed WAL and is checked and private',async()=>{
  const dir=await mkdtemp('/tmp/fp-backup-');const dbPath=path.join(dir,'source.sqlite'),destination=path.join(dir,'backup.sqlite');let store;
  try{store=await openStore({dbPath,ownerKey});store.save(validateReport(report()),{observations:{peerAddress:'127.0.0.1'}},{at:new Date().toISOString(),version:'test',text:'Test consent'});
    const result=spawnSync(process.execPath,['scripts/backup.mjs',destination],{cwd:path.resolve('.'),env:{...process.env,DATABASE_PATH:dbPath},encoding:'utf8'});assert.equal(result.status,0,result.stderr);assert.equal((await stat(destination)).mode&0o777,0o600);
    const copy=new DatabaseSync(destination,{readOnly:true});try{assert.equal(copy.prepare('SELECT count(*) AS count FROM reports').get().count,1);assert.equal(copy.prepare('PRAGMA quick_check').get().quick_check,'ok');}finally{copy.close();}
    assert.notEqual(spawnSync(process.execPath,['scripts/backup.mjs',destination],{env:{...process.env,DATABASE_PATH:dbPath}}).status,0);
  }finally{store?.close();await rm(dir,{recursive:true,force:true});}
});
test('production rejects database directories readable by other users',async()=>{
  const dir=await mkdtemp('/tmp/fp-mode-');try{await chmod(dir,0o755);await assert.rejects(openStore({dbPath:path.join(dir,'db.sqlite'),production:true,ownerKey}),/0700/);}finally{await rm(dir,{recursive:true,force:true});}
});

test('sibling origins and browser same-site metadata cannot access private API',async t=>{
  const {call}=await production(t);
  assert.equal((await call('/api/consent',{method:'POST',body:{granted:true,version:CONSENT_VERSION},headers:{'Sec-Fetch-Site':'same-site'}})).status,403);
  assert.equal((await call('/api/config',{headers:{Origin:'https://other.fingerprint.example'}})).status,403);
});
test('audit records fixed events without credentials or visitor data and limits log flooding',async t=>{
  const lines=[];const {call}=await production(t,{auditSink:line=>lines.push(line)});
  await call('/api/admin/login',{admin:true,method:'POST',body:{key:'wrong-key-do-not-log-01234567890123456789'}});
  const login=await call('/api/admin/login',{admin:true,method:'POST',body:{key:ownerKey}});const cookie=login.headers['set-cookie'][0].split(';')[0];
  await call('/api/admin/reports?q=PRIVATE-SEARCH',{admin:true,headers:{Cookie:cookie}});
  await call('/api/admin/logout',{admin:true,method:'POST',body:{},headers:{Cookie:cookie,'X-CSRF-Token':login.body.csrfToken}});
  assert.deepEqual(lines.map(line=>JSON.parse(line).event),['login_denied','login_success','reports_read','logout']);
  const output=lines.join('\n');for(const secret of [ownerKey,'wrong-key-do-not-log','PRIVATE-SEARCH',cookie,login.body.csrfToken,'203.0.113.7'])assert.ok(!output.includes(secret));
  let now=0;const limited=[];const log=createAuditLogger({sink:line=>limited.push(JSON.parse(line)),now:()=>now,perMinute:2});
  for(let i=0;i<20;i++)log('rate_limited','a'.repeat(16),429);assert.equal(limited.length,2);now=60001;log('rate_limited','b'.repeat(16),429);assert.equal(limited[2].suppressed,18);
  log('attacker\nmessage','c'.repeat(16),200);assert.equal(limited.length,3);
  assert.doesNotThrow(()=>createAuditLogger({sink:()=>{throw new Error('sink unavailable');}})('login_success','d'.repeat(16),200));
});
test('logging in rotates the presented session; old session is revoked',async t=>{
  const {call}=await production(t);const first=await call('/api/admin/login',{admin:true,method:'POST',body:{key:ownerKey}});const old=first.headers['set-cookie'][0].split(';')[0];
  const second=await call('/api/admin/login',{admin:true,method:'POST',body:{key:ownerKey},headers:{Cookie:old}});const next=second.headers['set-cookie'][0].split(';')[0];assert.notEqual(old,next);
  assert.equal((await call('/api/admin/session',{admin:true,headers:{Cookie:old}})).status,401);assert.equal((await call('/api/admin/session',{admin:true,headers:{Cookie:next}})).status,200);
});

test('slow concurrent login bodies cannot run multiple expensive key checks',async t=>{
  const {call,server}=await production(t);let active=0,peak=0;
  server.store.login=async()=>{active++;peak=Math.max(peak,active);await new Promise(resolve=>setTimeout(resolve,30));active--;return null;};
  const socketPath=server.address();
  const pending=Array.from({length:5},(_,i)=>new Promise((resolve,reject)=>{
    const req=http.request({socketPath,path:'/api/admin/login',method:'POST',headers:{Host:'127.0.0.1:8080',Origin:'http://127.0.0.1:8080','X-Real-IP':`203.0.113.${i+20}`,'X-Forwarded-Proto':'http','Content-Type':'application/json'}},res=>{res.resume();res.on('end',()=>resolve(res.statusCode));});
    req.on('error',reject);req.write('{"key":"');setTimeout(()=>req.end(ownerKey+'"}'),25);
  }));
  const statuses=await Promise.all(pending);assert.equal(peak,1);assert.ok(statuses.includes(401));assert.ok(statuses.includes(429));
});
test('an in-flight key verification cannot succeed after credentials change',async()=>{
  const dir=await mkdtemp('/tmp/fp-auth-race-');let store,db;
  try{const dbPath=path.join(dir,'db.sqlite');store=await openStore({dbPath,ownerKey});const next=await hashKey('next-owner-fixture-01234567890123456789');
    const verifying=store.authenticate(ownerKey),signingIn=store.login(ownerKey);db=new DatabaseSync(dbPath);db.prepare('UPDATE owner SET salt=?,hash=? WHERE id=1').run(next.salt,next.hash);assert.equal(await verifying,false);assert.equal(await signingIn,null);assert.equal(db.prepare('SELECT count(*) AS n FROM sessions').get().n,0);
  }finally{db?.close();store?.close();await rm(dir,{recursive:true,force:true});}
});

test('SQLite page quota returns 507 without corrupting existing reports',async t=>{
  const {call,server}=await production(t,{maxDatabaseBytes:1024*1024,maxReports:100});let saved=0,full=false;
  for(let i=0;i<6;i++){const token=await consent(call),body=payload(token);body.report.rows[0].value='x'.repeat(300000);const result=await call('/api/reports',{method:'POST',body});if(result.status===507){full=true;break;}assert.equal(result.status,201);saved++;}
  assert.equal(full,true);assert.ok(saved>0);assert.equal(server.store.list().total,saved);assert.equal((await call('/api/config')).status,200);
});
