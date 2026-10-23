// Isolated integration check: only random loopback ports, a temporary local CA
// and uniquely named disposable volumes. No public ACME issuance or real data.
import {spawnSync} from 'node:child_process';
import {mkdtemp,writeFile,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {randomBytes} from 'node:crypto';
import path from 'node:path';
import http from 'node:http';
import https from 'node:https';
import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const temp=await mkdtemp(path.join(tmpdir(),'fp-docker-smoke-'));
const project='fp-qa-'+randomBytes(5).toString('hex');
const env={...process.env,DOMAIN:'fingerprint.test',ACME_EMAIL:'qa@example.com'};
function run(args,{encoding='utf8'}={}){const result=spawnSync('docker',args,{cwd:root,env,encoding,timeout:120000,maxBuffer:4*1024*1024});if(result.status!==0)throw new Error(`Docker check failed: ${args[0]} ${args[1]??''} (${result.status??result.error?.code})`);return result.stdout;}
const composeArgs=['compose','-p',project,'-f',path.join(temp,'compose.json')];
const compose=(...args)=>run([...composeArgs,...args]);
let created=false;
try{
  const config=JSON.parse(run(['compose','--profile','tools','-f','compose.yaml','config','--format','json']));
  config.name=project;
  for(const [key,volume]of Object.entries(config.volumes))volume.name=project+'_'+key;
  for(const [key,network]of Object.entries(config.networks??{}))network.name=project+'_'+key;
  for(const name of ['app','backup','maintenance']){config.services[name].image='fingerprint-security-check:local';delete config.services[name].build;}
  config.services.app.environment.RETENTION_DAYS='0';
  config.services.caddy.ports=[{target:443,published:'0',host_ip:'127.0.0.1',protocol:'tcp'},{target:8080,published:'0',host_ip:'127.0.0.1',protocol:'tcp'}];
  config.services.caddy.volumes.find(v=>v.target==='/etc/caddy/Caddyfile').source=path.join(temp,'Caddyfile');
  const caddy=(await readFile(path.join(root,'deploy/Caddyfile'),'utf8')).replace('{\n','{\n\tskip_install_trust\n').replace('{$DOMAIN} {','{$DOMAIN} {\n\ttls internal');
  await writeFile(path.join(temp,'Caddyfile'),caddy);await writeFile(path.join(temp,'compose.json'),JSON.stringify(config));
  created=true;compose('up','-d','--wait','--wait-timeout','90','app','caddy');
  const publicPort=Number(compose('port','caddy','443').trim().split(':').at(-1)),adminPort=Number(compose('port','caddy','8080').trim().split(':').at(-1));
  const appId=compose('ps','-q','app').trim(),caddyId=compose('ps','-q','caddy').trim();
  const details=JSON.parse(run(['inspect',appId]))[0];assert.equal(details.HostConfig.NetworkMode,'none');assert.equal(details.HostConfig.ReadonlyRootfs,true);assert.equal(details.Config.User,'node');assert.deepEqual(details.HostConfig.PortBindings,{});
  assert.ok(!details.Mounts.some(m=>m.Destination==='/backups'));
  run(['cp',`${caddyId}:/data/caddy/pki/authorities/local/root.crt`,path.join(temp,'root.crt')]);
  const ca=await readFile(path.join(temp,'root.crt'));
  function request(route,{admin=false,method='GET',body,headers={}}={}){
    return new Promise((resolve,reject)=>{const origin=admin?'http://127.0.0.1:8080':'https://fingerprint.test';
      const req=(admin?http:https).request({host:'127.0.0.1',port:admin?adminPort:publicPort,path:route,method,servername:'fingerprint.test',ca,timeout:5000,headers:{Host:admin?'127.0.0.1:8080':'fingerprint.test',Origin:origin,...(body===undefined?{}:{'Content-Type':'application/json'}),...headers}},res=>{let data='';res.setEncoding('utf8');res.on('data',chunk=>data+=chunk);res.on('end',()=>{let value;try{value=JSON.parse(data);}catch{value=data;}resolve({status:res.statusCode,headers:res.headers,body:value});});});req.on('error',reject);req.on('timeout',()=>req.destroy(new Error('HTTP timeout')));req.end(body===undefined?undefined:JSON.stringify(body));});
  }
  assert.equal((await request('/')).status,200);assert.equal((await request('/admin')).status,404);assert.equal((await request('/api/admin/reports')).status,404);assert.equal((await request('/admin',{admin:true})).status,200);assert.equal((await request('/api/admin/reports',{admin:true})).status,401);
  const ownerKey=compose('exec','-T','app','cat','/data/owner-key.txt').trim();
  const login=await request('/api/admin/login',{admin:true,method:'POST',body:{key:ownerKey}});assert.equal(login.status,200);const cookie=login.headers['set-cookie'][0].split(';')[0];
  const ticket=await request('/api/consent',{method:'POST',body:{granted:true,version:(await request('/api/config')).body.consentVersion}});assert.equal(ticket.status,201);
  const version=(await request('/api/config')).body.consentVersion;
  const saved=await request('/api/reports',{method:'POST',headers:{'X-Real-IP':'1.2.3.4','X-Forwarded-For':'5.6.7.8','CF-Connecting-IP':'9.10.11.12'},body:{consent:{granted:true,version},uploadToken:ticket.body.uploadToken,report:{schemaVersion:1,rows:[{id:'navigator.userAgent',value:'QA private visitor marker',status:'ok',source:'browser',category:'browser'}]}}});assert.equal(saved.status,201);assert.deepEqual(saved.body,{saved:true});
  const list=await request('/api/admin/reports',{admin:true,headers:{Cookie:cookie}});assert.equal(list.body.total,1);for(const spoof of ['1.2.3.4','5.6.7.8','9.10.11.12'])assert.notEqual(list.body.reports[0].ip,spoof);
  const id=list.body.reports[0].id;assert.equal((await request('/api/admin/reports/'+id,{admin:true,headers:{Cookie:cookie}})).status,200);assert.equal((await request('/api/reports/'+id)).status,404);assert.equal((await request('/api/reports/'+id,{method:'DELETE'})).status,404);
  compose('run','--rm','--no-deps','backup','/backups/qa.sqlite');
  const backupCheck=compose('run','--rm','--no-deps','--entrypoint','node','backup','-e',"const {DatabaseSync}=require('node:sqlite'); const db=new DatabaseSync('/backups/qa.sqlite',{readOnly:true}); if(db.prepare('SELECT count(*) AS n FROM reports').get().n!==1)process.exit(1); db.close();");
  assert.equal((await request('/api/admin/logout',{admin:true,method:'POST',body:{},headers:{Cookie:cookie,'X-CSRF-Token':login.body.csrfToken}})).status,200);
  assert.equal((await request('/api/admin/reports',{admin:true,headers:{Cookie:cookie}})).status,401);
  const logs=compose('logs','--no-color','app');for(const secret of [ownerKey,cookie,login.body.csrfToken,'QA private visitor marker'])assert.ok(!logs.includes(secret));
  console.log('Docker smoke passed: verified TLS, admin isolation, Unix socket, login/logout, consent upload, anti-spoofing, online backup, private audit logs.');
}finally{
  if(created)compose('down','-v','--remove-orphans');
  await rm(temp,{recursive:true,force:true});
}
