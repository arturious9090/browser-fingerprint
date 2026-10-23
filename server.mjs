import http from 'node:http';
import {readFile,lstat,unlink,chmod} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import {randomBytes,timingSafeEqual} from 'node:crypto';
import {responseHeaders,localConnection} from './connection.mjs';
import {openStore,digest} from './database.mjs';
import {validateReport} from './reports.mjs';
import {configuration,clientContext,createLimiter,rateIdentity,assertJSONComplexity,fail} from './security.mjs';
import {CONSENT_VERSION,CONSENT_TEXT} from './public/consent.js';
import {createAuditLogger} from './audit.mjs';
const root=path.join(path.dirname(fileURLToPath(import.meta.url)),'public');
const files=['index.html','styles.css','app.js','collector.js','signals.js','behavior.js','consent.js','field-info.js','table.js','admin.html','admin.js','admin.css'];
function equal(a,b){if(typeof a!=='string'||typeof b!=='string')return false;const x=Buffer.from(a),y=Buffer.from(b);return x.length===y.length&&timingSafeEqual(x,y);}
function sessionToken(req){return /(?:^|;\s*)fp_admin=([A-Za-z0-9_-]{43})(?:;|$)/.exec(req.headers.cookie??'')?.[1];}
async function jsonBody(req,max=2*1024*1024){
  if(!/^application\/json(?:\s*;|$)/i.test(req.headers['content-type']??''))throw fail(415,'Нужен Content-Type application/json');
  if(req.headers['content-encoding']&&req.headers['content-encoding']!=='identity')throw fail(415,'Сжатые тела запросов не поддерживаются');
  if(Number(req.headers['content-length'])>max)throw fail(413,'Превышен допустимый размер запроса');
  const deadline=setTimeout(()=>req.destroy(),15000);deadline.unref();
  try{
    const chunks=[];let size=0;for await(const chunk of req.iterator({destroyOnReturn:false})){size+=chunk.length;if(size>max)throw fail(413,'Превышен допустимый размер запроса');chunks.push(chunk);}
    let value;try{value=JSON.parse(Buffer.concat(chunks).toString('utf8'));}catch{throw fail(400,'Некорректный JSON');}
    if(!value||Array.isArray(value)||typeof value!=='object')throw fail(400,'Некорректный JSON');
    assertJSONComplexity(value);return value;
  }finally{clearTimeout(deadline);}
}
export async function createServer(options={}){
  const config=configuration(options);const dbPath=options.dbPath??process.env.DATABASE_PATH??path.resolve('.data/fingerprints.sqlite');
  const assets=new Map(await Promise.all(files.map(async f=>['/'+f,{body:await readFile(path.join(root,f)),type:f.endsWith('.html')?'text/html; charset=utf-8':f.endsWith('.css')?'text/css; charset=utf-8':'text/javascript; charset=utf-8'}])));
  assets.set('/',assets.get('/index.html'));assets.set('/admin',assets.get('/admin.html'));assets.set('/admin/',assets.get('/admin.html'));
  const store=await openStore({dbPath,ownerKey:options.ownerKey,maxReports:config.maxReports,maxDatabaseBytes:config.maxDatabaseBytes,production:config.production});
  const tickets=new Map(),throttle=createLimiter();let loginActive=false,active=0;
  const audit=createAuditLogger({sink:options.auditSink??(config.production?undefined:()=>{})});
  const cleanup=()=>{const now=Date.now();for(const [key,ticket]of tickets)if(ticket.expiresAt<=now)tickets.delete(key);if(config.retentionDays)store.prune(new Date(now-config.retentionDays*86400000).toISOString());};
  cleanup();const cleanupTimer=setInterval(()=>{try{cleanup();}catch{console.error(JSON.stringify({event:'maintenance_failed'}));}},10*60*1000);cleanupTimer.unref();
  const server=http.createServer({maxHeaderSize:16384,requestTimeout:30000,headersTimeout:10000,connectionsCheckingInterval:1000},async(req,res)=>{
    const requestId=randomBytes(8).toString('hex');
    for(const [key,value]of Object.entries(responseHeaders))res.setHeader(key,value);
    res.setHeader('X-Request-ID',requestId);res.setHeader('X-Frame-Options','DENY');res.setHeader('X-Robots-Tag','noindex, nofollow, noarchive');
    res.setHeader('Content-Security-Policy',responseHeaders['Content-Security-Policy'].replace("frame-ancestors 'self'","frame-ancestors 'none'"));
    const send=(status,body,extra={})=>{if(res.destroyed)return;res.writeHead(status,{'Content-Type':'application/json; charset=utf-8',...extra});res.end(req.method==='HEAD'?undefined:JSON.stringify(body));};
    let counted=false;
    try{
      if(req.url?.length>2048)throw fail(414,'Слишком длинный адрес запроса');
      // Node receives only origin-form request targets; normalize neither encoded
      // slashes nor path segments before the allowlist check.
      if(!req.url?.startsWith('/')||req.url.startsWith('//'))throw fail(400,'Некорректный адрес запроса');
      const pathname=req.url.split('?')[0];
      if(pathname==='/healthz'&&req.method==='GET'){send(200,{ok:true});return;}
      if(active>=8)throw fail(503,'Сервис занят. Попробуйте позже.');active++;counted=true;
      const context=clientContext(req,config),identity=rateIdentity(context.ip);
      const port=req.socket.localPort;const localOrigins=[`http://127.0.0.1:${port}`,`http://localhost:${port}`,`http://[::1]:${port}`];
      const origins=config.production?[config.publicOrigin,config.adminOrigin]:config.publicOrigin?[config.publicOrigin,...localOrigins]:localOrigins;
      const requestOrigin=origins.find(o=>new URL(o).host===req.headers.host);
      if(!requestOrigin)throw fail(421,'Неверный адрес сервера');
      if(config.production&&context.scheme!==new URL(requestOrigin).protocol.slice(0,-1))throw fail(400,'Неверная схема соединения');
      const adminPath=pathname.startsWith('/api/admin')||/^\/admin(?:[/.]|$)/.test(pathname);
      if(config.production&&adminPath&&requestOrigin!==config.adminOrigin)throw fail(404,'Страница не найдена');
      if(context.scheme==='https')res.setHeader('Strict-Transport-Security','max-age=31536000');
      throttle(`request:${identity}`,config.requestsPerMinute,60000);
      if(pathname.startsWith('/api/')&&((req.headers.origin&&req.headers.origin!==requestOrigin)||['cross-site','same-site'].includes(req.headers['sec-fetch-site']))){audit('origin_denied',requestId,403);throw fail(403,'Запрос должен исходить с этого сайта');}
      const mutating=!['GET','HEAD'].includes(req.method);
      if(mutating&&(req.headers.origin!==requestOrigin||['cross-site','same-site'].includes(req.headers['sec-fetch-site']))){audit('origin_denied',requestId,403);throw fail(403,'Запрос должен исходить с этого сайта');}
      const token=sessionToken(req);let session;
      if(pathname.startsWith('/api/admin/')&&pathname!=='/api/admin/login'){
        session=store.session(token);if(!session){audit('session_denied',requestId,401);throw fail(401,'Требуется вход владельца');}
        if(mutating&&!equal(req.headers['x-csrf-token'],session.csrf)){audit('csrf_denied',requestId,403);throw fail(403,'Неверный CSRF-токен');}
      }
      if(pathname==='/api/config'&&req.method==='GET'){send(200,{storageAvailable:true,consentVersion:CONSENT_VERSION,consentText:CONSENT_TEXT});return;}
      if(pathname==='/api/admin/connection'&&['GET','HEAD'].includes(req.method)){send(200,localConnection(req,context));return;}
      if(pathname==='/api/ping'&&['GET','HEAD'].includes(req.method)){send(200,{ok:true});return;}
      if(pathname==='/api/consent'&&req.method==='POST'){
        throttle(`consent:${identity}`,config.uploadsPerHour,3600000);throttle('consent:global',config.globalUploadsPerHour*2,3600000);
        const body=await jsonBody(req,4096);if(body.granted!==true||body.version!==CONSENT_VERSION)throw fail(400,'Необходимо явное согласие с текущими условиями');
        const now=Date.now();for(const [key,v]of tickets)if(v.expiresAt<=now)tickets.delete(key);if(tickets.size>=2000)throw fail(503,'Сервис сохранения занят. Попробуйте позже.');
        const uploadToken=randomBytes(32).toString('base64url');tickets.set(digest(uploadToken),{at:new Date().toISOString(),expiresAt:now+10*60*1000,identity,origin:requestOrigin});send(201,{uploadToken,expiresInSeconds:600});return;
      }
      if(pathname==='/api/reports'&&req.method==='POST'){
        throttle(`upload:${identity}`,config.uploadsPerHour,3600000);throttle('upload:global',config.globalUploadsPerHour,3600000);
        const body=await jsonBody(req);if(body.consent?.granted!==true||body.consent?.version!==CONSENT_VERSION||typeof body.uploadToken!=='string'||body.uploadToken.length!==43)throw fail(400,'Нет согласия на сохранение');
        const ticketKey=digest(body.uploadToken),ticket=tickets.get(ticketKey);
        if(!ticket||ticket.expiresAt<=Date.now()||ticket.identity!==identity||ticket.origin!==requestOrigin)throw fail(403,'Согласие истекло или уже использовано. Подтвердите отправку снова.');
        const report=validateReport(body.report);store.save(report,localConnection(req,context),{at:ticket.at,version:CONSENT_VERSION,text:CONSENT_TEXT});tickets.delete(ticketKey);send(201,{saved:true});return;
      }
      const cookie=(value,maxAge)=>`fp_admin=${value}; HttpOnly; SameSite=Strict; Path=/api/admin; Max-Age=${maxAge}${context.scheme==='https'||(!config.production&&config.publicOrigin?.startsWith('https:'))?'; Secure':''}`;
      if(pathname==='/api/admin/login'&&req.method==='POST'){
        throttle(`login:${identity}`,5,15*60*1000);throttle('login:global',30,15*60*1000);
        const body=await jsonBody(req,4096);if(typeof body.key!=='string'||body.key.length<32||body.key.length>256){audit('login_denied',requestId,401);throw fail(401,'Неверный ключ владельца');}
        // Acquire after reading the body: an await before acquiring would let
        // multiple slow requests enter expensive scrypt work simultaneously.
        if(loginActive)throw fail(429,'Вход уже проверяется. Попробуйте позже.');
        loginActive=true;let created;try{created=await store.login(body.key,token);}finally{loginActive=false;}
        if(!created){audit('login_denied',requestId,401);throw fail(401,'Неверный ключ владельца');}
        audit('login_success',requestId,200);send(200,{authenticated:true,csrfToken:created.csrf},{'Set-Cookie':cookie(created.token,8*60*60)});return;
      }
      if(pathname==='/api/admin/session'&&req.method==='GET'){send(200,{authenticated:true,csrfToken:session.csrf,expiresAt:session.expiresAt});return;}
      if(pathname==='/api/admin/logout'&&req.method==='POST'){store.logout(token);audit('logout',requestId,200);send(200,{authenticated:false},{'Set-Cookie':cookie('',0)});return;}
      if(pathname==='/api/admin/reports'&&req.method==='GET'){
        const url=new URL(req.url,'http://localhost'),limit=Math.min(100,Math.max(1,Number(url.searchParams.get('limit'))||25)),offset=Math.max(0,Math.min(1000000,Number(url.searchParams.get('offset'))||0)),q=(url.searchParams.get('q')??'').slice(0,256);const result=store.list({q,limit:Math.floor(limit),offset:Math.floor(offset)});audit('reports_read',requestId,200);send(200,result);return;
      }
      const detail=/^\/api\/admin\/reports\/([a-f0-9]{32})$/.exec(pathname);
      if(detail&&req.method==='GET'){const report=store.get(detail[1]);if(!report)throw fail(404,'Отчёт не найден');audit('report_read',requestId,200);send(200,report);return;}
      if(pathname.startsWith('/api/'))throw fail(404,'Endpoint не найден');
      if(!['GET','HEAD'].includes(req.method))throw fail(405,'Метод не поддерживается');
      const asset=assets.get(pathname);if(!asset)throw fail(404,'Страница не найдена');res.writeHead(200,{'Content-Type':asset.type});res.end(req.method==='HEAD'?undefined:asset.body);
    }catch(e){
      const status=e.status??(e.code==='ERR_SQLITE_ERROR'&&/full/i.test(e.message)?507:500);
      if(status===429)audit('rate_limited',requestId,status);else if(status===507)audit('quota_reached',requestId,status);else if(status>=500)audit('request_failed',requestId,status);
      // Drain rejected input without buffering it so clients can read the error
      // response. HTTP request deadlines and the proxy body limit still apply.
      if(!req.complete)req.resume();
      if(!res.headersSent)send(status,{error:e.status?e.message:status===507?'Хранилище заполнено':'Не удалось обработать запрос',requestId},e.retryAfter?{'Retry-After':String(e.retryAfter)}:{});else res.end();
    }finally{if(counted)active--;}
  });
  server.maxHeadersCount=100;server.maxConnections=256;server.maxRequestsPerSocket=100;server.keepAliveTimeout=5000;
  server.on('close',()=>{clearInterval(cleanupTimer);store.close();});server.store=store;server.config=config;return server;
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  process.umask(0o077);
  const server=await createServer(),config=server.config;
  if(config.proxySocketPath){
    try{const info=await lstat(config.proxySocketPath);if(!info.isSocket())throw new Error('PROXY_SOCKET существует и не является socket');await unlink(config.proxySocketPath);}catch(e){if(e.code!=='ENOENT')throw e;}
    server.listen(config.proxySocketPath,async()=>{await chmod(config.proxySocketPath,0o660);console.log('Fingerprint Lab: Unix socket ready');});
  }else{
    const port=Number(process.env.PORT??4173),host=process.env.HOST??'127.0.0.1';
    if(!Number.isInteger(port)||port<1||port>65535)throw new Error('PORT должен быть числом от 1 до 65535');
    server.listen(port,host,()=>console.log(`Fingerprint Lab: http://${host}:${server.address().port}`));
  }
  console.log(`SQLite: ${server.store.dbPath}`);console.log(`Ключ владельца: ${server.store.keyPath} (не публикуйте этот файл)`);
  server.on('error',()=>{console.error('Не удалось запустить сервер');process.exitCode=1;});
  let stopping=false;const shutdown=()=>{if(stopping)return;stopping=true;server.close(()=>process.exit(0));server.closeIdleConnections();setTimeout(()=>{server.closeAllConnections();process.exit(1);},10000).unref();};
  process.on('SIGTERM',shutdown);process.on('SIGINT',shutdown);
}
