import {isIP} from 'node:net';

export const fail=(status,message)=>Object.assign(new Error(message),{status});
export function origin(value,name){
  let url;try{url=new URL(value);}catch{throw new Error(`${name}: нужен абсолютный URL`);}
  if(!['http:','https:'].includes(url.protocol)||url.username||url.password||url.pathname!=='/'||url.search||url.hash)throw new Error(`${name}: укажите только схему и адрес, без пути и пароля`);
  return url.origin;
}
export const isLoopback=host=>['localhost','127.0.0.1','[::1]'].includes(host);
function integer(value,fallback,min,max,name){const n=value===undefined?fallback:Number(value);if(!Number.isSafeInteger(n)||n<min||n>max)throw new Error(`${name}: допустимо целое число ${min}–${max}`);return n;}
export function configuration(options={},env=process.env){
  const production=options.production??env.NODE_ENV==='production';
  const publicOrigin=options.publicOrigin??env.PUBLIC_ORIGIN;
  const configured=publicOrigin?origin(publicOrigin,'PUBLIC_ORIGIN'):null;
  if(configured&&new URL(configured).protocol!=='https:'&&!isLoopback(new URL(configured).hostname))throw new Error('PUBLIC_ORIGIN должен использовать HTTPS');
  const adminOrigin=origin(options.adminOrigin??env.ADMIN_ORIGIN??'http://127.0.0.1:8080','ADMIN_ORIGIN');
  const proxySocketPath=options.proxySocketPath??env.PROXY_SOCKET;
  if(production){
    if(!configured||!configured.startsWith('https://'))throw new Error('В production требуется PUBLIC_ORIGIN с HTTPS');
    if(!proxySocketPath?.startsWith('/'))throw new Error('В production требуется абсолютный PROXY_SOCKET; TCP-порт приложения не публикуется');
    if(!isLoopback(new URL(adminOrigin).hostname)||!adminOrigin.startsWith('http://'))throw new Error('ADMIN_ORIGIN должен быть локальным HTTP-адресом SSH-туннеля');
  }
  return {
    production,publicOrigin:configured,adminOrigin,proxySocketPath,
    requestsPerMinute:integer(options.requestsPerMinute??env.REQUESTS_PER_MINUTE,240,1,10000,'REQUESTS_PER_MINUTE'),
    uploadsPerHour:integer(options.uploadsPerHour??env.UPLOADS_PER_HOUR,30,1,10000,'UPLOADS_PER_HOUR'),
    globalUploadsPerHour:integer(options.globalUploadsPerHour??env.GLOBAL_UPLOADS_PER_HOUR,1000,1,100000,'GLOBAL_UPLOADS_PER_HOUR'),
    maxReports:integer(options.maxReports??env.MAX_REPORTS,10000,1,1000000,'MAX_REPORTS'),
    maxDatabaseBytes:integer(options.maxDatabaseBytes??env.MAX_DATABASE_BYTES,512*1024*1024,1024*1024,16*1024**3,'MAX_DATABASE_BYTES'),
    retentionDays:integer(options.retentionDays??env.RETENTION_DAYS,production?30:0,0,3650,'RETENTION_DAYS'),
  };
}

// Only a local Unix socket can supply trusted proxy observations. No IP range
// or client-provided Forwarded/CF-* header grants trust.
export function clientContext(req,config){
  const peer=req.socket.remoteAddress;
  const proxied=!!config.proxySocketPath&&!peer;
  if(config.production&&!proxied)throw fail(403,'Прямой доступ к приложению запрещён');
  if(proxied){
    const ip=req.headers['x-real-ip'],scheme=req.headers['x-forwarded-proto'];
    if(typeof ip!=='string'||!isIP(ip)||!['http','https'].includes(scheme))throw fail(400,'Некорректное наблюдение прокси');
    return {ip:normalizeIP(ip),scheme,proxied:true};
  }
  return {ip:normalizeIP(peer??'unknown'),scheme:req.socket.encrypted?'https':'http',proxied:false};
}
export function normalizeIP(ip){return ip.startsWith('::ffff:')&&isIP(ip.slice(7))===4?ip.slice(7):ip;}
// Group IPv6 addresses by /64 so privacy address rotation is not a free new
// quota. A proxy network with many independent addresses still needs upstream protection.
export function rateIdentity(ip){
  if(isIP(ip)!==6)return ip;
  const [left,right='']=ip.split('::'),a=left?left.split(':'):[],b=right?right.split(':'):[];
  const groups=[...a,...Array(8-a.length-b.length).fill('0'),...b];
  return groups.slice(0,4).map(x=>parseInt(x,16).toString(16)).join(':')+'::/64';
}
export function createLimiter({maxKeys=10000,now=Date.now}={}){
  const entries=new Map();
  return (key,limit,windowMs)=>{
    const time=now();let item=entries.get(key);
    if(!item||item.until<=time){
      if(entries.size>=maxKeys){for(const [k,v]of entries)if(v.until<=time)entries.delete(k);if(entries.size>=maxKeys&&!entries.has(key))throw fail(503,'Лимит нагрузки сервиса достигнут');}
      item={count:0,until:time+windowMs};entries.set(key,item);
    }
    if(++item.count>limit){const error=fail(429,'Слишком много запросов. Попробуйте позже.');error.retryAfter=Math.max(1,Math.ceil((item.until-time)/1000));throw error;}
  };
}

export function assertJSONComplexity(value,{maxDepth=16,maxNodes=30000}={}){
  const queue=[[value,0]];let count=0;
  while(queue.length){const [item,depth]=queue.pop();if(++count>maxNodes||depth>maxDepth)throw fail(400,'Слишком сложная структура JSON');if(item&&typeof item==='object'){for(const [key,child]of Object.entries(item)){if(['__proto__','prototype','constructor'].includes(key))throw fail(400,'Недопустимое имя поля JSON');queue.push([child,depth+1]);}}}
}
