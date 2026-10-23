export const missing=(note)=>({__result:true,status:'unavailable',value:null,note});
const allowedHeaders=new Set(['host','user-agent','accept','accept-language','accept-encoding','priority','upgrade-insecure-requests','dnt','sec-gpc','save-data','sec-fetch-site','sec-fetch-mode','sec-fetch-user','sec-fetch-dest','sec-ch-ua','sec-ch-ua-mobile','sec-ch-ua-platform','sec-ch-ua-platform-version','sec-ch-ua-arch','sec-ch-ua-bitness','sec-ch-ua-model','sec-ch-ua-full-version','sec-ch-ua-full-version-list','sec-ch-ua-wow64','sec-ch-ua-form-factors','downlink','ect','rtt','viewport-width','width','device-memory','dpr']);
export function safeHeaders(headers){return Object.fromEntries([...headers.entries()].filter(([key])=>allowedHeaders.has(key)).map(([key,value])=>[key,value.slice(0,2048)]));}
export const responseHeaders={
  'Cache-Control':'no-store, max-age=0',
  'X-Content-Type-Options':'nosniff',
  'Referrer-Policy':'no-referrer',
  'Cross-Origin-Opener-Policy':'same-origin',
  'Cross-Origin-Resource-Policy':'same-origin',
  'Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; media-src 'self' blob:; object-src 'none'; base-uri 'none'; frame-ancestors 'self'; form-action 'none'",
  'Accept-CH':'Sec-CH-UA-Arch, Sec-CH-UA-Bitness, Sec-CH-UA-Full-Version-List, Sec-CH-UA-Model, Sec-CH-UA-Platform-Version, Sec-CH-UA-WoW64, Sec-CH-UA-Form-Factors',
  'Permissions-Policy':'camera=(self), microphone=(self), geolocation=(self), browsing-topics=()',
};
export function edgeConnection(request){
  const cf=request.cf;
  const observations={
    observedAt:new Date().toISOString(),runtime:'Cloudflare Worker',requestMethod:request.method,requestHeaders:safeHeaders(request.headers),
    peerAddress:missing('Worker не раскрывает TCP socket. CF-Connecting-IP отражает адрес, переданный инфраструктурой, и зависит от цепочки прокси.'),
    clientIP:cf?request.headers.get('cf-connecting-ip')??missing('Заголовок отсутствует'):missing('Нет подтверждённого edge-контекста'),
    rawClientHello:missing('Сырой TLS ClientHello не предоставляется Worker API'),
    residentialProxyVerdict:missing('Локальной репутационной базы нет. См. edge.botManagement, если сервис предоставляет данные.'),
  };
  for(const key of ['httpProtocol','tlsVersion','tlsCipher','asn','asOrganization','country','region','city','continent','colo','timezone','latitude','longitude','isEUCountry','clientTcpRtt','tlsClientAuth','botManagement']){
    // Never echo arbitrary request headers as trusted edge security metadata.
    observations[`edge.${key}`]=cf&&cf[key]!==undefined?cf[key]:missing('Данные не предоставлены доверенным edge-контекстом или недоступны на этом тарифе');
  }
  observations['edge.ja3']=cf?.botManagement?.ja3Hash??missing('JA3 не вычисляется в JavaScript; нужен внешний сервис с соответствующей функцией');
  observations['edge.ja4']=cf?.botManagement?.ja4??missing('JA4 не вычисляется в JavaScript; нужен внешний сервис с соответствующей функцией');
  observations.connectionScope='Наблюдения обслуживающей инфраструктуры для этого запроса; промежуточные прокси могут влиять на IP, протокол и TLS.';
  return {observations};
}
export function localConnection(req,context){
  const socket=req.socket;const headers=new Headers();for(const [key,value]of Object.entries(req.headers))if(value!==undefined)headers.set(key,Array.isArray(value)?value.join(', '):value);
  return {observations:{observedAt:new Date().toISOString(),runtime:'Node.js',requestMethod:req.method,httpVersion:req.httpVersion,peerAddress:socket.remoteAddress??null,peerPort:socket.remotePort??null,peerFamily:socket.remoteFamily??null,localAddress:socket.localAddress??null,localPort:socket.localPort??null,encrypted:!!socket.encrypted,tlsVersion:socket.getProtocol?.()??missing('Локальный HTTP-сервер: TLS здесь не завершается'),tlsCipher:socket.getCipher?.()??missing('TLS здесь не завершается'),alpnProtocol:socket.alpnProtocol??missing('ALPN отсутствует на HTTP-соединении'),requestHeaders:safeHeaders(headers),clientIP:context?.ip??socket.remoteAddress??null,clientScheme:context?.scheme??(socket.encrypted?'https':'http'),forwardedHeadersTrusted:context?.proxied===true,connectionScope:context?.proxied?'IP и схема переданы Caddy по локальному Unix socket; это наблюдение reverse proxy. TLS до клиента здесь не измеряется.':'Адрес socket — непосредственный сосед сервера. X-Forwarded-For и CF-* не считаются доверенными.',ja3:missing('Node-сервер не вычисляет отпечаток TLS ClientHello'),ja4:missing('Нужен TLS-терминатор или доверенный внешний сервис'),asn:missing('Не подключён внешний IP/ASN-сервис'),residentialProxyVerdict:missing('Нельзя определить тип прокси только по socket и браузерному отпечатку')}};
}
