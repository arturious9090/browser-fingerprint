import test from 'node:test';
import assert from 'node:assert/strict';
import {analyze} from '../public/signals.js';
import {runProbe,profileHash} from '../public/collector.js';
import {safeHeaders,localConnection,edgeConnection} from '../connection.mjs';
const row=(id,value,status='ok')=>({id,value,status});
test('a normal real-browser profile is not flagged just for missing plugins, cookies or mouse',()=>{
  assert.deepEqual(analyze([row('navigator.webdriver',false),row('navigator.plugins',[]),row('navigator.cookieEnabled',false),row('behavior.pointerEvents',0)]),[]);
});
test('webdriver explicitly reports automation, not maliciousness',()=>{
  const signals=analyze([row('navigator.webdriver',true)]);assert.equal(signals.length,1);assert.equal(signals[0].strength,'strong');assert.match(signals[0].falsePositives,/автотесты/);
});
test('software GPU is contextual rather than a hard verdict',()=>{const s=analyze([row('webgl.unmaskedRenderer','Google SwiftShader')]);assert.equal(s[0].strength,'context');});
test('no Canvas hash is not treated as randomized Canvas',()=>{assert.deepEqual(analyze([row('canvas.pixelHash',null,'blocked'),row('canvas.repeatPixelHash',null,'blocked')]),[]);});
test('inconsistent repeated Canvas is contextual',()=>{assert.equal(analyze([row('canvas.pixelHash','a'),row('canvas.repeatPixelHash','b')])[0].strength,'context');});
test('errors in a probe are isolated and reported',async()=>{const r=await runProbe({id:'broken',category:'browser',run:()=>{throw new Error('failed');}});assert.equal(r[0].status,'error');assert.match(r[0].note,/failed/);});
test('unsupported APIs and denied permissions are distinguishable',async()=>{for(const [name,status] of [['NotSupportedError','unsupported'],['NotAllowedError','blocked']]){const r=await runProbe({id:'probe',run:()=>{throw Object.assign(new Error(name),{name});}});assert.equal(r[0].status,status);}});
test('a hanging probe times out',async()=>{const r=await runProbe({id:'hang',run:()=>new Promise(()=>{})},10);assert.equal(r[0].status,'timeout');});
test('nonfinite numbers and typed arrays survive JSON export explicitly',async()=>{const r=await runProbe({id:'data',run:()=>({inf:Infinity,nan:NaN,array:new Int32Array([1,2])})});assert.equal(r[0].value,'Infinity');assert.equal(r[1].value,'NaN');assert.deepEqual(r[2].value,[1,2]);});
test('profile hash excludes clocks, IP addresses and volatile storage quota',async()=>{const a=[row('navigator.platform','MacIntel'),row('server.peerAddress','127.0.0.1'),row('intl.dateString','today')];const b=[row('intl.dateString','tomorrow'),row('server.peerAddress','10.0.0.1'),row('navigator.platform','MacIntel')];assert.equal((await profileHash(a)).hash,(await profileHash(b)).hash);assert.notEqual((await profileHash(a)).hash,(await profileHash([row('navigator.platform','Linux')])).hash);});
test('only safe request headers are returned: cookies and credentials excluded',()=>{const headers=new Headers({'cookie':'secret=private','authorization':'Bearer private','x-api-key':'private','user-agent':'Browser','cf-access-jwt-assertion':'private'});assert.deepEqual(safeHeaders(headers),{'user-agent':'Browser'});});
test('local server does not trust spoofed proxy/security headers',()=>{const r=localConnection({method:'GET',httpVersion:'1.1',headers:{'x-forwarded-for':'1.2.3.4','cf-connecting-ip':'5.6.7.8','x-bot-score':'99'},socket:{remoteAddress:'127.0.0.1'}}).observations;assert.equal(r.peerAddress,'127.0.0.1');assert.equal(r.forwardedHeadersTrusted,false);assert.equal(r.ja4.status,'unavailable');assert.deepEqual(r.requestHeaders,{});});
test('edge metadata is unavailable without platform context',()=>{const req=new Request('https://example.com',{headers:{'cf-connecting-ip':'spoof','x-ja4':'spoof'}});const o=edgeConnection(req).observations;assert.equal(o.clientIP.status,'unavailable');assert.equal(o['edge.ja4'].status,'unavailable');});
test('edge metadata comes from request.cf and client values cannot replace it',()=>{const req=new Request('https://example.com',{headers:{'x-ja4':'spoof'}});Object.defineProperty(req,'cf',{value:{httpProtocol:'HTTP/2',tlsVersion:'TLSv1.3',botManagement:{score:12,ja4:'observed'}}});const o=edgeConnection(req).observations;assert.equal(o['edge.ja4'],'observed');assert.equal(o['edge.tlsVersion'],'TLSv1.3');});
