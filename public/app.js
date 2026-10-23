import {collect,runProbe,profileHash,optionalProbes} from './collector.js';
import {analyze} from './signals.js';
import {snapshotRows} from './behavior.js';
import {CONSENT_VERSION,CONSENT_TEXT} from './consent.js';
const $=selector=>document.querySelector(selector);
const state={rows:[],profile:null,createdAt:null,running:false,saving:false,optionalActive:0};
function setStatus(message){$('#collection-status').textContent=message;}
function update(){const busy=state.running||state.saving||state.optionalActive>0;$('#scan').disabled=busy;$('#send-data').disabled=busy||!state.rows.length;$('#session-status').textContent=busy?'Выполняется проверка':'Диагностика браузера';}
async function api(path,body){const response=await fetch(path,{method:'POST',credentials:'same-origin',cache:'no-store',headers:{'Content-Type':'application/json'},body:JSON.stringify(body),signal:AbortSignal.timeout(15000)});const data=await response.json();if(!response.ok)throw new Error(data.error??`HTTP ${response.status}`);return data;}
function makeReport(){state.rows=state.rows.filter(r=>r.category!=='behavior').concat(snapshotRows());return {schemaVersion:1,createdAt:state.createdAt,profile:state.profile,rows:state.rows,signals:analyze(state.rows)};}
async function save(){
  if(state.saving||!state.rows.length)return;state.saving=true;update();setStatus('Отправка данных по вашему согласию…');
  try{const report=makeReport();const ticket=await api('/api/consent',{granted:true,version:CONSENT_VERSION});await api('/api/reports',{consent:{granted:true,version:CONSENT_VERSION},uploadToken:ticket.uploadToken,report});setStatus('Данные отправлены владельцу сайта. Проверка завершена.');}
  catch{setStatus('Не удалось подтвердить отправку. Для повторной попытки нажмите «Отправить данные» и подтвердите согласие снова.');}
  finally{state.saving=false;update();}
}
async function scan(share){
  if(state.running||state.saving||state.optionalActive)return;state.running=true;state.rows=[];state.profile=null;state.createdAt=new Date().toISOString();update();setStatus('Собираются диагностические данные…');
  try{state.rows=await collect(undefined,{includeServer:false});state.profile=await profileHash(state.rows);setStatus(share?'Проверка завершена. Подготовка отправки…':'Проверка завершена без отправки. Данные не сохранены на сервере.');}
  catch{setStatus('Не удалось завершить проверку. Попробуйте запустить её снова.');}
  finally{state.running=false;update();}
  if(share&&state.profile)await save();
}
function openConsent(existing=false){if(state.running||state.saving||state.optionalActive)return;const dialog=$('#consent-dialog');dialog.dataset.existing=String(existing);$('#consent-title').textContent=existing?'Отправить данные владельцу?':'Как запустить диагностику?';$('#consent-copy').textContent=CONSENT_TEXT;$('#consent-local').textContent=existing?'Не отправлять':'Только в браузере';dialog.showModal();}
$('#scan').onclick=()=>openConsent();$('#send-data').onclick=()=>openConsent(true);
$('#consent-local').onclick=()=>{const existing=$('#consent-dialog').dataset.existing==='true';$('#consent-dialog').close();if(!existing)scan(false);};
$('#consent-share').onclick=()=>{const existing=$('#consent-dialog').dataset.existing==='true';$('#consent-dialog').close();if(existing)save();else scan(true);};
$('#consent-cancel').onclick=()=>$('#consent-dialog').close();
for(const [key,probe]of Object.entries(optionalProbes)){
  const row=document.createElement('div');row.className='optional-row';const description=document.createElement('div'),title=document.createElement('h3'),copy=document.createElement('p'),button=document.createElement('button'),status=document.createElement('p');
  title.textContent=probe.title;copy.textContent=probe.description;status.className='optional-status';status.setAttribute('role','status');description.append(title,copy,status);button.textContent='Запустить проверку';button.dataset.optional=key;
  button.onclick=async()=>{if(state.running||state.saving||state.optionalActive)return;state.optionalActive++;update();button.disabled=true;status.textContent='Ожидание результата или решения браузера…';
    try{const rows=await runProbe({id:`optional.${key}`,category:'optional',source:'optional',label:probe.title,note:'Дополнительная проверка по явному действию посетителя.',run:probe.run},12000);state.rows=state.rows.filter(r=>r.id!==`optional.${key}`&&!r.id.startsWith(`optional.${key}.`)).concat(rows);state.createdAt??=new Date().toISOString();status.textContent=rows.some(r=>r.status==='ok')?'Проверка завершена. Для отправки данных нужно отдельное согласие.':'Проверка недоступна, не разрешена или не завершилась. Данные не отправлены.';setStatus('Дополнительная проверка завершена. Данные не отправляются автоматически.');}
    finally{state.optionalActive--;button.disabled=false;update();}
  };
  row.append(description,button);$('#optional-checks').append(row);
}
