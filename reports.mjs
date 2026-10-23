import {analyze} from './public/signals.js';
import {assertJSONComplexity} from './security.mjs';
const statuses=new Set(['ok','unsupported','blocked','error','timeout','unavailable']);
const sources=new Set(['browser','server','edge','optional','observation']);
const categories=new Set(['browser','device','locale','graphics','audio','fonts','media','storage','permissions','capabilities','network','server','behavior','optional']);
export function validateReport(input){
  assertJSONComplexity(input);
  const bad=()=>{throw Object.assign(new Error('Некорректный формат отчёта'),{status:400});};
  if(!input||input.schemaVersion!==1||!Array.isArray(input.rows)||input.rows.length<1||input.rows.length>2000)bad();
  const seen=new Set();const rows=input.rows.map(row=>{
    if(!row||typeof row.id!=='string'||row.id.length<1||row.id.length>240||/[\u0000-\u001f\u007f]/u.test(row.id)||seen.has(row.id)||!statuses.has(row.status)||!sources.has(row.source)||!categories.has(row.category))bad();seen.add(row.id);
    const value=row.value??null;const serialized=JSON.stringify(value);if(serialized.length>400000)bad();
    return {id:row.id,key:row.id,label:typeof row.label==='string'?row.label.slice(0,240):row.id,value,status:row.status,source:row.source,category:row.category,note:typeof row.note==='string'?row.note.slice(0,2000):'',durationMs:typeof row.durationMs==='number'&&Number.isFinite(row.durationMs)?Math.max(0,row.durationMs):0};
  });
  const createdAt=typeof input.createdAt==='string'&&!Number.isNaN(Date.parse(input.createdAt))?new Date(input.createdAt).toISOString():null;
  const hash=input.profile?.hash;const profile=typeof hash==='string'&&/^[a-f0-9]{64}$/.test(hash)?{hash,algorithm:'SHA-256',fields:Array.isArray(input.profile.fields)?input.profile.fields.filter(x=>typeof x==='string'&&seen.has(x)).slice(0,100):[],note:'Хеш сообщён клиентом. Не уникальный ID и не подтверждение подлинности.'}:null;
  return {schemaVersion:1,createdAt,rows,profile,signals:analyze(rows),trust:'Значения и источник строк сообщены посетителем; это не подтверждённые сервером факты. Серверное наблюдение при сохранении хранится отдельно.'};
}
