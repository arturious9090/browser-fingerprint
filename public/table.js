import {describeField,nestedHelp} from './field-info.js';
const names={ok:'Доступно',unsupported:'Нет поддержки',blocked:'Заблокировано',error:'Ошибка',timeout:'Тайм-аут',unavailable:'Нет данных'};
export const valueText=value=>typeof value==='string'?value:JSON.stringify(value,null,2)??'Нет значения';
export function element(tag,text,cls){const node=document.createElement(tag);node.textContent=text;if(cls)node.className=cls;return node;}
export function renderParameterRows(rows,target,{emptyMessage='По этому фильтру ничего не найдено.'}={}){
  target.replaceChildren();if(!rows.length){target.append(element('div',emptyMessage,'empty'));return;}
  const wrap=element('div','','table-wrap'),table=document.createElement('table'),head=document.createElement('thead'),hrow=document.createElement('tr');for(const label of ['Параметр / справка','Значение','Статус / источник']){const th=element('th',label);th.scope='col';hrow.append(th);}head.append(hrow);table.append(head);const body=document.createElement('tbody');
  for(const row of rows){const tr=document.createElement('tr'),field=document.createElement('td'),val=document.createElement('td'),status=document.createElement('td');field.append(element('span',row.label,'field-label'),element('span',row.key??row.id,'field-key'),element('p',describeField(row),'field-description'));
    const output=row.value===null?'—':valueText(row.value);if(output.length>280){const details=document.createElement('details');details.className='value-details';details.append(element('summary',Array.isArray(row.value)?`Показать список (${row.value.length})`:'Показать значение полностью'),element('pre',output,'value'));val.append(details);}else val.append(element('pre',output,'value'));
    if(row.note&&!row.note.startsWith('Значение сообщено браузером;'))val.append(element('span',row.note,'field-note'));
    const nested=nestedHelp(row.value);if(nested.length){const details=document.createElement('details');details.className='nested-help';details.append(element('summary','Справка по вложенным полям'));const dl=document.createElement('dl');for(const info of nested)dl.append(element('dt',info.key),element('dd',info.description));details.append(dl);val.append(details);}
    status.append(element('span',names[row.status]??row.status,`badge ${row.status}`),element('span',({browser:'Браузер',server:'Сервер',edge:'Внешний прокси',optional:'По запросу',observation:'События вкладки'})[row.source]??row.source,'source-label'));tr.append(field,val,status);body.append(tr);
  }table.append(body);wrap.append(table);target.append(wrap);
}
