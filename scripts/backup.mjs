import {DatabaseSync,backup} from 'node:sqlite';
import {mkdir,chmod,stat} from 'node:fs/promises';
import path from 'node:path';
process.umask(0o077);
const source=process.env.DATABASE_PATH??path.resolve('.data/fingerprints.sqlite');
const target=path.resolve(process.argv[2]??`/backups/fingerprints-${new Date().toISOString().replaceAll(':','-')}.sqlite`);
if(target===path.resolve(source))throw new Error('Резервная копия должна иметь другой путь');
await mkdir(path.dirname(target),{recursive:true,mode:0o700});
try{await stat(target);throw new Error('Файл назначения уже существует');}catch(e){if(e.code!=='ENOENT')throw e;}
const db=new DatabaseSync(source,{readOnly:true});
try{await backup(db,target);await chmod(target,0o600);const copy=new DatabaseSync(target,{readOnly:true});try{if(copy.prepare('PRAGMA quick_check').get().quick_check!=='ok')throw new Error('Проверка резервной копии не прошла');}finally{copy.close();}console.log(`Резервная копия проверена: ${target}`);}finally{db.close();}
