import {DatabaseSync} from 'node:sqlite';
import {mkdirSync,existsSync,readFileSync,writeFileSync,chmodSync,statSync} from 'node:fs';
import path from 'node:path';
import {randomBytes,scrypt as scryptCallback,timingSafeEqual,createHash} from 'node:crypto';
import {promisify} from 'node:util';
const scrypt=promisify(scryptCallback);
export const digest=value=>createHash('sha256').update(value).digest('hex');
export async function hashKey(key,salt=randomBytes(24).toString('hex')){return {salt,hash:Buffer.from(await scrypt(key,salt,64)).toString('hex')};}
export async function verifyKey(key,credential){const candidate=Buffer.from(await scrypt(key,credential.salt,64));const expected=Buffer.from(credential.hash,'hex');return candidate.length===expected.length&&timingSafeEqual(candidate,expected);}
export async function openStore({dbPath=path.resolve('.data/fingerprints.sqlite'),ownerKey,maxReports=10000,maxDatabaseBytes=512*1024*1024,production=false}={}){
  if(dbPath!==':memory:')mkdirSync(path.dirname(dbPath),{recursive:true,mode:0o700});
  if(production&&dbPath!==':memory:'&&(statSync(path.dirname(dbPath)).mode&0o077))throw new Error('Каталог DATABASE_PATH должен иметь права 0700');
  const db=new DatabaseSync(dbPath);if(dbPath!==':memory:')chmodSync(dbPath,0o600);
  db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000; PRAGMA secure_delete=ON; PRAGMA wal_autocheckpoint=1000; PRAGMA journal_size_limit=16777216;
    CREATE TABLE IF NOT EXISTS owner(id INTEGER PRIMARY KEY CHECK(id=1), salt TEXT NOT NULL, hash TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS reports(id TEXT PRIMARY KEY, created_at TEXT NOT NULL, consent_at TEXT NOT NULL, consent_version TEXT NOT NULL, consent_text TEXT NOT NULL, fingerprint TEXT, ip TEXT, user_agent TEXT, row_count INTEGER NOT NULL, signal_count INTEGER NOT NULL, report_json TEXT NOT NULL, connection_json TEXT NOT NULL, revoke_hash TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS reports_created ON reports(created_at DESC);
    CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, csrf TEXT NOT NULL, created_at INTEGER NOT NULL, touched_at INTEGER NOT NULL, expires_at INTEGER NOT NULL);
    PRAGMA user_version=1;`);
  let credential=db.prepare('SELECT salt,hash FROM owner WHERE id=1').get();
  const keyPath=dbPath===':memory:'?null:path.join(path.dirname(dbPath),'owner-key.txt');
  if(keyPath&&existsSync(keyPath))chmodSync(keyPath,0o600);
  if(!credential){
    let key=ownerKey;
    if(!key){if(!keyPath)throw new Error('In-memory database requires ownerKey');key=existsSync(keyPath)?readFileSync(keyPath,'utf8').trim():randomBytes(32).toString('base64url');if(!existsSync(keyPath))writeFileSync(keyPath,key+'\n',{flag:'wx',mode:0o600});}
    if(key.length<32)throw new Error('Owner key must contain at least 32 characters');
    credential=await hashKey(key);db.prepare('INSERT INTO owner(id,salt,hash) VALUES(1,?,?)').run(credential.salt,credential.hash);
  }
  const pageSize=db.prepare('PRAGMA page_size').get().page_size;
  db.exec(`PRAGMA max_page_count=${Math.floor(maxDatabaseBytes/pageSize)}`);
  const insert=db.prepare('INSERT INTO reports VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)');
  function createSession(expectedCredential,previousToken){
    db.exec('BEGIN IMMEDIATE');
    try{
      if(expectedCredential){const current=db.prepare('SELECT salt,hash FROM owner WHERE id=1').get();if(current.hash!==expectedCredential.hash||current.salt!==expectedCredential.salt){db.exec('ROLLBACK');return null;}}
      const token=randomBytes(32).toString('base64url'),csrf=randomBytes(32).toString('base64url'),now=Date.now();
      if(previousToken)db.prepare('DELETE FROM sessions WHERE token_hash=?').run(digest(previousToken));
      db.prepare('DELETE FROM sessions WHERE expires_at <= ? OR touched_at <= ?').run(now,now-30*60*1000);
      db.prepare('DELETE FROM sessions WHERE token_hash IN (SELECT token_hash FROM sessions ORDER BY created_at DESC LIMIT -1 OFFSET 15)').run();
      db.prepare('INSERT INTO sessions VALUES(?,?,?,?,?)').run(digest(token),csrf,now,now,now+8*60*60*1000);
      db.exec('COMMIT');return {token,csrf};
    }catch(error){db.exec('ROLLBACK');throw error;}
  }
  return {dbPath,keyPath,
    async authenticate(key){const used=db.prepare('SELECT salt,hash FROM owner WHERE id=1').get();const valid=await verifyKey(key,used);const current=db.prepare('SELECT salt,hash FROM owner WHERE id=1').get();return valid&&used.hash===current.hash&&used.salt===current.salt;},
    async login(key,previousToken){const used=db.prepare('SELECT salt,hash FROM owner WHERE id=1').get();return await verifyKey(key,used)?createSession(used,previousToken):null;},
    save(report,connection,consent){
      if(db.prepare('SELECT count(*) AS count FROM reports').get().count>=maxReports)throw Object.assign(new Error('Лимит сохранённых отчётов достигнут'),{status:507});
      const id=randomBytes(16).toString('hex'),createdAt=new Date().toISOString(),ua=report.rows.find(r=>r.id==='navigator.userAgent')?.value;
      insert.run(id,createdAt,consent.at,consent.version,consent.text,report.profile?.hash??null,connection.observations.clientIP??connection.observations.peerAddress??null,typeof ua==='string'?ua.slice(0,2048):'',report.rows.length,report.signals.length,JSON.stringify(report),JSON.stringify(connection),'');return {id,createdAt};
    },
    prune(cutoff){return db.prepare('DELETE FROM reports WHERE id IN (SELECT id FROM reports WHERE created_at < ? ORDER BY created_at LIMIT 500)').run(cutoff).changes;},
    list({q='',limit=25,offset=0}={}){const pattern=`%${q.replace(/[\\%_]/g,'\\$&')}%`;const where="(?='' OR ip LIKE ? ESCAPE '\\' OR user_agent LIKE ? ESCAPE '\\' OR fingerprint LIKE ? ESCAPE '\\' OR id LIKE ? ESCAPE '\\')";const args=[q,pattern,pattern,pattern,pattern];const total=db.prepare(`SELECT count(*) AS total FROM reports WHERE ${where}`).get(...args).total;const rows=db.prepare(`SELECT id,created_at,consent_at,consent_version,fingerprint,ip,user_agent,row_count,signal_count FROM reports WHERE ${where} ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?`).all(...args,limit,offset);return {total,limit,offset,reports:rows};},
    get(id){const row=db.prepare('SELECT * FROM reports WHERE id=?').get(id);if(!row)return null;const {report_json,connection_json,revoke_hash,...metadata}=row;return {...metadata,report:JSON.parse(report_json),connection:JSON.parse(connection_json)};},
    createSession:()=>createSession(),
    session(token){if(!token||token.length>200)return null;const hash=digest(token),now=Date.now();const row=db.prepare('SELECT * FROM sessions WHERE token_hash=?').get(hash);if(!row)return null;if(row.expires_at<=now||row.touched_at<=now-30*60*1000){db.prepare('DELETE FROM sessions WHERE token_hash=?').run(hash);return null;}db.prepare('UPDATE sessions SET touched_at=? WHERE token_hash=?').run(now,hash);return {csrf:row.csrf,expiresAt:row.expires_at};},
    logout(token){if(token)db.prepare('DELETE FROM sessions WHERE token_hash=?').run(digest(token));},
    async rotateOwner(){const key=randomBytes(32).toString('base64url');const next=await hashKey(key);db.prepare('UPDATE owner SET salt=?,hash=? WHERE id=1').run(next.salt,next.hash);db.exec('DELETE FROM sessions');credential=next;if(keyPath)writeFileSync(keyPath,key+'\n',{mode:0o600});return keyPath;},
    close(){db.close();}
  };
}
