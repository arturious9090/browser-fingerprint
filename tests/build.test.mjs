import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile,readdir} from 'node:fs/promises';
import {createServer} from '../dist/server.mjs';
test('Node build contains persistence and admin code without private database or owner key',async()=>{
  assert.equal(typeof createServer,'function');for(const f of ['database.mjs','reports.mjs','public/admin.html','public/admin.js','public/field-info.js','public/table.js'])assert.ok((await readFile(new URL('../dist/'+f,import.meta.url),'utf8')).length);
  const names=await readdir(new URL('../dist/',import.meta.url));assert.ok(!names.includes('.data'));assert.ok(!names.includes('.openai'));assert.ok(!names.includes('.env'));
});
