import test from 'node:test';
import {fixture} from './runtime-fixture.mjs';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readFile,copyFile,rm,realpath} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {execFileSync,spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {run} from '../../scripts/verify-wedding-backup-staging.mjs';
import {fixtures,sha,digest,id,secret} from './fixtures.mjs';
const hash=x=>createHash('sha256').update(x).digest('hex'),node=process.execPath;
const source=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../../scripts');
for(const flag of [undefined,'false'])test('runner omitted/false performs no setup: '+String(flag),async()=>{
 assert.deepEqual(await run({WEDDING_BACKUP_VERIFY:flag}),{code:0,result:{verified:false,skipped:true}});
});
test('true refuses missing wait/publish success before setup',async()=>{
 assert.deepEqual(await run({WEDDING_BACKUP_VERIFY:'true'}),{code:2,result:{verified:false}});
});
test('real one-use CLI joins same-job publication and compares only two synthetic pairs',async t=>{
 const f=await fixture(t),entry=path.join(f.dir,'scripts/verify-wedding-backup-staging.mjs');
 const child=spawnSync(node,[entry],{cwd:f.dir,env:f.env,encoding:'utf8',stdio:['ignore','pipe','pipe']});assert.equal(child.status,0);assert.equal(child.stderr,'');const stdout=child.stdout;
 const result=JSON.parse(stdout);assert.deepEqual(result,{verified:true,projectionEqual:true,liveSourceStable:true,sourceSha:f.commit,digest,run:'12345'});
 const reads=(await readFile(path.join(f.dir,'reads'),'utf8')).trim().split('\n');assert.equal(reads.length,20);assert.equal(reads.filter(x=>x.includes('/Secret/')).length,4);assert.equal(stdout.includes(id)||stdout.includes(secret),false);
});
for(const [label,patch] of [['failed wait',{WEDDING_BACKUP_WAIT_RESULT:'failure'}],['missing digest',{WEDDING_BACKUP_DIGEST:''}],['wrong invocation',{GITHUB_EVENT_NAME:'pull_request'}],['rerun',{GITHUB_RUN_ATTEMPT:'2'}],['wrong ciphertext',{WEDDING_BACKUP_CIPHER_SHA256:'f'.repeat(64)}],['different workflow revision',{GITHUB_WORKFLOW_SHA:'f'.repeat(40)}],['different event revision',{GITHUB_SHA:'f'.repeat(40)}]])test('real CLI '+label+' makes no API reads',async t=>{
 const f=await fixture(t);let result;
 try{execFileSync(node,[path.join(f.dir,'scripts/verify-wedding-backup-staging.mjs')],{cwd:f.dir,env:{...f.env,...patch},encoding:'utf8',stdio:['ignore','pipe','pipe']});assert.fail('accepted');}catch(e){assert.equal(e.status,2);assert.equal(e.stderr,'');result=e.stdout;}
 assert.deepEqual(JSON.parse(result),{verified:false});await assert.rejects(readFile(path.join(f.dir,'reads')));
});
