import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,readFile,mkdir,rm,symlink,realpath} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {capture,createReader,createSourceGuard} from '../../scripts/wedding-backup-io.mjs';
const node=process.execPath,hash=b=>createHash('sha256').update(b).digest('hex');
async function temp(t){const p=await realpath(await mkdtemp(path.join(tmpdir(),'projection-io-')));t.after(()=>rm(p,{recursive:true,force:true}));return p;}
test('bounded private capture returns stdout without diagnostic output',async()=>{
 assert.equal((await capture(node,['-e','process.stderr.write("synthetic-private");process.stdout.write("okay")'],{env:{PATH:'/usr/bin:/bin'}})).toString(),'okay');
});
for(const [label,code,options] of [
 ['overflow','process.stdout.write("x".repeat(9000))',{maxBytes:100}],
 ['timeout','setTimeout(()=>{},5000)',{timeout:30}],
 ['child error','process.stderr.write("synthetic-private");process.exit(1)',{}]
])test(label+' returns only fixed refusal',async()=>{
 await assert.rejects(capture(node,['-e',code],{env:{PATH:'/usr/bin:/bin'},...options}),e=>e.message==='subprocess_refused');
});
test('reader invokes only the selected object with an explicit context and config',async t=>{
 const dir=await temp(t),bin=path.join(dir,'kubectl'),config=path.join(dir,'config');
 const source=`#!${node}\nconst expected=['--kubeconfig',${JSON.stringify(config)},'--context','admin@prod','--namespace','flux-system','get','secrets','wedding-db-backup-r2-bootstrap','--output=json','--request-timeout=20s'];if(JSON.stringify(process.argv.slice(2))!==JSON.stringify(expected))process.exit(3);if(Object.keys(process.env).some(x=>!['PATH','__CF_USER_TEXT_ENCODING'].includes(x)))process.exit(4);process.stdout.write(JSON.stringify({apiVersion:'v1',kind:'Secret'}));`;
 await writeFile(bin,source,{mode:0o700});
 const read=createReader({kubectl:bin,kubeconfig:config});
 assert.deepEqual(await read({id:'bootstrapSecret'}),{apiVersion:'v1',kind:'Secret'});
 await assert.rejects(read({id:'anything-else'}),e=>e.message==='read_refused');
});
test('malformed or oversized object response is suppressed',async t=>{
 const dir=await temp(t),bin=path.join(dir,'kubectl');
 for(const code of ['process.stdout.write("synthetic-private")','process.stdout.write("x".repeat(300000))']){
  await writeFile(bin,`#!${node}\n${code}`,{mode:0o700});
  await assert.rejects(createReader({kubectl:bin,kubeconfig:path.join(dir,'config')})({id:'bootstrapSecret'}),e=>e.message==='read_refused');
 }
});
async function sourceFixture(t){
 const dir=await temp(t),cipher='public synthetic encrypted marker\n',bootstrap='resources:\n  - secret-wedding-db-backup-r2.enc.yaml\n';
 const p='k8s/clusters/prod/bootstrap/';await mkdir(path.join(dir,p),{recursive:true});
 await writeFile(path.join(dir,p,'secret-wedding-db-backup-r2.enc.yaml'),cipher);await writeFile(path.join(dir,p,'kustomization.yaml'),bootstrap);
 await mkdir(path.join(dir,'scripts'));for(const file of ['wedding-backup-projection.mjs','wedding-backup-io.mjs','verify-wedding-backup-staging.mjs'])await writeFile(path.join(dir,'scripts',file),'// reviewed synthetic recipe\n');
 const git=(...args)=>execFileSync('git',['-C',dir,...args],{encoding:'utf8',stdio:['ignore','pipe','pipe']}).trim();
 git('init','-q');git('add','k8s/clusters/prod/bootstrap/secret-wedding-db-backup-r2.enc.yaml','k8s/clusters/prod/bootstrap/kustomization.yaml','scripts/wedding-backup-projection.mjs','scripts/wedding-backup-io.mjs','scripts/verify-wedding-backup-staging.mjs');git('-c','user.name=Fixture','-c','user.email=fixture@example.invalid','-c','commit.gpgsign=false','commit','-qm','fixture');
 const sha=git('rev-parse','HEAD');return{dir,sha,git,cipherPath:path.join(dir,p,'secret-wedding-db-backup-r2.enc.yaml'),options:{workspace:dir,recipeDirectory:path.join(dir,'scripts'),sourceSha:sha,recipeSha:sha,cipherSha:hash(cipher),bootstrapSha:hash(bootstrap),git:'/usr/bin/git'}};
}
test('actual committed source and recipe match without a decrypt subprocess',async t=>{
 const f=await sourceFixture(t);const guard=await createSourceGuard(f.options);assert.equal(await guard(),true);
 await writeFile(f.cipherPath,'other encrypted bytes');assert.equal(await guard(),false);
});
for(const [label,change] of [
 ['wrong cipher receipt',async f=>{f.options.cipherSha='f'.repeat(64);}],
 ['wrong bootstrap membership receipt',async f=>{f.options.bootstrapSha='f'.repeat(64);}],
 ['foreign recipe',async f=>{f.options.recipeSha='a'.repeat(40);}],
 ['changed executable',async f=>{await writeFile(path.join(f.dir,'scripts/wedding-backup-projection.mjs'),'// injected\n');}],
 ['symlinked source',async f=>{const b=await readFile(f.cipherPath);await rm(f.cipherPath);await writeFile(path.join(f.dir,'other.enc.yaml'),b);await symlink(path.join(f.dir,'other.enc.yaml'),f.cipherPath);}]
])test(label+' fails before any runtime read',async t=>{
 const f=await sourceFixture(t);await change(f);const guard=await createSourceGuard(f.options);assert.equal(await guard(),false);
});
