import test from 'node:test';
import assert from 'node:assert/strict';
import {execFileSync,spawnSync} from 'node:child_process';
import {readFile} from 'node:fs/promises';
import path from 'node:path';
import {fixture} from './runtime-fixture.mjs';
const root=path.resolve(import.meta.dirname,'../..');
const yaml=p=>JSON.parse(execFileSync('yq',['-o=json','.',path.join(root,p)],{encoding:'utf8'}));

test('Wedding archive identity is isolated from retained predecessor WAL',()=>{
 const overlay=yaml('k8s/providers/hetzner/apps/wedding-app/patches/flux-kustomization-protect-wedding-db.yaml');
 const candidate=overlay.spec?.patches?.find(entry=>entry.target?.group==='postgresql.cnpg.io'&&entry.target.kind==='Cluster'&&entry.target.name==='wedding-db'&&entry.patch.trimStart().startsWith('- op:'));
 assert.ok(candidate,'Wedding Cluster archive-incarnation patch is missing');
 const operations=JSON.parse(execFileSync('yq',['-o=json','.'],{input:candidate.patch,encoding:'utf8'}));
 assert.deepEqual(operations,[{op:'add',path:'/spec/plugins/0/parameters/serverName',value:'wedding-db-20260909'}]);
});
// Test-only resolution of scalar context references; the production proposal
// contains no expression language beyond these direct input/step handoffs.
function scalar(value,context){if(typeof value!=='string'||!value.startsWith('${{'))return value;const m=/^\$\{\{ ([a-zA-Z0-9_.-]+) \}\}$/.exec(value);assert.ok(m,'unsupported expression in proposed handoff');return m[1].split('.').reduce((v,k)=>v?.[k],context);}
async function executeStep(t,flag,{wait='success',publish='success'}={}){
 const workflow=yaml('.github/workflows/cd.yaml'),action=yaml('.github/actions/deploy-prod/action.yml');
 const definition=workflow.on.workflow_dispatch?.inputs?.['verify-wedding-backup-staging'];assert.ok(definition,'manual opt-in input is missing');assert.equal(definition.type,'boolean');
 const steps=workflow.jobs['deploy-prod'].steps,deploy=steps.find(s=>s.uses==='./.github/actions/deploy-prod');
 const input=flag===undefined?definition.default:flag;
 const resolved=scalar(deploy.with['verify-wedding-backup-staging'],{inputs:{'verify-wedding-backup-staging':input}});
 const value=resolved===undefined?action.inputs['verify-wedding-backup-staging'].default:String(resolved);
 const index=action.runs.steps.findIndex(s=>s.id==='verify_wedding_backup_staging');assert.ok(index>0);
 assert.ok(action.runs.steps.slice(0,index).some(s=>s.id==='wait_flux_revision'));
 const step=action.runs.steps[index];assert.equal(step.shell,'bash');assert.equal(step['continue-on-error'],undefined);
 const f=await fixture(t);
 const context={inputs:{'verify-wedding-backup-staging':value},steps:{publish_platform_manifest:{outcome:publish,outputs:{digest:f.env.WEDDING_BACKUP_DIGEST}},wait_flux_revision:{outcome:wait}}};
 const env={...f.env,PATH:f.dir+':'+path.dirname(process.execPath)+':/usr/bin:/bin'};
 for(const [k,v]of Object.entries(step.env))env[k]=String(scalar(v,context)??'');
 // Only the expected source receipts are synthetic; execute the proposed shell
// and actual helper against the disposable committed tree and bounded reader.
 env.WEDDING_BACKUP_CIPHER_SHA256=f.env.WEDDING_BACKUP_CIPHER_SHA256;env.WEDDING_BACKUP_BOOTSTRAP_SHA256=f.env.WEDDING_BACKUP_BOOTSTRAP_SHA256;
 const child=spawnSync('/bin/bash',['-e','-o','pipefail','-c',step.run],{cwd:f.dir,env,encoding:'utf8'});
 let reads='';try{reads=await readFile(path.join(f.dir,'reads'),'utf8');}catch{}
 return{child,reads};
}
for(const flag of [undefined,false])test('actual proposed omitted/false step does not read an object: '+String(flag),async t=>{
 const {child,reads}=await executeStep(t,flag);assert.equal(child.status,0);assert.equal(child.stderr,'');assert.equal(reads,'');assert.equal(child.stdout,'');
});
test('actual proposed true step uses the publisher digest and succeeds after wait',async t=>{
 const {child,reads}=await executeStep(t,true);assert.equal(child.status,0);assert.equal(child.stderr,'');assert.equal(JSON.parse(child.stdout).projectionEqual,true);assert.equal(reads.trim().split('\n').length,20);
});
for(const state of [{wait:'failure'},{publish:'failure'}])test('actual proposed true step refuses failed dependency before API reads '+JSON.stringify(state),async t=>{
 const {child,reads}=await executeStep(t,true,state);assert.equal(child.status,2);assert.equal(child.stderr,'');assert.deepEqual(JSON.parse(child.stdout),{verified:false});assert.equal(reads,'');
});
