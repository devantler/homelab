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
 const {child,reads}=await executeStep(t,true);assert.equal(child.status,0);assert.equal(child.stderr,'');assert.equal(JSON.parse(child.stdout).projectionEqual,true);assert.equal(reads.trim().split('\n').length,22);
});
for(const state of [{wait:'failure'},{publish:'failure'}])test('actual proposed true step refuses failed dependency before API reads '+JSON.stringify(state),async t=>{
 const {child,reads}=await executeStep(t,true,state);assert.equal(child.status,2);assert.equal(child.stderr,'');assert.deepEqual(JSON.parse(child.stdout),{verified:false});assert.equal(reads,'');
});

test('dedicated ObjectStore is staged without moving the active archive',()=>{
 const prodBootstrap=yaml('k8s/clusters/prod/bootstrap/secret-wedding-db-backup-r2.enc.yaml');
 assert.equal(prodBootstrap.metadata.name,'wedding-db-backup-r2-bootstrap');
 assert.deepEqual(Object.keys(prodBootstrap.stringData).sort(),['access_key_id','secret_access_key']);
 assert.ok(Object.values(prodBootstrap.stringData).every(value=>/^ENC\[AES256_GCM,/.test(value)));
 assert.ok(yaml('k8s/clusters/prod/bootstrap/kustomization.yaml').resources.includes('secret-wedding-db-backup-r2.enc.yaml'));
 const seed=yaml('k8s/bases/infrastructure/vault-seed/push-secret-seed-wedding-db-backup-r2.yaml');
 assert.equal(seed.spec.selector.secret.name,'wedding-db-backup-r2-bootstrap');
 assert.deepEqual(seed.spec.data.map(item=>[
  item.match.secretKey,
  item.match.remoteRef.remoteKey,
  item.match.remoteRef.property,
 ]),[
  ['access_key_id','apps/wedding-app/backup/r2','access_key_id'],
  ['secret_access_key','apps/wedding-app/backup/r2','secret_access_key'],
 ]);
 const projection=yaml('k8s/bases/apps/wedding-app/external-secret-db-backup-dedicated.yaml');
 assert.equal(projection.spec.target.name,'wedding-db-backup-r2-dedicated');
 assert.deepEqual(projection.spec.data.map(item=>[
  item.secretKey,
  item.remoteRef.key,
  item.remoteRef.property,
 ]),[
  ['ACCESS_KEY_ID','apps/wedding-app/backup/r2','access_key_id'],
  ['SECRET_ACCESS_KEY','apps/wedding-app/backup/r2','secret_access_key'],
 ]);
 const active=yaml('k8s/bases/apps/wedding-app/object-store.yaml');
 assert.equal(active.metadata.name,'wedding-db');
 assert.equal(active.spec.configuration.destinationPath,'s3://${r2_bucket}/cnpg/wedding-db');
 assert.deepEqual([
  active.spec.configuration.s3Credentials.accessKeyId.name,
  active.spec.configuration.s3Credentials.secretAccessKey.name,
  active.spec.configuration.s3Credentials.region.name,
 ],['wedding-db-backup-r2','wedding-db-backup-r2','wedding-db-backup-r2']);
 const store=yaml('k8s/bases/apps/wedding-app/object-store-dedicated.yaml');
 assert.equal(store.metadata.name,'wedding-db-dedicated');
 assert.equal(store.spec.configuration.destinationPath,'s3://wedding-db-backups/cnpg/wedding-db');
 assert.deepEqual([
  store.spec.configuration.s3Credentials.accessKeyId.name,
  store.spec.configuration.s3Credentials.secretAccessKey.name,
  store.spec.configuration.s3Credentials.region.name,
 ],['wedding-db-backup-r2-dedicated','wedding-db-backup-r2-dedicated','wedding-db-backup-r2-dedicated']);
 const resources=yaml('k8s/bases/apps/wedding-app/kustomization.yaml').resources;
  assert.ok(resources.includes('external-secret-db-backup-dedicated.yaml'));
 assert.ok(resources.includes('object-store-dedicated.yaml'));
 assert.ok(resources.includes('object-store.yaml'),'the active shared ObjectStore stays present during staging');
  assert.ok(resources.includes('external-secret-db-backup.yaml'),'shared projection remains available for rollback until restore acceptance');
});

test('thin local cluster does not advertise an unavailable Wedding backup path',async()=>{
 const localBootstrap=yaml('k8s/clusters/local/bootstrap/kustomization.yaml');
 assert.ok(!localBootstrap.resources.includes('secret-wedding-db-backup-r2.enc.yaml'));
 const minio=yaml('k8s/providers/docker/infrastructure/controllers/minio/kustomization.yaml');
 assert.ok(!minio.resources.includes('job-wedding-backup-bucket.yaml'));
 const infrastructure=yaml('k8s/providers/docker/infrastructure/kustomization.yaml');
 const prune=infrastructure.patches.find(patch=>patch.target?.kind==='PushSecret'&&patch.target?.name==='seed-wedding-db-backup-r2');
 assert.ok(prune,'the unused local Wedding PushSecret must be pruned with its source Secret');
 assert.match(prune.patch,/\$patch: delete/);
 assert.deepEqual(yaml('k8s/providers/docker/apps/kustomization.yaml').resources,[]);
 const architecture=await readFile(path.join(root,'docs/dr/velero-cnpg.md'),'utf8');
 assert.doesNotMatch(architecture,/Wedding's local bootstrap|local MinIO bucket/);
});

test('rotation docs keep staged Wedding inactive and use the non-printing SOPS path',async()=>{
 const runbook=await readFile(path.join(root,'docs/dr/runbook.md'),'utf8');
 const scenario=runbook.slice(runbook.indexOf('## Scenario 7 — R2 / Cloudflare credential rotation'));
 const revoke=scenario.indexOf('Revoke the old token');
 assert.ok(revoke>0,'rotation scenario must retain an explicit final revocation boundary');
 const beforeRevoke=scenario.slice(0,revoke);
 assert.match(beforeRevoke,/set -euo pipefail/);
 assert.match(beforeRevoke,/platform-backups[^]*r2_access_key_id[^]*r2_secret_access_key/);
 assert.match(beforeRevoke,/wedding-db-backups[^]*access_key_id[^]*secret_access_key/);
 assert.match(beforeRevoke,/gh run watch "\$run_id" --repo devantler-tech\/platform --exit-status/);
 assert.match(beforeRevoke,/sops set --value-stdin/);
 assert.doesNotMatch(beforeRevoke,/^sops k8s\/clusters\/prod\/bootstrap\//m);
 assert.match(beforeRevoke,/staged ObjectStore remains[^]*inactive/i);
 assert.match(beforeRevoke,/Do not revoke the shared credential/i);
 assert.match(beforeRevoke,/Wedding remains a shared-token consumer[^]*Umami[^]*Coroot/i);
 assert.doesNotMatch(beforeRevoke,/cnpg\.io\/instanceRole/);

 const architecture=await readFile(path.join(root,'docs/dr/velero-cnpg.md'),'utf8');
 assert.match(architecture,/apps\/wedding-app\/backup\/r2/);
 assert.match(architecture,/tenant-isolated database[^]*dedicated bucket[^]*dedicated OpenBao path/i);
 assert.doesNotMatch(architecture,/local MinIO bucket/);
});
