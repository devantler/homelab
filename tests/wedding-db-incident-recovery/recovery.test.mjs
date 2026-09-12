import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {
  buildBackup,
  buildMergeSQL,
  buildRecoveryResources,
  buildResumePatch,
  buildSuspendPatch,
  recoveryOwner,
  recoverySource,
  validateCoreInventory,
} from '../../scripts/recover-wedding-db-incident.mjs';

const CURRENT_UID='afea05ff-7daa-4d80-99a6-f2d696cbc3f1';
const SOURCE_UID='9cd2ba9b-c7bf-43e2-bd2d-a5c7c139fafb';
const BACKUP_UID='549fe940-b119-4010-bdc8-fa8e6ebc93ae';

function fixture(){
  return {
    cluster:{apiVersion:'postgresql.cnpg.io/v1',kind:'Cluster',metadata:{name:'wedding-db',namespace:'wedding-app',uid:CURRENT_UID,creationTimestamp:'2026-09-09T01:58:14Z',generation:6},spec:{
      imageName:'ghcr.io/cloudnative-pg/postgresql:18.4-system-trixie',storage:{size:'1Gi',storageClass:'longhorn-wffc'},
      bootstrap:{initdb:{database:'wedding'}},plugins:[{name:'barman-cloud.cloudnative-pg.io',enabled:true,isWALArchiver:true,parameters:{barmanObjectName:'wedding-db',serverName:'wedding-db-20260909'}}],
    },status:{observedGeneration:6,phase:'Cluster in healthy state',currentPrimary:'wedding-db-1',readyInstances:3,conditions:[
      {type:'Ready',status:'True'},{type:'ContinuousArchiving',status:'True'},
    ]}},
    store:{apiVersion:'barmancloud.cnpg.io/v1',kind:'ObjectStore',metadata:{name:'wedding-db',namespace:'wedding-app',uid:SOURCE_UID,creationTimestamp:'2026-06-16T20:39:55Z'},spec:{configuration:{
      destinationPath:'s3://platform-backups/cnpg/wedding-db',endpointURL:'https://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com',
      s3Credentials:{accessKeyId:{name:'wedding-db-backup-r2',key:'ACCESS_KEY_ID'},secretAccessKey:{name:'wedding-db-backup-r2',key:'SECRET_ACCESS_KEY'},region:{name:'wedding-db-backup-r2',key:'REGION'}},
    }}},
    backup:{apiVersion:'postgresql.cnpg.io/v1',kind:'Backup',metadata:{name:'wedding-db-daily-20260908030000',namespace:'wedding-app',uid:BACKUP_UID,creationTimestamp:'2026-09-08T03:00:00Z'},spec:{method:'plugin',pluginConfiguration:{name:'barman-cloud.cloudnative-pg.io'},cluster:{name:'wedding-db'}},status:{
      phase:'completed',backupId:'20260908T030001',backupName:'backup-20260908030000',startedAt:'2026-09-08T03:00:01Z',stoppedAt:'2026-09-08T03:00:11Z',majorVersion:18,
      pluginMetadata:{clusterUID:'6b6d4879-e437-4ea5-a0cb-257de8edad00',timeline:'162'},
    }},
  };
}

test('source is pinned to the empty replacement and last pre-loss backup',()=>{
  assert.deepEqual(recoverySource(fixture()),{
    currentClusterUid:CURRENT_UID,sourceUid:SOURCE_UID,prelossBackupUid:BACKUP_UID,
    database:'wedding',imageName:'ghcr.io/cloudnative-pg/postgresql:18.4-system-trixie',storageClass:'longhorn-wffc',size:'1Gi',
    endpoint:'https://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com',prelossBackupId:'20260908T030001',
  });
  for(const change of [
    value=>{value.cluster.metadata.uid='11111111-1111-1111-1111-111111111111';},
    value=>{value.cluster.metadata.creationTimestamp='2026-09-08T01:58:14Z';},
    value=>{value.cluster.spec.bootstrap={recovery:{source:'old'}};},
    value=>{value.cluster.spec.plugins[0].parameters.serverName='wedding-db';},
    value=>{value.cluster.status.conditions[1].status='False';},
    value=>{value.store.metadata.uid='33333333-3333-3333-3333-333333333333';},
    value=>{value.store.metadata.creationTimestamp='2026-06-17T20:39:55Z';},
    value=>{value.store.spec.configuration.destinationPath='s3://other/path';},
    value=>{value.backup.metadata.uid='22222222-2222-2222-2222-222222222222';},
    value=>{value.backup.status.pluginMetadata.clusterUID=CURRENT_UID;},
    value=>{value.backup.status.phase='failed';},
  ]){
    const value=structuredClone(fixture());change(value);
    assert.throws(()=>recoverySource(value),/refused/);
  }
});

test('recovery cluster replays the complete predecessor archive from the exact base',()=>{
  const source=recoverySource(fixture());
  const {cluster,policy}=buildRecoveryResources({run:'34710000000',attempt:'1',...source});
  assert.equal(cluster.metadata.name,'wedding-db-preloss-34710000000-1');
  assert.deepEqual(cluster.spec.bootstrap,{recovery:{source:'wedding-db-preloss',recoveryTarget:{backupID:'20260908T030001'}}});
  assert.deepEqual(cluster.spec.externalClusters,[{name:'wedding-db-preloss',plugin:{name:'barman-cloud.cloudnative-pg.io',parameters:{barmanObjectName:'wedding-db',serverName:'wedding-db'}}}]);
  assert.equal(cluster.spec.plugins,undefined);
  assert.equal(cluster.spec.instances,1);
  assert.equal(cluster.spec.enablePDB,false);
  assert.deepEqual(policy.spec.endpointSelector.matchLabels,{'cnpg.io/cluster':cluster.metadata.name});
  assert.deepEqual(policy.spec.egress.find(item=>item.toFQDNs).toFQDNs,[{matchName:'0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com'}]);
  assert.equal(policy.spec.egress.some(item=>item.toEndpoints),false);
});

test('application suspension ownership is bound to one workflow attempt',()=>{
  const owner=recoveryOwner('34710000000','1');
  assert.equal(owner,'34710000000/1');
  assert.throws(()=>recoveryOwner('34710000000','0'),/refused/);
  assert.deepEqual(buildSuspendPatch({resourceVersion:'279780874',kustomizationUid:'be31651e-fe0d-4826-9ffb-d41716a66720',owner}),[
    {op:'test',path:'/metadata/resourceVersion',value:'279780874'},
    {op:'test',path:'/metadata/uid',value:'be31651e-fe0d-4826-9ffb-d41716a66720'},
    {op:'add',path:'/metadata/annotations/devantler.tech~1wedding-db-recovery-owner',value:owner},
    {op:'add',path:'/metadata/annotations/kustomize.toolkit.fluxcd.io~1reconcile',value:'disabled'},
    {op:'add',path:'/spec/suspend',value:true},
  ]);
  assert.deepEqual(buildResumePatch({kustomizationUid:'be31651e-fe0d-4826-9ffb-d41716a66720',owner}),[
    {op:'test',path:'/metadata/uid',value:'be31651e-fe0d-4826-9ffb-d41716a66720'},
    {op:'test',path:'/metadata/annotations/devantler.tech~1wedding-db-recovery-owner',value:owner},
    {op:'test',path:'/metadata/annotations/kustomize.toolkit.fluxcd.io~1reconcile',value:'disabled'},
    {op:'test',path:'/spec/suspend',value:true},
    {op:'add',path:'/spec/suspend',value:false},
    {op:'remove',path:'/metadata/annotations/devantler.tech~1wedding-db-recovery-owner'},
    {op:'remove',path:'/metadata/annotations/kustomize.toolkit.fluxcd.io~1reconcile'},
  ]);
  assert.throws(()=>buildSuspendPatch({resourceVersion:'0',kustomizationUid:'be31651e-fe0d-4826-9ffb-d41716a66720',owner}),/refused/);
});

test('current and restored backups are distinct, run-owned plugin backups',()=>{
  const before=buildBackup({run:'34710000000',attempt:'1',phase:'before'});
  const after=buildBackup({run:'34710000000',attempt:'1',phase:'after'});
  assert.equal(before.metadata.name,'wedding-db-incident-before-34710000000-1');
  assert.equal(after.metadata.name,'wedding-db-incident-after-34710000000-1');
  assert.notEqual(before.metadata.name,after.metadata.name);
  for(const backup of [before,after]){
    assert.equal(backup.spec.cluster.name,'wedding-db');
    assert.equal(backup.spec.method,'plugin');
    assert.equal(backup.spec.pluginConfiguration.name,'barman-cloud.cloudnative-pg.io');
    assert.equal(backup.metadata.labels['app.kubernetes.io/managed-by'],'github-actions');
  }
});

test('core inventory accepts only keyed, duplicate-free recovery rows',()=>{
  const inventory={guestPairs:[{code:'PAIR01',name:'Pair',createdAt:'2026-05-01T10:00:00Z'}],guests:[{pairCode:'PAIR01',name:'Guest',attending:true,dietaryNotes:null,updatedAt:'2026-08-01T10:00:00Z'}],roomBookings:[{pairCode:'PAIR01',requested:true,notes:null,updatedAt:'2026-08-02T10:00:00Z'}]};
  assert.deepEqual(validateCoreInventory(inventory),{guestPairs:1,guests:1,roomBookings:1,meaningfulGuests:1});
  for(const change of [
    value=>value.guestPairs.push(structuredClone(value.guestPairs[0])),
    value=>{value.guests[0].pairCode='MISSING';},
    value=>{value.guests[0].attending=null;value.guests[0].dietaryNotes=null;value.roomBookings=[];},
    value=>value.roomBookings.push(structuredClone(value.roomBookings[0])),
  ]){const value=structuredClone(inventory);change(value);assert.throws(()=>validateCoreInventory(value),/refused/);}
});

test('merge restores pre-loss answers only where the replacement has no newer answer',()=>{
  const sql=buildMergeSQL('incident_restore_34710000000_1');
  assert.match(sql,/live\.attending IS NULL AND live\.dietary_notes IS NULL/);
  assert.match(sql,/recovered\.attending IS NOT NULL OR recovered\.dietary_notes IS NOT NULL/);
  assert.match(sql,/ON CONFLICT \(guest_pair_id\) DO NOTHING/);
  assert.match(sql,/LOCK TABLE guest_pairs, guests, room_bookings IN ACCESS EXCLUSIVE MODE/);
  assert.match(sql,/DROP SCHEMA incident_restore_34710000000_1 CASCADE/);
  assert.doesNotMatch(sql,/sessions|admin_sessions/);
  assert.throws(()=>buildMergeSQL('public'),/refused/);
});

test('Wedding reconciliation cannot globally force-recreate stateful data',async()=>{
  const fs=await import('node:fs/promises');
  const manifest=await fs.readFile(new URL('../../k8s/bases/apps/wedding-app/flux-kustomization.yaml',import.meta.url),'utf8');
  assert.match(manifest,/\n  force: false\n/);
});

test('manual recovery is serialized with production deployments and discloses no inputs',async()=>{
  const fs=await import('node:fs/promises');
  const workflow=await fs.readFile(new URL('../../.github/workflows/recover-wedding-db-incident.yaml',import.meta.url),'utf8');
  assert.match(workflow,/workflow_dispatch:\n\npermissions: \{\}/);
  assert.match(workflow,/group: prod-deploy\n  cancel-in-progress: false\n  queue: max/);
  assert.match(workflow,/timeout-minutes: 180/);
  assert.match(workflow,/needs: recover\n    if: \$\{\{ always\(\) \}\}/);
  assert.match(workflow,/timeout-minutes: 20/);
  assert.match(workflow,/node scripts\/recover-wedding-db-incident\.mjs --cleanup/);
  assert.equal(workflow.match(/run: \.\/scripts\/use-prod-stable-api-endpoint\.sh/g)?.length,2);
  assert.equal(workflow.match(/HCLOUD_TOKEN: \$\{\{ secrets\.HCLOUD_TOKEN \}\}/g)?.length,2);
  assert.match(workflow,/environment: prod/);
  assert.match(workflow,/persist-credentials: false/);
  assert.doesNotMatch(workflow,/pull_request|schedule:|inputs:/);
});

test('an untrusted invocation refuses without data or subprocess diagnostics',()=>{
  const script=new URL('../../scripts/recover-wedding-db-incident.mjs',import.meta.url);
  const result=spawnSync(process.execPath,[script.pathname],{encoding:'utf8',env:{PATH:process.env.PATH},maxBuffer:4096});
  assert.equal(result.status,2);
  assert.equal(result.stdout,'');
  assert.equal(result.stderr,'Wedding database incident recovery refused.\n');
});
