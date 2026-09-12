import {spawnSync} from 'node:child_process';
import {lstatSync,readFileSync,realpathSync} from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const NAMESPACE='wedding-app';
const LIVE_CLUSTER='wedding-db';
const LIVE_DEPLOYMENT='wedding-app';
const LIVE_KUSTOMIZATION='wedding-app';
const SOURCE_STORE='wedding-db';
const SOURCE_STORE_UID='9cd2ba9b-c7bf-43e2-bd2d-a5c7c139fafb';
const SOURCE_SECRET='wedding-db-backup-r2';
const CURRENT_CLUSTER_UID='afea05ff-7daa-4d80-99a6-f2d696cbc3f1';
const PRELOSS_BACKUP='wedding-db-daily-20260908030000';
const PRELOSS_BACKUP_UID='549fe940-b119-4010-bdc8-fa8e6ebc93ae';
const PRELOSS_CLUSTER_UID='6b6d4879-e437-4ea5-a0cb-257de8edad00';
const RECOVERY_MODE='full archive from backup 20260908T030001';
const PROOF='wedding-db-data-recovery-proof';
const RECOVERY_OWNER_ANNOTATION='devantler.tech/wedding-db-recovery-owner';
const check=value=>{if(!value)throw Error('refused');return value;};
const integer=value=>{check(typeof value==='string'&&/^[1-9][0-9]*$/.test(value));return value;};
const uid=value=>{check(typeof value==='string'&&/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(value));return value;};
const timestamp=value=>{check(typeof value==='string'&&!Number.isNaN(Date.parse(value)));return value;};
const condition=(value,type)=>value.status?.conditions?.some(item=>item.type===type&&item.status==='True');

function exactObject(value,{apiVersion,kind,name}){
  check(value?.apiVersion===apiVersion&&value.kind===kind);
  check(value.metadata?.name===name&&value.metadata.namespace===NAMESPACE&&!value.metadata.deletionTimestamp);
  uid(value.metadata.uid);
}

function endpointHost(endpoint){
  return check(/^https:\/\/([0-9a-f]{32}\.r2\.cloudflarestorage\.com)$/.exec(endpoint))?.[1];
}

export function recoverySource({cluster,store,backup}){
  exactObject(cluster,{apiVersion:'postgresql.cnpg.io/v1',kind:'Cluster',name:LIVE_CLUSTER});
  check(cluster.metadata.uid===CURRENT_CLUSTER_UID&&cluster.metadata.creationTimestamp==='2026-09-09T01:58:14Z');
  check(cluster.spec?.bootstrap?.initdb?.database==='wedding');
  check(cluster.status?.phase==='Cluster in healthy state'&&cluster.status.currentPrimary&&cluster.status.readyInstances>=1);
  check(condition(cluster,'Ready')&&condition(cluster,'ContinuousArchiving'));
  const plugins=cluster.spec?.plugins;
  check(Array.isArray(plugins)&&plugins.length===1);
  check(plugins[0].name==='barman-cloud.cloudnative-pg.io'&&plugins[0].enabled===true&&plugins[0].isWALArchiver===true);
  check(plugins[0].parameters?.barmanObjectName===SOURCE_STORE&&plugins[0].parameters.serverName==='wedding-db-20260909');

  exactObject(store,{apiVersion:'barmancloud.cnpg.io/v1',kind:'ObjectStore',name:SOURCE_STORE});
  check(store.metadata.uid===SOURCE_STORE_UID&&store.metadata.creationTimestamp==='2026-06-16T20:39:55Z');
  const configuration=store.spec?.configuration;
  check(configuration?.destinationPath==='s3://platform-backups/cnpg/wedding-db');
  const endpoint=configuration.endpointURL;
  endpointHost(endpoint);
  for(const [field,key] of [['accessKeyId','ACCESS_KEY_ID'],['secretAccessKey','SECRET_ACCESS_KEY'],['region','REGION']]){
    check(configuration.s3Credentials?.[field]?.name===SOURCE_SECRET&&configuration.s3Credentials[field].key===key);
  }

  exactObject(backup,{apiVersion:'postgresql.cnpg.io/v1',kind:'Backup',name:PRELOSS_BACKUP});
  check(backup.metadata.uid===PRELOSS_BACKUP_UID&&backup.metadata.creationTimestamp==='2026-09-08T03:00:00Z');
  check(backup.spec?.cluster?.name===LIVE_CLUSTER&&backup.spec.method==='plugin'&&backup.spec.pluginConfiguration?.name==='barman-cloud.cloudnative-pg.io');
  check(backup.status?.phase==='completed'&&backup.status.backupId==='20260908T030001'&&backup.status.majorVersion===18);
  check(backup.status.pluginMetadata?.clusterUID===PRELOSS_CLUSTER_UID&&backup.status.pluginMetadata.timeline==='162');
  check(backup.status.startedAt&&backup.status.stoppedAt&&!backup.status.error);

  const imageName=cluster.spec.imageName;
  check(typeof imageName==='string'&&/^ghcr\.io\/cloudnative-pg\/postgresql:18\.[0-9]+-[a-z0-9-]+$/.test(imageName));
  check(cluster.spec.storage?.storageClass==='longhorn-wffc');
  check(/^[1-9][0-9]*(?:Mi|Gi|Ti)$/.test(cluster.spec.storage?.size));
  return {currentClusterUid:cluster.metadata.uid,sourceUid:store.metadata.uid,prelossBackupUid:backup.metadata.uid,database:'wedding',imageName,storageClass:'longhorn-wffc',size:cluster.spec.storage.size,endpoint,prelossBackupId:backup.status.backupId};
}

function labels(run,attempt){
  integer(run);integer(attempt);
  return {'app.kubernetes.io/name':'wedding-db-incident-recovery','app.kubernetes.io/managed-by':'github-actions','devantler.tech/github-run':run,'devantler.tech/github-attempt':attempt};
}

function recoveryName(run,attempt){
  const name=`wedding-db-preloss-${integer(run)}-${integer(attempt)}`;
  check(name.length<=63);return name;
}

export function recoveryOwner(run,attempt){return integer(run)+'/'+integer(attempt);}

export function buildRecoveryResources({run,attempt,endpoint,imageName,storageClass,prelossBackupId}){
  check(storageClass==='longhorn-wffc');
  check(typeof imageName==='string'&&/^ghcr\.io\/cloudnative-pg\/postgresql:18\.[0-9]+-[a-z0-9-]+$/.test(imageName));
  check(prelossBackupId==='20260908T030001');
  const name=recoveryName(run,attempt),owned=labels(run,attempt),hostname=endpointHost(endpoint);
  const cluster={apiVersion:'postgresql.cnpg.io/v1',kind:'Cluster',metadata:{name,namespace:NAMESPACE,labels:owned},spec:{
    instances:1,imageName,enableSuperuserAccess:false,enablePDB:false,
    storage:{size:'2Gi',storageClass},
    resources:{requests:{cpu:'50m',memory:'256Mi'},limits:{cpu:'1',memory:'1Gi'}},
    bootstrap:{recovery:{source:'wedding-db-preloss',recoveryTarget:{backupID:prelossBackupId}}},
    externalClusters:[{name:'wedding-db-preloss',plugin:{name:'barman-cloud.cloudnative-pg.io',parameters:{barmanObjectName:SOURCE_STORE,serverName:'wedding-db'}}}],
  }};
  const policy={apiVersion:'cilium.io/v2',kind:'CiliumNetworkPolicy',metadata:{name,namespace:NAMESPACE,labels:owned},spec:{endpointSelector:{matchLabels:{'cnpg.io/cluster':name}},egress:[
    {toEndpoints:[{matchLabels:{'io.kubernetes.pod.namespace':'kube-system','k8s-app':'kube-dns'}}],toPorts:[{ports:[{port:'53',protocol:'UDP'},{port:'53',protocol:'TCP'}],rules:{dns:[{matchPattern:'*'}]}}]},
    {toEntities:['kube-apiserver']},
    {toFQDNs:[{matchName:hostname}],toPorts:[{ports:[{port:'443',protocol:'TCP'}]}]},
  ]}};
  return {cluster,policy};
}

export function buildBackup({run,attempt,phase}){
  check(['before','after'].includes(phase));
  const name=`wedding-db-incident-${phase}-${integer(run)}-${integer(attempt)}`;
  check(name.length<=63);
  return {apiVersion:'postgresql.cnpg.io/v1',kind:'Backup',metadata:{name,namespace:NAMESPACE,labels:labels(run,attempt)},spec:{method:'plugin',pluginConfiguration:{name:'barman-cloud.cloudnative-pg.io'},cluster:{name:LIVE_CLUSTER}}};
}

function string(value,max=1024){check(typeof value==='string'&&value.length>0&&value.length<=max&&!value.includes('\0'));return value;}
function nullableString(value,max=1024){check(value===null||(typeof value==='string'&&value.length<=max&&!value.includes('\0')));return value;}
function nullableBoolean(value){check(value===null||typeof value==='boolean');return value;}

export function validateCoreInventory(value,{requireMeaningful=true}={}){
  check(value&&typeof value==='object'&&!Array.isArray(value));
  const {guestPairs,guests,roomBookings}=value;
  check(Array.isArray(guestPairs)&&guestPairs.length>0&&guestPairs.length<=100);
  check(Array.isArray(guests)&&guests.length>0&&guests.length<=300);
  check(Array.isArray(roomBookings)&&roomBookings.length<=100);
  const codes=new Set();
  for(const pair of guestPairs){
    check(pair&&typeof pair==='object'&&/^[A-Za-z0-9_-]{1,32}$/.test(pair.code));string(pair.name,255);timestamp(pair.createdAt);check(!codes.has(pair.code));codes.add(pair.code);
  }
  const guestKeys=new Set();let meaningfulGuests=0;
  for(const guest of guests){
    check(guest&&typeof guest==='object'&&codes.has(guest.pairCode));string(guest.name,255);nullableBoolean(guest.attending);nullableString(guest.dietaryNotes,500);timestamp(guest.updatedAt);
    const key=guest.pairCode+'\0'+guest.name;check(!guestKeys.has(key));guestKeys.add(key);
    if(guest.attending!==null||guest.dietaryNotes!==null)meaningfulGuests+=1;
  }
  const bookingCodes=new Set();
  for(const booking of roomBookings){
    check(booking&&typeof booking==='object'&&codes.has(booking.pairCode)&&typeof booking.requested==='boolean');nullableString(booking.notes,500);timestamp(booking.updatedAt);check(!bookingCodes.has(booking.pairCode));bookingCodes.add(booking.pairCode);
  }
  if(requireMeaningful)check(meaningfulGuests>0||roomBookings.length>0);
  return {guestPairs:guestPairs.length,guests:guests.length,roomBookings:roomBookings.length,meaningfulGuests};
}

function schemaName(run,attempt){
  const value=`incident_restore_${integer(run)}_${integer(attempt)}`;
  check(/^incident_restore_[1-9][0-9]*_[1-9][0-9]*$/.test(value)&&value.length<=63);return value;
}

export function buildMergeSQL(schema){
  check(/^incident_restore_[1-9][0-9]*_[1-9][0-9]*$/.test(schema)&&schema.length<=63);
  return `BEGIN;
LOCK TABLE guest_pairs, guests, room_bookings IN ACCESS EXCLUSIVE MODE;
DO $guard$
BEGIN
  IF EXISTS (
    (SELECT code, name FROM ${schema}.guest_pairs EXCEPT SELECT code, name FROM guest_pairs)
    UNION ALL
    (SELECT code, name FROM guest_pairs EXCEPT SELECT code, name FROM ${schema}.guest_pairs)
  ) THEN RAISE EXCEPTION 'guest pair identity mismatch'; END IF;
  IF EXISTS (
    (SELECT recovered.pair_code, recovered.name FROM ${schema}.guests recovered
      EXCEPT SELECT pairs.code, live.name FROM guests live JOIN guest_pairs pairs ON pairs.id=live.guest_pair_id)
    UNION ALL
    (SELECT pairs.code, live.name FROM guests live JOIN guest_pairs pairs ON pairs.id=live.guest_pair_id
      EXCEPT SELECT recovered.pair_code, recovered.name FROM ${schema}.guests recovered)
  ) THEN RAISE EXCEPTION 'guest identity mismatch'; END IF;
END $guard$;
WITH restored_guests AS (
  UPDATE guests live
  SET attending=recovered.attending,dietary_notes=recovered.dietary_notes,updated_at=recovered.updated_at
  FROM ${schema}.guests recovered JOIN guest_pairs pairs ON pairs.code=recovered.pair_code
  WHERE live.guest_pair_id=pairs.id AND live.name=recovered.name
    AND live.attending IS NULL AND live.dietary_notes IS NULL
    AND (recovered.attending IS NOT NULL OR recovered.dietary_notes IS NOT NULL)
  RETURNING live.id
), restored_bookings AS (
  INSERT INTO room_bookings (guest_pair_id,requested,notes,updated_at)
  SELECT pairs.id,recovered.requested,recovered.notes,recovered.updated_at
  FROM ${schema}.room_bookings recovered JOIN guest_pairs pairs ON pairs.code=recovered.pair_code
  ON CONFLICT (guest_pair_id) DO NOTHING
  RETURNING id
)
SELECT json_build_object(
  'restoredGuestAnswers',(SELECT count(*) FROM restored_guests),
  'restoredRoomBookings',(SELECT count(*) FROM restored_bookings),
  'finalMeaningfulGuestAnswers',(SELECT count(*) FROM guests WHERE attending IS NOT NULL OR dietary_notes IS NOT NULL),
  'finalRoomBookings',(SELECT count(*) FROM room_bookings)
);
DROP SCHEMA ${schema} CASCADE;
COMMIT;`;
}

function kubectl(args,{input,timeout=30000,maxBytes=2*1024*1024}={}){
  const result=spawnSync('kubectl',['--kubeconfig',path.join(process.env.HOME,'.kube/config'),'--context','admin@prod',...args],{input,env:{PATH:process.env.PATH,HOME:process.env.HOME},timeout,maxBuffer:maxBytes});
  check(!result.error&&result.status===0&&result.stdout.length<=maxBytes&&result.stderr.length<=maxBytes);
  return result.stdout;
}

function object(resource,name){
  const value=JSON.parse(kubectl(['--namespace',NAMESPACE,'get',resource,name,'--output=json','--request-timeout=20s']).toString('utf8'));
  check(value&&typeof value==='object'&&!Array.isArray(value));return value;
}

function optionalObject(resource,name){
  const output=kubectl(['--namespace',NAMESPACE,'get',resource,name,'--ignore-not-found=true','--output=json','--request-timeout=20s']);
  return output.length?JSON.parse(output.toString('utf8')):null;
}

function list(resource,selector){
  const value=JSON.parse(kubectl(['--namespace',NAMESPACE,'get',resource,'--selector',selector,'--output=json','--request-timeout=20s']).toString('utf8'));
  check(value?.apiVersion==='v1'&&Array.isArray(value.items)&&value.items.length<=32);return value.items;
}

function verifyCandidate(){
  check(process.env.GITHUB_REPOSITORY==='devantler-tech/platform'&&process.env.GITHUB_EVENT_NAME==='workflow_dispatch');
  check(process.env.GITHUB_REF==='refs/heads/main'&&process.env.GITHUB_REF_NAME==='main'&&/^[0-9a-f]{40}$/.test(process.env.GITHUB_SHA));
  const workspace=realpathSync(process.env.GITHUB_WORKSPACE);check(workspace===process.env.GITHUB_WORKSPACE);
  const head=spawnSync('git',['--no-replace-objects','-C',workspace,'rev-parse','HEAD'],{encoding:'utf8',env:{PATH:process.env.PATH,GIT_NO_REPLACE_OBJECTS:'1'},maxBuffer:1024});
  check(!head.error&&head.status===0&&head.stdout===process.env.GITHUB_SHA+'\n');
  for(const relative of ['scripts/recover-wedding-db-incident.mjs','.github/workflows/recover-wedding-db-incident.yaml','k8s/bases/apps/wedding-app/flux-kustomization.yaml']){
    const filename=path.join(workspace,relative),stat=lstatSync(filename);check(stat.isFile()&&!stat.isSymbolicLink()&&stat.size>0&&stat.size<=524288&&realpathSync(filename)===filename);
    const local=readFileSync(filename),source=spawnSync('git',['--no-replace-objects','-C',workspace,'show',process.env.GITHUB_SHA+':'+relative],{env:{PATH:process.env.PATH,GIT_NO_REPLACE_OBJECTS:'1'},maxBuffer:524288});
    check(!source.error&&source.status===0&&local.equals(source.stdout));local.fill(0);source.stdout.fill(0);
  }
  integer(process.env.GITHUB_RUN_ID);integer(process.env.GITHUB_RUN_ATTEMPT);
  return {run:process.env.GITHUB_RUN_ID,attempt:process.env.GITHUB_RUN_ATTEMPT};
}

function sourceState(){
  check(kubectl(['--namespace',NAMESPACE,'get','secret',SOURCE_SECRET,'--output=name','--request-timeout=20s']).toString('utf8').trim()==='secret/'+SOURCE_SECRET);
  check(!optionalObject('configmaps',PROOF));
  const kustomization=object('kustomizations.kustomize.toolkit.fluxcd.io',LIVE_KUSTOMIZATION);
  check(kustomization.spec?.force===false&&kustomization.spec.suspend!==true&&condition(kustomization,'Ready'));
  return recoverySource({cluster:object('clusters.postgresql.cnpg.io',LIVE_CLUSTER),store:object('objectstores.barmancloud.cnpg.io',SOURCE_STORE),backup:object('backups.postgresql.cnpg.io',PRELOSS_BACKUP)});
}

function backup(config,phase,source){
  const primary=object('clusters.postgresql.cnpg.io',LIVE_CLUSTER).status?.currentPrimary;check(/^wedding-db-[1-9][0-9]*$/.test(primary));
  kubectl(['--namespace',NAMESPACE,'exec',primary,'--container=postgres','--','psql','--username=postgres','--dbname=postgres','--set=ON_ERROR_STOP=1','--tuples-only','--no-align','--command=SELECT pg_switch_wal();']);
  const manifest=buildBackup({...config,phase});check(!optionalObject('backups.postgresql.cnpg.io',manifest.metadata.name));
  kubectl(['create','--filename=-'],{input:Buffer.from(JSON.stringify(manifest))});
  const end=Date.now()+30*60*1000;
  while(Date.now()<end){
    const value=object('backups.postgresql.cnpg.io',manifest.metadata.name);
    if(value.status?.phase==='completed'){
      check(value.status.pluginMetadata?.clusterUID===source.currentClusterUid&&value.status.backupId&&value.status.startedAt&&value.status.stoppedAt&&!value.status.error);
      return {name:value.metadata.name,uid:uid(value.metadata.uid),backupId:string(value.status.backupId,64)};
    }
    check(!['failed','walArchivingFailing'].includes(value.status?.phase));Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,10000);
  }
  throw Error('refused');
}

const INVENTORY_SQL=`SELECT json_build_object(
  'guestPairs',COALESCE((SELECT json_agg(json_build_object('code',code,'name',name,'createdAt',created_at) ORDER BY code) FROM guest_pairs),'[]'::json),
  'guests',COALESCE((SELECT json_agg(json_build_object('pairCode',pairs.code,'name',guests.name,'attending',guests.attending,'dietaryNotes',guests.dietary_notes,'updatedAt',guests.updated_at) ORDER BY pairs.code,guests.name) FROM guests JOIN guest_pairs pairs ON pairs.id=guests.guest_pair_id),'[]'::json),
  'roomBookings',COALESCE((SELECT json_agg(json_build_object('pairCode',pairs.code,'requested',bookings.requested,'notes',bookings.notes,'updatedAt',bookings.updated_at) ORDER BY pairs.code) FROM room_bookings bookings JOIN guest_pairs pairs ON pairs.id=bookings.guest_pair_id),'[]'::json)
)::text;`;

function inventory(primary,database,{requireMeaningful}){
  const output=kubectl(['--namespace',NAMESPACE,'exec',primary,'--container=postgres','--','psql','--username=postgres','--dbname='+database,'--set=ON_ERROR_STOP=1','--tuples-only','--no-align','--quiet','--command='+INVENTORY_SQL],{timeout:120000,maxBytes:1024*1024});
  return {value:JSON.parse(output.toString('utf8').trim()),summary:null,requireMeaningful};
}

function csv(value){
  if(value===null)return '\\N';
  const text=value instanceof Date?value.toISOString():String(value);
  return '"'+text.replaceAll('"','""')+'"';
}

function csvRows(rows,columns){return Buffer.from(rows.map(row=>columns.map(column=>csv(row[column])).join(',')).join('\n')+'\n');}

function psql(primary,database,command,{input,maxBytes=65536}={}){
  return kubectl(['--namespace',NAMESPACE,'exec',...(input?['--stdin']:[]),primary,'--container=postgres','--','psql','--username=postgres','--dbname='+database,'--set=ON_ERROR_STOP=1','--tuples-only','--no-align','--quiet','--command='+command],{input,timeout:120000,maxBytes});
}

function loadRecovered(primary,database,recovered,config){
  const schema=schemaName(config.run,config.attempt);
  psql(primary,database,`CREATE SCHEMA ${schema}; CREATE TABLE ${schema}.guest_pairs(code text PRIMARY KEY,name text NOT NULL,created_at timestamptz NOT NULL); CREATE TABLE ${schema}.guests(pair_code text NOT NULL,name text NOT NULL,attending boolean,dietary_notes text,updated_at timestamptz NOT NULL,PRIMARY KEY(pair_code,name)); CREATE TABLE ${schema}.room_bookings(pair_code text PRIMARY KEY,requested boolean NOT NULL,notes text,updated_at timestamptz NOT NULL);`);
  const loads=[
    ['guest_pairs',['code','name','createdAt'],recovered.guestPairs],
    ['guests',['pairCode','name','attending','dietaryNotes','updatedAt'],recovered.guests],
    ['room_bookings',['pairCode','requested','notes','updatedAt'],recovered.roomBookings],
  ];
  for(const [table,columns,rows] of loads){
    if(!rows.length)continue;
    const sqlColumns=columns.map(column=>({pairCode:'pair_code',dietaryNotes:'dietary_notes',updatedAt:'updated_at',createdAt:'created_at'}[column]??column)).join(',');
    psql(primary,database,`\\copy ${schema}.${table}(${sqlColumns}) FROM STDIN WITH (FORMAT csv, NULL '\\N')`,{input:csvRows(rows,columns)});
  }
  return schema;
}

function suspendApplication(config){
  const owner=recoveryOwner(config.run,config.attempt);
  const current=object('kustomizations.kustomize.toolkit.fluxcd.io',LIVE_KUSTOMIZATION);
  check(current.spec?.suspend!==true&&!current.metadata?.annotations?.[RECOVERY_OWNER_ANNOTATION]);
  const patch={metadata:{annotations:{[RECOVERY_OWNER_ANNOTATION]:owner}},spec:{suspend:true}};
  kubectl(['--namespace',NAMESPACE,'patch','kustomization.kustomize.toolkit.fluxcd.io',LIVE_KUSTOMIZATION,'--field-manager=flux-client-side-apply','--type=merge','--patch='+JSON.stringify(patch)]);
  const suspended=object('kustomizations.kustomize.toolkit.fluxcd.io',LIVE_KUSTOMIZATION);
  check(suspended.spec?.suspend===true&&suspended.metadata?.annotations?.[RECOVERY_OWNER_ANNOTATION]===owner);
  kubectl(['--namespace',NAMESPACE,'scale','deployment',LIVE_DEPLOYMENT,'--replicas=0']);
  const end=Date.now()+5*60*1000;
  while(Date.now()<end){
    const deployment=object('deployments.apps',LIVE_DEPLOYMENT);
    if((deployment.status?.replicas??0)===0&&list('pods','app.kubernetes.io/name=wedding-app').filter(pod=>!pod.metadata.deletionTimestamp).length===0)return;
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,3000);
  }
  throw Error('refused');
}

function resumeApplication(config){
  const owner=recoveryOwner(config.run,config.attempt);
  const current=object('kustomizations.kustomize.toolkit.fluxcd.io',LIVE_KUSTOMIZATION);
  if(!current.metadata?.annotations?.[RECOVERY_OWNER_ANNOTATION])return false;
  check(current.metadata.annotations[RECOVERY_OWNER_ANNOTATION]===owner);
  check(object('clusters.postgresql.cnpg.io',LIVE_CLUSTER).metadata.uid===CURRENT_CLUSTER_UID);
  let failed=false;
  try{kubectl(['--namespace',NAMESPACE,'scale','deployment',LIVE_DEPLOYMENT,'--replicas=2']);}catch{failed=true;}
  const patch={metadata:{annotations:{[RECOVERY_OWNER_ANNOTATION]:null}},spec:{suspend:false}};
  try{kubectl(['--namespace',NAMESPACE,'patch','kustomization.kustomize.toolkit.fluxcd.io',LIVE_KUSTOMIZATION,'--field-manager=flux-client-side-apply','--type=merge','--patch='+JSON.stringify(patch)]);}catch{failed=true;}
  try{kubectl(['--namespace',NAMESPACE,'rollout','status','deployment/'+LIVE_DEPLOYMENT,'--timeout=10m'],{timeout:630000});}catch{failed=true;}
  try{
    const restored=object('kustomizations.kustomize.toolkit.fluxcd.io',LIVE_KUSTOMIZATION);
    const deployment=object('deployments.apps',LIVE_DEPLOYMENT);
    check(restored.spec?.suspend===false&&!restored.metadata?.annotations?.[RECOVERY_OWNER_ANNOTATION]);
    check(deployment.spec?.replicas===2&&deployment.status?.availableReplicas===2);
  }catch{failed=true;}
  check(!failed);
  return true;
}

function createRecovery(config,source){
  const resources=buildRecoveryResources({...config,...source}),name=resources.cluster.metadata.name;
  check(!optionalObject('clusters.postgresql.cnpg.io',name)&&!optionalObject('ciliumnetworkpolicies.cilium.io',name));
  kubectl(['create','--filename=-'],{input:Buffer.from(JSON.stringify({apiVersion:'v1',kind:'List',items:[resources.policy,resources.cluster]}))});
  kubectl(['--namespace',NAMESPACE,'wait','cluster.postgresql.cnpg.io/'+name,'--for=condition=Ready','--timeout=30m'],{timeout:1830000});
  const cluster=object('clusters.postgresql.cnpg.io',name);check(cluster.status?.readyInstances===1&&cluster.status.currentPrimary&&condition(cluster,'Ready'));
  check(cluster.spec?.bootstrap?.recovery?.recoveryTarget?.backupID===source.prelossBackupId&&!cluster.spec.plugins);
  return {name,uid:uid(cluster.metadata.uid),primary:cluster.status.currentPrimary};
}

function cleanupRecovery(config,recovery){
  const name=recoveryName(config.run,config.attempt),owned=labels(config.run,config.attempt);
  if(recovery)check(recovery.name===name);
  const cluster=optionalObject('clusters.postgresql.cnpg.io',name);
  if(cluster){
    for(const [key,value] of Object.entries(owned))check(cluster.metadata?.labels?.[key]===value);
    if(recovery?.uid)check(cluster.metadata.uid===recovery.uid);
    kubectl(['--namespace',NAMESPACE,'delete','cluster.postgresql.cnpg.io',name,'--wait=true','--timeout=10m'],{timeout:630000});
  }
  for(const claim of list('persistentvolumeclaims','cnpg.io/cluster='+name))kubectl(['--namespace',NAMESPACE,'delete','persistentvolumeclaim',claim.metadata.name,'--wait=true','--timeout=5m'],{timeout:330000});
  const policy=optionalObject('ciliumnetworkpolicies.cilium.io',name);
  if(policy){
    for(const [key,value] of Object.entries(owned))check(policy.metadata?.labels?.[key]===value);
    kubectl(['--namespace',NAMESPACE,'delete','ciliumnetworkpolicy.cilium.io',name,'--wait=true','--timeout=2m'],{timeout:150000});
  }
  check(!optionalObject('clusters.postgresql.cnpg.io',name)&&list('persistentvolumeclaims','cnpg.io/cluster='+name).length===0&&!optionalObject('ciliumnetworkpolicies.cilium.io',name));
}

function recordProof({config,source,recovery,before,after,recovered,liveBefore,merge}){
  const manifest={apiVersion:'v1',kind:'ConfigMap',metadata:{name:PROOF,namespace:NAMESPACE,labels:{'app.kubernetes.io/name':'wedding-db','app.kubernetes.io/managed-by':'github-actions'}},data:{
    version:'1',recoveryMode:RECOVERY_MODE,replacementCreatedAt:'2026-09-09T01:58:14Z',currentClusterUid:source.currentClusterUid,prelossClusterUid:PRELOSS_CLUSTER_UID,prelossBackupUid:source.prelossBackupUid,recoveryClusterUid:recovery.uid,
    beforeBackupUid:before.uid,afterBackupUid:after.uid,recoveredGuests:String(recovered.guests),recoveredMeaningfulGuests:String(recovered.meaningfulGuests),recoveredRoomBookings:String(recovered.roomBookings),
    liveBeforeMeaningfulGuests:String(liveBefore.meaningfulGuests),liveBeforeRoomBookings:String(liveBefore.roomBookings),restoredGuestAnswers:String(merge.restoredGuestAnswers),restoredRoomBookings:String(merge.restoredRoomBookings),
    finalMeaningfulGuestAnswers:String(merge.finalMeaningfulGuestAnswers),finalRoomBookings:String(merge.finalRoomBookings),githubRun:config.run,githubAttempt:config.attempt,
  }};
  kubectl(['create','--filename=-'],{input:Buffer.from(JSON.stringify(manifest))});
  exactObject(object('configmaps',PROOF),{apiVersion:'v1',kind:'ConfigMap',name:PROOF});
}

function run(){
  const config=verifyCandidate(),source=sourceState();
  const before=backup(config,'before',source);
  let recovery,recoveredInventory,recovered,liveBefore,merge,error,resumeError,cleanupError;
  try{
    recovery=createRecovery(config,source);
    recoveredInventory=inventory(recovery.primary,source.database,{requireMeaningful:true});
    recovered=validateCoreInventory(recoveredInventory.value,{requireMeaningful:true});
    const livePrimary=object('clusters.postgresql.cnpg.io',LIVE_CLUSTER).status.currentPrimary;
    const liveInventory=inventory(livePrimary,source.database,{requireMeaningful:false});
    liveBefore=validateCoreInventory(liveInventory.value,{requireMeaningful:false});
    check(recovered.guestPairs===liveBefore.guestPairs&&recovered.guests===liveBefore.guests);
    suspendApplication(config);
    check(object('clusters.postgresql.cnpg.io',LIVE_CLUSTER).metadata.uid===source.currentClusterUid);
    const mergePrimary=object('clusters.postgresql.cnpg.io',LIVE_CLUSTER).status.currentPrimary;
    check(/^wedding-db-[1-9][0-9]*$/.test(mergePrimary));
    const schema=loadRecovered(mergePrimary,source.database,recoveredInventory.value,config);
    const output=psql(mergePrimary,source.database,buildMergeSQL(schema));
    merge=JSON.parse(output.toString('utf8').trim());
    for(const key of ['restoredGuestAnswers','restoredRoomBookings','finalMeaningfulGuestAnswers','finalRoomBookings'])check(Number.isSafeInteger(merge[key])&&merge[key]>=0);
    check(merge.finalMeaningfulGuestAnswers>=recovered.meaningfulGuests&&merge.finalRoomBookings>=recovered.roomBookings);
  }catch(candidate){error=candidate;}
  try{resumeApplication(config);}catch(candidate){resumeError=candidate;}
  try{cleanupRecovery(config,recovery);}catch(candidate){cleanupError=candidate;}
  if(error||resumeError||cleanupError)throw Error('refused');
  const after=backup(config,'after',source);
  recordProof({config,source,recovery,before,after,recovered,liveBefore,merge});
  return {restored:true,currentClusterUid:source.currentClusterUid,prelossBackupUid:source.prelossBackupUid,recoveryClusterUid:recovery.uid,beforeBackupUid:before.uid,afterBackupUid:after.uid,recovered,liveBefore,merge,cleanup:true};
}

function runCleanup(){
  const config=verifyCandidate();
  let resumeError,cleanupError,resumed=false;
  try{resumed=resumeApplication(config);}catch(candidate){resumeError=candidate;}
  try{cleanupRecovery(config);}catch(candidate){cleanupError=candidate;}
  if(resumeError||cleanupError)throw Error('refused');
  return {cleanup:true,resumed};
}

if(process.argv[1]===fileURLToPath(import.meta.url)){
  try{
    check(process.argv.length===2||(process.argv.length===3&&process.argv[2]==='--cleanup'));
    process.stdout.write(JSON.stringify(process.argv[2]==='--cleanup'?runCleanup():run())+'\n');
  }catch{process.stderr.write('Wedding database incident recovery refused.\n');process.exitCode=2;}
}
