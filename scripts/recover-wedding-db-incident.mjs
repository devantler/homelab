import {spawnSync} from 'node:child_process';
import {lstatSync,readFileSync,realpathSync} from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const NAMESPACE='wedding-app';
const PARENT_NAMESPACE='flux-system';
const PARENT_KUSTOMIZATION='apps';
const PARENT_KUSTOMIZATION_UID='7a4f35ea-01c8-460e-aefe-6fdf6d10eb48';
const FLUX_CONTROLLER='kustomize-controller';
const FLUX_CONTROLLER_UID='48c6521a-483a-4de9-895a-bae1a61ea25e';
const FLUX_CONTROLLER_REPLICAS=2;
const FLUX_CONTROLLER_RESTART_PATH='/spec/template/metadata/annotations/kubectl.kubernetes.io~1restartedAt';
const LIVE_CLUSTER='wedding-db';
const LIVE_DEPLOYMENT='wedding-app';
const LIVE_KUSTOMIZATION='wedding-app';
const LIVE_KUSTOMIZATION_UID='be31651e-fe0d-4826-9ffb-d41716a66720';
const LIVE_APP_POLICY_UID='60848dbb-144f-41e0-a47f-f602e8271d04';
const LIVE_DNS_POLICY_UID='89789584-31f8-407b-99e0-b8f4f2c23c11';
const SOURCE_STORE='wedding-db';
const SOURCE_STORE_UID='9cd2ba9b-c7bf-43e2-bd2d-a5c7c139fafb';
const SOURCE_SECRET='wedding-db-backup-r2';
const CURRENT_CLUSTER_UID='afea05ff-7daa-4d80-99a6-f2d696cbc3f1';
const PRELOSS_BACKUP='wedding-db-daily-20260908030000';
const PRELOSS_BACKUP_UID='549fe940-b119-4010-bdc8-fa8e6ebc93ae';
const PRELOSS_CLUSTER_UID='6b6d4879-e437-4ea5-a0cb-257de8edad00';
const PRELOSS_TARGET_TIME='2026-09-09T01:57:41Z';
const PRELOSS_TARGET_TIMELINE='162';
const PRELOSS_RECONCILIATION_DIGEST='sha256:022128434868723705c489546f68ba344a9cbe9e5c2b930a404d8aa2122ad9c7';
const RECOVERY_MODE='latest consistent archived WAL after backup 20260908T030001 on timeline 162';
const PROOF='wedding-db-data-recovery-proof';
const RECOVERY_OWNER_ANNOTATION='devantler.tech/wedding-db-recovery-owner';
const RECOVERY_RECONCILE_ANNOTATION='kustomize.toolkit.fluxcd.io/reconcile';
const RECOVERY_OWNER_PATH='/metadata/annotations/devantler.tech~1wedding-db-recovery-owner';
const RECOVERY_RECONCILE_PATH='/metadata/annotations/kustomize.toolkit.fluxcd.io~1reconcile';
const RECOVERY_REFUSAL_PHASES=new Set(['source-state','before-backup','restore-and-merge','after-backup','proof','cleanup']);
const RECOVERY_REFUSAL_CHECKPOINTS=new Set([
  'create-recovery','recovered-inventory-query','recovered-replay-time','recovered-core-inventory',
  'live-inventory-query','live-core-inventory','core-cardinality','suspend-application',
  'live-cluster-identity','live-primary','stage-recovered-data','application-fences',
  'merge-recovered-data','merge-shape','merge-postcondition','drop-staging-schema',
  'resume-application','cleanup-recovery',
]);
let recoveryInvocationVerified=false;
let recoveryPhase='invocation';
let recoveryCheckpoint;
let recoveryFailureSqlstate;
const check=value=>{if(!value)throw Error('refused');return value;};
const integer=value=>{check(typeof value==='string'&&/^[1-9][0-9]*$/.test(value));return value;};
const uid=value=>{check(typeof value==='string'&&/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(value));return value;};
const timestamp=value=>{check(typeof value==='string'&&!Number.isNaN(Date.parse(value)));return value;};
const condition=(value,type)=>value.status?.conditions?.some(item=>item.type===type&&item.status==='True');

export function extractRecoverySqlstate(stderr){
  if(typeof stderr!=='string'||stderr.length>65536)return undefined;
  const codes=stderr.split('\n').flatMap(line=>{const match=/^ERROR:\s+([0-9A-Z]{5})\s*$/.exec(line);return match?[match[1]]:[];});
  return codes.length===1?codes[0]:undefined;
}

export function recoveryRefusalMessage({verified=false,phase='invocation',checkpoint,sqlstate}={}){
  if(!verified||!RECOVERY_REFUSAL_PHASES.has(phase))return 'Wedding database incident recovery refused.\n';
  const checkpointAllowed=phase==='restore-and-merge'&&RECOVERY_REFUSAL_CHECKPOINTS.has(checkpoint);
  const checkpointDetail=checkpointAllowed?`; checkpoint: ${checkpoint}`:'';
  const sqlstateDetail=checkpointAllowed&&checkpoint==='merge-recovered-data'&&/^[0-9A-Z]{5}$/.test(sqlstate)?`; sqlstate: ${sqlstate}`:'';
  return `Wedding database incident recovery refused (phase: ${phase}${checkpointDetail}${sqlstateDetail}).\n`;
}

export function hasPrelossWitness(kustomization){
  return kustomization.status?.history?.some(item=>item.lastReconciled===PRELOSS_TARGET_TIME&&item.lastReconciledStatus==='ReconciliationSucceeded'&&item.digest===PRELOSS_RECONCILIATION_DIGEST&&item.metadata?.originRevision==='v1.15.11@sha1:5f0f5be0a228ee189ea3d10e4bd1b61ef0a8efe9')===true;
}

export function validateRecoveryReplayTimestamp(value,{replacementCreatedAt}){
  const upper=timestamp(replacementCreatedAt);
  if(value===null)return null;
  const replay=timestamp(value);check(Date.parse(replay)<Date.parse(upper));
  return replay;
}

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
  check(Date.parse(PRELOSS_TARGET_TIME)>Date.parse(backup.status.stoppedAt)&&Date.parse(PRELOSS_TARGET_TIME)<Date.parse(cluster.metadata.creationTimestamp));

  const imageName=cluster.spec.imageName;
  check(typeof imageName==='string'&&/^ghcr\.io\/cloudnative-pg\/postgresql:18\.[0-9]+-[a-z0-9-]+$/.test(imageName));
  check(cluster.spec.storage?.storageClass==='longhorn-wffc');
  check(/^[1-9][0-9]*(?:Mi|Gi|Ti)$/.test(cluster.spec.storage?.size));
  return {currentClusterUid:cluster.metadata.uid,sourceUid:store.metadata.uid,prelossBackupUid:backup.metadata.uid,database:'wedding',imageName,storageClass:'longhorn-wffc',size:cluster.spec.storage.size,endpoint,prelossBackupId:backup.status.backupId,replacementCreatedAt:cluster.metadata.creationTimestamp,prelossTargetTime:PRELOSS_TARGET_TIME,prelossTargetTimeline:PRELOSS_TARGET_TIMELINE};
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

export function recoveryOwnerAttempt(run,currentAttempt,owner){
  integer(run);integer(currentAttempt);
  const match=new RegExp('^'+run+'/([1-9][0-9]*)$').exec(owner);
  check(match&&BigInt(match[1])<=BigInt(currentAttempt));
  return match[1];
}

export function buildSuspendPatch({resourceVersion,kustomizationUid,annotationsPresent,owner}){
  integer(resourceVersion);check([LIVE_KUSTOMIZATION_UID,PARENT_KUSTOMIZATION_UID].includes(kustomizationUid)&&typeof annotationsPresent==='boolean'&&/^[1-9][0-9]*\/[1-9][0-9]*$/.test(owner));
  return [
    {op:'test',path:'/metadata/resourceVersion',value:resourceVersion},
    {op:'test',path:'/metadata/uid',value:kustomizationUid},
    ...(annotationsPresent?[]:[{op:'add',path:'/metadata/annotations',value:{}}]),
    {op:'add',path:RECOVERY_OWNER_PATH,value:owner},
    {op:'add',path:RECOVERY_RECONCILE_PATH,value:'disabled'},
    {op:'add',path:'/spec/suspend',value:true},
  ];
}

export function buildResumePatch({kustomizationUid,owner}){
  check([LIVE_KUSTOMIZATION_UID,PARENT_KUSTOMIZATION_UID].includes(kustomizationUid)&&/^[1-9][0-9]*\/[1-9][0-9]*$/.test(owner));
  return [
    {op:'test',path:'/metadata/uid',value:kustomizationUid},
    {op:'test',path:RECOVERY_OWNER_PATH,value:owner},
    {op:'test',path:RECOVERY_RECONCILE_PATH,value:'disabled'},
    {op:'test',path:'/spec/suspend',value:true},
    {op:'add',path:'/spec/suspend',value:false},
    {op:'remove',path:RECOVERY_OWNER_PATH},
    {op:'remove',path:RECOVERY_RECONCILE_PATH},
  ];
}

export function buildControllerRestartPatch({resourceVersion,deploymentUid,annotationsPresent,restartToken}){
  integer(resourceVersion);
  check(deploymentUid===FLUX_CONTROLLER_UID&&typeof annotationsPresent==='boolean');
  check(/^wedding-db-recovery-[1-9][0-9]*-[1-9][0-9]*$/.test(restartToken));
  return [
    {op:'test',path:'/metadata/resourceVersion',value:resourceVersion},
    {op:'test',path:'/metadata/uid',value:deploymentUid},
    ...(annotationsPresent?[]:[{op:'add',path:'/spec/template/metadata/annotations',value:{}}]),
    {op:'add',path:FLUX_CONTROLLER_RESTART_PATH,value:restartToken},
  ];
}

export function buildRecoveryResources({run,attempt,endpoint,imageName,storageClass,prelossBackupId,prelossTargetTime,prelossTargetTimeline}){
  check(storageClass==='longhorn-wffc');
  check(typeof imageName==='string'&&/^ghcr\.io\/cloudnative-pg\/postgresql:18\.[0-9]+-[a-z0-9-]+$/.test(imageName));
  check(prelossBackupId==='20260908T030001');
  check(prelossTargetTime===PRELOSS_TARGET_TIME&&prelossTargetTimeline===PRELOSS_TARGET_TIMELINE);
  const name=recoveryName(run,attempt),owned=labels(run,attempt),hostname=endpointHost(endpoint);
  const cluster={apiVersion:'postgresql.cnpg.io/v1',kind:'Cluster',metadata:{name,namespace:NAMESPACE,labels:owned},spec:{
    instances:1,imageName,enableSuperuserAccess:false,enablePDB:false,
    storage:{size:'2Gi',storageClass},
    resources:{requests:{cpu:'50m',memory:'256Mi'},limits:{cpu:'1',memory:'1Gi'}},
    bootstrap:{recovery:{source:'wedding-db-preloss',recoveryTarget:{backupID:prelossBackupId,targetTLI:prelossTargetTimeline}}},
    externalClusters:[{name:'wedding-db-preloss',plugin:{name:'barman-cloud.cloudnative-pg.io',parameters:{barmanObjectName:SOURCE_STORE,serverName:'wedding-db'}}}],
  }};
  const policy={apiVersion:'cilium.io/v2',kind:'CiliumNetworkPolicy',metadata:{name,namespace:NAMESPACE,labels:owned},spec:{endpointSelector:{matchLabels:{'cnpg.io/cluster':name}},egress:[
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
  const codes=new Set(),pairNames=new Set();
  for(const pair of guestPairs){
    check(pair&&typeof pair==='object'&&/^[A-Za-z0-9_-]{1,32}$/.test(pair.code));string(pair.name,255);timestamp(pair.createdAt);check(!codes.has(pair.code)&&!pairNames.has(pair.name));codes.add(pair.code);pairNames.add(pair.name);
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

export function buildSchemaCleanupSQL(run,attempt){
  integer(run);integer(attempt);
  const last=Number(attempt);check(Number.isSafeInteger(last)&&last<=100);
  return Array.from({length:last},(_,index)=>`DROP SCHEMA IF EXISTS ${schemaName(run,String(index+1))} CASCADE;`).join('\n');
}

export function buildMergeSQL(schema){
  check(/^incident_restore_[1-9][0-9]*_[1-9][0-9]*$/.test(schema)&&schema.length<=63);
  return `BEGIN;
SET TRANSACTION ISOLATION LEVEL READ COMMITTED;
LOCK TABLE guest_pairs, guests, room_bookings IN ACCESS EXCLUSIVE MODE;
DO $guard$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM ${schema}.room_bookings recovered
    JOIN ${schema}.guest_pairs recovered_pairs ON recovered_pairs.code=recovered.pair_code
    LEFT JOIN guest_pairs live_pairs ON live_pairs.name=recovered_pairs.name
    GROUP BY recovered.pair_code
    HAVING count(live_pairs.id) <> 1
  ) THEN RAISE SQLSTATE 'P1001' USING MESSAGE = 'room booking pair mapping mismatch'; END IF;
  IF EXISTS (
    SELECT 1
    FROM ${schema}.guests recovered
    JOIN ${schema}.guest_pairs recovered_pairs ON recovered_pairs.code=recovered.pair_code
    LEFT JOIN guest_pairs live_pairs ON live_pairs.name=recovered_pairs.name
    LEFT JOIN guests live ON live.guest_pair_id=live_pairs.id AND live.name=recovered.name
    WHERE recovered.attending IS NOT NULL OR recovered.dietary_notes IS NOT NULL
    GROUP BY recovered.pair_code,recovered.name
    HAVING count(live.id) <> 1
  ) THEN RAISE SQLSTATE 'P1002' USING MESSAGE = 'answered guest mapping mismatch'; END IF;
END $guard$;
CREATE TEMP TABLE incident_restore_counts (
  restored_guest_answers bigint NOT NULL,
  restored_room_bookings bigint NOT NULL
) ON COMMIT DROP;
WITH restored_guests AS (
  UPDATE guests live
  SET attending=recovered.attending,dietary_notes=recovered.dietary_notes,updated_at=recovered.updated_at
  FROM ${schema}.guests recovered
  JOIN ${schema}.guest_pairs recovered_pairs ON recovered_pairs.code=recovered.pair_code
  JOIN guest_pairs pairs ON pairs.name=recovered_pairs.name
  WHERE live.guest_pair_id=pairs.id AND live.name=recovered.name
    AND live.attending IS NULL AND live.dietary_notes IS NULL
    AND (recovered.attending IS NOT NULL OR recovered.dietary_notes IS NOT NULL)
  RETURNING live.id
), restored_bookings AS (
  INSERT INTO room_bookings (guest_pair_id,requested,notes,updated_at)
  SELECT pairs.id,recovered.requested,recovered.notes,recovered.updated_at
  FROM ${schema}.room_bookings recovered
  JOIN ${schema}.guest_pairs recovered_pairs ON recovered_pairs.code=recovered.pair_code
  JOIN guest_pairs pairs ON pairs.name=recovered_pairs.name
  ON CONFLICT (guest_pair_id) DO NOTHING
  RETURNING id
)
INSERT INTO incident_restore_counts (restored_guest_answers,restored_room_bookings)
SELECT (SELECT count(*) FROM restored_guests),(SELECT count(*) FROM restored_bookings);
SELECT json_build_object(
  'restoredGuestAnswers',(SELECT restored_guest_answers FROM incident_restore_counts),
  'restoredRoomBookings',(SELECT restored_room_bookings FROM incident_restore_counts),
  'finalMeaningfulGuestAnswers',(SELECT count(*) FROM guests WHERE attending IS NOT NULL OR dietary_notes IS NOT NULL),
  'finalRoomBookings',(SELECT count(*) FROM room_bookings)
);
DROP SCHEMA ${schema} CASCADE;
COMMIT;`;
}

function kubectl(args,{input,timeout=30000,maxBytes=2*1024*1024,captureSqlstate=false}={}){
  const result=spawnSync('kubectl',['--kubeconfig',path.join(process.env.HOME,'.kube/config'),'--context','admin@prod',...args],{input,env:{PATH:process.env.PATH,HOME:process.env.HOME},timeout,maxBuffer:maxBytes});
  const valid=!result.error&&result.status===0&&result.stdout.length<=maxBytes&&result.stderr.length<=maxBytes;
  if(!valid&&captureSqlstate&&!result.error){
    const sqlstate=extractRecoverySqlstate(result.stderr.toString('utf8'));
    if(sqlstate)throw Error('sqlstate:'+sqlstate);
  }
  check(valid);
  return result.stdout;
}

function objectAt(namespace,resource,name){
  const value=JSON.parse(kubectl(['--namespace',namespace,'get',resource,name,'--output=json','--request-timeout=20s']).toString('utf8'));
  check(value&&typeof value==='object'&&!Array.isArray(value));return value;
}

function object(resource,name){return objectAt(NAMESPACE,resource,name);}

function optionalObject(resource,name){
  const output=kubectl(['--namespace',NAMESPACE,'get',resource,name,'--ignore-not-found=true','--output=json','--request-timeout=20s']);
  return output.length?JSON.parse(output.toString('utf8')):null;
}

function listAt(namespace,resource,selector){
  const value=JSON.parse(kubectl(['--namespace',namespace,'get',resource,'--selector',selector,'--output=json','--request-timeout=20s']).toString('utf8'));
  check(typeof value?.apiVersion==='string'&&Array.isArray(value.items)&&value.items.length<=32);return value.items;
}

function list(resource,selector){return listAt(NAMESPACE,resource,selector);}

function verifyCandidate(){
  check(process.env.GITHUB_REPOSITORY==='devantler-tech/platform'&&process.env.GITHUB_EVENT_NAME==='workflow_dispatch');
  check(process.env.GITHUB_REF==='refs/heads/main'&&process.env.GITHUB_REF_NAME==='main'&&/^[0-9a-f]{40}$/.test(process.env.GITHUB_SHA));
  const workspace=realpathSync(process.env.GITHUB_WORKSPACE);check(workspace===process.env.GITHUB_WORKSPACE);
  const head=spawnSync('git',['--no-replace-objects','-C',workspace,'rev-parse','HEAD'],{encoding:'utf8',env:{PATH:process.env.PATH,GIT_NO_REPLACE_OBJECTS:'1'},maxBuffer:1024});
  check(!head.error&&head.status===0&&head.stdout===process.env.GITHUB_SHA+'\n');
  for(const relative of ['scripts/recover-wedding-db-incident.mjs','scripts/use-prod-stable-api-endpoint.sh','.github/workflows/recover-wedding-db-incident.yaml','k8s/bases/apps/wedding-app/flux-kustomization.yaml']){
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
  const parent=objectAt(PARENT_NAMESPACE,'kustomizations.kustomize.toolkit.fluxcd.io',PARENT_KUSTOMIZATION);
  check(parent.metadata.uid===PARENT_KUSTOMIZATION_UID&&parent.metadata.creationTimestamp==='2026-05-23T00:41:58Z');
  check(parent.spec?.suspend!==true&&condition(parent,'Ready')&&!parent.metadata?.annotations?.[RECOVERY_OWNER_ANNOTATION]&&!parent.metadata?.annotations?.[RECOVERY_RECONCILE_ANNOTATION]);
  const kustomization=object('kustomizations.kustomize.toolkit.fluxcd.io',LIVE_KUSTOMIZATION);
  check(kustomization.metadata.uid===LIVE_KUSTOMIZATION_UID&&kustomization.metadata.creationTimestamp==='2026-05-23T01:52:44Z');
  check(kustomization.spec?.force===false&&kustomization.spec.suspend!==true&&condition(kustomization,'Ready'));
  check(hasPrelossWitness(kustomization));
  const appPolicy=object('ciliumnetworkpolicies.cilium.io','app');
  check(appPolicy.metadata.uid===LIVE_APP_POLICY_UID&&appPolicy.metadata.creationTimestamp==='2026-06-16T18:14:37Z');
  check(appPolicy.spec?.endpointSelector&&Object.keys(appPolicy.spec.endpointSelector).length===0);
  check(appPolicy.spec.egress?.some(rule=>rule.toFQDNs?.some(target=>target.matchPattern==='*.r2.cloudflarestorage.com')&&rule.toPorts?.some(item=>item.ports?.some(port=>port.port==='443'&&port.protocol==='TCP'))));
  check(appPolicy.spec.egress?.some(rule=>rule.toPorts?.some(item=>item.rules?.dns?.some(dns=>dns.matchPattern==='*'))));
  const dnsPolicy=object('ciliumnetworkpolicies.cilium.io','allow-dns');
  check(dnsPolicy.metadata.uid===LIVE_DNS_POLICY_UID&&dnsPolicy.metadata.creationTimestamp==='2026-05-23T01:52:43Z');
  check(dnsPolicy.spec?.endpointSelector&&Object.keys(dnsPolicy.spec.endpointSelector).length===0);
  check(dnsPolicy.spec.egress?.some(rule=>rule.toPorts?.some(item=>item.ports?.some(port=>port.port==='53'&&(port.protocol==='UDP'||port.protocol==='TCP')))));
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
  'recoveryReplayTimestamp',pg_last_xact_replay_timestamp(),
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

function psql(primary,database,command,{input,maxBytes=65536,captureSqlstate=false}={}){
  return kubectl(['--namespace',NAMESPACE,'exec',...(input?['--stdin']:[]),primary,'--container=postgres','--','psql','--username=postgres','--dbname='+database,'--set=ON_ERROR_STOP=1','--set=VERBOSITY=sqlstate','--tuples-only','--no-align','--quiet','--command='+command],{input,timeout:120000,maxBytes,captureSqlstate});
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

function dropStagingSchema(primary,database,config){
  psql(primary,database,`DROP SCHEMA IF EXISTS ${schemaName(config.run,config.attempt)} CASCADE;`);
}

function dropRunStagingSchemas(primary,database,config){
  psql(primary,database,buildSchemaCleanupSQL(config.run,config.attempt));
}

function fenceOwner(state,uidValue,config){
  check(state.metadata.uid===uidValue);
  const owner=state.metadata?.annotations?.[RECOVERY_OWNER_ANNOTATION];
  if(!owner)return null;
  recoveryOwnerAttempt(config.run,config.attempt,owner);
  check(state.metadata.annotations[RECOVERY_RECONCILE_ANNOTATION]==='disabled'&&state.spec?.suspend===true);
  return owner;
}

function acquireFence(namespace,name,uidValue,config){
  const owner=recoveryOwner(config.run,config.attempt),end=Date.now()+5*60*1000;
  let current;
  while(Date.now()<end){
    current=objectAt(namespace,'kustomizations.kustomize.toolkit.fluxcd.io',name);
    check(current.metadata.uid===uidValue&&typeof current.metadata.resourceVersion==='string');
    check(current.metadata.annotations===undefined||(current.metadata.annotations!==null&&typeof current.metadata.annotations==='object'&&!Array.isArray(current.metadata.annotations)));
    check(current.spec?.suspend!==true&&!current.metadata.annotations?.[RECOVERY_OWNER_ANNOTATION]&&!current.metadata.annotations?.[RECOVERY_RECONCILE_ANNOTATION]);
    if(condition(current,'Ready')&&!condition(current,'Reconciling')&&current.status?.observedGeneration===current.metadata.generation)break;
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,3000);
  }
  check(current&&Date.now()<end);
  const patch=buildSuspendPatch({resourceVersion:current.metadata.resourceVersion,kustomizationUid:current.metadata.uid,annotationsPresent:current.metadata.annotations!==undefined,owner});
  kubectl(['--namespace',namespace,'patch','kustomization.kustomize.toolkit.fluxcd.io',name,'--type=json','--patch='+JSON.stringify(patch)]);
  let stableResourceVersion='';
  for(let attempt=0;attempt<3;attempt+=1){
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,3000);
    const fenced=objectAt(namespace,'kustomizations.kustomize.toolkit.fluxcd.io',name);
    check(fenced.metadata.uid===uidValue&&fenced.spec?.suspend===true&&!condition(fenced,'Reconciling'));
    check(fenced.metadata?.annotations?.[RECOVERY_OWNER_ANNOTATION]===owner&&fenced.metadata.annotations[RECOVERY_RECONCILE_ANNOTATION]==='disabled');
    if(stableResourceVersion===fenced.metadata.resourceVersion)return;
    stableResourceVersion=fenced.metadata.resourceVersion;
  }
  throw Error('refused');
}

function releaseFence(namespace,name,uidValue,config){
  const current=objectAt(namespace,'kustomizations.kustomize.toolkit.fluxcd.io',name);
  const owner=fenceOwner(current,uidValue,config);if(!owner)return false;
  const patch=buildResumePatch({kustomizationUid:current.metadata.uid,owner});
  kubectl(['--namespace',namespace,'patch','kustomization.kustomize.toolkit.fluxcd.io',name,'--type=json','--patch='+JSON.stringify(patch)]);
  const released=objectAt(namespace,'kustomizations.kustomize.toolkit.fluxcd.io',name);
  check(released.metadata.uid===uidValue&&released.spec?.suspend===false);
  check(!released.metadata?.annotations?.[RECOVERY_OWNER_ANNOTATION]&&!released.metadata?.annotations?.[RECOVERY_RECONCILE_ANNOTATION]);
  return true;
}

function proveApplicationFences(config){
  const owner=recoveryOwner(config.run,config.attempt);
  const parent=objectAt(PARENT_NAMESPACE,'kustomizations.kustomize.toolkit.fluxcd.io',PARENT_KUSTOMIZATION);
  const child=object('kustomizations.kustomize.toolkit.fluxcd.io',LIVE_KUSTOMIZATION);
  check(fenceOwner(parent,PARENT_KUSTOMIZATION_UID,config)===owner);
  check(fenceOwner(child,LIVE_KUSTOMIZATION_UID,config)===owner);
}

function assertControllerReady(controller,{restartToken}={}){
  check(controller.apiVersion==='apps/v1'&&controller.kind==='Deployment');
  check(controller.metadata?.name===FLUX_CONTROLLER&&controller.metadata.namespace===PARENT_NAMESPACE);
  check(controller.metadata.uid===FLUX_CONTROLLER_UID&&controller.metadata.creationTimestamp==='2026-05-23T00:41:46Z'&&!controller.metadata.deletionTimestamp);
  check(typeof controller.metadata.resourceVersion==='string'&&Number.isSafeInteger(controller.metadata.generation));
  check(controller.spec?.replicas===FLUX_CONTROLLER_REPLICAS&&controller.spec.selector?.matchLabels?.app===FLUX_CONTROLLER);
  check(controller.status?.observedGeneration===controller.metadata.generation&&controller.status.updatedReplicas===FLUX_CONTROLLER_REPLICAS&&controller.status.readyReplicas===FLUX_CONTROLLER_REPLICAS&&controller.status.availableReplicas===FLUX_CONTROLLER_REPLICAS);
  check(controller.spec.template?.metadata?.annotations&&typeof controller.spec.template.metadata.annotations==='object');
  if(restartToken)check(controller.spec.template.metadata.annotations['kubectl.kubernetes.io/restartedAt']===restartToken);
}

function assertReadyControllerPods(pods,expected){
  check(pods.length===expected);
  for(const pod of pods)check(pod.metadata?.namespace===PARENT_NAMESPACE&&!pod.metadata.deletionTimestamp&&uid(pod.metadata.uid)&&condition(pod,'Ready'));
}

function restartKustomizeController(config){
  proveApplicationFences(config);
  const beforeController=objectAt(PARENT_NAMESPACE,'deployments.apps',FLUX_CONTROLLER);
  assertControllerReady(beforeController);
  const beforePods=listAt(PARENT_NAMESPACE,'pods','app='+FLUX_CONTROLLER);
  assertReadyControllerPods(beforePods,FLUX_CONTROLLER_REPLICAS);
  const oldUids=new Set(beforePods.map(pod=>pod.metadata.uid));
  const restartToken=`wedding-db-recovery-${integer(config.run)}-${integer(config.attempt)}`;
  const patch=buildControllerRestartPatch({
    resourceVersion:beforeController.metadata.resourceVersion,
    deploymentUid:beforeController.metadata.uid,
    annotationsPresent:typeof beforeController.spec.template.metadata.annotations==='object',
    restartToken,
  });
  try{
    kubectl(['--namespace',PARENT_NAMESPACE,'patch','deployment.apps',FLUX_CONTROLLER,'--type=json','--patch='+JSON.stringify(patch)]);
  }catch{
    assertControllerReady(objectAt(PARENT_NAMESPACE,'deployments.apps',FLUX_CONTROLLER),{restartToken});
  }
  kubectl(['--namespace',PARENT_NAMESPACE,'rollout','status','deployment.apps/'+FLUX_CONTROLLER,'--timeout=10m'],{timeout:630000});
  const end=Date.now()+5*60*1000;
  while(Date.now()<end){
    proveApplicationFences(config);
    const controller=objectAt(PARENT_NAMESPACE,'deployments.apps',FLUX_CONTROLLER);
    const pods=listAt(PARENT_NAMESPACE,'pods','app='+FLUX_CONTROLLER);
    const current=pods.filter(pod=>!pod.metadata?.deletionTimestamp);
    if([...oldUids].every(oldUid=>!pods.some(pod=>pod.metadata?.uid===oldUid))){
      assertControllerReady(controller,{restartToken});
      assertReadyControllerPods(current,FLUX_CONTROLLER_REPLICAS);
      return;
    }
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,3000);
  }
  throw Error('refused');
}

function suspendApplication(config){
  acquireFence(PARENT_NAMESPACE,PARENT_KUSTOMIZATION,PARENT_KUSTOMIZATION_UID,config);
  acquireFence(NAMESPACE,LIVE_KUSTOMIZATION,LIVE_KUSTOMIZATION_UID,config);
  // Suspension cannot cancel a reconciliation that already started. Replacing
  // every controller process under both fences drains that cached work first.
  restartKustomizeController(config);
  kubectl(['--namespace',NAMESPACE,'scale','deployment',LIVE_DEPLOYMENT,'--replicas=0']);
  const end=Date.now()+5*60*1000;let stable=0;
  while(Date.now()<end){
    const deployment=object('deployments.apps',LIVE_DEPLOYMENT);
    proveApplicationFences(config);
    if((deployment.status?.replicas??0)===0&&list('pods','app.kubernetes.io/name=wedding-app').length===0)stable+=1;else stable=0;
    if(stable>=2)return;
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,3000);
  }
  throw Error('refused');
}

function resumeApplication(config){
  const child=object('kustomizations.kustomize.toolkit.fluxcd.io',LIVE_KUSTOMIZATION);
  const parent=objectAt(PARENT_NAMESPACE,'kustomizations.kustomize.toolkit.fluxcd.io',PARENT_KUSTOMIZATION);
  const childOwner=fenceOwner(child,LIVE_KUSTOMIZATION_UID,config);
  const parentOwner=fenceOwner(parent,PARENT_KUSTOMIZATION_UID,config);
  if(!childOwner&&!parentOwner)return false;
  if(!childOwner)check(child.spec?.suspend!==true&&!child.metadata?.annotations?.[RECOVERY_RECONCILE_ANNOTATION]);
  check(object('clusters.postgresql.cnpg.io',LIVE_CLUSTER).metadata.uid===CURRENT_CLUSTER_UID);
  let failed=false;
  try{kubectl(['--namespace',NAMESPACE,'scale','deployment',LIVE_DEPLOYMENT,'--replicas=2']);}catch{failed=true;}
  let childReleased=!childOwner;
  if(childOwner){try{releaseFence(NAMESPACE,LIVE_KUSTOMIZATION,LIVE_KUSTOMIZATION_UID,config);childReleased=true;}catch{failed=true;}}
  try{kubectl(['--namespace',NAMESPACE,'rollout','status','deployment/'+LIVE_DEPLOYMENT,'--timeout=10m'],{timeout:630000});}catch{failed=true;}
  try{
    const restored=object('kustomizations.kustomize.toolkit.fluxcd.io',LIVE_KUSTOMIZATION);
    const deployment=object('deployments.apps',LIVE_DEPLOYMENT);
    check(restored.metadata.uid===LIVE_KUSTOMIZATION_UID&&restored.spec?.suspend!==true);
    check(!restored.metadata?.annotations?.[RECOVERY_OWNER_ANNOTATION]&&!restored.metadata?.annotations?.[RECOVERY_RECONCILE_ANNOTATION]);
    check(deployment.spec?.replicas===2&&deployment.status?.availableReplicas>=2);
  }catch{failed=true;}
  if(parentOwner&&childReleased&&!failed){try{releaseFence(PARENT_NAMESPACE,PARENT_KUSTOMIZATION,PARENT_KUSTOMIZATION_UID,config);}catch{failed=true;}}
  check(!failed);
  return true;
}

function createRecovery(config,source){
  const resources=buildRecoveryResources({...config,...source}),name=resources.cluster.metadata.name;
  check(!optionalObject('clusters.postgresql.cnpg.io',name)&&!optionalObject('ciliumnetworkpolicies.cilium.io',name));
  kubectl(['create','--filename=-'],{input:Buffer.from(JSON.stringify({apiVersion:'v1',kind:'List',items:[resources.policy,resources.cluster]}))});
  kubectl(['--namespace',NAMESPACE,'wait','cluster.postgresql.cnpg.io/'+name,'--for=condition=Ready','--timeout=30m'],{timeout:1830000});
  const cluster=object('clusters.postgresql.cnpg.io',name);check(cluster.status?.readyInstances===1&&cluster.status.currentPrimary&&condition(cluster,'Ready'));
  const target=cluster.spec?.bootstrap?.recovery?.recoveryTarget;
  check(target?.backupID===source.prelossBackupId&&target.targetTLI===source.prelossTargetTimeline&&!target.targetTime&&!target.targetImmediate&&!target.targetLSN&&!target.targetName&&!target.targetXID&&!target.exclusive&&!cluster.spec.plugins);
  return {name,uid:uid(cluster.metadata.uid),primary:cluster.status.currentPrimary};
}

function cleanupRecovery(config,recovery){
  const attempts=new Set([config.attempt]);
  const selector='app.kubernetes.io/name=wedding-db-incident-recovery,app.kubernetes.io/managed-by=github-actions,devantler.tech/github-run='+config.run;
  const collect=item=>{
    const attempt=recoveryOwnerAttempt(config.run,config.attempt,config.run+'/'+integer(item.metadata?.labels?.['devantler.tech/github-attempt']));
    check(item.metadata?.name===recoveryName(config.run,attempt));
    for(const [key,value] of Object.entries(labels(config.run,attempt)))check(item.metadata.labels[key]===value);
    attempts.add(attempt);
  };
  const clusters=list('clusters.postgresql.cnpg.io',selector);for(const cluster of clusters)collect(cluster);
  const policies=list('ciliumnetworkpolicies.cilium.io',selector);for(const policy of policies)collect(policy);
  for(const claim of list('persistentvolumeclaims','cnpg.io/cluster')){
    const clusterName=claim.metadata?.labels?.['cnpg.io/cluster'];
    const match=new RegExp('^wedding-db-preloss-'+config.run+'-([1-9][0-9]*)$').exec(clusterName);
    if(match)attempts.add(recoveryOwnerAttempt(config.run,config.attempt,config.run+'/'+match[1]));
  }
  const names=[...attempts].map(attempt=>recoveryName(config.run,attempt));
  if(recovery){check(names.includes(recovery.name));const found=clusters.find(cluster=>cluster.metadata.name===recovery.name);if(found)check(found.metadata.uid===recovery.uid);}
  const clusterNames=clusters.map(cluster=>cluster.metadata.name);
  if(clusterNames.length)kubectl(['--namespace',NAMESPACE,'delete','cluster.postgresql.cnpg.io',...clusterNames,'--wait=true','--timeout=10m'],{timeout:630000});
  const claims=list('persistentvolumeclaims','cnpg.io/cluster').filter(claim=>names.includes(claim.metadata?.labels?.['cnpg.io/cluster']));
  if(claims.length)kubectl(['--namespace',NAMESPACE,'delete','persistentvolumeclaim',...claims.map(claim=>claim.metadata.name),'--wait=true','--timeout=10m'],{timeout:630000});
  const policyNames=policies.map(policy=>policy.metadata.name);
  if(policyNames.length)kubectl(['--namespace',NAMESPACE,'delete','ciliumnetworkpolicy.cilium.io',...policyNames,'--wait=true','--timeout=2m'],{timeout:150000});
  for(const name of names)check(!optionalObject('clusters.postgresql.cnpg.io',name)&&list('persistentvolumeclaims','cnpg.io/cluster='+name).length===0&&!optionalObject('ciliumnetworkpolicies.cilium.io',name));
}

function recordProof({config,source,recovery,before,after,recovered,recoveryReplayTimestamp,liveBefore,merge}){
  const manifest={apiVersion:'v1',kind:'ConfigMap',metadata:{name:PROOF,namespace:NAMESPACE,labels:{'app.kubernetes.io/name':'wedding-db','app.kubernetes.io/managed-by':'github-actions'}},data:{
    version:'3',recoveryMode:RECOVERY_MODE,recoveryReplayTimestamp:recoveryReplayTimestamp??'none-after-base-backup',prelossReconciliationWitness:source.prelossTargetTime,recoveryArchiveUpperBound:source.replacementCreatedAt,recoveryTargetTimeline:source.prelossTargetTimeline,replacementCreatedAt:source.replacementCreatedAt,currentClusterUid:source.currentClusterUid,prelossClusterUid:PRELOSS_CLUSTER_UID,prelossBackupUid:source.prelossBackupUid,recoveryClusterUid:recovery.uid,
    beforeBackupUid:before.uid,afterBackupUid:after.uid,recoveredGuests:String(recovered.guests),recoveredMeaningfulGuests:String(recovered.meaningfulGuests),recoveredRoomBookings:String(recovered.roomBookings),
    liveBeforeMeaningfulGuests:String(liveBefore.meaningfulGuests),liveBeforeRoomBookings:String(liveBefore.roomBookings),restoredGuestAnswers:String(merge.restoredGuestAnswers),restoredRoomBookings:String(merge.restoredRoomBookings),
    finalMeaningfulGuestAnswers:String(merge.finalMeaningfulGuestAnswers),finalRoomBookings:String(merge.finalRoomBookings),githubRun:config.run,githubAttempt:config.attempt,
  }};
  kubectl(['create','--filename=-'],{input:Buffer.from(JSON.stringify(manifest))});
  exactObject(object('configmaps',PROOF),{apiVersion:'v1',kind:'ConfigMap',name:PROOF});
}

function run(){
  const config=verifyCandidate();recoveryInvocationVerified=true;recoveryPhase='source-state';
  const source=sourceState();recoveryPhase='before-backup';
  const before=backup(config,'before',source);
  recoveryPhase='restore-and-merge';
  let recovery,recoveredInventory,recovered,recoveryReplayTimestamp,liveBefore,merge,mergePrimary,error,errorCheckpoint,errorSqlstate,schemaCleanupError,resumeError,cleanupError;
  try{
    recoveryCheckpoint='create-recovery';
    recovery=createRecovery(config,source);
    recoveryCheckpoint='recovered-inventory-query';
    recoveredInventory=inventory(recovery.primary,source.database,{requireMeaningful:true});
    recoveryCheckpoint='recovered-replay-time';
    recoveryReplayTimestamp=validateRecoveryReplayTimestamp(recoveredInventory.value.recoveryReplayTimestamp,{replacementCreatedAt:source.replacementCreatedAt});
    recoveryCheckpoint='recovered-core-inventory';
    recovered=validateCoreInventory(recoveredInventory.value,{requireMeaningful:true});
    recoveryCheckpoint='live-inventory-query';
    const livePrimary=object('clusters.postgresql.cnpg.io',LIVE_CLUSTER).status.currentPrimary;
    const liveInventory=inventory(livePrimary,source.database,{requireMeaningful:false});
    recoveryCheckpoint='live-core-inventory';
    liveBefore=validateCoreInventory(liveInventory.value,{requireMeaningful:false});
    recoveryCheckpoint='core-cardinality';
    check(recovered.guestPairs===liveBefore.guestPairs&&recovered.guests===liveBefore.guests);
    recoveryCheckpoint='suspend-application';
    suspendApplication(config);
    recoveryCheckpoint='live-cluster-identity';
    check(object('clusters.postgresql.cnpg.io',LIVE_CLUSTER).metadata.uid===source.currentClusterUid);
    recoveryCheckpoint='live-primary';
    mergePrimary=object('clusters.postgresql.cnpg.io',LIVE_CLUSTER).status.currentPrimary;
    check(/^wedding-db-[1-9][0-9]*$/.test(mergePrimary));
    recoveryCheckpoint='stage-recovered-data';
    const schema=loadRecovered(mergePrimary,source.database,recoveredInventory.value,config);
    recoveryCheckpoint='application-fences';
    proveApplicationFences(config);check(list('pods','app.kubernetes.io/name=wedding-app').length===0);
    recoveryCheckpoint='merge-recovered-data';
    const output=psql(mergePrimary,source.database,buildMergeSQL(schema),{captureSqlstate:true});
    merge=JSON.parse(output.toString('utf8').trim());
    recoveryCheckpoint='merge-shape';
    for(const key of ['restoredGuestAnswers','restoredRoomBookings','finalMeaningfulGuestAnswers','finalRoomBookings'])check(Number.isSafeInteger(merge[key])&&merge[key]>=0);
    recoveryCheckpoint='merge-postcondition';
    check(merge.finalMeaningfulGuestAnswers>=recovered.meaningfulGuests&&merge.finalRoomBookings>=recovered.roomBookings);
  }catch(candidate){
    error=candidate;errorCheckpoint=recoveryCheckpoint;
    const match=/^sqlstate:([0-9A-Z]{5})$/.exec(candidate?.message);errorSqlstate=match?.[1];
  }
  if(error&&mergePrimary){try{dropStagingSchema(mergePrimary,source.database,config);}catch(candidate){schemaCleanupError=candidate;}}
  try{resumeApplication(config);}catch(candidate){resumeError=candidate;}
  try{cleanupRecovery(config,recovery);}catch(candidate){cleanupError=candidate;}
  if(error||schemaCleanupError||resumeError||cleanupError){
    recoveryCheckpoint=schemaCleanupError?'drop-staging-schema':resumeError?'resume-application':cleanupError?'cleanup-recovery':errorCheckpoint;
    recoveryFailureSqlstate=recoveryCheckpoint===errorCheckpoint?errorSqlstate:undefined;
    throw Error('refused');
  }
  recoveryCheckpoint=undefined;recoveryPhase='after-backup';
  const after=backup(config,'after',source);
  recoveryPhase='proof';
  recordProof({config,source,recovery,before,after,recovered,recoveryReplayTimestamp,liveBefore,merge});
  return {restored:true,currentClusterUid:source.currentClusterUid,prelossBackupUid:source.prelossBackupUid,recoveryClusterUid:recovery.uid,beforeBackupUid:before.uid,afterBackupUid:after.uid,recoveryReplayTimestamp,recovered,liveBefore,merge,cleanup:true};
}

function runCleanup(){
  const config=verifyCandidate();recoveryInvocationVerified=true;recoveryPhase='cleanup';
  let schemaCleanupError,resumeError,cleanupError,resumed=false,schemaCleaned=false;
  const kustomization=object('kustomizations.kustomize.toolkit.fluxcd.io',LIVE_KUSTOMIZATION);
  const owner=kustomization.metadata?.annotations?.[RECOVERY_OWNER_ANNOTATION];
  if(owner)recoveryOwnerAttempt(config.run,config.attempt,owner);
  const cleanupSchema=()=>{
    const cluster=object('clusters.postgresql.cnpg.io',LIVE_CLUSTER);check(cluster.metadata.uid===CURRENT_CLUSTER_UID);
    const primary=cluster.status?.currentPrimary;check(/^wedding-db-[1-9][0-9]*$/.test(primary));
    dropRunStagingSchemas(primary,'wedding',config);schemaCleaned=true;schemaCleanupError=undefined;
  };
  if(owner){
    try{
      check(kustomization.metadata.uid===LIVE_KUSTOMIZATION_UID&&kustomization.spec?.suspend===true&&kustomization.metadata.annotations[RECOVERY_RECONCILE_ANNOTATION]==='disabled');
      cleanupSchema();
    }catch(candidate){schemaCleanupError=candidate;}
  }
  try{resumed=resumeApplication(config);}catch(candidate){resumeError=candidate;}
  if(!schemaCleaned){try{cleanupSchema();}catch(candidate){schemaCleanupError=candidate;}}
  try{cleanupRecovery(config);}catch(candidate){cleanupError=candidate;}
  if(schemaCleanupError||resumeError||cleanupError)throw Error('refused');
  return {cleanup:true,resumed};
}

if(process.argv[1]===fileURLToPath(import.meta.url)){
  try{
    check(process.argv.length===2||(process.argv.length===3&&['--cleanup','--verify-source'].includes(process.argv[2])));
    const result=process.argv[2]==='--verify-source'?(verifyCandidate(),{sourceVerified:true}):process.argv[2]==='--cleanup'?runCleanup():run();
    process.stdout.write(JSON.stringify(result)+'\n');
  }catch{process.stderr.write(recoveryRefusalMessage({verified:recoveryInvocationVerified,phase:recoveryPhase,checkpoint:recoveryCheckpoint,sqlstate:recoveryFailureSqlstate}));process.exitCode=2;}
}
