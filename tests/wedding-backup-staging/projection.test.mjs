import test from 'node:test';
import assert from 'node:assert/strict';
import {verifyProjection} from '../../scripts/wedding-backup-projection.mjs';
import {harness,opts,enc,id,secret} from './fixtures.mjs';

for (const enabled of [undefined,false,'false']) test(`disabled ${String(enabled)} never calls a dependency`,async()=>{
 const deps=new Proxy({}, {get(){throw Error('disabled check read a dependency');}});
 assert.deepEqual(await verifyProjection({enabled},deps),{verified:false,skipped:true});
});
test('true compares only the fixed dedicated pairs and returns no source-decryption claim',async()=>{
 const h=harness();
 const result=await verifyProjection({...opts,enabled:true},h.deps);
 assert.deepEqual(result,{verified:true,projectionEqual:true,liveSourceStable:true});
 assert.equal(h.reads.filter(x=>x==='bootstrapSecret').length,2);
 assert.equal(h.reads.filter(x=>x==='projectedSecret').length,2);
 assert.deepEqual(h.bindings,[
  {sourceSha:'f'.repeat(40),recipeSha:'a'.repeat(40),digest:'sha256:'+'b'.repeat(64)},
  {sourceSha:'f'.repeat(40),recipeSha:'a'.repeat(40),digest:'sha256:'+'b'.repeat(64)}
 ]);
 assert.deepEqual(h.calls,[]);
 assert.equal(JSON.stringify(result).includes(id),false);
 assert.equal(JSON.stringify(result).includes(secret),false);
});
for(const [label,change] of [
 ['access mismatch',d=>d.projectedSecret.data.ACCESS_KEY_ID=enc('a'.repeat(32))],
 ['secret mismatch',d=>d.projectedSecret.data.SECRET_ACCESS_KEY=enc('a'.repeat(64))],
 ['extra field',d=>d.projectedSecret.data.EXTRA=enc('extra')],
 ['malformed base64',d=>d.bootstrapSecret.data.access_key_id='not base64'],
 ['wrong region',d=>d.projectedSecret.data.REGION=enc('eu-west-1')],
 ['wrong owner',d=>d.projectedSecret.metadata.ownerReferences[0].uid='00000000-0000-0000-0000-999999999999'],
 ['foreign source',d=>d.source.spec.url='oci://example.invalid/other'],
 ['stale digest',d=>d.apps.status.lastAppliedRevision='latest@sha256:'+ 'f'.repeat(64)],
 ['unverified source',d=>d.source.status.conditions.pop()],
 ['wrong mapping',d=>d.projection.spec.data[0].remoteRef.property='secret_access_key'],
 ['early active cutover',d=>{
   d.active.spec.configuration.destinationPath='s3://wedding-db-backups/cnpg/wedding-db';
   for(const credential of Object.values(d.active.spec.configuration.s3Credentials))credential.name='wedding-db-backup-r2-dedicated';
 }],
 ['wrong staged destination',d=>d.staged.spec.configuration.destinationPath='s3://platform-backups/cnpg/wedding-db'],
 ['reused predecessor archive',d=>d.cluster.spec.plugins[0].parameters.serverName='wedding-db'],
 ['deleted seed',d=>d.seed.metadata.deletionTimestamp='2026-01-01T00:00:00Z']
])test(label+' refuses without payload output',async()=>{
 const h=harness(change);const result=await verifyProjection({...opts,enabled:'true'},h.deps);
 assert.deepEqual(result,{verified:false});
 assert.deepEqual(h.calls,[]);
});
test('controller refusal happens before either Secret read',async()=>{
 const h=harness(d=>d.seed.status.conditions=[]);
 assert.deepEqual(await verifyProjection({...opts,enabled:true},h.deps),{verified:false});
 assert.equal(h.reads.some(x=>x.endsWith('Secret')),false);
});
for(const [label,change] of [
 ['UID replacement',d=>d.bootstrapSecret.metadata.uid='00000000-0000-0000-0000-999999999999'],
 ['resourceVersion movement',d=>d.projectedSecret.metadata.resourceVersion='999'],
 ['generation movement',d=>{d.projection.metadata.generation=2;d.projection.status.observedGeneration=2;}],
 ['pair replacement',d=>{d.bootstrapSecret.data.access_key_id=enc('a'.repeat(32));d.projectedSecret.data.ACCESS_KEY_ID=enc('a'.repeat(32));}]
])test(label+' between samples refuses',async()=>{
 const h=harness(); const read=h.deps.read; let sources=0;
 h.deps.read=async t=>{if(t.id==='source'&&++sources===2)change(h.docs);return read(t);};
 assert.deepEqual(await verifyProjection({...opts,enabled:true},h.deps),{verified:false});
});
for(const patch of [{event:'pull_request'},{ref:'refs/heads/other'},{attempt:'2'},{workflowSha:'f'.repeat(40)}])test('untrusted invocation refuses '+JSON.stringify(patch),async()=>{
 const h=harness(()=>{},patch);
 assert.deepEqual(await verifyProjection({...opts,enabled:true},h.deps),{verified:false});
 assert.equal(h.reads.length,0);
});
test('source refusal happens before reads and source change after sampling fails',async()=>{
 const h=harness();h.deps.sourceUnchanged=async()=>false;
 assert.deepEqual(await verifyProjection({...opts,enabled:true},h.deps),{verified:false});assert.equal(h.reads.length,0);
 let n=0;h.deps.sourceUnchanged=async()=>++n===1;
 assert.deepEqual(await verifyProjection({...opts,enabled:true},h.deps),{verified:false});
});
test('reader diagnostics are suppressed',async()=>{
 const h=harness();h.deps.read=async()=>{throw Error(secret);};
 assert.deepEqual(await verifyProjection({...opts,enabled:true},h.deps),{verified:false});
});
