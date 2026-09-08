import {spawn} from 'node:child_process';
import {readFile,lstat,realpath} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import path from 'node:path';
import {targets} from './wedding-backup-projection.mjs';
const check=x=>{if(!x)throw Error('refused');};
const hash=b=>createHash('sha256').update(b).digest('hex');

// Bounded stdout stays inside the caller; child diagnostics never reach a log.
export function capture(command,args,{env,timeout=25000,maxBytes=262144}={}){
 return new Promise((resolve,reject)=>{
  const child=spawn(command,args,{shell:false,env,stdio:['ignore','pipe','ignore']});
  const chunks=[];let size=0,failed=false;
  const refuse=()=>{failed=true;child.kill('SIGKILL');};
  const timer=setTimeout(refuse,timeout);
  child.stdout.on('data',b=>{size+=b.length;if(size>maxBytes){b.fill(0);refuse();}else chunks.push(b);});
  child.on('error',()=>{clearTimeout(timer);for(const b of chunks)b.fill(0);reject(Error('subprocess_refused'));});
  child.on('close',code=>{clearTimeout(timer);const out=Buffer.concat(chunks);for(const b of chunks)b.fill(0);if(failed||code!==0){out.fill(0);reject(Error('subprocess_refused'));}else resolve(out);});
 });
}
export function createReader({kubectl,kubeconfig}){
 return async requested=>{
  let out;
  try{
   const t=targets.find(x=>x.id===requested.id);check(t&&path.isAbsolute(kubectl)&&path.isAbsolute(kubeconfig));
   check(await realpath(kubectl)===kubectl&&(await lstat(kubectl)).isFile());
   out=await capture(kubectl,['--kubeconfig',kubeconfig,'--context','admin@prod','--namespace',t.namespace,'get',t.resource,t.name,'--output=json','--request-timeout=20s'],{env:{PATH:'/usr/bin:/bin'},maxBytes:t.kind==='Secret'?32768:262144});
   const object=JSON.parse(out.toString('utf8'));check(object&&typeof object==='object'&&!Array.isArray(object));return object;
  }catch{throw Error('read_refused');}finally{out?.fill(0);}
 };
}

const cipher='k8s/clusters/prod/bootstrap/secret-wedding-db-backup-r2.enc.yaml';
const bootstrap='k8s/clusters/prod/bootstrap/kustomization.yaml';
const recipes=['wedding-backup-projection.mjs','wedding-backup-io.mjs','verify-wedding-backup-staging.mjs'];
export async function createSourceGuard({workspace,recipeDirectory,sourceSha,recipeSha,cipherSha,bootstrapSha,git}){
 return async()=>{
  const captured=[];
  try{
   check([sourceSha,recipeSha].every(x=>/^[a-f0-9]{40}$/.test(x))&&[cipherSha,bootstrapSha].every(x=>/^[a-f0-9]{64}$/.test(x)));
   // This invocation publishes the same checkout from which the helper runs.
   // A different-source recipe needs a separately reviewed route, never inference.
   check(sourceSha===recipeSha&&await realpath(workspace)===workspace&&await realpath(recipeDirectory)===path.join(workspace,'scripts')&&await realpath(git)===git);
   const run=async args=>{const b=await capture(git,['--no-replace-objects','-C',workspace,...args],{env:{PATH:'/usr/bin:/bin',GIT_NO_REPLACE_OBJECTS:'1'},maxBytes:262144});captured.push(b);return b;};
   check((await run(['rev-parse','HEAD'])).toString().trim()===sourceSha);
   for(const relative of [cipher,bootstrap,...recipes.map(x=>'scripts/'+x)]){
    const filename=path.join(workspace,relative),s=await lstat(filename);
    check(s.isFile()&&!s.isSymbolicLink()&&s.size>0&&s.size<=262144&&await realpath(filename)===filename);
    const local=await readFile(filename);captured.push(local);
    const committed=await run(['show',sourceSha+':'+relative]);check(local.equals(committed));
    const entry=(await run(['ls-tree',sourceSha,'--',relative])).toString();
    const mode=entry.split(' ')[0];check(mode===(s.mode&0o111?'100755':'100644'));
    if(relative===cipher)check(hash(local)===cipherSha);
    if(relative===bootstrap)check(hash(local)===bootstrapSha);
   }
   return true;
  }catch{return false;}finally{for(const b of captured)b.fill(0);}
 };
}
