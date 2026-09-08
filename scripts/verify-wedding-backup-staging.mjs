import {fileURLToPath} from 'node:url';
import {realpath} from 'node:fs/promises';
import path from 'node:path';
import {verifyProjection} from './wedding-backup-projection.mjs';
import {createReader,createSourceGuard} from './wedding-backup-io.mjs';
export async function run(env){
 if(env.WEDDING_BACKUP_VERIFY===undefined||env.WEDDING_BACKUP_VERIFY==='false')return {code:0,result:{verified:false,skipped:true}};
 try{
  if(env.WEDDING_BACKUP_VERIFY!=='true'||env.WEDDING_BACKUP_PUBLISH_RESULT!=='success'||env.WEDDING_BACKUP_WAIT_RESULT!=='success')throw Error('refused');
  const workspace=await realpath(env.GITHUB_WORKSPACE),recipeDirectory=await realpath(path.dirname(fileURLToPath(import.meta.url)));
  // CD's default checkout publishes GITHUB_SHA. Preserve that event identity;
  // the source guard refuses a different workflow revision instead of claiming
  // that GITHUB_WORKFLOW_SHA was the checkout which produced the artifact.
  const options={enabled:true,sourceSha:env.GITHUB_SHA,recipeSha:env.GITHUB_WORKFLOW_SHA,digest:env.WEDDING_BACKUP_DIGEST};
  const sourceUnchanged=await createSourceGuard({workspace,recipeDirectory,sourceSha:options.sourceSha,recipeSha:options.recipeSha,cipherSha:env.WEDDING_BACKUP_CIPHER_SHA256,bootstrapSha:env.WEDDING_BACKUP_BOOTSTRAP_SHA256,git:await realpath(env.WEDDING_BACKUP_GIT_BIN)});
  const result=await verifyProjection(options,{
   invocation:{repository:env.GITHUB_REPOSITORY,event:env.GITHUB_EVENT_NAME,ref:env.GITHUB_REF,sha:env.GITHUB_SHA,checkout:env.GITHUB_SHA,attempt:env.GITHUB_RUN_ATTEMPT,run:env.GITHUB_RUN_ID,workflowRef:env.GITHUB_WORKFLOW_REF,workflowSha:env.GITHUB_WORKFLOW_SHA},
   sourceUnchanged,
   read:createReader({kubectl:await realpath(env.WEDDING_BACKUP_KUBECTL_BIN),kubeconfig:path.join(env.HOME,'.kube/config')})
  });
  if(!result.verified)return {code:2,result:{verified:false}};
  return{code:0,result:{...result,sourceSha:options.sourceSha,digest:options.digest,run:env.GITHUB_RUN_ID}};
 }catch{return {code:2,result:{verified:false}};}
}
if(process.argv[1]===fileURLToPath(import.meta.url)){
 const {code,result}=await run(process.env);process.stdout.write(JSON.stringify(result)+'\n');process.exitCode=code;
}
