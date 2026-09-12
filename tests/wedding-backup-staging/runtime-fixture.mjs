import {mkdtemp,mkdir,writeFile,copyFile,rm,realpath} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {fixtures,digest} from './fixtures.mjs';
const hash=x=>createHash('sha256').update(x).digest('hex'),node=process.execPath;
const source=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../../scripts');
export async function fixture(t){
 const dir=await realpath(await mkdtemp(path.join(tmpdir(),'projection-runner-')));t.after(()=>rm(dir,{recursive:true,force:true}));
 await mkdir(path.join(dir,'scripts'));for(const name of ['wedding-backup-projection.mjs','wedding-backup-io.mjs','verify-wedding-backup-staging.mjs'])await copyFile(path.join(source,name),path.join(dir,'scripts',name));
 const p=path.join(dir,'k8s/clusters/prod/bootstrap');await mkdir(p,{recursive:true});const cipher='public synthetic encrypted marker\n',bootstrap='resources:\n  - secret-wedding-db-backup-r2.enc.yaml\n';
 await writeFile(path.join(p,'secret-wedding-db-backup-r2.enc.yaml'),cipher);await writeFile(path.join(p,'kustomization.yaml'),bootstrap);
 const git=(...args)=>execFileSync('git',['-C',dir,...args],{encoding:'utf8',stdio:['ignore','pipe','pipe']}).trim();git('init','-q');git('add','scripts/wedding-backup-projection.mjs','scripts/wedding-backup-io.mjs','scripts/verify-wedding-backup-staging.mjs','k8s/clusters/prod/bootstrap/secret-wedding-db-backup-r2.enc.yaml','k8s/clusters/prod/bootstrap/kustomization.yaml');git('-c','user.name=Fixture','-c','user.email=fixture@example.invalid','-c','commit.gpgsign=false','commit','-qm','fixture');const commit=git('rev-parse','HEAD');
 const docs=fixtures();const byName=Object.fromEntries(Object.values(docs).map(d=>[d.metadata.namespace+'/'+d.kind+'/'+d.metadata.name,d]));
 await writeFile(path.join(dir,'objects.json'),JSON.stringify(byName));
 const reader=path.join(dir,'kubectl');const fake=`#!${node}\nconst fs=require('node:fs');const p=${JSON.stringify(dir)};const a=process.argv.slice(2);if(a.length!==11||a[0]!=='--kubeconfig'||a[2]!=='--context'||a[3]!=='admin@prod'||a[4]!=='--namespace'||a[6]!=='get'||a[9]!=='--output=json'||a[10]!=='--request-timeout=20s')process.exit(3);if(Object.keys(process.env).some(x=>!['PATH','__CF_USER_TEXT_ENCODING'].includes(x)))process.exit(4);const objects=JSON.parse(fs.readFileSync(p+'/objects.json'));const kinds={'secrets':'Secret','ocirepositories.source.toolkit.fluxcd.io':'OCIRepository','kustomizations.kustomize.toolkit.fluxcd.io':'Kustomization','pushsecrets.external-secrets.io':'PushSecret','externalsecrets.external-secrets.io':'ExternalSecret','objectstores.barmancloud.cnpg.io':'ObjectStore','clusters.postgresql.cnpg.io':'Cluster'};const key=a[5]+'/'+kinds[a[7]]+'/'+a[8];if(!objects[key])process.exit(5);fs.appendFileSync(p+'/reads',key+'\\n');process.stdout.write(JSON.stringify(objects[key]));`;
 await writeFile(reader,fake,{mode:0o700});
 const env={PATH:'/usr/bin:/bin',HOME:dir,GITHUB_WORKSPACE:dir,GITHUB_REPOSITORY:'devantler-tech/platform',GITHUB_EVENT_NAME:'workflow_dispatch',GITHUB_REF:'refs/heads/main',GITHUB_SHA:commit,GITHUB_RUN_ID:'12345',GITHUB_RUN_ATTEMPT:'1',GITHUB_WORKFLOW_REF:'devantler-tech/platform/.github/workflows/cd.yaml@refs/heads/main',GITHUB_WORKFLOW_SHA:commit,WEDDING_BACKUP_VERIFY:'true',WEDDING_BACKUP_PUBLISH_RESULT:'success',WEDDING_BACKUP_WAIT_RESULT:'success',WEDDING_BACKUP_DIGEST:digest,WEDDING_BACKUP_CIPHER_SHA256:hash(cipher),WEDDING_BACKUP_BOOTSTRAP_SHA256:hash(bootstrap),WEDDING_BACKUP_KUBECTL_BIN:reader,WEDDING_BACKUP_GIT_BIN:'/usr/bin/git'};
 return{dir,env,commit,docs:byName};
}
