import { timingSafeEqual } from 'node:crypto';

export const targets = [
  ['source','source.toolkit.fluxcd.io/v1','OCIRepository','ocirepositories.source.toolkit.fluxcd.io','flux-system','flux-system',null],
  ...['bootstrap','infrastructure','apps'].map(x => [x,'kustomize.toolkit.fluxcd.io/v1','Kustomization','kustomizations.kustomize.toolkit.fluxcd.io','flux-system',x,null]),
  ['seed','external-secrets.io/v1alpha1','PushSecret','pushsecrets.external-secrets.io','flux-system','seed-wedding-db-backup-r2','infrastructure'],
  ['projection','external-secrets.io/v1','ExternalSecret','externalsecrets.external-secrets.io','wedding-app','wedding-db-backup-r2-dedicated','apps'],
  ['active','barmancloud.cnpg.io/v1','ObjectStore','objectstores.barmancloud.cnpg.io','wedding-app','wedding-db','apps'],
  ['cluster','postgresql.cnpg.io/v1','Cluster','clusters.postgresql.cnpg.io','wedding-app','wedding-db',null],
  ['bootstrapSecret','v1','Secret','secrets','flux-system','wedding-db-backup-r2-bootstrap','bootstrap'],
  ['projectedSecret','v1','Secret','secrets','wedding-app','wedding-db-backup-r2-dedicated',null],
].map(([id,apiVersion,kind,resource,namespace,name,owner]) => ({id,apiVersion,kind,resource,namespace,name,owner}));

const check = condition => { if (!condition) throw Error('refused'); };
const keys = (obj, expected) => check(obj && typeof obj === 'object' && !Array.isArray(obj) && Object.keys(obj).sort().join(',') === [...expected].sort().join(','));
const equal = (a, b) => { const x = Buffer.from(a), y = Buffer.from(b); try { return x.length === y.length && timingSafeEqual(x, y); } finally { x.fill(0); y.fill(0); } };
function ready(obj, generation = false) {
  check(obj.status?.conditions?.filter(x => x.type === 'Ready' && x.status === 'True').length === 1);
  check(!obj.spec?.suspend && !obj.metadata.deletionTimestamp);
  if (generation) check(obj.status.observedGeneration === obj.metadata.generation);
}
function metadata(obj, target) {
  check(obj?.apiVersion === target.apiVersion && obj.kind === target.kind);
  const m = obj.metadata;
  check(m?.namespace === target.namespace && m.name === target.name && !m.deletionTimestamp);
  check(/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(m.uid));
  check(/^[1-9][0-9]*$/.test(m.resourceVersion));
  // Secrets do not carry a generation; controller resources do.
  if (target.kind !== 'Secret') check(Number.isSafeInteger(m.generation) && m.generation > 0);
  if (target.owner) check(m.labels?.['kustomize.toolkit.fluxcd.io/name'] === target.owner && m.labels?.['kustomize.toolkit.fluxcd.io/namespace'] === 'flux-system');
  return { namespace: target.namespace, kind: target.kind, name: target.name, uid: m.uid, resourceVersion: m.resourceVersion, ...(target.kind === 'Secret' ? {} : { generation: m.generation }) };
}
function decode(value, expression) {
  check(typeof value === 'string' && value.length <= 256);
  const bytes = Buffer.from(value, 'base64');
  try { check(bytes.toString('base64') === value); const decoded = bytes.toString('utf8'); check(expression.test(decoded)); return decoded; }
  finally { bytes.fill(0); }
}
function pair(bootstrap, projected) {
  check(bootstrap.type === 'Opaque' && projected.type === 'Opaque');
  check(!bootstrap.stringData && !projected.stringData);
  keys(bootstrap.data, ['access_key_id','secret_access_key']);
  keys(projected.data, ['ACCESS_KEY_ID','SECRET_ACCESS_KEY','REGION']);
  const source = { access_key_id: decode(bootstrap.data.access_key_id, /^[a-f0-9]{32}$/), secret_access_key: decode(bootstrap.data.secret_access_key, /^[a-f0-9]{64}$/) };
  const result = { access_key_id: decode(projected.data.ACCESS_KEY_ID, /^[a-f0-9]{32}$/), secret_access_key: decode(projected.data.SECRET_ACCESS_KEY, /^[a-f0-9]{64}$/) };
  check(decode(projected.data.REGION, /^auto$/) === 'auto');
  check(equal(source.access_key_id, result.access_key_id) && equal(source.secret_access_key, result.secret_access_key));
  return result;
}
function validateControllers(d, options) {
  ready(d.source, true);
  check(d.source.spec.url === 'oci://ghcr.io/devantler-tech/platform/manifests' && d.source.spec.ref?.tag === 'latest' && d.source.spec.verify?.provider === 'cosign');
  check(d.source.status.artifact?.revision === `latest@${options.digest}`);
  check(d.source.status.conditions.filter(x => x.type === 'SourceVerified' && x.status === 'True').length === 1);
  for (const [name, path] of Object.entries({ bootstrap: 'clusters/prod/bootstrap', infrastructure: 'providers/hetzner/infrastructure', apps: 'providers/hetzner/apps' })) {
    const obj = d[name]; ready(obj, true);
    check(obj.spec.sourceRef?.kind === 'OCIRepository' && obj.spec.sourceRef.name === 'flux-system' && (!obj.spec.sourceRef.namespace || obj.spec.sourceRef.namespace === 'flux-system'));
    check(obj.spec.path === path && obj.status.lastAppliedRevision === `latest@${options.digest}`);
  }
  ready(d.seed); ready(d.projection);
  const seed = d.seed.spec, projection = d.projection.spec;
  check(seed.selector?.secret?.name === 'wedding-db-backup-r2-bootstrap' && !seed.selector.generatorRef);
  check(seed.secretStoreRefs?.length === 1 && seed.secretStoreRefs[0].name === 'openbao' && seed.secretStoreRefs[0].kind === 'ClusterSecretStore');
  check(seed.data?.length === 2);
  for (const key of ['access_key_id', 'secret_access_key']) check(seed.data.filter(x => x.match?.secretKey === key && x.match.remoteRef?.remoteKey === 'apps/wedding-app/backup/r2' && x.match.remoteRef.property === key).length === 1);
  check(!seed.template && !seed.pushSecretRef);
  check(projection.secretStoreRef?.name === 'openbao' && projection.secretStoreRef.kind === 'ClusterSecretStore');
  check(projection.target?.name === 'wedding-db-backup-r2-dedicated' && projection.target.creationPolicy === 'Owner');
  keys(projection.target.template?.data, ['ACCESS_KEY_ID','SECRET_ACCESS_KEY','REGION']);
  check(projection.target.template.data.ACCESS_KEY_ID === '{{ .ACCESS_KEY_ID }}' && projection.target.template.data.SECRET_ACCESS_KEY === '{{ .SECRET_ACCESS_KEY }}' && projection.target.template.data.REGION === 'auto');
  check(!projection.dataFrom && !projection.target.template.templateFrom && !projection.target.template.stringData);
  check(projection.data?.length === 2);
  for (const [key, property] of [['ACCESS_KEY_ID','access_key_id'], ['SECRET_ACCESS_KEY','secret_access_key']]) check(projection.data.filter(x => x.secretKey === key && x.remoteRef?.key === 'apps/wedding-app/backup/r2' && x.remoteRef.property === property).length === 1);
  const active = d.active.spec.configuration;
  check(active?.destinationPath === 's3://platform-backups/cnpg/wedding-db');
  for (const [key, value] of [['accessKeyId','ACCESS_KEY_ID'],['secretAccessKey','SECRET_ACCESS_KEY'],['region','REGION']]) check(active.s3Credentials?.[key]?.name === 'wedding-db-backup-r2' && active.s3Credentials[key].key === value);
  const plugins = d.cluster.spec?.plugins;
  check(Array.isArray(plugins));
  const barman = plugins.filter(plugin => plugin.name === 'barman-cloud.cloudnative-pg.io');
  check(barman.length === 1 && barman[0].enabled === true && barman[0].isWALArchiver === true);
  check(barman[0].parameters?.barmanObjectName === 'wedding-db');
  check(barman[0].parameters.serverName === 'wedding-db-20260909');
}
async function snapshot(options, deps) {
  const docs = {}, identities = {};
  // Controller/source refusals happen before either Secret read.
  for (const target of targets.filter(t => t.kind !== 'Secret')) {
    docs[target.id] = await deps.read(target); identities[target.id] = metadata(docs[target.id], target);
  }
  validateControllers(docs, options);
  for (const target of targets.filter(t => t.kind === 'Secret')) {
    docs[target.id] = await deps.read(target); identities[target.id] = metadata(docs[target.id], target);
  }
  const owners = docs.projectedSecret.metadata.ownerReferences;
  check(owners?.length === 1 && owners[0].apiVersion === 'external-secrets.io/v1' && owners[0].kind === 'ExternalSecret' && owners[0].name === 'wedding-db-backup-r2-dedicated' && owners[0].uid === docs.projection.metadata.uid && owners[0].controller === true);
  return { identities, credential: pair(docs.bootstrapSecret, docs.projectedSecret) };
}
function stable(a, b) {
  check(JSON.stringify(a.identities) === JSON.stringify(b.identities));
  check(equal(a.credential.access_key_id, b.credential.access_key_id) && equal(a.credential.secret_access_key, b.credential.secret_access_key));
}
export async function verifyProjection(options, deps) {
  if(options.enabled === undefined || options.enabled === false || options.enabled === 'false') return {verified:false, skipped:true};
  try {
    check(options.enabled === true || options.enabled === 'true');
    const i = deps.invocation;
    check(/^[a-f0-9]{40}$/.test(options.sourceSha) && /^[a-f0-9]{40}$/.test(options.recipeSha) && /^sha256:[a-f0-9]{64}$/.test(options.digest));
    check(i.repository === 'devantler-tech/platform' && i.event === 'workflow_dispatch' && i.ref === 'refs/heads/main' && i.sha === options.recipeSha && i.checkout === options.recipeSha && i.attempt === '1' && /^[1-9][0-9]*$/.test(i.run));
    check(i.workflowRef === 'devantler-tech/platform/.github/workflows/cd.yaml@refs/heads/main' && i.workflowSha === options.recipeSha);
    // The trusted same-job publication adapter binds source and digest.
    // This two-way check never decrypts source or claims plaintext-source equality.
    const binding = { recipeSha: options.recipeSha, sourceSha: options.sourceSha, digest: options.digest };
    check(await deps.sourceUnchanged(binding));
    const first = await snapshot(options, deps);
    const after = await snapshot(options, deps); stable(first, after);
    check(await deps.sourceUnchanged(binding));
    return { verified: true, projectionEqual: true, liveSourceStable: true };
  } catch { return { verified: false }; }
}
