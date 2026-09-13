import { targets } from '../../scripts/wedding-backup-projection.mjs';
export const sha = 'a'.repeat(40), digest = `sha256:${'b'.repeat(64)}`;
export const id = 'c'.repeat(32), secret = 'd'.repeat(64);
export const enc = s => Buffer.from(s).toString('base64');
export const opts = { sourceSha: 'f'.repeat(40), recipeSha: sha, digest, endpoint: `https://${'e'.repeat(32)}.r2.cloudflarestorage.com` };
export const invocation = { repository: 'devantler-tech/platform', event: 'workflow_dispatch', ref: 'refs/heads/main', sha, checkout: sha, attempt: '1', run: '12345', workflowRef:'devantler-tech/platform/.github/workflows/cd.yaml@refs/heads/main', workflowSha:sha };
const ready = { conditions: [{ type: 'Ready', status: 'True' }], observedGeneration: 1 };
export function fixtures() {
  const docs = Object.fromEntries(targets.map((t, i) => [t.id, {
    apiVersion: t.apiVersion, kind: t.kind,
    metadata: { name: t.name, namespace: t.namespace, uid: `00000000-0000-0000-0000-${String(i+1).padStart(12, '0')}`, resourceVersion: String(i+10), generation: 1,
      labels: { 'kustomize.toolkit.fluxcd.io/name': t.owner, 'kustomize.toolkit.fluxcd.io/namespace': 'flux-system' } },
    spec: {}, status: structuredClone(ready)
  }]));
  docs.source.spec = { url: 'oci://ghcr.io/devantler-tech/platform/manifests', ref: { tag: 'latest' }, verify: { provider: 'cosign' } };
  docs.source.status.artifact = { revision: `latest@${digest}` };
  docs.source.status.conditions.push({ type: 'SourceVerified', status: 'True' });
  for (const name of ['bootstrap', 'infrastructure', 'apps']) {
    docs[name].spec = { sourceRef: { kind: 'OCIRepository', name: 'flux-system' }, path: { bootstrap: 'clusters/prod/bootstrap', infrastructure: 'providers/hetzner/infrastructure', apps: 'providers/hetzner/apps' }[name] };
    docs[name].status.lastAppliedRevision = `latest@${digest}`;
  }
  docs.seed.spec = {
    secretStoreRefs: [{ name: 'openbao', kind: 'ClusterSecretStore' }],
    selector: { secret: { name: 'wedding-db-backup-r2-bootstrap' } },
    data: ['access_key_id', 'secret_access_key'].map(key => ({ match: { secretKey: key, remoteRef: { remoteKey: 'apps/wedding-app/backup/r2', property: key } } }))
  };
  docs.projection.spec = {
    secretStoreRef: { name: 'openbao', kind: 'ClusterSecretStore' },
    target: { name: 'wedding-db-backup-r2-dedicated', creationPolicy: 'Owner', template: { data: { ACCESS_KEY_ID: '{{ .ACCESS_KEY_ID }}', SECRET_ACCESS_KEY: '{{ .SECRET_ACCESS_KEY }}', REGION: 'auto' } } },
    data: [['ACCESS_KEY_ID','access_key_id'], ['SECRET_ACCESS_KEY','secret_access_key']].map(([secretKey, property]) => ({ secretKey, remoteRef: { key: 'apps/wedding-app/backup/r2', property } }))
  };
  docs.active.spec.configuration = {
    destinationPath: 's3://platform-backups/cnpg/wedding-db', endpointURL: opts.endpoint,
    s3Credentials: Object.fromEntries([['accessKeyId','ACCESS_KEY_ID'],['secretAccessKey','SECRET_ACCESS_KEY'],['region','REGION']].map(([key, value]) => [key, { name: 'wedding-db-backup-r2', key: value }]))
  };
  docs.staged.spec.configuration = {
    destinationPath: 's3://wedding-db-backups/cnpg/wedding-db', endpointURL: opts.endpoint,
    s3Credentials: Object.fromEntries([['accessKeyId','ACCESS_KEY_ID'],['secretAccessKey','SECRET_ACCESS_KEY'],['region','REGION']].map(([key, value]) => [key, { name: 'wedding-db-backup-r2-dedicated', key: value }]))
  };
  docs.cluster.spec.plugins = [{
    name: 'barman-cloud.cloudnative-pg.io', enabled: true, isWALArchiver: true,
    parameters: { barmanObjectName: 'wedding-db', serverName: 'wedding-db-20260909' }
  }];
  docs.bootstrapSecret.type = docs.projectedSecret.type = 'Opaque';
  docs.bootstrapSecret.data = { access_key_id: enc(id), secret_access_key: enc(secret) };
  docs.projectedSecret.data = { ACCESS_KEY_ID: enc(id), SECRET_ACCESS_KEY: enc(secret), REGION: enc('auto') };
  docs.projectedSecret.metadata.ownerReferences = [{ apiVersion: 'external-secrets.io/v1', kind: 'ExternalSecret', name: 'wedding-db-backup-r2-dedicated', uid: docs.projection.metadata.uid, controller: true }];
  return docs;
}
export function harness(change = () => {}, invocationPatch = {}) {
  const docs = fixtures(); change(docs);
  const reads = [], calls = [], receipts = [], bindings = [];
  const deps = {
    invocation: { ...invocation, ...invocationPatch },
    read: async target => { reads.push(target.id); return structuredClone(docs[target.id]); },
    decrypt: async () => { calls.push('decrypt'); return {access_key_id:id,secret_access_key:secret}; },
    sourceUnchanged: async binding => { bindings.push(structuredClone(binding)); return true; },
    probe: async () => { throw Error('S3 execution is forbidden'); },
    record: async () => { throw Error('Private identity recording is forbidden'); }
  };
  return { docs, reads, calls, receipts, bindings, deps };
}
