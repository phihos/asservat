// Build-time only. All schema input is local; generated validators need no eval.
import { readFile, writeFile, mkdir, readdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { parse } from 'yaml';
import openapiTS, { astToString } from 'openapi-typescript';
import Ajv from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import standalone from 'ajv/dist/standalone/index.js';

const root = fileURLToPath(new URL('../../', import.meta.url));
// specs/contracts/implemented/ holds the earlier version of each contract this
// console does not yet implement in its canonical ADR-330 form (see
// scripts/implemented_contracts.py); it takes precedence over the canonical file.
const implemented = resolve(root, 'specs/contracts/implemented');
const implementedFiles = new Set(await readdir(implemented));
const browser = parse(await readFile(implementedFiles.has('browser-openapi.yaml') ? resolve(implemented, 'browser-openapi.yaml') : resolve(root, 'docs/interfaces/browser-openapi.yaml'), 'utf8'));
const auth = parse(await readFile(implementedFiles.has('browser-auth-openapi.yaml') ? resolve(implemented, 'browser-auth-openapi.yaml') : resolve(root, 'docs/interfaces/browser-auth-openapi.yaml'), 'utf8'));
auth.components.schemas = { Session: browser.components.schemas.Session };
auth.paths['/api/v1/session'] = browser.paths['/api/v1/session'];
auth.components.schemas.Problem = browser.components.schemas.Problem;
const csrf = auth.paths['/auth/csrf'].get.responses['200'].content['application/json'].schema;
auth.components.schemas.CSRF = csrf;
function localize(value) {
  if (!value || typeof value !== 'object') return;
  if (value.$ref === 'browser-openapi.yaml#/components/schemas/Session') value.$ref = '#/components/schemas/Session';
  if (value.$ref && !value.$ref.startsWith('#/')) throw new Error('Nonlocal authentication schema reference');
  for (const child of Object.values(value)) localize(child);
}
localize(auth);
const ajv = new Ajv({ code: { source: true, esm: true }, allErrors: false, strict: true });
addFormats(ajv);
ajv.addSchema(auth.components.schemas.Session, 'Session');
ajv.addSchema(csrf, 'CSRF');
const outputs = {
  'auth.d.ts': astToString(await openapiTS(auth)),
  'validate-auth.js': standalone(ajv, { validSession: 'Session', validCSRF: 'CSRF' }),
  'validate-auth.d.ts': "import type { components } from './auth';\nexport declare function validSession(value: unknown): value is components['schemas']['Session'];\nexport declare function validCSRF(value: unknown): value is components['schemas']['CSRF'];\n",
};
// Build separate local contract bundles. The evidence bundle is loaded only on
// case navigation; generated clients do not advertise backend capabilities.
// The capture bundle covers the five implemented business operations. The
// canonical documents remain shared with MCP; this is a code-generation adapter,
// not another manually maintained wire schema or a network schema loader.
const registry = new Map();
const contractFiles = new Set([...(await readdir(resolve(root, 'specs/contracts'))), ...implementedFiles]);
for (const file of [...contractFiles].filter(file => file.endsWith('.schema.json')).sort()) {
  const schema = JSON.parse(await readFile(implementedFiles.has(file) ? resolve(implemented, file) : resolve(root, 'specs/contracts', file), 'utf8'));
  registry.set(schema.$id, { name: 'Contract_' + file.replace('.schema.json', '').replaceAll('-', '_'), schema });
}
async function operationBundle(names, bundle, direct = []) {
  const capture = { openapi: browser.openapi, info: browser.info, paths: {}, components: { schemas: {} } };
  function localSchema(value, base) {
    if (Array.isArray(value)) return value.map(child => localSchema(child, base));
    if (!value || typeof value !== 'object') return value;
    const result = {};
    for (const [key, child] of Object.entries(value)) {
      if (key === '$id' || key === '$schema') continue;
      if (key !== '$ref') { result[key] = localSchema(child, base); continue; }
      const [document, fragment = ''] = child.split('#');
      if (!document && !base) { result[key] = child; continue; }
      const target = registry.get(document || base);
      if (!target) throw new Error('Nonlocal capture schema reference: ' + child);
      const component = target.name + (fragment ? '_' + createHash('sha256').update(fragment).digest('hex').slice(0, 16) : '');
      if (!(component in capture.components.schemas)) {
        let pointed = target.schema;
        if (fragment) {
          if (!fragment.startsWith('/')) throw new Error('Unsupported schema anchor: ' + child);
          for (const part of fragment.slice(1).split('/')) pointed = pointed[part.replaceAll('~1', '/').replaceAll('~0', '~')];
        }
        if (!pointed) throw new Error('Missing schema pointer: ' + child);
        capture.components.schemas[component] = {};
        capture.components.schemas[component] = localSchema(pointed, document || base);
      }
      result[key] = '#/components/schemas/' + component;
    }
    return result;
  }
  const validators = new Ajv({ code: { source: true, esm: true }, allErrors: false, strict: false });
  addFormats(validators);
  for (const { schema } of registry.values()) validators.addSchema(schema);
  const exports = {};
  for (const name of names) {
    for (const direction of ['Input', 'Output']) {
      const key = 'Mcp' + direction + '_' + name;
      const schema = browser.components.schemas[key];
      capture.components.schemas[key] = localSchema(schema);
      validators.addSchema(schema, key);
      exports['valid' + direction + '_' + name] = key;
    }
  }
  for (const name of direct) {
    const schema = browser.components.schemas[name];
    capture.components.schemas[name] = localSchema(schema);
    validators.addSchema(schema, name);
    exports['valid' + name] = name;
  }
  outputs[bundle + '.d.ts'] = astToString(await openapiTS(capture, { emptyObjectsUnknown: true }));
  outputs['validate-' + bundle + '.js'] = standalone(validators, exports);
  outputs['validate-' + bundle + '.d.ts'] = `import type { components } from './${bundle}';\n` + Object.entries(exports).map(([name, key]) =>
    `export declare function ${name}(value: unknown): value is components['schemas']['${key}'];\n`).join('');

}
await operationBundle([], 'processing', ['ProcessingInventory', 'ProcessingChange', 'ProcessingReceipt']);
await operationBundle(['list_diagnostics', 'preview_capture', 'request_capture', 'resolve_capture_request', 'get_capture', 'cancel_capture', 'list_capture_history', 'get_capture_settings', 'list_capture_profiles', 'get_capture_profile'], 'capture');
await operationBundle(['get_case', 'prepare_artifact_download', 'get_artifact_download', 'cancel_artifact_download'], 'evidence');
await operationBundle(['get_file_excerpt', 'get_profile_summary', 'get_pcap_summary', 'pcap_query', 'compare_profiles', 'get_syscall_summary', 'get_syscall_events', 'syscall_query', 'get_logs', 'get_query_result'], 'projection');
await operationBundle(['activate_policy', 'deactivate_policy', 'get_policy_status'], 'policy');
await operationBundle(['list_recordings', 'preview_recording_save'], 'recordings');
await operationBundle(['create_share', 'list_shares', 'revoke_share', 'transfer_share', 'stop_future_sharing'], 'sharing');
await operationBundle(['explain_access'], 'access');
await operationBundle(['preview_access_change'], 'access-preview');
await operationBundle(['preview_retention_change'], 'retention-preview');
await operationBundle(['search_processing_evidence'], 'processing-discovery');
await operationBundle(['get_processing_erasure'], 'processing-erasure');
await operationBundle(['get_processing_report'], 'processing-report', ['ProcessingReportExport']);
await operationBundle(['request_policy_grant', 'request_raw_access', 'get_grant', 'list_reviews', 'decide_review', 'revoke_grant'], 'approvals');

await operationBundle(['list_live_sources', 'open_live_watch', 'read_live_watch', 'update_live_watch', 'close_live_watch'], 'live');

// AJV's standalone ESM source references a small fixed set of CommonJS helpers.
// Explicit ESM imports let Vite bundle them; no browser require/eval is allowed.
function browserModules(source) {
  const imports = new Map();
  const result = source.replace(/require\("(ajv\/dist\/runtime\/[a-zA-Z0-9]+|ajv-formats\/dist\/formats)"\)/g, (_, path) => {
    if (!['ajv/dist/runtime/ucs2length', 'ajv/dist/runtime/equal', 'ajv-formats/dist/formats'].includes(path)) throw new Error('Unqualified standalone validator helper: ' + path);
    if (!imports.has(path)) imports.set(path, 'ajvHelper' + imports.size);
    return imports.get(path);
  });
  if (/\brequire\s*\(/.test(result)) throw new Error('Unqualified standalone validator helper');
  return [...imports].map(([path, name]) => {
    if (path === 'ajv-formats/dist/formats') return `import * as ${name} from '${path}.js';\n`;
    // Node/native ESM exposes CommonJS exports.default beneath the namespace's
    // default object; some test transforms expose the function directly. Keep
    // AJV's generated .default access intact and normalize only that known,
    // pinned helper boundary. This must work in both Vite and native ESM.
    return `import * as ${name}Module from '${path}.js';\nconst ${name} = { default: typeof ${name}Module.default === 'function' ? ${name}Module.default : ${name}Module.default.default };\n`;
  }).join('') + result;
}
outputs['validate-processing.js'] = browserModules(outputs['validate-processing.js']);
outputs['validate-processing-discovery.js'] = browserModules(outputs['validate-processing-discovery.js']);
outputs['validate-processing-report.js'] = browserModules(outputs['validate-processing-report.js']);
outputs['validate-processing-erasure.js'] = browserModules(outputs['validate-processing-erasure.js']);
outputs['validate-live.js'] = browserModules(outputs['validate-live.js']);
outputs['validate-auth.js'] = browserModules(outputs['validate-auth.js']);
outputs['validate-capture.js'] = browserModules(outputs['validate-capture.js']);
outputs['validate-evidence.js'] = browserModules(outputs['validate-evidence.js']);
outputs['validate-projection.js'] = browserModules(outputs['validate-projection.js']);
outputs['validate-policy.js'] = browserModules(outputs['validate-policy.js']);
outputs['validate-recordings.js'] = browserModules(outputs['validate-recordings.js']);
outputs['validate-sharing.js'] = browserModules(outputs['validate-sharing.js']);
outputs['validate-access.js'] = browserModules(outputs['validate-access.js']);
outputs['validate-access-preview.js'] = browserModules(outputs['validate-access-preview.js']);
outputs['validate-retention-preview.js'] = browserModules(outputs['validate-retention-preview.js']);
outputs['validate-approvals.js'] = browserModules(outputs['validate-approvals.js']);
const output = resolve(root, 'web/src/generated');
await mkdir(output, { recursive: true });
for (const [name, body] of Object.entries(outputs)) {
  const content = '// Generated from canonical browser OpenAPI. Run npm run generate; do not edit.\n' + body;
  const path = resolve(output, name);
  if (process.argv.includes('--write')) await writeFile(path, content);
  else if (await readFile(path, 'utf8') !== content) throw new Error(`Generated contract drift: ${name}`);
}
