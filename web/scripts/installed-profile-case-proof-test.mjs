// Pure checks of real-driver observation acceptance; no authority or HTTP replay.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { checkInstalledProfileCaseRefreshes as check } from './installed-profile-case-proof.mjs';
const original = JSON.parse(await readFile(new URL('../../examples/mcp-shared-case-notice-result.json', import.meta.url)));
original.data.case.access = 'ordinary';
const artifact = original.data.artifacts[0];
Object.assign(artifact, { kind: 'profile', native_format: 'pprof', data_class: 'raw', profile_acquisition: { requested_type: 'heap', mode: 'snapshot', requested_duration_ms: null, force_gc: false, execution_mode: 'onTrigger', started_at: '2026-10-09T17:50:00.123456Z', completed_at: '2026-10-09T17:50:01.123456Z', clock_uncertainty_ms: null, process_attribution: 'unknown', window_kind: 'httpAcquisition', timestamp_precision: 'microsecond' } });
const session = { principal: { issuer: 'https://identity.invalid', subject_id: 'original-human', kind: 'user' }, roles: [], csrf_token: 'C'.repeat(43), expires_at: '2026-10-09T18:00:00Z', step_up: 'unavailable' };
artifact.target = {cluster_id: '00000000-0000-4000-8000-000000000011', namespace_uid: '00000000-0000-4000-8000-000000000012', workload_uid: '00000000-0000-4000-8000-000000000013', pod_uid: '00000000-0000-4000-8000-000000000014'};
const options = { heap: true, caseID: original.data.case.case_id, artifactID: artifact.artifact_id };
const first = [{ kind: 'session', reply: session }, { kind: 'case', reply: original }];
const clone = value => structuredClone(value);
const refreshed = clone(original); refreshed.data.artifacts[0].handling_notice.asOf = '2026-10-09T12:21:00Z';
// A fresh notice/shorter retention is mutable metadata, not a replacement source.
refreshed.data.artifacts[0].expires_at = refreshed.data.artifacts[0].handling_notice.expiresAt = '2026-10-09T17:54:00Z';
const two = [...first, { kind: 'session', reply: clone(session) }, { kind: 'case', reply: refreshed }];
assert.equal(check({ ...options, observations: first }), 1);
assert.equal(check({ ...options, observations: two }), 2, 'existing successful refresh legitimately causes a second identical-source case');
assert.equal(check({ ...options, heap: false, observations: first }), 1);
assert.throws(() => check({ ...options, heap: false, observations: two }), 'comparison remains strict single case');
assert.throws(() => check({ ...options, observations: [...first, two[3]] }), 'extra case without actual refresh refused');
assert.throws(() => check({ ...options, observations: [...first, two[2]] }), 'refresh without its case refused');
for (const mutate of [
  rows => { rows[2].reply.principal.subject_id = 'replacement-human'; },
  rows => { rows[2].reply.expires_at = '2026-10-09T18:00:01Z'; },
  rows => { rows[3].reply.data.case.case_id = '00000000-0000-4000-8000-000000000099'; },
  rows => { rows[3].reply.data.artifacts[0].digest = '44'.repeat(32); },
  rows => { rows[3].reply.data.artifacts[0].target.pod_uid = '00000000-0000-4000-8000-000000000099'; },
  rows => { rows[3].reply.data.artifacts[0].profile_acquisition.completed_at = '2026-10-09T17:50:02.123456Z'; },
  rows => { rows[3].reply.data.artifacts[0].profile_acquisition.force_gc = true; },
  rows => { rows[3].reply.extra = true; },
]) {
  const rows = clone(two); mutate(rows); assert.throws(() => check({ ...options, observations: rows }));
}
assert.throws(() => check({ ...options, observations: Array.from({length: 6}, () => clone(first)).flat() }), 'original five-minute driver count remains bounded');
console.log('profile case refresh proof: same original source/timing after current same-human refresh; eight changed/malformed observations refused');
