import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { ContextProjection } from './projection';
import { SyntheticProjection, session, id, pending, profileComparison, comparisonResult, incompatibleProfiles, profileVersion, baselineVersion } from './test-fixtures';

const controllers: ContextProjection[] = [];
const selection = { sample_type: 'cpu', normalization: 'perSecond' as const, top_n: 20 };
const incident = { caseID: id(2), artifactID: id(3), version: profileVersion };
const baseline = { caseID: id(2), artifactID: id(4), version: baselineVersion };
beforeEach(() => vi.useFakeTimers());
afterEach(() => { controllers.forEach(controller => controller.close()); controllers.length = 0; vi.useRealTimers(); });
function setup() {
  const client = new SyntheticProjection(); let now = 1000;
  client.responder = () => profileComparison();
  const controller = ContextProjection.comparison(client, () => now); controllers.push(controller);
  const scope = new AbortController(); controller.attachComparison(session, scope.signal, incident, baseline);
  return { client, controller, scope, advance: async (ms: number) => { now += ms; await vi.advanceTimersByTimeAsync(ms); }, delay: (ms: number) => { now += ms; } };
}
it('submits exactly two explicit sources and display selection with both versions retained locally', async () => {
  const { client, controller } = setup(); expect(client.calls).toHaveLength(0);
  await controller.inspectComparison(selection);
  expect(client.calls[0]).toMatchObject({ name: 'compare_profiles', input: { case_id: id(2), artifact_id: id(3), baseline_case_id: id(2), baseline_artifact_id: id(4), ...selection } });
  expect(controller.snapshot().phase).toBe('result');
  expect(controller.snapshot().comparison).toMatchObject({ source_version: profileVersion, baseline_source_version: baselineVersion, baseline_artifact_id: id(4), artifact_id: id(3) });
  expect(controller.snapshot().summary).toBeUndefined(); controller.close(); expect(controller.snapshot()).toEqual({ phase: 'idle' });
});
it('polls only the original handle and never renews the initial lifetime', async () => {
  const { client, controller, delay, advance } = setup();
  client.responder = () => { delay(3000); return pending(); }; await controller.inspectComparison(selection);
  await advance(1000); client.responder = () => comparisonResult(); await controller.check();
  expect(client.calls[1]).toMatchObject({ name: 'get_query_result', input: { query_handle: 'synthetic-original-query' } });
  expect(controller.snapshot().phase).toBe('result');
  await advance(5999); expect(controller.snapshot()).toEqual({ phase: 'expired' }); expect(client.calls).toHaveLength(2);
});
it.each(['incident case', 'incident artifact', 'incident version', 'baseline case', 'baseline artifact', 'baseline version', 'provenance', 'missing provenance', 'extra provenance', 'sample', 'normalization', 'selection', 'unsafe total', 'extra user label', 'raw', 'time', 'request', 'tool', 'handle'])('refuses comparison association change: %s', async change => {
  const { client, controller, advance } = setup(); client.responder = () => pending(); await controller.inspectComparison(selection); await advance(1000);
  const outer = comparisonResult(), value = outer.data.result;
  if (change === 'incident case') value.data.case_id = id(9);
  if (change === 'incident artifact') value.data.artifact_id = id(9);
  if (change === 'incident version') value.data.source_version = '9'.repeat(64);
  if (change === 'baseline case') value.data.baseline_case_id = id(9);
  if (change === 'baseline artifact') value.data.baseline_artifact_id = id(9);
  if (change === 'baseline version') value.data.baseline_source_version = '9'.repeat(64);
  if (change === 'provenance') value.provenance[0].digest = '9'.repeat(64);
  if (change === 'missing provenance') value.provenance.pop();
  if (change === 'extra provenance') value.provenance.push({ artifactID: id(9), digest: '9'.repeat(64) });
  if (change === 'sample') value.data.sample_type = 'inuse_space';
  if (change === 'normalization') value.data.normalization = 'none';
  if (change === 'selection') value.data.rows = Array.from({ length: 21 }, () => ({ ...value.data.rows[0] }));
  if (change === 'unsafe total') value.data.baseline.total = Number.MAX_SAFE_INTEGER + 1;
  if (change === 'extra user label') Object.assign(value.data.rows[0], { label: 'private' });
  if (change === 'raw') value.data_class = 'raw';
  if (change === 'time') value.data.query_expires_at = '2026-10-18T12:00:11Z';
  if (change === 'request') value.request_id = id(99);
  if (change === 'tool') outer.data.tool_name = 'get_profile_summary';
  if (change === 'handle') outer.data.query_handle = 'replacement';
  client.responder = () => outer; await controller.check(); expect(controller.snapshot()).toEqual({ phase: 'unavailable' });
});
it('preserves two source roles with one unique provenance reference for the same artifact', async () => {
  const { client, controller, scope } = setup(); controller.attachComparison(session, scope.signal, incident, incident);
  const value = profileComparison(); value.data.baseline_artifact_id = id(3); value.data.baseline_source_version = profileVersion; value.provenance = [{ artifactID: id(3), digest: profileVersion }];
  client.responder = () => value; await controller.inspectComparison(selection); expect(controller.snapshot().phase).toBe('result');
});
it.each(['begin', 'poll'])('renders only the closed incompatibility state on %s', async phase => {
  const { client, controller, advance } = setup();
  if (phase === 'poll') { client.responder = () => pending(); await controller.inspectComparison(selection); await advance(1000); }
  client.responder = () => incompatibleProfiles();
  if (phase === 'poll') await controller.check(); else await controller.inspectComparison(selection);
  expect(controller.snapshot()).toEqual({ phase: 'incompatible' }); expect(vi.getTimerCount()).toBe(0);
});
it.each(['baseline version', 'baseline ID', 'incident version', 'incident ID', 'session', 'scope'])('clears and discards a late response after %s changes', async change => {
  const { client, controller, scope } = setup(); let finish!: (value: unknown) => void;
  client.responder = () => new Promise(resolve => { finish = resolve; }); const work = controller.inspectComparison(selection);
  if (change === 'scope') scope.abort();
  else controller.attachComparison(change === 'session' ? { ...session } : session, scope.signal, { ...incident, ...(change === 'incident version' ? { version: '9'.repeat(64) } : {}), ...(change === 'incident ID' ? { artifactID: id(9) } : {}) }, { ...baseline, ...(change === 'baseline version' ? { version: '9'.repeat(64) } : {}), ...(change === 'baseline ID' ? { artifactID: id(9) } : {}) });
  expect(client.calls[0].signal.aborted).toBe(true); finish(profileComparison()); await work; expect(controller.snapshot()).toEqual({ phase: 'idle' });
});
it.each([{ ...selection, sample_type: '' }, { ...selection, sample_type: '\u0000cpu' }, { ...selection, sample_type: 'é'.repeat(33) }, { ...selection, top_n: 101 }])('refuses invalid comparison selection without a call', async invalid => {
  const { client, controller } = setup(); await controller.inspectComparison(invalid); expect(client.calls).toHaveLength(0);
});

it('accepts explicit raw totals with unknown durations and rejects inconsistent raw deltas', async () => {
  const { client, controller } = setup(); const value = profileComparison();
  value.data.normalization = 'none'; value.data.baseline.duration_seconds = null; value.data.incident.duration_seconds = null;
  client.responder = () => value; await controller.inspectComparison({ ...selection, normalization: 'none' });
  expect(controller.snapshot().phase).toBe('result');
  value.data.rows[0].delta = 4; await controller.inspectComparison({ ...selection, normalization: 'none' });
  expect(controller.snapshot()).toEqual({ phase: 'unavailable' });
});
it('refuses a same-artifact pair with contradictory local source versions before issuing a query', async () => {
  const { client, controller, scope } = setup();
  controller.attachComparison(session, scope.signal, incident, { ...incident, version: baselineVersion });
  await controller.inspectComparison(selection); expect(client.calls).toHaveLength(0);
});
