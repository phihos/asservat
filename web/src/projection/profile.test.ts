import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { ContextProjection } from './projection';
import { SyntheticProjection, session, id, pending, profileResult, profileSummary, profileVersion } from './test-fixtures';
const controllers: ContextProjection[] = [];
const selection = { sample_type: 'cpu', top_n: 20 };
beforeEach(() => vi.useFakeTimers());
afterEach(() => { controllers.forEach(c => c.close()); controllers.length = 0; vi.useRealTimers(); });
function setup() {
  const client = new SyntheticProjection(); let now = 1000;
  client.responder = () => profileSummary();
  const controller = ContextProjection.profile(client, () => now); controllers.push(controller);
  const scope = new AbortController(); controller.attach(session, scope.signal, id(2), id(3), profileVersion);
  return { client, controller, scope, advance: async (ms: number) => { now += ms; await vi.advanceTimersByTimeAsync(ms); }, delay: (ms: number) => { now += ms; } };
}
it('makes one explicit summary request and retains only the closed result', async () => {
  const { client, controller } = setup(); expect(client.calls).toHaveLength(0);
  await controller.inspect(selection);
  expect(client.calls[0]).toMatchObject({ name: 'get_profile_summary', input: { case_id: id(2), artifact_id: id(3), ...selection } });
  expect(controller.snapshot().phase).toBe('result'); expect(controller.snapshot().summary?.top[0].fraction).toBe(0.25);
  controller.close(); expect(controller.snapshot()).toEqual({ phase: 'idle' });
});
it('polls the same summary and includes initial network delay in its original lifetime', async () => {
  const { client, controller, delay, advance } = setup();
  client.responder = () => { delay(3000); return pending(); }; await controller.inspect(selection);
  await advance(1000); client.responder = () => profileResult(); await controller.check();
  expect(controller.snapshot().phase).toBe('result'); expect(client.calls).toHaveLength(2);
  await advance(5999); expect(controller.snapshot()).toEqual({ phase: 'expired' }); expect(client.calls).toHaveLength(2);
});
it.each(['artifact', 'version', 'sample', 'selection', 'unsafe integer', 'extra label', 'raw', 'outer class', 'time', 'request', 'tool', 'handle'])('rejects summary substitution: %s', async change => {
  const { client, controller, advance } = setup(); client.responder = () => pending();
  await controller.inspect(selection); await advance(1000); const output = profileResult();
  const value = output.data.result;
  if (change === 'artifact') value.provenance[0].artifactID = id(8);
  if (change === 'version') value.provenance[0].digest = '8'.repeat(64);
  if (change === 'sample') value.data.sample_type = 'inuse_space';
  if (change === 'selection') value.data.top = Array.from({ length: 21 }, () => ({ ...value.data.top[0] }));
  if (change === 'unsafe integer') value.data.total = Number.MAX_SAFE_INTEGER + 1;
  if (change === 'extra label') Object.assign(value.data.top[0], { label: 'private' });
  if (change === 'raw') value.data_class = 'raw';
  if (change === 'outer class') output.data_class = 'metadata';
  if (change === 'time') value.data.query_expires_at = '2026-10-18T12:00:11Z';
  if (change === 'request') value.request_id = id(99);
  if (change === 'tool') output.data.tool_name = 'get_file_excerpt';
  if (change === 'handle') output.data.query_handle = 'replacement';
  client.responder = () => output; await controller.check(); expect(controller.snapshot()).toEqual({ phase: 'unavailable' });
});
it.each([{ sample_type: '', top_n: 20 }, { sample_type: '\u0000cpu', top_n: 20 }, { sample_type: 'é'.repeat(33), top_n: 20 }, { sample_type: 'cpu', top_n: 101 }])('refuses invalid selection without calling the server', async selection => {
  const { client, controller } = setup(); await controller.inspect(selection); expect(client.calls).toHaveLength(0);
});
it('discards a late summary after source version replacement or session loss', async () => {
  const { client, controller, scope } = setup(); let finish!: (value: unknown) => void;
  client.responder = () => new Promise(resolve => { finish = resolve; }); const work = controller.inspect(selection);
  controller.attach(session, scope.signal, id(2), id(3), '8'.repeat(64));
  expect(client.calls[0].signal.aborted).toBe(true); finish(profileSummary()); await work;
  expect(controller.snapshot()).toEqual({ phase: 'idle' }); scope.abort(); expect(vi.getTimerCount()).toBe(0);
});
