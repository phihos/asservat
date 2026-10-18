import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { ContextProjection } from './projection';
import { SyntheticProjection, session, id, excerpt, pending, result, queryHandle } from './test-fixtures';
const controllers: ContextProjection[] = [];
beforeEach(() => vi.useFakeTimers());
afterEach(() => { for (const controller of controllers) controller.close(); controllers.length = 0; vi.useRealTimers(); });
function setup() {
  const client = new SyntheticProjection(); let monotonic = 1000;
  const controller = new ContextProjection(client, () => monotonic); controllers.push(controller);
  const scope = new AbortController(); const detach = controller.attach(session, scope.signal, id(2), id(3));
  const advance = async (ms: number) => { monotonic += ms; await vi.advanceTimersByTimeAsync(ms); };
  return { client, controller, scope, detach, advance, delay: (ms: number) => { monotonic += ms; } };
}
it('does no implicit work and requests only exact case/artifact without idempotency', async () => {
  const { controller, client } = setup(); expect(client.calls).toHaveLength(0);
  await controller.inspect(); expect(controller.snapshot().phase).toBe('result');
  expect(client.calls).toHaveLength(1); expect(client.calls[0].input).toEqual({ case_id: id(2), artifact_id: id(3), line_start: 1, max_lines: 14 });
});
it('includes response delay in the original cutoff and clears without network work', async () => {
  const { controller, client, delay, advance } = setup();
  client.responder = () => { delay(9000); return excerpt(); };
  await controller.inspect(); expect(controller.snapshot().phase).toBe('result');
  await advance(999); expect(controller.snapshot().phase).toBe('expired');
  expect(controller.snapshot().excerpt).toBeUndefined(); expect(client.calls).toHaveLength(1);
});
it('discards an already expired reply rather than starting a new local lifetime', async () => {
  const { controller, client, delay } = setup();
  client.responder = () => { delay(10_000); return excerpt(); };
  await controller.inspect(); expect(controller.snapshot()).toEqual({ phase: 'expired' });
});
it('does not use browser wall-clock agreement to accept or extend a result', async () => {
  const { controller, advance } = setup(); vi.setSystemTime(new Date('2040-01-01'));
  await controller.inspect(); expect(controller.snapshot().phase).toBe('result');
  vi.setSystemTime(new Date('1990-01-01')); await advance(9999);
  expect(controller.snapshot().phase).toBe('expired');
});
it('polls only the acknowledged handle and never automatically creates another query', async () => {
  const { controller, client, advance } = setup(); client.responder = () => pending();
  await controller.inspect(); await controller.check(); expect(client.calls).toHaveLength(1);
  await advance(1000); expect(client.calls).toHaveLength(1);
  client.responder = () => result(); await controller.check();
  expect(client.calls.map(c => c.name)).toEqual(['get_file_excerpt', 'get_query_result']);
  expect(client.calls[1].input).toEqual({ query_handle: queryHandle });
  expect(controller.snapshot().phase).toBe('result');
  await advance(8999); expect(controller.snapshot().phase).toBe('expired'); expect(client.calls).toHaveLength(2);
});
it('a refreshed observation cannot extend the oldest cutoff for the same handle', async () => {
  const { controller, client, advance } = setup(); client.responder = () => pending();
  await controller.inspect(); await advance(1000);
  const newer = result();
  const times = { query_observed_at: '2026-10-18T12:00:01Z', query_expires_at: '2026-10-18T12:01:01Z' };
  Object.assign(newer.data, times); Object.assign(newer.data.result.data, times);
  client.responder = () => newer; await controller.check(); expect(controller.snapshot().phase).toBe('result');
  await advance(8999); expect(controller.snapshot().phase).toBe('expired');
});
it.each(['handle', 'tool', 'request', 'time', 'class', 'path', 'lines'])('rejects substituted poll association: %s', async change => {
  const { controller, client, advance } = setup(); client.responder = () => pending();
  await controller.inspect(); await advance(1000); const output = result();
  if (change === 'handle') output.data.query_handle = 'replacement';
  if (change === 'tool') output.data.tool_name = 'other';
  if (change === 'request') output.data.result.request_id = id(999);
  if (change === 'time') output.data.result.data.query_expires_at = '2026-10-18T12:00:11Z';
  if (change === 'class') output.data.result.data_class = 'raw';
  if (change === 'path') output.data.result.data.logical_path = 'secrets.txt';
  if (change === 'lines') output.data.result.data.lines.pop();
  client.responder = () => output; await controller.check(); expect(controller.snapshot()).toEqual({ phase: 'unavailable' });
});
it('scope cancellation and closing clear results, abort requests and discard late replies', async () => {
  const { controller, client, scope } = setup(); let finish!: (value: unknown) => void;
  client.responder = () => new Promise(resolve => { finish = resolve; });
  const work = controller.inspect(); scope.abort();
  expect(client.calls[0].signal.aborted).toBe(true); finish(excerpt()); await work;
  expect(controller.snapshot()).toEqual({ phase: 'idle' }); expect(vi.getTimerCount()).toBe(0);
});
it('old effect cleanup cannot erase a newly attached scope', async () => {
  const { controller, detach } = setup();
  controller.attach(session, new AbortController().signal, id(2), id(4));
  detach(); await controller.inspect(); expect(controller.snapshot().phase).toBe('result');
});
it('an unknown initial reply never retries or converts into an invented pending handle', async () => {
  const { controller, client, advance } = setup(); client.responder = () => { throw new Error('lost reply'); };
  await controller.inspect(); await controller.check(); await advance(60_000);
  expect(controller.snapshot().phase).toBe('unavailable'); expect(client.calls).toHaveLength(1);
});
