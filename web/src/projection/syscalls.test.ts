import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { ContextProjection, type SyscallSelection } from './projection';
import { SyntheticProjection, session, id, pending, syscallResult, syscallSummary, syscallEvents, profileVersion } from './test-fixtures';

const controllers: ContextProjection[] = [];
const summarySelection: SyscallSelection = { view: 'summary', limit: 100, names: [], errorsOnly: false };
const eventSelection: SyscallSelection = { view: 'events', limit: 100, names: ['write'], errorsOnly: true };
beforeEach(() => vi.useFakeTimers());
afterEach(() => { controllers.forEach(controller => controller.close()); controllers.length = 0; vi.useRealTimers(); });
function setup() {
  const client = new SyntheticProjection(); let now = 1000;
  client.responder = () => syscallSummary();
  const controller = ContextProjection.syscalls(client, () => now); controllers.push(controller);
  const scope = new AbortController(); controller.attach(session, scope.signal, id(2), id(3), profileVersion);
  return { client, controller, scope, advance: async (ms: number) => { now += ms; await vi.advanceTimersByTimeAsync(ms); }, delay: (ms: number) => { now += ms; } };
}

it('reads summary and metadata events explicitly without another approval or native download', async () => {
  const { client, controller } = setup(); expect(client.calls).toHaveLength(0);
  await controller.inspectSyscalls(summarySelection);
  expect(client.calls[0]).toMatchObject({ name: 'get_syscall_summary', input: { case_id: id(2), artifact_id: id(3), limit: 100 } });
  expect(controller.snapshot().syscallSummary?.rows[1]).toMatchObject({ syscall: 'write', count: 2, errors: 1 });
  const events = syscallEvents(); client.responder = () => events;
  await controller.inspectSyscalls(eventSelection);
  expect(client.calls[1]).toMatchObject({ name: 'get_syscall_events', input: { case_id: id(2), artifact_id: id(3), limit: 100, syscall_names: ['write'], errors_only: true } });
  expect(controller.snapshot().syscallSummary).toBeUndefined(); expect(controller.snapshot().syscallEvents?.events[0].errno).toBe('ENOENT');
  events.data.events[0].identity.process_ref = 'mutated-source'; events.data.coverage.gaps[0] = 'mutated-source';
  expect(controller.snapshot().syscallEvents?.events[0].identity.process_ref).not.toBe('mutated-source');
  expect(controller.snapshot().syscallEvents?.coverage.gaps).not.toContain('mutated-source');
  controller.close(); expect(controller.snapshot()).toEqual({ phase: 'idle' });
});

it('retains the exact source and owned display filter for a new explicitly requested page', async () => {
  const { client, controller } = setup();
  const cursor = '1:' + 'a'.repeat(32);
  const selection = { ...eventSelection, names: ['write', 'read'] };
  client.responder = () => syscallEvents(cursor);
  await controller.inspectSyscalls(selection);
  selection.names[0] = 'changed'; expect(client.calls).toHaveLength(1);
  client.responder = () => syscallEvents(); await controller.nextSyscallPage();
  expect(client.calls[1]).toMatchObject({ name: 'get_syscall_events', input: { case_id: id(2), artifact_id: id(3), cursor, limit: 100, syscall_names: ['read', 'write'], errors_only: true } });
  expect(controller.snapshot().nextCursor).toBeUndefined();
  await controller.nextSyscallPage(); expect(client.calls).toHaveLength(2);
  controller.close(); await controller.nextSyscallPage(); expect(client.calls).toHaveLength(2);
});

it('polls only the original handle and keeps the nested page cursor with the original lifetime', async () => {
  const { client, controller, advance, delay } = setup();
  client.responder = () => { delay(3000); return pending(); };
  await controller.inspectSyscalls(eventSelection); expect(controller.snapshot().phase).toBe('pending');
  await controller.check(); expect(client.calls).toHaveLength(1);
  await advance(1000); const output = syscallResult('events');
  output.data.result.next_cursor = '1:' + 'a'.repeat(32);
  client.responder = () => output; await controller.check();
  expect(controller.snapshot().phase).toBe('result'); expect(controller.snapshot().nextCursor).toBe(output.data.result.next_cursor);
  expect(client.calls[1]).toMatchObject({ name: 'get_query_result', input: { query_handle: 'synthetic-original-query' } });
  await advance(5999); expect(controller.snapshot()).toEqual({ phase: 'expired' }); expect(client.calls).toHaveLength(2);
});

it.each(['artifact', 'version', 'request', 'tool', 'handle', 'time', 'missing-time', 'raw-class', 'outer-class', 'raw-field', 'coverage', 'count', 'unsafe-count', 'filter', 'view', 'cursor'])('rejects a replaced syscall poll or invalid result: %s', async change => {
  const { client, controller, advance } = setup(); client.responder = () => pending();
  await controller.inspectSyscalls(eventSelection); await advance(1000);
  const output = syscallResult('events');
  const inner = output.data.result as ReturnType<typeof syscallEvents>;
  if (change === 'artifact') inner.provenance[0].artifactID = id(8);
  if (change === 'version') inner.provenance[0].digest = '8'.repeat(64);
  if (change === 'request') inner.request_id = id(99);
  if (change === 'tool') output.data.tool_name = 'get_syscall_summary';
  if (change === 'handle') output.data.query_handle = 'replacement';
  if (change === 'time') inner.data.query_expires_at = '2026-10-18T12:00:11Z';
  if (change === 'missing-time') Object.assign(inner.data, { query_expires_at: undefined });
  if (change === 'raw-class') inner.data_class = 'raw';
  if (change === 'outer-class') output.data_class = 'metadata';
  if (change === 'raw-field') Object.assign(inner.data.events[0], { arguments: [{ name: 'buffer', value: 'secret', truncated: false }] });
  if (change === 'coverage') inner.data.coverage.dropped_events = 0;
  if (change === 'count') inner.data.coverage.record_count = 1;
  if (change === 'unsafe-count') inner.data.coverage.record_count = Number.MAX_SAFE_INTEGER + 1;
  if (change === 'filter') inner.data.events[0].syscall = 'read';
  if (change === 'view') output.data.result = syscallSummary();
  if (change === 'cursor') inner.next_cursor = 'replacement';
  client.responder = () => output; await controller.check();
  expect(controller.snapshot()).toEqual({ phase: 'unavailable' }); expect(client.calls).toHaveLength(2);
});

it.each([
  { ...summarySelection, limit: 101 },
  { ...summarySelection, names: ['read'] },
  { ...summarySelection, errorsOnly: true },
  { ...eventSelection, names: ['write', 'write'] },
  { ...eventSelection, names: [''] },
  { ...eventSelection, names: ['w'.repeat(65)] },
  { ...eventSelection, names: Array.from({ length: 65 }, (_, i) => 'syscall_' + i) },
])('refuses an invalid display selection before any server request', async selection => {
  const { client, controller } = setup(); await controller.inspectSyscalls(selection);
  expect(client.calls).toHaveLength(0); expect(controller.snapshot()).toEqual({ phase: 'unavailable' });
});

it.each(['version', 'session', 'scope', 'close'])('cancels and discards a late syscall result after %s loss', async change => {
  const { client, controller, scope } = setup(); let finish!: (value: unknown) => void;
  client.responder = () => new Promise(resolve => { finish = resolve; });
  const work = controller.inspectSyscalls(summarySelection);
  if (change === 'version') controller.attach(session, scope.signal, id(2), id(3), '8'.repeat(64));
  if (change === 'session') controller.attach({ ...session }, scope.signal, id(2), id(3), profileVersion);
  if (change === 'scope') scope.abort();
  if (change === 'close') controller.close();
  expect(client.calls[0].signal.aborted).toBe(true);
  finish(syscallSummary()); await work;
  expect(controller.snapshot()).toEqual({ phase: 'idle' }); expect(vi.getTimerCount()).toBe(0);
});

it('accepts an empty display without claiming complete observation or reading automatically again', async () => {
  const { client, controller } = setup(); const output = syscallEvents(); output.data.events = [];
  client.responder = () => output; await controller.inspectSyscalls(eventSelection);
  expect(controller.snapshot().phase).toBe('result'); expect(controller.snapshot().syscallEvents?.events).toEqual([]);
  expect(controller.snapshot().syscallEvents?.coverage.record_count).toBe(4); expect(client.calls).toHaveLength(1);
});

it('accepts canonical UTF-8 syscall ordering across supplementary Unicode names', async () => {
  const { client, controller } = setup(); const output = syscallSummary();
  output.data.rows = ['\uE000', '\u{10000}'].map(syscall => ({ syscall, count: 2, errors: 0, paired_count: 0, total_duration_ns: 0 }));
  client.responder = () => output; await controller.inspectSyscalls(summarySelection);
  expect(controller.snapshot().phase).toBe('result');
});
