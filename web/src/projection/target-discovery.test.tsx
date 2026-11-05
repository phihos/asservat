import { act, fireEvent, render, screen, cleanup } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { TargetDiscovery } from './target-discovery';
import { TargetDiscoveryView } from './TargetDiscoveryView';
import { SyntheticProjection, session, id, pending, timing, profileVersion, queryHandle } from './test-fixtures';
import { validOutput_get_target_discovery } from '../generated/validate-projection';

afterEach(() => { cleanup(); vi.useRealTimers(); });
const captureID = id(9);
function page(cursor: string | null = null) {
  return { schema_version: 'mcp-result/v1', request_id: id(80), data_class: 'extract', status: 'ok', truncated: cursor !== null, next_cursor: cursor, narrowing_hint: cursor === null ? null : 'Use the next page to continue.', warnings: [], provenance: [{ artifactID: id(3), digest: profileVersion }],
    data: { kind: 'discoveryPage', capture_id: captureID, source_artifact_ids: [id(3)], expires_at: timing.query_expires_at, section: 'processes', ...timing,
      summary: { started_at: '2026-10-18T11:59:59Z', ended_at: '2026-10-18T12:00:00Z', observed_wire_bytes: 0, retained_bytes: 1024, capture_mode: 'none', coverage: { requested_pods: 1, covered_pods: 1, process_inventory_complete: true, traffic_complete: false, dropped_packets: 0, stop_reason: 'completed' } },
      processes: [{ process_ref: 'p:original', pod_uid: id(4), display_pid: 1, executable_path: '/app/<script>marker</script>', runtime: 'unknown', identity_basis: { confidence: 'observed', reason: 'Exact original identity' }, rss_bytes: 0, observed_at: '2026-10-18T12:00:00Z' }], gaps: ['socketOwnersUnsupported'] } };
}

it('uses the canonical process schema, retaining zero memory and untrusted paths', () => {
  expect(validOutput_get_target_discovery(page())).toBe(true);
  const p = page(); p.data.processes[0].runtime = 'guessed';
  expect(validOutput_get_target_discovery(p)).toBe(false);
});

it('does not read on attach; renders saved inert data only after explicit inspection', async () => {
  const client = new SyntheticProjection(); client.responder = () => page();
  const controller = new TargetDiscovery(client), scope = new AbortController();
  render(<TargetDiscoveryView controller={controller} session={session} scope={scope.signal} captureID={captureID}/>);
  expect(client.calls).toHaveLength(0);
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Inspect saved processes' })); });
  expect(client.calls).toHaveLength(1); expect(client.calls[0].name).toBe('get_target_discovery');
  expect(client.calls[0].input).toEqual({ capture_id: captureID, section: 'processes', limit: 20 });
  expect(screen.getByText('/app/<script>marker</script>')).toBeTruthy(); expect(document.querySelector('script')).toBeNull();
  expect(screen.getByText('0 bytes')).toBeTruthy();
  act(() => scope.abort());
  expect(screen.queryByText('/app/<script>marker</script>')).toBeNull(); expect(controller.snapshot().page).toBeUndefined();
});

it('keeps the original pending handle and relative expiry without restarting acquisition', async () => {
  vi.useFakeTimers(); let now = 0;
  const client = new SyntheticProjection(); client.responder = () => pending();
  const controller = new TargetDiscovery(client, () => now), scope = new AbortController();
  controller.attach(session, scope.signal, captureID); await controller.inspect();
  expect(controller.snapshot().phase).toBe('pending');
  await controller.check(); expect(client.calls).toHaveLength(1);
  now = 1000; await vi.advanceTimersByTimeAsync(1000);
  client.responder = () => ({ ...page(), next_cursor: null, provenance: [], data: { query_handle: queryHandle, tool_name: 'get_target_discovery', result: page(), ...timing } });
  await controller.check();
  expect(client.calls[1].name).toBe('get_query_result'); expect(client.calls[1].input).toEqual({ query_handle: queryHandle });
  expect(controller.snapshot().phase).toBe('result');
  now = 10_000; await vi.advanceTimersByTimeAsync(9000);
  expect(controller.snapshot().phase).toBe('expired'); expect(controller.snapshot().page).toBeUndefined();
  expect(client.calls).toHaveLength(2); controller.close();
});

it('refuses changed capture, provenance, wrapper tool or query expiry', async () => {
  for (const mode of ['capture', 'provenance', 'expiry', 'tool']) {
    vi.useFakeTimers(); let now = 0;
    const client = new SyntheticProjection(); client.responder = () => pending();
    const controller = new TargetDiscovery(client, () => now), scope = new AbortController();
    controller.attach(session, scope.signal, captureID); await controller.inspect();
    now = 1000; await vi.advanceTimersByTimeAsync(1000);
    const p = page();
    const outer = { ...p, provenance: [], data: { query_handle: queryHandle, tool_name: mode === 'tool' ? 'get_syscall_events' : 'get_target_discovery', result: p, ...timing } };
    if (mode === 'capture') p.data.capture_id = id(10);
    if (mode === 'provenance') p.provenance[0].artifactID = id(8);
    if (mode === 'expiry') outer.data.query_expires_at = '2026-10-18T12:00:20Z';
    client.responder = () => outer;
    await controller.check(); expect(controller.snapshot().phase).toBe('unavailable'); expect(controller.snapshot().page).toBeUndefined();
    controller.close(); vi.useRealTimers();
  }
});

it('never automatically repeats an unknown Begin and aborts late results', async () => {
  const client = new SyntheticProjection(); client.responder = () => { throw new Error('unknown delivery'); };
  const controller = new TargetDiscovery(client), scope = new AbortController();
  controller.attach(session, scope.signal, captureID); await controller.inspect();
  expect(controller.snapshot().phase).toBe('uncertain'); expect(client.calls).toHaveLength(1);
  let finish!: (value: unknown) => void;
  client.responder = () => new Promise(resolve => { finish = resolve; });
  const work = controller.inspect(); controller.close(); finish(page()); await work;
  expect(controller.snapshot().phase).toBe('idle'); expect(controller.snapshot().page).toBeUndefined();
});

it('pages explicitly within the same saved source and rejects a changed source version', async () => {
  const client = new SyntheticProjection(); client.responder = () => page('20:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
  const controller = new TargetDiscovery(client), scope = new AbortController();
  controller.attach(session, scope.signal, captureID); await controller.inspect();
  expect(client.calls).toHaveLength(1);
  expect(controller.snapshot().nextCursor).toBe('20:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
  const changed = page(); changed.provenance[0].digest = 'a'.repeat(64);
  client.responder = () => changed;
  await controller.nextPage();
  expect(client.calls).toHaveLength(2);
  expect(client.calls[1].input).toEqual({ capture_id: captureID, section: 'processes', limit: 20, cursor: '20:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' });
  expect(controller.snapshot().phase).toBe('unavailable'); expect(controller.snapshot().page).toBeUndefined();
  controller.close();
});
