import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { ContextProjection } from './projection';
import { SyntheticProjection, session, id, pending, packetResult, packetSummary, profileVersion } from './test-fixtures';
const controllers: ContextProjection[] = [];
beforeEach(() => vi.useFakeTimers());
afterEach(() => { controllers.forEach(controller => controller.close()); controllers.length = 0; vi.useRealTimers(); });
function setup() {
  const client = new SyntheticProjection(); let now = 1000;
  client.responder = () => packetSummary();
  const controller = ContextProjection.packet(client, () => now); controllers.push(controller);
  const scope = new AbortController(); controller.attach(session, scope.signal, id(2), id(3), profileVersion);
  return { client, controller, scope, advance: async (ms: number) => { now += ms; await vi.advanceTimersByTimeAsync(ms); }, delay: (ms: number) => { now += ms; } };
}
it('requests only the attached saved packet explicitly and owns an independent result copy', async () => {
  const { client, controller } = setup(); const value = packetSummary(); client.responder = () => value;
  expect(client.calls).toHaveLength(0); await controller.inspect();
  expect(client.calls).toHaveLength(1); expect(client.calls[0]).toMatchObject({ name: 'get_pcap_summary', input: { case_id: id(2), artifact_id: id(3) } });
  expect(controller.snapshot().phase).toBe('result'); value.data.conversations[0].source = 'changed'; value.warnings.push('later');
  expect(controller.snapshot().packetSummary?.conversations[0].source).toBe('192.0.2.1:40000'); expect(controller.snapshot().warnings).toEqual([]);
  controller.close(); expect(controller.snapshot()).toEqual({ phase: 'idle' }); expect(client.calls).toHaveLength(1);
});
it('polls one original handle without renewing the request-start lifetime', async () => {
  const { client, controller, delay, advance } = setup();
  client.responder = () => { delay(3000); return pending(); }; await controller.inspect();
  expect(controller.snapshot().phase).toBe('pending'); await controller.check(); expect(client.calls).toHaveLength(1);
  await advance(1000); client.responder = () => packetResult(); await controller.check();
  expect(client.calls[1]).toMatchObject({ name: 'get_query_result', input: { query_handle: 'synthetic-original-query' } });
  expect(controller.snapshot().phase).toBe('result'); await advance(5999);
  expect(controller.snapshot()).toEqual({ phase: 'expired' }); expect(client.calls).toHaveLength(2);
});
it.each(['artifact', 'version', 'request', 'tool', 'handle', 'time', 'outer-class', 'raw', 'raw-mode', 'packet-total', 'counter-null', 'counter-label', 'total-rows', 'truncation', 'hostname', 'port', 'ipv6', 'duplicate', 'ranking', 'payload'])('refuses a changed packet association or inconsistent fixed result: %s', async mode => {
  const { client, controller, advance } = setup(); client.responder = () => pending(); await controller.inspect(); await advance(1000);
  const output = packetResult(), inner = output.data.result, data = inner.data;
  if (mode === 'artifact') inner.provenance[0].artifactID = id(8);
  if (mode === 'version') inner.provenance[0].digest = '8'.repeat(64);
  if (mode === 'request') inner.request_id = id(99);
  if (mode === 'tool') output.data.tool_name = 'get_profile_summary';
  if (mode === 'handle') output.data.query_handle = 'replacement';
  if (mode === 'time') inner.data.query_expires_at = '2026-10-18T12:00:11Z';
  if (mode === 'outer-class') output.data_class = 'metadata';
  if (mode === 'raw') inner.data_class = 'raw';
  if (mode === 'raw-mode') data.capture_mode = 'rawPackets';
  if (mode === 'packet-total') data.packets = 2;
  if (mode === 'counter-null') data.drops = null;
  if (mode === 'counter-label') data.drop_reporting = 'unavailable';
  if (mode === 'total-rows') data.conversations_total = 2;
  if (mode === 'truncation') data.conversations_truncated = true;
  if (mode === 'hostname') data.conversations[0].source = 'private.internal:80';
  if (mode === 'port') data.conversations[0].source = '192.0.2.1:65536';
  if (mode === 'ipv6') data.conversations[0].source = '[2001:db8:invalid]:80';
  if (mode === 'duplicate') { data.packets = 6; data.conversations_total = 2; data.conversations.push({ ...data.conversations[0] }); }
  if (mode === 'ranking') { data.conversations_total = 2; data.conversations[0].packets = 1; data.conversations.push({ source: '192.0.2.9:1', destination: '192.0.2.2:443', protocol: 'TCP', packets: 2 }); }
  if (mode === 'payload') Object.assign(data.conversations[0], { payload: 'private' });
  client.responder = () => output; await controller.check(); expect(controller.snapshot()).toEqual({ phase: 'unavailable' });
});
it('accepts explicit unknown counters and numeric IPv6/ICMP with full saved counts', async () => {
  const { client, controller } = setup(); const value = packetSummary(); value.data.drops = null; value.data.drop_reporting = 'unavailable';
  value.data.conversations = [{ source: '2001:db8::1', destination: '2001:db8::2', protocol: 'ICMPv6', packets: 3 }];
  client.responder = () => value; await controller.inspect(); expect(controller.snapshot().packetSummary?.drops).toBeNull();
});
it('clears prior results and discards late replies on case, version and session replacement', async () => {
  const { client, controller, scope } = setup(); let finish!: (value: unknown) => void;
  client.responder = () => new Promise(resolve => { finish = resolve; }); const work = controller.inspect();
  controller.attach(session, scope.signal, id(5), id(3), profileVersion);
  expect(client.calls[0].signal.aborted).toBe(true); finish(packetSummary()); await work; expect(controller.snapshot()).toEqual({ phase: 'idle' });
  controller.attach(session, scope.signal, id(2), id(3), profileVersion); client.responder = () => packetSummary(); await controller.inspect();
  controller.attach({ ...session }, scope.signal, id(2), id(3), profileVersion); expect(controller.snapshot()).toEqual({ phase: 'idle' });
  expect(client.calls).toHaveLength(2); scope.abort(); expect(vi.getTimerCount()).toBe(0);
});
it('rejects a missing immutable version before issuing a query', async () => {
  const { client, controller, scope } = setup(); controller.attach(session, scope.signal, id(2), id(3)); await controller.inspect();
  expect(client.calls).toHaveLength(0); expect(controller.snapshot()).toEqual({ phase: 'unavailable' });
});
