import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { ContextProjection } from './projection';
import { SyntheticProjection, session, id, packetSummary, profileVersion } from './test-fixtures';
const controllers: ContextProjection[] = [];
beforeEach(() => vi.useFakeTimers());
afterEach(() => { controllers.forEach(c => c.close()); controllers.length = 0; vi.useRealTimers(); });
function rawSummary() {
  const value = packetSummary();
  return { ...value, data: { ...value.data, capture_mode: 'rawPackets', packets: 5, unclassified_packets: 2 } };
}
function setup(raw = true) {
  const client = new SyntheticProjection(), controller = ContextProjection.packet(client), scope = new AbortController();
  controllers.push(controller); controller.attach(session, scope.signal, id(2), id(3), profileVersion, raw ? 'rawPackets' : 'networkHeaders');
  return { client, controller, scope };
}
it('inspects only the attached raw source and explicitly counts unclassified saved records', async () => {
  const { client, controller } = setup(); client.responder = () => rawSummary(); await controller.inspect();
  expect(controller.snapshot().phase).toBe('result'); expect(controller.snapshot().packetSummary).toMatchObject({ capture_mode: 'rawPackets', packets: 5, unclassified_packets: 2 });
  expect(client.calls).toHaveLength(1); expect(client.calls[0]).toMatchObject({ name: 'get_pcap_summary', input: { case_id: id(2), artifact_id: id(3) } });
});
it('keeps a complete raw result unavailable to a metadata-attached view', async () => {
  const { client, controller } = setup(false); client.responder = () => rawSummary(); await controller.inspect(); expect(controller.snapshot()).toEqual({ phase: 'unavailable' });
});
it.each(['missing', 'null', 'negative', 'fraction', 'over-packets', 'classified-sum', 'mode', 'version', 'payload'])('rejects raw counters or source mismatch: %s', async change => {
  const { client, controller } = setup(); const value = rawSummary();
  if (change === 'missing') Reflect.deleteProperty(value.data, 'unclassified_packets');
  if (change === 'null') Object.assign(value.data, { unclassified_packets: null });
  if (change === 'negative') value.data.unclassified_packets = -1;
  if (change === 'fraction') value.data.unclassified_packets = 0.5;
  if (change === 'over-packets') value.data.unclassified_packets = 6;
  if (change === 'classified-sum') value.data.unclassified_packets = 1;
  if (change === 'mode') { value.data.capture_mode = 'networkHeaders'; Reflect.deleteProperty(value.data, 'unclassified_packets'); value.data.packets = 3; }
  if (change === 'version') value.provenance[0].digest = '8'.repeat(64);
  if (change === 'payload') Object.assign(value.data.conversations[0], { payload: 'synthetic-payload-must-not-display' });
  client.responder = () => value; await controller.inspect(); expect(controller.snapshot()).toEqual({ phase: 'unavailable' });
});
it('accepts zero unclassified and entirely unclassified files without guessing conversations', async () => {
  const { client, controller } = setup(); const value = rawSummary(); value.data.packets = 3; value.data.unclassified_packets = 0;
  client.responder = () => value; await controller.inspect(); expect(controller.snapshot().phase).toBe('result');
  value.data.packets = 5; value.data.unclassified_packets = 5; value.data.conversations = []; value.data.conversations_total = 0;
  await controller.inspect(); expect(controller.snapshot().packetSummary?.conversations).toEqual([]);
});
it('clears and aborts when the attached source mode changes, even with identical IDs/version', async () => {
  const { client, controller, scope } = setup(false); let finish!: (value: unknown) => void;
  client.responder = () => new Promise(resolve => { finish = resolve; }); const work = controller.inspect();
  controller.attach(session, scope.signal, id(2), id(3), profileVersion, 'rawPackets');
  expect(controller.isAttachedTo(session, scope.signal, id(2), id(3), profileVersion, 'networkHeaders')).toBe(false);
  expect(client.calls[0].signal.aborted).toBe(true); finish(packetSummary()); await work; expect(controller.snapshot()).toEqual({ phase: 'idle' });
});
