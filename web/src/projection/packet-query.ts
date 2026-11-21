import type { Session } from '../auth/session';
import { validInput_query_artifact, validOutput_get_query_result } from '../generated/validate-projection';
import { operations, validQuery, type Operations, type Input, type PacketQueryData } from './http';

export type PacketField = NonNullable<Input<'query_artifact'>['fields']>[number];
export type PacketQuerySelection = { fields: PacketField[]; limit: number; packet_filter?: string; start_time?: string; end_time?: string; tcp_flags?: { mask: number; value: number }; frame_prefix?: { offset: number; length: number }; grant_id?: string };
type PacketInput = PacketQuerySelection & { operation: 'packets'; case_id: string; artifact_id: string; idempotency_key: string };
export type PacketQuerySource = { caseID: string; artifactID: string; version: string; captureMode: 'networkHeaders' | 'rawPackets' };
export type PacketQueryState = { phase: 'idle' | 'loading' | 'pending' | 'result' | 'uncertain' | 'unavailable' | 'expired'; result?: PacketQueryData; warnings?: string[]; canCheck?: boolean };
export const packetFields: readonly PacketField[] = ['packet_index', 'packet_time', 'captured_length', 'wire_length', 'source_address', 'destination_address', 'source_port', 'destination_port', 'protocol', 'tcp_flags', 'tcp_seq', 'tcp_ack', 'tcp_window', 'icmp_type', 'icmp_code', 'frame_prefix_hex'];
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const integer = (x: unknown, max = 0xffff_ffff): x is number => typeof x === 'number' && Number.isInteger(x) && x >= 0 && x <= max;
function instant(text: string): bigint | undefined {
  const m = /^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?Z$/.exec(text);
  if (!m) return;
  const ms = Date.parse(m[1] + 'Z');
  if (!Number.isFinite(ms) || new Date(ms).toISOString().slice(0, 19) !== m[1]) return;
  return BigInt(ms) * 1_000_000n + BigInt((m[2] ?? '').padEnd(9, '0'));
}
function numericAddress(s: string) {
  if (s.includes(':')) { try { return /^[0-9a-f:]+$/.test(s) && new URL('http://[' + s + ']/').hostname === '[' + s + ']'; } catch { return false; } }
  const parts = s.split('.'); return parts.length === 4 && parts.every(p => /^(0|[1-9]\d{0,2})$/.test(p) && Number(p) <= 255);
}
function validSelection(input: PacketInput, source: PacketQuerySource) {
  if (!validInput_query_artifact(input) || !input.fields.length || new Set(input.fields).size !== input.fields.length || input.fields.some(f => !packetFields.includes(f))) return false;
  if (source.captureMode === 'rawPackets' ? !uuid.test(input.grant_id ?? '') : input.grant_id !== undefined || input.fields.includes('frame_prefix_hex')) return false;
  if (input.fields.includes('frame_prefix_hex') !== !!input.frame_prefix || input.frame_prefix && input.frame_prefix.offset + input.frame_prefix.length > 1500) return false;
  if (input.tcp_flags && (input.tcp_flags.value & ~input.tcp_flags.mask) !== 0) return false;
  const start = input.start_time === undefined ? undefined : instant(input.start_time), end = input.end_time === undefined ? undefined : instant(input.end_time);
  return !(input.start_time !== undefined && start === undefined || input.end_time !== undefined && end === undefined || start !== undefined && end !== undefined && end <= start);
}
function validRows(data: PacketQueryData, input: PacketInput, mode: PacketQuerySource['captureMode']) {
  if (data.capture_mode !== mode || JSON.stringify(data.fields) !== JSON.stringify(input.fields) || data.rows.length > input.limit || !integer(data.scanned_packets) || !Number.isSafeInteger(data.scanned_bytes) || data.scanned_bytes < 0 || data.rows.length > data.scanned_packets) return false;
  const stops = Number(data.row_limit_reached) + Number(data.scan_limit_reached) + Number(data.output_limit_reached);
  if (stops > 1 || data.row_limit_reached && data.rows.length !== input.limit) return false;
  let previous = 0;
  for (const row of data.rows) {
    if (row.length !== input.fields.length) return false;
    for (let i = 0; i < row.length; i++) {
      const field = input.fields[i], value = row[i];
      if (value === null) { if (['packet_index', 'captured_length', 'wire_length'].includes(field)) return false; continue; }
      switch (field) {
        case 'packet_time': if (typeof value !== 'string' || instant(value) === undefined) return false; break;
        case 'source_address': case 'destination_address': if (typeof value !== 'string' || !numericAddress(value)) return false; break;
        case 'protocol': if (typeof value !== 'string' || !['TCP', 'UDP', 'ICMPv4', 'ICMPv6'].includes(value)) return false; break;
        case 'frame_prefix_hex': if (typeof value !== 'string' || !/^(?:[0-9a-f]{2})+$/.test(value) || value.length > 2 * (input.frame_prefix?.length ?? 0)) return false; break;
        default: {
          const max = ['source_port', 'destination_port', 'tcp_window'].includes(field) ? 65535 : ['icmp_type', 'icmp_code'].includes(field) ? 255 : field === 'tcp_flags' ? 511 : field === 'captured_length' ? 1500 : 0xffff_ffff;
          if (!integer(value, max)) return false;
          if (field === 'packet_index') { if (value <= previous || value > data.scanned_packets) return false; previous = value; }
        }
      }
    }
    const at = (field: PacketField) => row[input.fields.indexOf(field)];
    const cap = at('captured_length'), wire = at('wire_length'), prefix = at('frame_prefix_hex');
    if (typeof cap === 'number' && typeof wire === 'number' && cap > wire) return false;
    if (typeof cap === 'number' && typeof prefix === 'string' && prefix.length / 2 !== Math.min(input.frame_prefix!.length, cap - input.frame_prefix!.offset)) return false;
  }
  return true;
}

// One explicit transient query. Unknown Begin can only replay its frozen input/key.
export class PacketQuery {
  private state: PacketQueryState = { phase: 'idle' };
  private listeners = new Set<() => void>();
  private session?: Session; private scope?: AbortSignal; private source?: PacketQuerySource;
  private active?: AbortController; private detach?: () => void; private generation = 0;
  private attempt?: PacketInput; private handle?: string; private firstStarted = 0;
  private cutoff = Infinity; private revision = 1;
  private timer?: ReturnType<typeof setTimeout>;
  constructor(private client: Operations = operations, private now = () => performance.now(), private newID: () => string = () => crypto.randomUUID()) {}
  readonly snapshot = () => this.state;
  readonly subscribe = (listener: () => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  private publish(state: PacketQueryState) { this.state = state; for (const fn of this.listeners) fn(); }
  close = () => { ++this.generation; this.active?.abort(); this.active = undefined; clearTimeout(this.timer); this.attempt = undefined; this.handle = undefined; this.cutoff = Infinity; this.publish({ phase: 'idle' }); };
  isAttachedTo(session: Session, scope: AbortSignal, source: PacketQuerySource) { return this.session === session && this.scope === scope && !scope.aborted && JSON.stringify(this.source) === JSON.stringify(source); }
  attach(session: Session, scope: AbortSignal, source: PacketQuerySource) {
    this.detach?.(); this.close(); this.session = session; this.scope = scope;
    this.source = uuid.test(source.caseID) && uuid.test(source.artifactID) && /^[0-9a-f]{64}$/.test(source.version) ? { ...source } : undefined;
    const abort = () => { this.session = undefined; this.source = undefined; this.close(); };
    const detach = () => { if (this.detach !== detach) return; scope.removeEventListener('abort', abort); this.detach = undefined; abort(); };
    this.detach = detach; scope.addEventListener('abort', abort, { once: true }); if (scope.aborted) abort(); return detach;
  }
  run = async (selection: PacketQuerySelection) => {
    if (!this.source || !this.session || this.scope?.aborted || ['loading', 'pending', 'uncertain'].includes(this.state.phase)) return;
    this.close(); const input: PacketInput = { ...structuredClone(selection), operation: 'packets', case_id: this.source.caseID, artifact_id: this.source.artifactID, idempotency_key: this.newID() };
    if (!validSelection(input, this.source)) { this.publish({ phase: 'unavailable' }); return; }
    this.attempt = input; this.firstStarted = this.now(); this.cutoff = this.firstStarted + 60_000; this.arm(); await this.read(false);
  };
  retryBegin = async () => { if (this.state.phase === 'uncertain' && this.attempt) await this.read(false); };
  check = async () => { if (this.state.phase === 'pending' && this.handle) await this.read(true); };
  private arm() { clearTimeout(this.timer); this.timer = setTimeout(() => { this.close(); this.publish({ phase: 'expired' }); }, Math.max(0, this.cutoff - this.now())); }
  private async read(poll: boolean) {
    if (!this.session || !this.scope || !this.source || !this.attempt || this.now() >= this.cutoff) return;
    const generation = ++this.generation, scope = this.scope, request = new AbortController(), started = this.now();
    this.active = request; const abort = () => request.abort(); scope.addEventListener('abort', abort, { once: true }); this.publish({ phase: 'loading' });
    let received = false;
    try {
      const outer = poll ? await this.client.call('get_query_result', { query_handle: this.handle!, after_revision: this.revision }, this.session.csrf_token, request.signal) : await this.client.call('query_artifact', this.attempt as unknown as Input<'query_artifact'>, this.session.csrf_token, request.signal);
      received = true;
      if (generation !== this.generation || scope.aborted || request.signal.aborted) return;
      if (!(poll ? validOutput_get_query_result(outer) : validQuery('packets', outer)) || outer.status === 'error' || outer.next_cursor !== null) throw new Error('Query unavailable');
      if (poll && (!('query_handle' in outer.data) || outer.data.query_handle !== this.handle || outer.provenance.length !== 0)) throw new Error('Query changed');
      const times = outer.data as { query_observed_at: string; query_expires_at: string };
      const duration = Date.parse(times.query_expires_at) - Date.parse(times.query_observed_at);
      if (!Number.isFinite(duration) || duration <= 1 || duration > 60_000) throw new Error('Invalid lifetime');
      this.cutoff = Math.min(this.cutoff, started + duration - 1); this.arm();
      if (this.now() >= this.cutoff) { this.close(); this.publish({ phase: 'expired' }); return; }
      if (outer.status === 'pending') {
        if (outer.data_class !== 'metadata' || outer.truncated || outer.provenance.length !== 0 || this.handle && this.handle !== outer.data.query_handle) throw new Error('Pending changed');
        this.handle = outer.data.query_handle; this.revision = outer.data.revision;
        this.publish({ phase: 'pending', canCheck: true }); return;
      }
      const page: unknown = poll && 'result' in outer.data ? outer.data.result : outer;
      if (poll && (!('tool_name' in outer.data) || outer.data.tool_name !== 'query_artifact')) throw new Error('Tool changed');
      if (!validQuery('packets', page) || page.status !== 'ok' || page.next_cursor !== null || page.request_id !== outer.request_id || page.data.query_observed_at !== outer.data.query_observed_at || page.data.query_expires_at !== outer.data.query_expires_at || page.provenance.length !== 1 || page.provenance[0].artifactID !== this.source.artifactID || page.provenance[0].digest !== this.source.version || page.data_class !== (this.source.captureMode === 'rawPackets' ? 'raw' : 'extract') || outer.data_class !== page.data_class || !validRows(page.data, this.attempt, this.source.captureMode)) throw new Error('Result association changed');
      const limited = page.data.row_limit_reached || page.data.scan_limit_reached || page.data.output_limit_reached;
      if (page.truncated !== limited || outer.truncated !== (poll ? false : limited)) throw new Error('Limit changed');
      this.attempt = undefined; this.publish({ phase: 'result', result: structuredClone(page.data), warnings: [...page.warnings] });
    } catch { if (generation === this.generation && !scope.aborted) { this.publish({ phase: !poll && !received && this.attempt ? 'uncertain' : 'unavailable' }); } }
    finally { scope.removeEventListener('abort', abort); if (this.active === request) this.active = undefined; }
  }
}
