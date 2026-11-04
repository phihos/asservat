import type { Session } from '../auth/session';
import { validOutput_get_pcap_summary, validOutput_compare_profiles, validOutput_get_file_excerpt, validOutput_get_profile_summary, validOutput_get_query_result, validOutput_get_syscall_summary, validOutput_get_syscall_events } from '../generated/validate-projection';
import { operations, type Operations, type Excerpt, type Summary, type PacketSummary, type Comparison, type SyscallSummary, type SyscallEvents } from './http';

export type State = { phase: 'idle' | 'loading' | 'pending' | 'result' | 'incompatible' | 'expired' | 'unavailable'; excerpt?: Excerpt; summary?: Summary; packetSummary?: PacketSummary; comparison?: Comparison; syscallSummary?: SyscallSummary; syscallEvents?: SyscallEvents; nextCursor?: string; warnings?: string[]; retryAt?: number; canCheck?: boolean };
export type ProfileSource = { caseID: string; artifactID: string; version: string };
export type ComparisonSelection = { sample_type: string; normalization: 'none' | 'perSecond'; top_n: number };
export type SyscallSelection = { view: 'summary' | 'events'; limit: number; names: string[]; errorsOnly: boolean };
type Timing = { query_observed_at: string; query_expires_at: string };
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
// Go's canonical UTF-8 ordering follows code points, whereas JavaScript's
// default string comparison orders supplementary characters by UTF-16 units.
function compareSyscallNames(a: string, b: string) {
  const left = [...a], right = [...b];
  for (let i = 0; i < Math.min(left.length, right.length); i++) {
    const difference = left[i].codePointAt(0)! - right[i].codePointAt(0)!;
    if (difference) return difference;
  }
  return left.length - right.length;
}

// One transient view, with no storage, global result cache or implicit repeat.
// The request-start clock deliberately includes network/audit delay in its TTL.
export class ContextProjection {
  private state: State = { phase: 'idle' };
  private listeners = new Set<() => void>();
  private session?: Session;
  private scope?: AbortSignal;
  private target?: { case_id: string; artifact_id: string };
  private version?: string;
  private baseline?: ProfileSource;
  private comparisonSelection?: ComparisonSelection;
  private selection = { sample_type: 'cpu', top_n: 20 };
  private syscallSelection?: SyscallSelection;
  private syscallCursor?: string;
  private detach?: () => void;
  private active?: AbortController;
  private generation = 0;
  private cutoff = Infinity;
  private handle?: string;
  private timer?: ReturnType<typeof setTimeout>;
  private pollTimer?: ReturnType<typeof setTimeout>;
  readonly snapshot = () => this.state;
  readonly subscribe = (listener: () => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  constructor(private client: Operations = operations, private now: () => number = () => performance.now(), private kind: 'pod-status' | 'profile' | 'syscalls' | 'comparison' | 'packet' = 'pod-status') {}
  static packet(client?: Operations, now?: () => number) { return new ContextProjection(client, now, 'packet'); }
  static profile(client?: Operations, now?: () => number) { return new ContextProjection(client, now, 'profile'); }
  static comparison(client?: Operations, now?: () => number) { return new ContextProjection(client, now, 'comparison'); }
  static syscalls(client?: Operations, now?: () => number) { return new ContextProjection(client, now, 'syscalls'); }
  private publish(state: State) { this.state = state; for (const listener of this.listeners) listener(); }
  private clear(phase: State['phase']) {
    ++this.generation; this.active?.abort(); this.active = undefined;
    clearTimeout(this.timer); clearTimeout(this.pollTimer); this.timer = undefined; this.pollTimer = undefined; this.handle = undefined; this.cutoff = Infinity;
    this.syscallSelection = undefined; this.syscallCursor = undefined; this.comparisonSelection = undefined;
    this.publish({ phase });
  }
  close = () => this.clear('idle');
  isAttachedTo(session: Session, scope: AbortSignal, caseID: string, artifactID: string, version?: string) {
    return this.session === session && this.scope === scope && !scope.aborted &&
      this.target?.case_id === caseID && this.target.artifact_id === artifactID && this.version === version;
  }
  attach(session: Session, scope: AbortSignal, caseID: string, artifactID: string, version?: string) {
    this.detach?.(); this.close();
    this.session = session; this.scope = scope; this.version = version; this.baseline = undefined;
    this.target = uuid.test(caseID) && uuid.test(artifactID) ? { case_id: caseID, artifact_id: artifactID } : undefined;
    const abort = () => { this.session = undefined; this.target = undefined; this.version = undefined; this.baseline = undefined; this.close(); };
    const detach = () => {
      if (this.detach !== detach) return;
      scope.removeEventListener('abort', abort); this.detach = undefined; abort();
    };
    this.detach = detach;
    scope.addEventListener('abort', abort, { once: true });
    if (scope.aborted) abort();
    return detach;
  }
  isComparisonAttachedTo(session: Session, scope: AbortSignal, incident: ProfileSource, baseline: ProfileSource) {
    return this.isAttachedTo(session, scope, incident.caseID, incident.artifactID, incident.version) &&
      this.baseline?.caseID === baseline.caseID && this.baseline.artifactID === baseline.artifactID && this.baseline.version === baseline.version;
  }
  attachComparison(session: Session, scope: AbortSignal, incident: ProfileSource, baseline: ProfileSource) {
    const detach = this.attach(session, scope, incident.caseID, incident.artifactID, incident.version);
    if (!scope.aborted && uuid.test(baseline.caseID) && uuid.test(baseline.artifactID)) this.baseline = { ...baseline };
    return detach;
  }
  inspectComparison = async (selection: ComparisonSelection) => {
    if (this.kind !== 'comparison' || !this.target || !this.baseline || !this.session || this.scope?.aborted || this.state.phase === 'loading') return;
    this.close();
    if (!selection.sample_type || new TextEncoder().encode(selection.sample_type).length > 64 || /[\u0000-\u001f\u007f-\u009f]/u.test(selection.sample_type) || !['none', 'perSecond'].includes(selection.normalization) || !Number.isInteger(selection.top_n) || selection.top_n < 1 || selection.top_n > 100 || !/^[0-9a-f]{64}$/.test(this.version ?? '') || !/^[0-9a-f]{64}$/.test(this.baseline.version) || this.baseline.artifactID === this.target.artifact_id && (this.baseline.caseID !== this.target.case_id || this.baseline.version !== this.version)) { this.clear('unavailable'); return; }
    this.comparisonSelection = { ...selection };
    await this.read(false);
  };
  private acceptTiming(timing: Timing, started: number) {
    // Date.parse truncates fractions to milliseconds. Subtract one millisecond
    // so different fractional endpoints can never extend the original interval.
    const duration = Date.parse(timing.query_expires_at) - Date.parse(timing.query_observed_at);
    if (!Number.isFinite(duration) || duration <= 1 || duration > 60_000) throw new Error('Invalid query interval');
    this.cutoff = Math.min(this.cutoff, started + duration - 1);
    if (this.now() >= this.cutoff) { this.clear('expired'); return false; }
    clearTimeout(this.timer);
    this.timer = setTimeout(() => this.clear('expired'), Math.max(0, this.cutoff - this.now()));
    return true;
  }
  inspect = async (selection?: { sample_type: string; top_n: number }) => {
    if (this.state.phase === 'loading' || !this.target || !this.session || this.scope?.aborted) return;
    this.close();
    if (this.kind === 'syscalls' || this.kind === 'comparison') { this.clear('unavailable'); return; }
    if (this.kind === 'packet' && !/^[0-9a-f]{64}$/.test(this.version ?? '')) { this.clear('unavailable'); return; }
    if (this.kind === 'profile') {
      if (!selection || !selection.sample_type || new TextEncoder().encode(selection.sample_type).length > 64 || /[\u0000-\u001f\u007f-\u009f]/u.test(selection.sample_type) || !Number.isInteger(selection.top_n) || selection.top_n < 1 || selection.top_n > 100 || !/^[0-9a-f]{64}$/.test(this.version ?? '')) { this.clear('unavailable'); return; }
      this.selection = { ...selection };
    }
    await this.read(false);
  };
  inspectSyscalls = async (selection: SyscallSelection) => {
    if (this.kind !== 'syscalls' || !this.target || !this.session || this.scope?.aborted || this.state.phase === 'loading') return;
    this.close();
    const names = [...selection.names].sort(compareSyscallNames);
    if (!['summary', 'events'].includes(selection.view) || !Number.isInteger(selection.limit) || selection.limit < 1 || selection.limit > 100 || names.length > 64 || names.some((name, i) => [...name].length < 1 || [...name].length > 64 || /[\uD800-\uDFFF]/u.test(name) || i > 0 && names[i - 1] === name) || typeof selection.errorsOnly !== 'boolean' || selection.view === 'summary' && (names.length > 0 || selection.errorsOnly) || !/^[0-9a-f]{64}$/.test(this.version ?? '')) { this.clear('unavailable'); return; }
    this.syscallSelection = { ...selection, names };
    this.syscallCursor = undefined;
    await this.read(false);
  };
  nextSyscallPage = async () => {
    if (this.kind !== 'syscalls' || this.state.phase !== 'result' || !this.state.nextCursor || !this.syscallSelection) return;
    // A page is a new explicitly charged query with the same source/filter.
    // It replaces the displayed page and receives its own current authority.
    const cursor = this.state.nextCursor;
    const selection = this.syscallSelection;
    this.close(); this.syscallSelection = selection; this.syscallCursor = cursor;
    await this.read(false);
  };
  check = async () => {
    if (this.state.phase !== 'pending' || !this.handle || this.now() < (this.state.retryAt ?? Infinity)) return;
    if (this.now() >= this.cutoff) { this.clear('expired'); return; }
    await this.read(true);
  };
  private async read(poll: boolean) {
    if (!this.session || !this.target || !this.scope || this.scope.aborted) return;
    const generation = ++this.generation;
    const request = new AbortController(); this.active = request;
    const scope = this.scope;
    const abort = () => request.abort(); scope.addEventListener('abort', abort, { once: true });
    const started = this.now();
    clearTimeout(this.pollTimer);
    this.publish({ phase: 'loading' });
    try {
      const response = poll
        ? await this.client.call('get_query_result', { query_handle: this.handle! }, this.session.csrf_token, request.signal)
        : this.kind === 'packet'
          ? await this.client.call('get_pcap_summary', { ...this.target }, this.session.csrf_token, request.signal)
        : this.kind === 'comparison'
          ? await this.client.call('compare_profiles', { ...this.target, baseline_case_id: this.baseline!.caseID, baseline_artifact_id: this.baseline!.artifactID, ...this.comparisonSelection! }, this.session.csrf_token, request.signal)
          : this.kind === 'profile'
          ? await this.client.call('get_profile_summary', { ...this.target, ...this.selection }, this.session.csrf_token, request.signal)
          : this.kind === 'syscalls'
            ? await this.readSyscalls(request.signal)
          : await this.client.call('get_file_excerpt', { ...this.target, line_start: 1, max_lines: 14 }, this.session.csrf_token, request.signal);
      if (generation !== this.generation || scope.aborted || request.signal.aborted) return;
      if (this.kind === 'packet') { this.acceptPacket(response, poll, started, generation, scope); return; }
      if (this.kind === 'comparison') { this.acceptComparison(response, poll, started, generation, scope); return; }
      if (this.kind === 'profile') { this.acceptProfile(response, poll, started, generation, scope); return; }
      if (this.kind === 'syscalls') { this.acceptSyscalls(response, poll, started, generation, scope); return; }
      if (!validOutput_get_file_excerpt(response) && !validOutput_get_query_result(response)) throw new Error('Unexpected query');
      const valid = poll ? validOutput_get_query_result(response) : validOutput_get_file_excerpt(response);
      if (!valid || response.data_class !== 'metadata' || response.truncated || response.next_cursor !== null || response.status === 'error') throw new Error('Query unavailable');
      if (poll && response.data.query_handle !== this.handle) throw new Error('Query replaced');
      if (!this.acceptTiming(response.data as Timing, started)) return;
      if (response.status === 'pending') {
        this.acceptPending(response.data, generation, scope);
        return;
      }
      let excerpt: unknown = response;
      if (poll) {
        if (!('result' in response.data) || response.data.tool_name !== 'get_file_excerpt') throw new Error('Unexpected query');
        excerpt = response.data.result;
        if (!validOutput_get_file_excerpt(excerpt) || excerpt.request_id !== response.request_id || excerpt.status !== 'ok' ||
          excerpt.data.query_observed_at !== response.data.query_observed_at || excerpt.data.query_expires_at !== response.data.query_expires_at) throw new Error('Query association changed');
      }
      if (!validOutput_get_file_excerpt(excerpt) || excerpt.status !== 'ok' || excerpt.data_class !== 'metadata' || excerpt.truncated || excerpt.next_cursor !== null ||
        excerpt.data.logical_path !== 'pod-status.txt' || excerpt.data.line_start !== 1 || excerpt.data.lines.length !== 14) throw new Error('Unexpected projection');
      this.publish({ phase: 'result', excerpt: { ...excerpt.data, lines: [...excerpt.data.lines] } });
    } catch {
      if (generation === this.generation && !scope.aborted) this.clear('unavailable');
    } finally {
      scope.removeEventListener('abort', abort);
      if (this.active === request) this.active = undefined;
    }
  }
  private acceptPending(data: { query_handle: string; retry_after_seconds: number }, generation: number, scope: AbortSignal) {
    if (this.handle && data.query_handle !== this.handle) throw new Error('Query replaced');
    this.handle = data.query_handle;
    const retryAt = this.now() + data.retry_after_seconds * 1000;
    this.publish({ phase: 'pending', retryAt, canCheck: false });
    if (retryAt < this.cutoff) this.pollTimer = setTimeout(() => {
      if (generation === this.generation && this.state.phase === 'pending' && !scope.aborted && this.now() < this.cutoff) this.publish({ phase: 'pending', retryAt, canCheck: true });
    }, Math.max(0, retryAt - this.now()));
  }
  private acceptPacket(response: unknown, poll: boolean, started: number, generation: number, scope: AbortSignal) {
    if (!validOutput_get_pcap_summary(response) && !validOutput_get_query_result(response)) throw new Error('Invalid packet summary');
    if (!(poll ? validOutput_get_query_result(response) : validOutput_get_pcap_summary(response)) || response.truncated || response.next_cursor !== null || response.status === 'error') throw new Error('Packet summary unavailable');
    if (poll && (!('query_handle' in response.data) || response.data.query_handle !== this.handle || response.provenance.length !== 0)) throw new Error('Query replaced');
    if (!this.acceptTiming(response.data, started)) return;
    if (response.status === 'pending') {
      if (response.data_class !== 'metadata' || response.provenance.length !== 0) throw new Error('Unexpected pending packet summary');
      this.acceptPending(response.data, generation, scope); return;
    }
    if (response.data_class !== 'extract') throw new Error('Unexpected packet summary class');
    let summary: unknown = response;
    if (poll) {
      if (!('result' in response.data) || response.data.tool_name !== 'get_pcap_summary') throw new Error('Unexpected packet summary tool');
      summary = response.data.result;
    }
    if (!validOutput_get_pcap_summary(summary) || summary.status !== 'ok' || summary.data_class !== 'extract' || summary.truncated || summary.next_cursor !== null || summary.request_id !== response.request_id || summary.data.query_observed_at !== response.data.query_observed_at || summary.data.query_expires_at !== response.data.query_expires_at || summary.provenance.length !== 1 || summary.provenance[0].artifactID !== this.target?.artifact_id || summary.provenance[0].digest !== this.version) throw new Error('Packet summary association changed');
    const data = summary.data;
    if (data.capture_mode !== 'networkHeaders' || !Number.isSafeInteger(data.packets) || !Number.isSafeInteger(data.conversations_total) || data.conversations_total > data.packets || data.conversations.length !== Math.min(data.conversations_total, 100) || data.conversations_truncated !== (data.conversations_total > data.conversations.length) || (data.drops === null) !== (data.drop_reporting === 'unavailable') || data.drops !== null && !Number.isSafeInteger(data.drops)) throw new Error('Inconsistent packet counters');
    let count = 0;
    const seen = new Set<string>();
    for (let i = 0; i < data.conversations.length; i++) {
      const row = data.conversations[i];
      const key = JSON.stringify([row.protocol, row.source, row.destination]);
      if (!Number.isSafeInteger(row.packets) || row.packets > data.packets || !packetEndpoint(row.source, row.protocol) || !packetEndpoint(row.destination, row.protocol) || seen.has(key)) throw new Error('Invalid packet endpoints');
      seen.add(key); count += row.packets;
      if (i > 0) {
        const previous = data.conversations[i - 1];
        if (previous.packets < row.packets || previous.packets === row.packets && (previous.protocol > row.protocol || previous.protocol === row.protocol && (previous.source > row.source || previous.source === row.source && previous.destination >= row.destination))) throw new Error('Packet ranking changed');
      }
    }
    if (count > data.packets || !data.conversations_truncated && count !== data.packets) throw new Error('Packet total changed');
    this.publish({ phase: 'result', packetSummary: { ...data, conversations: data.conversations.map(row => ({ ...row })) }, warnings: [...summary.warnings] });
  }

  private acceptProfile(response: unknown, poll: boolean, started: number, generation: number, scope: AbortSignal) {
    if (!validOutput_get_profile_summary(response) && !validOutput_get_query_result(response)) throw new Error('Invalid summary');
    if (!(poll ? validOutput_get_query_result(response) : validOutput_get_profile_summary(response)) || response.truncated || response.next_cursor !== null || response.status === 'error') throw new Error('Summary unavailable');
    if (poll && (!('query_handle' in response.data) || response.data.query_handle !== this.handle)) throw new Error('Query replaced');
    if (!this.acceptTiming(response.data, started)) return;
    if (response.status === 'pending') {
      if (response.data_class !== 'metadata') throw new Error('Unexpected pending summary');
      this.acceptPending(response.data, generation, scope); return;
    }
    if (response.data_class !== 'extract') throw new Error('Unexpected summary class');
    let summary: unknown = response;
    if (poll) {
      if (!('result' in response.data) || response.data.tool_name !== 'get_profile_summary') throw new Error('Unexpected summary tool');
      summary = response.data.result;
    }
    if (!validOutput_get_profile_summary(summary) || summary.status !== 'ok' || summary.data_class !== 'extract' || summary.truncated || summary.next_cursor !== null || summary.request_id !== response.request_id || summary.data.query_observed_at !== response.data.query_observed_at || summary.data.query_expires_at !== response.data.query_expires_at || summary.provenance.length !== 1 || summary.provenance[0].artifactID !== this.target?.artifact_id || summary.provenance[0].digest !== this.version || summary.data.sample_type !== this.selection.sample_type || summary.data.top.length > this.selection.top_n) throw new Error('Summary association changed');
    if (!Number.isSafeInteger(summary.data.total) || summary.data.top.some(row => !Number.isSafeInteger(row.flat) || !Number.isSafeInteger(row.cumulative))) throw new Error('Inexact summary');
    this.publish({ phase: 'result', summary: { ...summary.data, top: summary.data.top.map(row => ({ ...row })) }, warnings: [...summary.warnings] });
  }

  private acceptComparison(response: unknown, poll: boolean, started: number, generation: number, scope: AbortSignal) {
    if (!validOutput_compare_profiles(response) && !validOutput_get_query_result(response)) throw new Error('Invalid comparison');
    if (!(poll ? validOutput_get_query_result(response) : validOutput_compare_profiles(response)) || response.truncated || response.next_cursor !== null) throw new Error('Comparison unavailable');
    if (response.status === 'error') {
      if (response.data_class === 'metadata' && response.data.code === 'IncompatibleProfiles' && response.provenance.length === 0) {
        this.clear('incompatible'); return;
      }
      throw new Error('Comparison unavailable');
    }
    if (poll && (!('query_handle' in response.data) || response.data.query_handle !== this.handle)) throw new Error('Query replaced');
    if (!this.acceptTiming(response.data, started)) return;
    if (response.status === 'pending') {
      if (response.data_class !== 'metadata' || response.provenance.length !== 0) throw new Error('Unexpected pending comparison');
      this.acceptPending(response.data, generation, scope); return;
    }
    if (response.data_class !== 'extract') throw new Error('Unexpected comparison class');
    let result: unknown = response;
    if (poll) {
      if (!('result' in response.data) || response.data.tool_name !== 'compare_profiles') throw new Error('Unexpected comparison tool');
      result = response.data.result;
    }
    if (!validOutput_compare_profiles(result) || result.status !== 'ok' || result.data_class !== 'extract' || result.truncated || result.next_cursor !== null || result.request_id !== response.request_id || result.data.query_observed_at !== response.data.query_observed_at || result.data.query_expires_at !== response.data.query_expires_at) throw new Error('Comparison association changed');
    const data = result.data;
    const baseline = this.baseline!, incident = this.target!, selection = this.comparisonSelection!;
    if (data.case_id !== incident.case_id || data.artifact_id !== incident.artifact_id || data.source_version !== this.version || data.baseline_case_id !== baseline.caseID || data.baseline_artifact_id !== baseline.artifactID || data.baseline_source_version !== baseline.version || data.sample_type !== selection.sample_type || data.normalization !== selection.normalization || data.rows.length > selection.top_n) throw new Error('Comparison sources or selection changed');
    const expected = new Set([incident.artifact_id + ':' + this.version, baseline.artifactID + ':' + baseline.version]);
    const matches = (refs: { artifactID: string; digest: string }[]) => refs.length === expected.size && refs.every(ref => expected.has(ref.artifactID + ':' + ref.digest));
    if (!matches(result.provenance) || poll && response.provenance.length > 0 && !matches(response.provenance)) throw new Error('Comparison provenance changed');
    if (![data.baseline.total, data.incident.total, data.baseline.period?.value ?? 0, data.incident.period?.value ?? 0].every(Number.isSafeInteger) || data.rows.some(row => ![row.baseline, row.incident, row.delta].every(value => Number.isFinite(value) && Math.abs(value) <= Number.MAX_SAFE_INTEGER) || selection.normalization === 'none' && (![row.baseline, row.incident, row.delta].every(Number.isSafeInteger) || row.delta !== row.incident - row.baseline))) throw new Error('Inexact comparison');
    this.publish({ phase: 'result', comparison: structuredClone(data), warnings: [...result.warnings] });
  }

  private readSyscalls(signal: AbortSignal) {
    const selection = this.syscallSelection!;
    const input = { ...this.target!, limit: selection.limit, ...(this.syscallCursor ? { cursor: this.syscallCursor } : {}) };
    return selection.view === 'summary'
      ? this.client.call('get_syscall_summary', input, this.session!.csrf_token, signal)
      : this.client.call('get_syscall_events', { ...input, errors_only: selection.errorsOnly, ...(selection.names.length ? { syscall_names: [...selection.names] } : {}) }, this.session!.csrf_token, signal);
  }
  private acceptSyscalls(response: unknown, poll: boolean, started: number, generation: number, scope: AbortSignal) {
    const view = this.syscallSelection!.view;
    const validTool = view === 'summary' ? validOutput_get_syscall_summary : validOutput_get_syscall_events;
    if (!validTool(response) && !validOutput_get_query_result(response)) throw new Error('Invalid syscall view');
    if (!(poll ? validOutput_get_query_result(response) : validTool(response)) || response.status === 'error' || response.truncated) throw new Error('Syscall view unavailable');
    if (poll && (!('query_handle' in response.data) || response.data.query_handle !== this.handle || response.next_cursor !== null)) throw new Error('Query replaced');
    if (typeof response.data.query_observed_at !== 'string' || typeof response.data.query_expires_at !== 'string') throw new Error('Missing query lifetime');
    if (!this.acceptTiming({ query_observed_at: response.data.query_observed_at, query_expires_at: response.data.query_expires_at }, started)) return;
    if (response.status === 'pending') {
      if (response.data_class !== 'metadata' || response.next_cursor !== null) throw new Error('Unexpected pending view');
      this.acceptPending(response.data, generation, scope); return;
    }
    if (response.data_class !== 'extract') throw new Error('Unexpected syscall class');
    let result: unknown = response;
    if (poll) {
      if (!('result' in response.data) || response.data.tool_name !== (view === 'summary' ? 'get_syscall_summary' : 'get_syscall_events')) throw new Error('Unexpected syscall tool');
      result = response.data.result;
    }
    if (!validTool(result) || result.status !== 'ok' || result.data_class !== 'extract' || result.truncated || result.request_id !== response.request_id || result.data.query_observed_at !== response.data.query_observed_at || result.data.query_expires_at !== response.data.query_expires_at || result.provenance.length !== 1 || result.provenance[0].artifactID !== this.target?.artifact_id || result.provenance[0].digest !== this.version) throw new Error('Syscall association changed');
    const coverage = result.data.coverage;
    const recorded = coverage.record_count;
    if (!Number.isSafeInteger(recorded) || !Number.isSafeInteger(coverage.unfinished_events) || !Number.isSafeInteger(coverage.unknown_events) || !Number.isSafeInteger(coverage.unmatched_events) || coverage.unmatched_events + coverage.unfinished_events! + coverage.unknown_events! > recorded! || coverage.dropped_events !== null || coverage.truncated !== null) throw new Error('Invalid recorded counts');
    const next = result.next_cursor;
    if (next !== null && (!/^[1-9][0-9]*:[0-9a-f]{32}$/.test(next) || next === this.syscallCursor)) throw new Error('Invalid continuation');
    const common = { phase: 'result' as const, nextCursor: next ?? undefined, warnings: [...result.warnings] };
    if (result.data.kind === 'syscallSummary') {
      const rows = result.data.rows;
      if (rows.length > this.syscallSelection!.limit || rows.reduce((count, row) => count + row.count, 0) > recorded! || rows.some((row, i) => !Number.isSafeInteger(row.count) || row.count < 1 || row.count > recorded! || !Number.isSafeInteger(row.errors) || row.errors > row.count || !Number.isSafeInteger(row.paired_count) || row.paired_count > row.count || !Number.isSafeInteger(row.total_duration_ns) || row.paired_count === 0 && row.total_duration_ns !== 0 || i > 0 && compareSyscallNames(rows[i - 1].syscall, row.syscall) >= 0)) throw new Error('Invalid summary rows');
      this.publish({ ...common, syscallSummary: { ...result.data, rows: rows.map(row => ({ ...row })), coverage: { ...coverage, gaps: [...coverage.gaps] } } });
    } else {
      const events = result.data.events;
      if (events.length > this.syscallSelection!.limit || events.some(event => event.duration_ns !== undefined && !Number.isSafeInteger(event.duration_ns) || this.syscallSelection!.errorsOnly && event.outcome !== 'error' || this.syscallSelection!.names.length > 0 && !this.syscallSelection!.names.includes(event.syscall))) throw new Error('Event display selection changed');
      this.publish({ ...common, syscallEvents: { ...result.data, events: events.map(event => ({ ...event, identity: { ...event.identity } })), coverage: { ...coverage, gaps: [...coverage.gaps] } } });
    }
  }

}

// Numeric canonical addresses only; URL's built-in IPv6 parser performs no I/O.
function packetIP(value: string, v6: boolean) {
  if (!v6) return /^(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}$/.test(value) && value.split('.').every(part => Number(part) <= 255);
  if (!/^[0-9a-f:]+$/.test(value) || !value.includes(':')) return false;
  try { return new URL('http://[' + value + ']/').hostname === '[' + value + ']'; } catch { return false; }
}
function packetEndpoint(value: string, protocol: string) {
  if (protocol === 'ICMPv4' || protocol === 'ICMPv6') return packetIP(value, protocol === 'ICMPv6');
  const match = /^(\[[0-9a-f:]+\]|[0-9.]+):(0|[1-9][0-9]{0,4})$/.exec(value);
  if (!match || Number(match[2]) > 65535) return false;
  const ipv6 = match[1].startsWith('[');
  return packetIP(ipv6 ? match[1].slice(1, -1) : match[1], ipv6);
}
