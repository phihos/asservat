import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { ProcessingReport } from './ProcessingReport';
import { OperationFailure } from '../capture/http';
import { session } from '../live/test-fixtures';
import { validOutput_get_processing_report, validProcessingReportExport } from '../generated/validate-processing-report';
import type { ProcessingReportClient, ProcessingReportExport, ProcessingReportQuery, ProcessingReportResponse } from './report-http';

const id = (n: number) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const selection = '2026-11-01T00:00:00Z', digest = 'a'.repeat(64);
const sections = ['artifacts', 'shares', 'downloads', 'operations', 'rules', 'paths', 'processors'] as const;
const artifactRecord = (artifactID: string) => ({ visible_until: '2026-12-01T00:00:00Z', artifact: {
  artifact_id: artifactID, capture_id: id(5), case_id: id(6), cluster_id: id(8), attempt_id: id(9), namespace_uid: 'namespace', workload_uid: 'workload',
  store_id: id(7), purpose_ref: 'diagnostics', native_type: 'podStatus', data_class: 'metadata', privacy_class: 'potentialPersonalData', origin: 'capture', parents: [],
  anchor_at: selection, original_expires_at: '2026-12-01T00:00:00Z', original_delete_by: '2026-12-02T00:00:00Z', expires_at: '2026-12-01T00:00:00Z', delete_by: '2026-12-02T00:00:00Z',
  custody_state: 'stored_unpublished', deletion_state: 'retained',
} });
const bound = <S extends typeof sections[number],>(section: S) => ({ section, limit: 3, created_before: selection, policy_digest: digest });
function page(query: ProcessingReportQuery, next?: ProcessingReportQuery): ProcessingReportResponse {
  const now = Date.now();
  return { schema_version: 'mcp-result/v1', request_id: id(1), status: 'ok', data_class: 'metadata',
    truncated: false, next_cursor: null, narrowing_hint: null, warnings: [], provenance: [], data: {
      schema_version: 'processing-report/v1', root_id: id(2), installation_id: id(3), section: query.section ?? 'artifacts',
      selection_created_before: selection, policy_revision: { uid: id(4), generation: 1, digest }, records: next?.section === 'artifacts' && next.after ? [artifactRecord(next.after.id)] : [],
      observed_at: new Date(now-10).toISOString(), valid_until: new Date(now+4990).toISOString(),
      processor_declarations: 'unsupplied', coverage: ['retained metadata observations', 'unknown client receipt', 'legal exceptions disabled', 'recorded lineage'],
      ...(next ? { next } : {}),
    } } as ProcessingReportResponse;
}
const nextSection = (query: ProcessingReportQuery) => {
  const next = sections[sections.indexOf(query.section ?? 'artifacts')+1];
  return page(query, next ? bound(next) : undefined);
};
const deferred = <T,>() => { let resolve!: (value: T) => void; const promise = new Promise<T>(done => { resolve = done; }); return { promise, resolve }; };
let files: Blob[], names: string[];
beforeEach(() => {
  files = []; names = [];
  vi.stubGlobal('URL', Object.assign(class extends URL {}, {
    createObjectURL: vi.fn((blob: Blob) => { files.push(blob); return 'blob:synthetic-report'; }), revokeObjectURL: vi.fn(),
  }));
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) { names.push(this.download); });
});
afterEach(async () => {
  cleanup();
  if (files.length) await waitFor(() => expect(URL.revokeObjectURL).toHaveBeenCalledTimes(files.length));
  vi.unstubAllGlobals();
});
const readFile = (index = 0): Promise<ProcessingReportExport> => new Promise((resolve, reject) => {
  const reader = new FileReader(); reader.onload = () => resolve(JSON.parse(reader.result as string)); reader.onerror = reject; reader.readAsText(files[index]);
});
const clickExport = () => fireEvent.click(screen.getByRole('button', { name: 'Export inventory report' }));

it('exports every sequential section only after a click, with full validated envelopes and no automatic restart', async () => {
  const read = vi.fn<ProcessingReportClient['read']>(async query => nextSection(query));
  render(<ProcessingReport session={session} scope={new AbortController().signal} disabled={false} client={{ read }}/>);
  expect(read).not.toHaveBeenCalled(); clickExport(); await screen.findByText('Inventory export complete.');
  expect(read.mock.calls.map(([query]) => query)).toEqual([{ section: 'artifacts', limit: 3 }, ...sections.slice(1).map(bound)]);
  expect(files).toHaveLength(1); expect(names[0]).toMatch(/^asservat-processing-inventory-.*-part-1\.json$/);
  const result = await readFile(); expect(validProcessingReportExport(result)).toBe(true);
  expect(result).toMatchObject({ format: 'asservat-processing-inventory/v1', part: 1, selection_created_before: selection,
    policy_revision: { uid: id(4), generation: 1, digest }, complete: true });
  expect(result.pages.map(reply => reply.status === 'ok' && reply.data.section)).toEqual(sections);
  expect(result).not.toHaveProperty('next'); expect(screen.queryByRole('button', { name: 'Export next report part' })).toBeNull();
  expect(files[0].type).toBe('application/json'); expect(read).toHaveBeenCalledTimes(7);
});

it('caps each part at 32 pages and resumes only on click using the exact exported cursor and selection', async () => {
  let count = 0;
  const read = vi.fn<ProcessingReportClient['read']>(async query => {
    if (++count <= 32) return page(query, { ...bound('artifacts'), after: { id: id(count+10), cluster_id: id(8), attempt_id: id(9) } });
    return nextSection(query);
  });
  render(<ProcessingReport session={session} scope={new AbortController().signal} disabled={false} client={{ read }}/>);
  clickExport(); await screen.findByText('Report part exported. More report pages remain.');
  expect(read).toHaveBeenCalledTimes(32); expect(files).toHaveLength(1);
  const first = await readFile(); expect(validProcessingReportExport(first)).toBe(true);
  expect(first.pages).toHaveLength(32); expect(first.complete).toBe(false);
  expect(first.next).toEqual({ ...bound('artifacts'), after: { id: id(42), cluster_id: id(8), attempt_id: id(9) } });
  fireEvent.click(screen.getByRole('button', { name: 'Export next report part' })); await screen.findByText('Inventory export complete.');
  expect(read.mock.calls[32][0]).toEqual(first.next); expect(files).toHaveLength(2);
  const last = await readFile(1); expect(validProcessingReportExport(last)).toBe(true);
  expect(last).toMatchObject({ part: 2, complete: true, selection_created_before: first.selection_created_before, policy_revision: first.policy_revision });
  expect(last.pages.map(reply => reply.status === 'ok' && reply.data.section)).toEqual(sections);
  expect(last).not.toHaveProperty('next'); expect(names[1]).toMatch(/-part-2\.json$/);
});

it('uses refreshed same-human CSRF for subsequent pages without changing the selection', async () => {
  const first = deferred<ProcessingReportResponse>(), scope = new AbortController();
  const read = vi.fn<ProcessingReportClient['read']>().mockImplementationOnce(() => first.promise).mockImplementation(async query => nextSection(query));
  const view = render(<ProcessingReport session={session} scope={scope.signal} disabled={false} client={{ read }}/>);
  clickExport();
  view.rerender(<ProcessingReport session={{ ...session, csrf_token: 'D'.repeat(43) }} scope={scope.signal} disabled={false} client={{ read }}/>);
  await act(async () => first.resolve(nextSection({ section: 'artifacts', limit: 3 }))); await screen.findByText('Inventory export complete.');
  expect(read.mock.calls[0][1]).toBe(session.csrf_token); expect(read.mock.calls.slice(1).every(([, csrf]) => csrf === 'D'.repeat(43))).toBe(true);
  expect(read.mock.calls[1][0]).toEqual(bound('shares'));
});

it('discards a partially collected part on identity loss and ignores late replies after a new scope starts', async () => {
  const oldScope = new AbortController(), newScope = new AbortController(), pending = deferred<ProcessingReportResponse>();
  const read = vi.fn<ProcessingReportClient['read']>().mockImplementationOnce(async query => nextSection(query)).mockImplementationOnce(() => pending.promise).mockImplementation(async query => nextSection(query));
  const view = render(<ProcessingReport session={session} scope={oldScope.signal} disabled={false} client={{ read }}/>);
  clickExport(); await waitFor(() => expect(read).toHaveBeenCalledTimes(2));
  const interrupted = read.mock.calls[1][2]; act(() => oldScope.abort()); expect(interrupted.aborted).toBe(true);
  expect(screen.queryByRole('status')).toBeNull(); expect(files).toHaveLength(0);
  view.rerender(<ProcessingReport session={{ ...session, principal: { ...session.principal, subject_id: 'another-operator' } }} scope={newScope.signal} disabled={false} client={{ read }}/>);
  await act(async () => pending.resolve(nextSection(bound('shares'))));
  expect(files).toHaveLength(0); expect(screen.queryByRole('button', { name: 'Export next report part' })).toBeNull();
  clickExport(); await screen.findByText('Inventory export complete.');
  expect(read.mock.calls[2][0]).toEqual({ section: 'artifacts', limit: 3 }); expect(files).toHaveLength(1);
});

it.each(['root', 'installation', 'policy-uid', 'policy-generation', 'policy-digest', 'selection', 'refusal', 'network', 'cycle', 'malformed'])('never creates a partial file when a later page fails: %s', async mode => {
  const read = vi.fn<ProcessingReportClient['read']>().mockImplementationOnce(async query => nextSection(query)).mockImplementation(async query => {
    if (mode === 'network') throw new OperationFailure(503);
    const value = nextSection(query);
    if (mode === 'root') value.data.root_id = id(99);
    if (mode === 'installation') value.data.installation_id = id(99);
    if (mode === 'policy-uid') value.data.policy_revision.uid = id(99);
    if (mode === 'policy-generation') value.data.policy_revision.generation++;
    if (mode === 'policy-digest') value.data.policy_revision.digest = 'b'.repeat(64);
    if (mode === 'selection') value.data.selection_created_before = '2026-11-02T00:00:00Z';
    if (mode === 'cycle') value.data.next = query;
    if (mode === 'malformed') Object.assign(value.data, { credential: 'untrusted' });
    if (mode === 'refusal') return { ...value, status: 'error', data: { code: 'unavailable', message: 'unavailable', retryable: true } };
    return value;
  });
  render(<ProcessingReport session={session} scope={new AbortController().signal} disabled={false} client={{ read }}/>);
  clickExport(); await screen.findByRole('alert');
  expect(files).toHaveLength(0); expect(screen.queryByRole('status')).toBeNull(); expect(read).toHaveBeenCalledTimes(mode === 'malformed' ? 7 : 2);
});


it('refuses a part exceeding 1 MiB even when its 32 individual pages validate and fit the HTTP limit', async () => {
  let count = 0;
  const read = vi.fn<ProcessingReportClient['read']>(async query => {
    const value = page(query, { ...bound('artifacts'), after: { id: id(++count+10), cluster_id: id(8), attempt_id: id(9) } });
    value.warnings = Array.from({ length: 32 }, (_, index) => `warning-${index}:`+'x'.repeat(1012));
    // Fill the real serialized page boundary using valid, distinct warning text.
    let surplus = new TextEncoder().encode(JSON.stringify(value)).byteLength-32_768;
    for (let index = value.warnings.length-1; surplus > 0; index--) {
      const trim = Math.min(surplus, value.warnings[index].length-16);
      value.warnings[index] = value.warnings[index].slice(0, -trim); surplus -= trim;
    }
    expect(new TextEncoder().encode(JSON.stringify(value)).byteLength).toBe(32_768);
    expect(validOutput_get_processing_report(value)).toBe(true);
    return value;
  });
  render(<ProcessingReport session={session} scope={new AbortController().signal} disabled={false} client={{ read }}/>);
  clickExport(); await screen.findByRole('alert');
  expect(read).toHaveBeenCalledTimes(32); expect(files).toHaveLength(0);
  expect(screen.queryByRole('button', { name: 'Export next report part' })).toBeNull();
});

it('blocks disabled or already-aborted scopes without an operation', () => {
  const read = vi.fn(), scope = new AbortController();
  const view = render(<ProcessingReport session={session} scope={scope.signal} disabled client={{ read }}/>);
  clickExport(); expect(read).not.toHaveBeenCalled();
  act(() => scope.abort());
  view.rerender(<ProcessingReport session={session} scope={scope.signal} disabled={false} client={{ read }}/>);
  clickExport(); expect(read).not.toHaveBeenCalled(); expect(files).toHaveLength(0);
});

it.each(['root', 'installation', 'policy-uid', 'policy-generation', 'policy-digest', 'selection'])('keeps the first part scope when a later part changes %s', async mode => {
  let count = 0;
  const read = vi.fn<ProcessingReportClient['read']>(async query => {
    if (++count <= 32) return page(query, { ...bound('artifacts'), after: { id: id(count+10), cluster_id: id(8), attempt_id: id(9) } });
    const value = nextSection(query);
    // Every page in part two agrees with its own first page. The boundary must
    // still compare it with the already exported first part's exact scope.
    if (mode === 'root') value.data.root_id = id(99);
    if (mode === 'installation') value.data.installation_id = id(99);
    if (mode === 'policy-uid') value.data.policy_revision.uid = id(99);
    if (mode === 'policy-generation') value.data.policy_revision.generation++;
    if (mode === 'policy-digest') value.data.policy_revision.digest = 'b'.repeat(64);
    if (mode === 'selection') value.data.selection_created_before = '2026-11-02T00:00:00Z';
    return value;
  });
  render(<ProcessingReport session={session} scope={new AbortController().signal} disabled={false} client={{ read }}/>);
  clickExport(); await screen.findByText('Report part exported. More report pages remain.');
  expect(files).toHaveLength(1);
  fireEvent.click(screen.getByRole('button', { name: 'Export next report part' })); await screen.findByRole('alert');
  expect(files).toHaveLength(1); expect(read).toHaveBeenCalledTimes(33);
  expect(screen.queryByText('Inventory export complete.')).toBeNull();
});
