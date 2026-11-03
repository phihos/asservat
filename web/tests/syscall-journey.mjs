// Explicitly synthetic case/query wires in the owned real Go HTTPS/built-UI
// harness. This is render/CSP/filter/paging/a11y evidence, not SQL, key, native
// source verification, collection, installed runtime or disclosure authority.
import { expect } from '@playwright/test';
import assert from 'node:assert/strict';

export async function syscallJourney({ page, origin, output, scan, checks, wire }) {
  const sourceCase = structuredClone(wire);
  const artifact = sourceCase.data.artifacts[0];
  artifact.kind = 'syscallTrace'; artifact.data_class = 'raw'; artifact.native_format = 'asservat-syscall-arguments/v1';
  const caseID = sourceCase.data.case.case_id;
  const caseRoute = origin + '/api/v1/operations/get_case';
  const summaryRoute = origin + '/api/v1/operations/get_syscall_summary';
  const eventsRoute = origin + '/api/v1/operations/get_syscall_events';
  const pollRoute = origin + '/api/v1/operations/get_query_result';
  const handle = 'synthetic-saved-syscall-query';
  const summaryCursor = '1:' + 'a'.repeat(32), eventCursor = '1:' + 'b'.repeat(32);
  const calls = [], unrelated = [];
  const requestListener = request => {
    const path = new URL(request.url()).pathname;
    if (/\/api\/v1\/operations\/(?:request_raw_access|prepare_artifact_download|request_capture|preview_capture|syscall_query)$/.test(path) || /\/api\/v1\/downloads\//.test(path)) unrelated.push(path);
  };
  const times = () => { const now = Date.now(); return { query_observed_at: new Date(now).toISOString(), query_expires_at: new Date(now + 10000).toISOString() }; };
  const envelope = (data, timing, nextCursor = null) => ({ schema_version: 'mcp-result/v1', request_id: '00000000-0000-4000-8000-000000000092', data_class: 'extract', status: 'ok', data: { ...data, ...timing }, next_cursor: nextCursor, truncated: false, narrowing_hint: null, warnings: [], provenance: [{ artifactID: artifact.artifact_id, digest: artifact.digest }] });
  const coverage = () => ({ record_count: 4, unmatched_events: 1, unfinished_events: 1, unknown_events: 0, dropped_events: null, truncated: null, gaps: ['Acquisition coverage is unknown.'] });
  const summary = (name, timing, cursor = null) => envelope({ kind: 'syscallSummary', rows: [{ syscall: name, count: 2, errors: name === 'write' ? 1 : 0, paired_count: name === 'write' ? 2 : 0, total_duration_ns: name === 'write' ? 5 : 0 }], coverage: coverage() }, timing, cursor);
  const record = thread => ({ identity: { process_ref: '<img src=x onerror=alert(1)>', thread_ref: thread, pod_uid: 'synthetic-pod' }, syscall: 'write', abi: 'x86_64', timestamp: new Date().toISOString(), outcome: 'error', errno: 'ENOENT', duration_ns: 5 });
  let summaryCalls = 0, pendingTiming;
  const checkRequest = route => {
    const request = route.request(), input = request.postDataJSON();
    assert.equal(request.method(), 'POST'); assert(request.headers()['x-csrf-token']);
    assert.equal(request.headers()['idempotency-key'], undefined);
    calls.push({ name: new URL(request.url()).pathname.split('/').at(-1), input });
    return input;
  };
  await page.route(caseRoute, route => route.fulfill({ json: sourceCase }));
  await page.route(summaryRoute, route => {
    const input = checkRequest(route);
    const timing = times();
    assert.deepEqual(input, { case_id: caseID, artifact_id: artifact.artifact_id, limit: 100, ...(summaryCalls === 1 ? { cursor: summaryCursor } : {}) });
    if (summaryCalls++ === 0) {
      pendingTiming = timing;
      return route.fulfill({ json: { ...envelope({}, timing), status: 'pending', data_class: 'metadata', provenance: [], data: { query_handle: handle, retry_after_seconds: 1, ...timing } } });
    }
    return route.fulfill({ json: summary('write', timing) });
  });
  await page.route(pollRoute, route => {
    assert.deepEqual(checkRequest(route), { query_handle: handle });
    const timing = { query_observed_at: new Date().toISOString(), query_expires_at: pendingTiming.query_expires_at }, inner = summary('read', timing, summaryCursor);
    return route.fulfill({ json: { ...inner, next_cursor: null, provenance: [], data: { query_handle: handle, tool_name: 'get_syscall_summary', result: inner, ...timing } } });
  });
  await page.route(eventsRoute, route => {
    const input = checkRequest(route), next = input.cursor === eventCursor;
    assert.deepEqual(input, { case_id: caseID, artifact_id: artifact.artifact_id, limit: 2, errors_only: true, syscall_names: ['write'], ...(next ? { cursor: eventCursor } : {}) });
    return route.fulfill({ json: envelope({ kind: 'syscallEvents', events: [record(next ? 'thread-second' : 'thread-first')], coverage: coverage() }, times(), next ? null : eventCursor) });
  });
  page.on('request', requestListener);
  try {
    await page.reload();
    const view = page.getByRole('region', { name: 'Saved syscall views', exact: true });
    await expect(view).toBeVisible(); assert.deepEqual(calls, []);
    await expect(view.getByRole('combobox')).toHaveCount(1);
    assert.deepEqual(await view.locator('option').evaluateAll(options => options.map(option => option.value)), ['summary', 'events']);
    await expect(view.getByLabel(/arguments|buffers|paths|pointers/i)).toHaveCount(0);
    await view.getByRole('button', { name: 'Inspect saved syscalls', exact: true }).click();
    await expect(view.getByRole('button', { name: 'Check result', exact: true })).toBeDisabled();
    await expect(view.getByRole('button', { name: 'Check result', exact: true })).toBeEnabled();
    assert.equal(calls.length, 1, 'pending must not poll automatically');
    await view.getByRole('button', { name: 'Check result', exact: true }).click();
    await expect(view.getByRole('table', { name: 'Syscall counts' })).toBeVisible();
    await expect(view.getByRole('cell', { name: 'read', exact: true })).toBeVisible();
    await expect(view.getByText(/Acquisition coverage, dropped events and truncation are unknown/)).toBeVisible();
    await view.getByRole('button', { name: 'Next page', exact: true }).click();
    await expect(view.getByRole('cell', { name: 'write', exact: true })).toBeVisible();
    await expect(view.getByRole('button', { name: 'Next page', exact: true })).toHaveCount(0);
    await view.getByRole('combobox', { name: 'Syscall view', exact: true }).selectOption('events');
    await expect(view.getByRole('table')).toHaveCount(0);
    await view.getByLabel('Rows per page', { exact: true }).fill('2');
    await view.getByLabel('Syscall names, separated by commas', { exact: true }).fill('write');
    await view.getByLabel('Errors only', { exact: true }).check();
    assert.equal(calls.length, 3, 'filter edits must not create queries');
    await view.getByRole('button', { name: 'Inspect saved syscalls', exact: true }).click();
    await expect(view.getByRole('table', { name: 'Recorded syscall events' })).toBeVisible();
    await expect(view.getByRole('cell', { name: /thread-first/ })).toBeVisible();
    await expect(view.locator('table img')).toHaveCount(0);
    await expect(view.getByRole('cell', { name: /<img src=x onerror=alert\(1\)>/ })).toBeVisible();
    await page.setViewportSize({ width: 320, height: 740 });
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
    await scan('saved-syscall-events-mobile');
    await page.screenshot({ path: output + '/saved-syscall-events-mobile.png', fullPage: true });
    await view.getByRole('button', { name: 'Next page', exact: true }).click();
    await expect(view.getByRole('cell', { name: /thread-second/ })).toBeVisible();
    await expect(view.getByRole('cell', { name: /thread-first/ })).toHaveCount(0);
    await view.getByRole('button', { name: 'Close view', exact: true }).click();
    await expect(view.getByRole('table')).toHaveCount(0);
    assert.equal(calls.length, 5); assert.deepEqual(unrelated, []);
    artifact.data_class = 'metadata'; artifact.native_format = 'asservat-syscall-events/v1';
    await page.reload();
    await expect(page.getByRole('button', { name: 'Inspect saved syscalls', exact: true })).toBeVisible();
    assert.equal(calls.length, 5, 'metadata source mount must remain passive');
    checks.push('synthetic saved syscall wires in built UI: raw/metadata actions under ordinary read, fixed extract only, original pending handle, exact filtered paging, full counts/unknown coverage, text-only identities, mobile/a11y/close and no acquisition/raw query/download');
  } finally {
    page.off('request', requestListener);
    await page.unroute(caseRoute); await page.unroute(summaryRoute); await page.unroute(eventsRoute); await page.unroute(pollRoute);
    await page.setViewportSize({ width: 1440, height: 1080 }); await page.reload();
    await expect(page.getByRole('heading', { name: 'Pod status', exact: true })).toBeVisible();
  }
}
