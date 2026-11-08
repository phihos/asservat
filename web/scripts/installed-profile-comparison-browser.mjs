// Installed image-owned React, original Keycloak-backed HttpOnly cookie.
// The Go owner schedules each existing paid poll; this driver only clicks UI.
import { chromium, expect } from '@playwright/test';
import assert from 'node:assert/strict';
import { createInterface } from 'node:readline';
import { readInstalledHistoryResponse, parseInstalledHistoryText } from './installed-history-response.mjs';
import { validOutput_get_case } from '../src/generated/validate-evidence.js';
import { checkInstalledProfileCaseRefreshes } from './installed-profile-case-proof.mjs';

const lines = createInterface({ input: process.stdin, crlfDelay: Infinity })[Symbol.asyncIterator]();
async function command() {
  const next = await lines.next();
  assert(!next.done && Buffer.byteLength(next.value) <= 16 * 1024, 'bounded private input');
  return JSON.parse(next.value);
}
function event(value) {
  const encoded = JSON.stringify(value);
  assert(Buffer.byteLength(encoded) < 64 * 1024, 'bounded operation event');
  process.stdout.write(encoded + '\n');
}
const config = await command();
const heap = config.mode === 'heap';
assert(config.restoreDuringNative === undefined || typeof config.restoreDuringNative === 'boolean' && (!config.restoreDuringNative || heap), 'closed local restoration selection');
assert(['comparison', 'heap'].includes(config.mode), 'fixed profile browser mode');
const origin = new URL(config.origin);
assert.equal(origin.protocol, 'https:');
assert.equal(new URL(config.proxy).hostname, '127.0.0.1');
assert.match(config.caseID, /^[0-9a-f-]{36}$/);
assert.match(config.artifactID, /^[0-9a-f-]{36}$/);
const browser = await chromium.launch({ headless: true, proxy: { server: config.proxy, bypass: '<-loopback>' }, ...(process.env.ASSERVAT_CHROMIUM ? { executablePath: process.env.ASSERVAT_CHROMIUM } : {}) });
const context = await browser.newContext({ ignoreHTTPSErrors: true, acceptDownloads: heap, locale: 'en-US', viewport: { width: 1440, height: 900 } });
let stage = 'session';
let complete = false;
let page;
let caseDiagnostic;
let attachmentDiagnostic;
const errors = [];
const timeline = [];
const started = Date.now();
try {
  await context.addCookies(config.cookies);
  config.cookies = [];
  // Same known Chromium workaround as installed history: observe only text the
  // real page consumed, without replacing any HTTP response or issuing fetches.
  await context.addInitScript(() => {
    const original = window.fetch.bind(window);
    const replies = new Map();
    Object.defineProperty(window, '__installedReplies', { value: replies });
    window.fetch = async (input, init) => {
      const response = await original(input, init);
      const path = new URL(typeof input === 'string' ? input : input.url, location.href).pathname;
      if ((path === '/auth/refresh' || /^\/api\/v1\/operations\/(get_case|compare_profiles|get_profile_summary|get_query_result|prepare_artifact_download|get_artifact_download)$/.test(path)) && response.status === 200) {
        const key = path + '\n' + (typeof init?.body === 'string' ? init.body : '');
        response.clone().text().then(text => { if (text.length <= 32_768) replies.set(key, text); }, () => {});
      }
      return response;
    };
  });
  page = await context.newPage();
  const seen = [];
  let compareRequests = 0;
  let pollRequests = 0;
  let caseRequests = 0;
  page.on('pageerror', () => errors.push('pageerror'));
  page.on('request', request => {
    const path = new URL(request.url()).pathname;
    if (path === '/api/v1/operations/' + (heap ? 'get_profile_summary' : 'compare_profiles')) compareRequests++;
    if (path === '/api/v1/operations/get_query_result') pollRequests++;
    if (path === '/api/v1/operations/get_case') caseRequests++;
    if (path.startsWith('/api/')) timeline.push(`+${Date.now() - started}ms request ${request.method()} ${path}`);
  });
  page.on('response', response => {
    seen.push(response);
    const path = new URL(response.url()).pathname;
    if (path.startsWith('/api/')) timeline.push(`+${Date.now() - started}ms response ${response.status()} ${path}`);
  });
  page.on('requestfailed', request => {
    const path = new URL(request.url()).pathname;
    if (path.startsWith('/api/')) timeline.push(`+${Date.now() - started}ms failed ${/^net::ERR_[A-Z_]+$/.exec(request.failure()?.errorText ?? '')?.[0] ?? 'other'} ${path}`);
  });
  const responseReads = new WeakMap();
  async function readResponse(response, path) {
    if (responseReads.has(response)) return responseReads.get(response);
    let read = await readInstalledHistoryResponse(response);
    let pageConsumed = false;
    if (read.requestFailed && read.readFailure.includes('ERR_ABORTED') && response.status() === 200) {
      const key = path + '\n' + (response.request().postData() ?? '');
      let text = null;
      for (const until = Date.now() + 2000; Date.now() < until;) {
        text = await page.evaluate(k => { const value = window.__installedReplies.get(k) ?? null; window.__installedReplies.delete(k); return value; }, key);
        if (text !== null) break;
        await page.waitForTimeout(100);
      }
      if (text === null) return { read, pageConsumed, superseded: true }; // No extra fetch or replay.
      read = parseInstalledHistoryText(200, text);
      pageConsumed = true;
    }
    const value = { read, pageConsumed };
    responseReads.set(response, value);
    return value;
  }
  async function observed(name, from) {
    const names = Array.isArray(name) ? name : [name];
    for (let index = from, end = Date.now() + 30_000; Date.now() < end;) {
      if (index >= seen.length) { await page.waitForTimeout(100); continue; }
      const response = seen[index++];
      const path = new URL(response.url()).pathname;
      const operationName = path.split('/').at(-1);
      if (!names.includes(operationName)) continue;
      const { read, pageConsumed, superseded } = await readResponse(response, path);
      if (superseded) continue; // Original observer skips a page-superseded reply.
      if (name === 'get_case') {
        const reply = read.reply;
        const artifacts = Array.isArray(reply?.data?.artifacts) ? reply.data.artifacts : [];
        const data = reply?.data;
        caseDiagnostic = {
          http: read.http, status: ['ok', 'error', 'pending'].includes(read.status) ? read.status : 'invalid',
          body: read.body, pageConsumed, schema: validOutput_get_case(reply),
          encodedBytes: reply ? Math.min(32_769, Buffer.byteLength(JSON.stringify(reply))) : 0,
          code: reply?.status === 'error' ? (reply.data?.code === 'NotAvailable' ? 'NotAvailable' : 'other') : 'none',
          caseMatch: data?.case?.case_id === config.caseID,
          access: ['ordinary', 'shared'].includes(data?.case?.access) ? data.case.access : 'other',
          artifactCount: Math.min(32, artifacts.length),
          selectedPresent: artifacts.some(a => a.artifact_id === config.artifactID),
          eligibleProfiles: Math.min(32, artifacts.filter(a => a.kind === 'profile' && a.native_format === 'pprof' && a.data_class === 'raw' && Date.parse(a.expires_at) > Date.now()).length),
          relational: artifacts.length > 0 && new Set(artifacts.map(a => a.artifact_id)).size === artifacts.length && artifacts.every(a => Date.parse(a.expires_at) === Date.parse(a.handling_notice?.expiresAt) && Date.parse(a.handling_notice?.deleteBy) > Date.parse(a.expires_at)),
        };
        process.stderr.write('installed comparison case ' + JSON.stringify(caseDiagnostic) + '\n');
      }
      assert.equal(read.http, 200, 'operation HTTP result');
      assert.equal(read.body, 'complete', 'operation body completion');
      const transport = {
        post: response.request().method() === 'POST',
        sameOrigin: await response.request().headerValue('origin') === config.origin,
        csrf: /^[A-Za-z0-9_-]{43}$/.test(await response.request().headerValue('x-csrf-token') ?? ''),
        noBearer: await response.request().headerValue('authorization') === null,
      };
      return { name: operationName, responseIndex: index, input: JSON.parse(response.request().postData()), reply: read.reply, transport };
    }
    throw new Error('operation response unavailable');
  }
  stage = 'case-navigation';
  const caseFrom = seen.length;
  await page.goto(config.origin + '/cases/' + config.caseID);
  stage = 'case-response';
  const caseResponse = await observed('get_case', caseFrom);
  assert(caseDiagnostic?.schema && caseDiagnostic.status === 'ok' && caseDiagnostic.caseMatch && caseDiagnostic.relational && caseDiagnostic.access === 'ordinary' && caseDiagnostic.selectedPresent && caseDiagnostic.eligibleProfiles === 1, 'current ordinary profile case');
  stage = 'case-heading';
  await expect(page.getByRole('heading', { name: 'Evidence', exact: true })).toBeVisible();
  stage = 'case-profile-timing';
  const timing = page.getByRole('table', { name: 'Profile collection timing', exact: true });
  await expect(timing).toBeVisible();
  const profiles = caseResponse.reply.data.artifacts.filter(artifact => artifact.kind === 'profile');
  await expect(timing.getByRole('row')).toHaveCount(profiles.length + 1);
  for (const artifact of profiles) {
    const row = timing.getByRole('rowheader', { name: artifact.artifact_id, exact: true }).locator('..');
    await expect(row).toHaveCount(1);
    const cells = row.getByRole('cell');
    await expect(cells).toHaveCount(3);
    const acquisition = artifact.profile_acquisition;
    if (acquisition) {
      await expect(cells.nth(0)).toContainText(`${acquisition.requested_type} · ${acquisition.mode}`);
      await expect(cells.nth(0)).toContainText(acquisition.requested_duration_ms === null ? 'No requested interval' : `Requested duration: ${acquisition.requested_duration_ms / 1000} s`);
      await expect(cells.nth(0)).toContainText(acquisition.force_gc ? 'Forced GC requested' : 'Forced GC not requested');
    } else {
      await expect(cells.nth(0)).toHaveText('Request parameters unavailable');
    }
    if (acquisition?.started_at !== null && acquisition?.started_at !== undefined) {
      const times = cells.nth(1).locator('time');
      await expect(times).toHaveCount(2);
      await expect(times).toHaveText([acquisition.started_at, acquisition.completed_at]);
      await expect(times.nth(0)).toHaveAttribute('datetime', acquisition.started_at);
      await expect(times.nth(1)).toHaveAttribute('datetime', acquisition.completed_at);
    } else {
      await expect(cells.nth(1)).toHaveText('Unknown');
      await expect(cells.nth(1).locator('time')).toHaveCount(0);
    }
    await expect(cells.nth(2)).toHaveText(artifact.target?.pod_uid ?? 'Unknown');
  }
  await expect(page.getByText('Go endpoint profiles are collected on trigger and do not provide a pre-trigger recording. Requested duration describes the request. HTTP acquisition does not establish the precise sample interval or cumulative history.', { exact: true })).toBeVisible();
  await expect(page.getByText('Clock uncertainty and serving process attribution are unknown. Matching Pod identity does not prove the same process or restart. Times use UTC with up to microsecond precision.', { exact: true })).toBeVisible();
  async function assertTimingMobile() {
    await page.evaluate(() => document.fonts.ready);
    for (const width of [375, 320]) {
      await page.setViewportSize({ width, height: 740 });
      // Profile sections must contain their tables: the page gutter otherwise hides
      // a font- and data-dependent overflow that crosses the viewport in CI.
      const layout = await page.evaluate(() => ({ viewport: innerWidth, document: document.documentElement.scrollWidth, timing: document.querySelector('table[aria-label="Profile collection timing"]').getBoundingClientRect().width, sections: [...document.querySelectorAll('section[aria-labelledby="profile-collection-timing"], section[aria-label="Saved profile comparison"], section[aria-label="Saved profile summary"]')].filter(node => node.scrollWidth > node.clientWidth).map(node => `${node.getAttribute('aria-label') ?? node.getAttribute('aria-labelledby') ?? 'section'} ${node.scrollWidth}>${node.clientWidth}`) }));
      process.stderr.write('installed comparison timing mobile ' + JSON.stringify(layout) + '\n');
      if (layout.document > layout.viewport) {
        // Name the widest overflowing elements so one failed run identifies the layout cause.
        const wide = await page.evaluate(() => [...document.body.querySelectorAll('*')].map(node => ({ node, right: node.getBoundingClientRect().right })).filter(({ right }) => right > innerWidth).sort((a, b) => b.right - a.right).slice(0, 6).map(({ node, right }) => `${node.tagName.toLowerCase()}${node.className ? '.' + String(node.className).split(' ').join('.') : ''}[${node.getAttribute('aria-label') ?? ''}] right=${right.toFixed(1)} text=${JSON.stringify((node.textContent ?? '').slice(0, 40))}`));
        process.stderr.write('installed comparison overflow ' + JSON.stringify(wide) + '\n');
      }
      assert(layout.document <= layout.viewport, 'profile collection timing preserves page width after fonts load');
      assert.deepEqual(layout.sections, [], 'profile sections contain their tables after fonts load');
      await expect(timing).toBeVisible();
      await expect(timing.getByRole('row')).toHaveCount(profiles.length + 1);
    }
    await page.setViewportSize({ width: 1440, height: 900 });
  }
  stage = 'case-profile-timing-mobile';
  await assertTimingMobile();
  stage = 'case-profile-region';
  const panel = page.getByRole('region', { name: heap ? 'Saved profile summary' : 'Saved profile comparison', exact: true });
  await expect(panel).toHaveCount(1, { timeout: 30_000 }); // Two captures are in separate real cases.
  await expect(panel).toBeVisible();
  stage = 'case-private-state';
  assert.equal(await page.evaluate(() => document.cookie), '');
  assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
  if (heap) {
    stage = 'case-heap-default';
    await expect(panel.getByRole('textbox', { name: 'Sample type', exact: true })).toHaveValue('inuse_space');
    await expect(panel.getByRole('spinbutton', { name: 'Number of functions', exact: true })).toHaveValue('20');
    await expect(panel.getByRole('button', { name: 'Inspect saved profile', exact: true })).toBeEnabled();
  } else {
    stage = 'case-baseline-select';
    const baseline = panel.getByRole('combobox', { name: 'Baseline profile', exact: true });
    await baseline.selectOption(config.artifactID);
    stage = 'case-compare-enabled';
    await expect(panel.getByRole('button', { name: 'Compare profiles', exact: true })).toBeEnabled();
  }
  assert.equal(compareRequests + pollRequests, 0, 'no automatic query on case load or selection');
  assert.equal(caseRequests, 1, 'timing uses the original case response');
  event({ kind: 'ready' });
  async function assertRenderedResult(result) {
    const table = panel.getByRole('table', { name: heap ? 'Profile function costs' : 'Profile comparison function costs', exact: true });
    const rows = heap ? result.top : result.rows;
    await expect(table).toBeVisible();
    await expect(table.getByRole('row')).toHaveCount(rows.length + 1);
    for (const [index, row] of rows.entries()) {
      await expect(table.getByRole('row').nth(index + 1).getByRole('cell')).toHaveText(heap
        ? [row.function ?? 'Unresolved', row.flat.toLocaleString('en-US'), row.cumulative.toLocaleString('en-US'), row.fraction === null ? 'Unavailable' : `${(row.fraction * 100).toFixed(2)}%`]
        : [row.function ?? 'Unresolved', row.baseline.toLocaleString('en-US'), row.incident.toLocaleString('en-US'), row.delta.toLocaleString('en-US')]);
    }
    if (heap) {
      await expect(panel.locator('dt:has-text("Unit") + dd')).toHaveText('bytes');
      await expect(panel.locator('dt:has-text("Total") + dd')).toHaveText(result.total.toLocaleString('en-US'));
      await expect(panel.locator('dt:has-text("Duration") + dd')).toHaveText('Unavailable');
    }
  }
  let heapSummaryChecked = false;
  let heapRenderedCaseRequests = 0;
  let handle;
  let terminal = false;
  let terminalComparison;
  let nativeCompleted = false;
  let calls = 0;
  for (;;) {
    const next = await command();
    if (next.kind === 'download') {
      assert(heap && terminal && heapSummaryChecked && !nativeCompleted, 'one native download after rendered summary');
      stage = 'heap-native-prepare';
      let from = seen.length;
      await panel.locator('..').getByRole('button', { name: 'Download', exact: true }).click();
      let response = await observed('prepare_artifact_download', from);
      let original, key, deadline;
      const end = Date.now() + 180_000; // Existing native helper ceiling; parent Go context still wins.
      for (;;) {
        event({ kind: 'operation', ...response });
        assert(Object.values(response.transport).every(Boolean), 'original native browser transport');
        assert.equal(response.reply.status, 'ok');
        const data = response.reply.data;
        assert.equal(data.artifact_id, config.artifactID);
        if (original === undefined) { original = data.download_id; deadline = data.expires_at; key = response.input.idempotency_key; }
        assert.equal(data.download_id, original);
        assert.equal(data.expires_at, deadline);
        if (response.name === 'prepare_artifact_download') assert.equal(response.input.idempotency_key, key);
        else assert.equal(response.input.download_id, original);
        assert(['Preparing', 'Ready'].includes(data.state), 'finite native preparation');
        if (data.state === 'Ready') break;
        assert(Date.now() < Math.min(end, Date.parse(deadline)), 'original preparation deadline');
        response = await observed(['prepare_artifact_download', 'get_artifact_download'], response.responseIndex);
      }
      const ready = response.reply.data;
      assert.equal(ready.content_path, '/api/v1/downloads/' + original + '/content');
      stage = 'heap-native-link';
      const link = page.getByRole('link', { name: 'Download native file', exact: true });
      await expect(link).toHaveAttribute('href', ready.content_path);
      const refreshedFrom = seen.length;
      if (config.restoreDuringNative) {
        // Synthetic local lifecycle event after the real anchor activation.
        // The actual SessionGate listener performs current HTTP session reads.
        await link.evaluate(element => element.addEventListener('click', () => {
          queueMicrotask(() => window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true })));
        }, { once: true }));
      }
      const downloadEvent = page.waitForEvent('download');
      await link.click();
      const download = await downloadEvent;
      if (config.restoreDuringNative) await observed('get_case', refreshedFrom);
      attachmentDiagnostic = { urlMatch: download.url() === config.origin + ready.content_path, filenameMatch: download.suggestedFilename() === 'artifact-' + config.artifactID + '.pb.gz', body: 'pending' };
      stage = 'heap-native-attachment-url';
      assert.equal(download.url(), config.origin + ready.content_path);
      stage = 'heap-native-attachment-filename';
      assert.equal(download.suggestedFilename(), 'artifact-' + config.artifactID + '.pb.gz');
      stage = 'heap-native-attachment-body';
      const failure = await download.failure();
      attachmentDiagnostic.body = failure === null ? 'complete' : 'failed';
      assert.equal(failure, null, 'native browser attachment completion');
      stage = 'heap-native-attachment-save';
      await download.saveAs(config.nativeDestination);
      nativeCompleted = true;
      event({ kind: 'native', file: 'heap-native.pb.gz', filename: download.suggestedFilename() });
      continue;
    }
    if (next.kind === 'close') {
      assert(terminal && compareRequests === 1 && pollRequests <= 4, 'exact original query count');
      stage = 'case-current-refresh';
      const observations = [];
      for (const response of seen) {
        const path = new URL(response.url()).pathname;
        if (path === '/auth/refresh' && response.status() === 200 || path === '/api/v1/operations/get_case') {
          const { read } = await readResponse(response, path);
          assert.equal(read.http, 200, 'current metadata/session HTTP response');
          assert.equal(response.request().method(), 'POST', 'existing same-origin session/case POST');
          assert.equal(await response.request().headerValue('origin'), config.origin);
          assert(/^[A-Za-z0-9_-]{43}$/.test(await response.request().headerValue('x-csrf-token') ?? ''), 'original CSRF transport');
          assert.equal(await response.request().headerValue('authorization'), null);
          if (path === '/api/v1/operations/get_case') assert.equal(JSON.parse(response.request().postData()).case_id, config.caseID);
          observations.push({ kind: path === '/auth/refresh' ? 'session' : 'case', reply: read.reply });
        }
      }
      assert.equal(checkInstalledProfileCaseRefreshes({ heap, caseID: config.caseID, artifactID: config.artifactID, observations }), caseRequests, 'all actual case reads verified');
      process.stderr.write(`installed profile current metadata reads=${caseRequests}; same-human refresh/source/timing pins checked\n`);
      stage = 'close-profile-timing';
      await expect(timing).toBeVisible();
      if (heap) {
        assert(heapSummaryChecked && nativeCompleted, 'rendered summary and native download before joined close');
        const table = panel.getByRole('table', { name: 'Profile function costs', exact: true });
        // Session reattachment clears the old projection to idle. Accept that
        // only after the successful same-human/current-source proof above.
        // Without that refresh, the original expiry still requires Expired.
        const viewExpires = Date.parse(terminalComparison.query_expires_at);
        stage = 'close-summary-original-expiry';
        assert(Number.isFinite(viewExpires), 'original summary expiry');
        if (caseRequests > heapRenderedCaseRequests) {
          stage = 'close-summary-refreshed-idle-rows';
          await expect(table).toHaveCount(0);
          stage = 'close-summary-refreshed-idle-status';
          await expect(panel.getByRole('status')).toHaveCount(0);
          await expect(panel.getByRole('alert')).toHaveCount(0);
          stage = 'close-summary-refreshed-idle-control';
          await expect(panel.getByRole('button', { name: 'Inspect saved profile', exact: true })).toBeEnabled();
          await expect(panel.getByRole('button', { name: 'Close view', exact: true })).toHaveCount(0);
          process.stderr.write('installed heap summary cleared to idle after verified current session/case refresh; no additional query\n');
        } else {
          if (Date.now() >= viewExpires || await table.count() === 0) {
            stage = 'close-summary-cleared-rows';
            await expect(table).toHaveCount(0);
            stage = 'close-summary-expired-status';
            await expect(panel.getByRole('status')).toHaveText('This view has expired. Inspect again to request a fresh view.');
            process.stderr.write('installed heap summary expired during native download; no additional query\n');
          } else {
            stage = 'close-summary-current-rows';
            await expect(table).toBeVisible();
          }
          stage = 'close-summary-control';
          await panel.getByRole('button', { name: 'Close view', exact: true }).click();
          stage = 'close-summary-final-cleared-rows';
          await expect(table).toHaveCount(0);
        }
        stage = 'close-summary-no-new-query';
        assert(compareRequests === 1 && pollRequests <= 4, 'no automatic replacement query after current session refresh');
      } else {
        await expect(panel.getByRole('table', { name: 'Profile acquisition details', exact: true })).toBeVisible();
        await assertRenderedResult(terminalComparison);
      }
      stage = 'result-profile-timing-mobile';
      await assertTimingMobile();
      assert.deepEqual(errors, []);
      assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
      complete = true;
      break;
    }
    assert.equal(next.kind, 'call');
    assert(!terminal && ++calls <= 5, 'bounded original query calls');
    const name = calls === 1 ? (heap ? 'get_profile_summary' : 'compare_profiles') : 'get_query_result';
    assert.equal(next.name, name);
    const expected = name === 'get_profile_summary'
      ? { case_id: config.caseID, artifact_id: config.artifactID, sample_type: 'inuse_space', top_n: 20 }
      : name === 'compare_profiles'
      ? { case_id: config.caseID, artifact_id: config.artifactID, baseline_case_id: config.caseID, baseline_artifact_id: config.artifactID, sample_type: 'cpu', normalization: 'perSecond', top_n: 20 }
      : { query_handle: handle };
    assert.deepEqual(next.input, expected);
    stage = name;
    const button = panel.getByRole('button', { name: heap ? (calls === 1 ? 'Inspect saved profile' : 'Check result') : (calls === 1 ? 'Compare profiles' : 'Check comparison result'), exact: true });
    await expect(button).toBeEnabled({ timeout: 30_000 });
    // Clear before clicking, so an earlier identical paid poll cannot supply
    // this attempt's page-consumed response.
    await page.evaluate(prefix => { for (const key of window.__installedReplies.keys()) if (key.startsWith(prefix)) window.__installedReplies.delete(key); }, '/api/v1/operations/' + name + '\n');
    const from = seen.length;
    await button.click();
    const response = await observed(name, from);
    // Emit before interpretation; Go can retain the early pending handle and
    // operation ID for independent cleanup even if later assertions fail.
    event({ kind: 'operation', name, ...response });
    assert.deepEqual(response.input, expected);
    assert(Object.values(response.transport).every(Boolean), 'original browser transport');
    if (response.reply.status === 'pending') {
      const pending = response.reply.data;
      if (handle !== undefined) assert.equal(pending.query_handle, handle);
      handle = pending.query_handle;
      assert.equal(typeof handle, 'string');
    } else {
      assert.equal(response.reply.status, 'ok');
      terminalComparison = name === 'get_query_result' ? response.reply.data.result.data : response.reply.data;
      terminal = true;
      if (heap) {
        stage = 'heap-summary-rendered';
        await assertRenderedResult(terminalComparison);
        heapSummaryChecked = true;
        heapRenderedCaseRequests = caseRequests;
        process.stderr.write('installed heap summary rows/bytes/null duration checked before native download\n');
      }
    }
  }
} catch (error) {
  const category = error?.code === 'ERR_ASSERTION' ? 'assertion' : error?.matcherResult ? 'expectation' : error?.name === 'TimeoutError' ? 'timeout' : 'operation';
  const dom = page && !page.isClosed() ? {
    evidenceHeading: await page.getByRole('heading', { name: 'Evidence', exact: true }).count() > 0,
    summaryRegion: await page.getByRole('region', { name: 'Saved profile summary', exact: true }).count() > 0,
    comparisonRegion: await page.getByRole('region', { name: 'Saved profile comparison', exact: true }).count() > 0,
    alerts: Math.min(8, await page.getByRole('alert').count()), pageErrors: Math.min(8, errors.length),
    refresh: await page.getByRole('button', { name: 'Check evidence access', exact: true }).count() > 0,
  } : {};
  process.stderr.write(`installed comparison failure stage=${stage} category=${category} dom=${JSON.stringify(dom)} attachment=${JSON.stringify(attachmentDiagnostic ?? null)}\n` + timeline.slice(-40).join('\n') + '\n');
  process.exitCode = 1;
} finally {
  await context.close();
  await browser.close();
  if (complete) event({ kind: 'closed' });
  process.stdin.destroy();
}
