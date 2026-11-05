// Installed React, original HttpOnly session and actual operation transport.
// Go owns the single query, every paid poll and independent SQL/worker proof.
import { chromium, expect } from '@playwright/test';
import assert from 'node:assert/strict';
import { createInterface } from 'node:readline';
import { readInstalledHistoryResponse, parseInstalledHistoryText } from './installed-history-response.mjs';
import { validInput_get_target_discovery, validOutput_get_target_discovery, validOutput_get_query_result } from '../src/generated/validate-projection.js';

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
assert.equal(config.mode, 'processes-query');
assert.equal(new URL(config.origin).protocol, 'https:');
assert.equal(new URL(config.proxy).hostname, '127.0.0.1');
assert.match(config.captureID, /^[0-9a-f-]{36}$/);
assert.match(config.artifactID, /^[0-9a-f-]{36}$/);
assert.match(config.version, /^[0-9a-f]{64}$/);
const browser = await chromium.launch({ headless: true, proxy: { server: config.proxy, bypass: '<-loopback>' }, ...(process.env.ASSERVAT_CHROMIUM ? { executablePath: process.env.ASSERVAT_CHROMIUM } : {}) });
const context = await browser.newContext({ ignoreHTTPSErrors: true, acceptDownloads: false, locale: 'en-US', viewport: { width: 1440, height: 900 } });
let stage = 'session';
let complete = false;
let page;

const errors = [];
const timeline = [];
try {
  await context.addCookies(config.cookies);
  config.cookies = [];
  // Observe only bodies consumed by the page for Chromium's known aborted
  // inspector response. This neither replaces responses nor performs a fetch.
  await context.addInitScript(() => {
    const original = window.fetch.bind(window);
    const replies = new Map();
    Object.defineProperty(window, '__installedReplies', { value: replies });
    window.fetch = async (input, init) => {
      const response = await original(input, init);
      const path = new URL(typeof input === 'string' ? input : input.url, location.href).pathname;
      if (/^\/api\/v1\/operations\/(get_capture|get_capture_settings|get_target_discovery|get_query_result)$/.test(path) && response.status === 200) {
        const key = path + '\n' + (typeof init?.body === 'string' ? init.body : '');
        response.clone().text().then(text => { if (text.length <= 32_768) replies.set(key, text); }, () => {});
      }
      return response;
    };
  });
  page = await context.newPage();
  const seen = [];
  let starts = 0, polls = 0;
  page.on('pageerror', () => errors.push('pageerror'));
  page.on('request', request => {
    const path = new URL(request.url()).pathname;
    if (path === '/api/v1/operations/get_target_discovery') starts++;
    if (path === '/api/v1/operations/get_query_result') polls++;
    if (path.startsWith('/api/v1/operations/')) {
      if (!['/api/v1/operations/get_capture', '/api/v1/operations/get_capture_settings', '/api/v1/operations/get_target_discovery', '/api/v1/operations/get_query_result'].includes(path)) errors.push('unexpected-operation');
      timeline.push(`${request.method()} ${path}`);
    }
  });
  page.on('response', response => {
    seen.push(response);
    const path = new URL(response.url()).pathname;
    if (path.startsWith('/api/')) timeline.push(`response ${response.status()} ${path}`);
  });
  async function observed(name, from) {
    for (let index = from, end = Date.now() + 30_000; Date.now() < end;) {
      if (index >= seen.length) { await page.waitForTimeout(100); continue; }
      const response = seen[index++];
      const path = new URL(response.url()).pathname;
      if (path !== '/api/v1/operations/' + name) continue;
      let read = await readInstalledHistoryResponse(response);
      if (read.requestFailed && read.readFailure.includes('ERR_ABORTED') && response.status() === 200) {
        const key = path + '\n' + (response.request().postData() ?? '');
        let text = null;
        for (const until = Date.now() + 2000; Date.now() < until;) {
          text = await page.evaluate(k => { const value = window.__installedReplies.get(k) ?? null; window.__installedReplies.delete(k); return value; }, key);
          if (text !== null) break;
          await page.waitForTimeout(100);
        }
        if (text === null) continue; // No replay of a superseded response.
        read = parseInstalledHistoryText(200, text);
      }
      assert.equal(read.http, 200, 'operation HTTP status');
      assert.equal(read.body, 'complete', 'complete operation body');
      return { name, input: JSON.parse(response.request().postData()), reply: read.reply, transport: {
        post: response.request().method() === 'POST',
        sameOrigin: await response.request().headerValue('origin') === config.origin,
        csrf: /^[A-Za-z0-9_-]{43}$/.test(await response.request().headerValue('x-csrf-token') ?? ''),
        noBearer: await response.request().headerValue('authorization') === null,
      } };
    }
    throw new Error('operation response unavailable');
  }


  stage = 'capture';
  await page.goto(config.origin + '/captures/' + config.captureID);
  await observed('get_capture', 0);
  assert.equal(await page.evaluate(() => document.cookie), '');
  assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
  assert.equal(starts + polls, 0, 'loading status does not read or collect evidence');
  // Existing saved-settings authority identifies the recorded action. No case
  // projection is widened to expose its private parent capture identifier.
  const settingsFrom = seen.length;
  await page.getByRole('button', { name: 'View settings', exact: true }).click();
  const settings = await observed('get_capture_settings', settingsFrom);
  assert(Object.values(settings.transport).every(Boolean));
  assert.equal(settings.reply.status, 'ok');
  assert.equal(settings.input.capture_id, config.captureID);
  const panel = page.getByRole('region', { name: 'Saved process snapshot', exact: true });
  await expect(panel).toHaveCount(1);
  await expect(panel.getByRole('button', { name: 'Inspect saved processes', exact: true })).toBeEnabled();
  assert.equal(starts + polls, 0, 'settings do not initiate a saved read');
  event({ kind: 'ready' });
  let handle, expiresAt;
  let terminal = false, calls = 0;
  for (;;) {
    const next = await command();
    if (next.kind === 'close') {
      assert(terminal && starts === 1 && polls <= 4);
      await panel.getByRole('button', { name: 'Close view', exact: true }).click();
      await expect(panel.getByRole('table', { name: 'Recorded processes', exact: true })).toHaveCount(0);
      await expect(panel.getByRole('button', { name: 'Inspect saved processes', exact: true })).toBeEnabled();
      assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
      assert.deepEqual(errors, []);
      complete = true; break;
    }
    assert.equal(next.kind, 'call');
    assert(++calls <= 5);
    const begin = next.name === 'get_target_discovery';
    let button;
    if (begin) {
      assert.equal(starts, 0, 'single original read, no replay or invented key');
      button = 'Inspect saved processes';
    } else {
      assert.equal(next.name, 'get_query_result');
      assert(!terminal && handle);
      button = 'Check result';
    }
    stage = next.name;
    await expect(panel.getByRole('button', { name: button, exact: true })).toBeEnabled({ timeout: 30_000 });
    const from = seen.length;
    await panel.getByRole('button', { name: button, exact: true }).click();
    const response = await observed(next.name, from);
    assert(Object.values(response.transport).every(Boolean));
    assert.deepEqual(response.input, next.input, 'exact original capture/section/window or query handle');
    if (begin) assert(validInput_get_target_discovery(response.input));
    else assert.deepEqual(response.input, { query_handle: handle });
    const reply = response.reply;
    assert((begin ? validOutput_get_target_discovery : validOutput_get_query_result)(reply));
    const observedAt = reply.data.query_observed_at;
    if (expiresAt === undefined) expiresAt = reply.data.query_expires_at;
    assert.equal(reply.data.query_expires_at, expiresAt);
    assert(Date.parse(observedAt) < Date.parse(expiresAt));
    if (reply.status === 'pending') {
      if (handle !== undefined) assert.equal(reply.data.query_handle, handle);
      handle = reply.data.query_handle;
      event({ kind: 'operation', ...response });
      continue;
    }
    assert.equal(reply.status, 'ok');
    const result = begin ? reply : reply.data.result;
    if (!begin) {
      assert.equal(reply.data.query_handle, handle);
      assert.equal(reply.data.tool_name, 'get_target_discovery');
      assert.equal(reply.truncated, false); assert.equal(reply.next_cursor, null);
    }
    assert(validOutput_get_target_discovery(result) && result.status === 'ok');
    assert.equal(result.request_id, reply.request_id);
    assert.equal(reply.data_class, 'extract'); assert.equal(result.data_class, 'extract');
    assert.equal(result.data.kind, 'discoveryPage');
    assert.equal(result.data.capture_id, config.captureID);
    assert.deepEqual(result.data.source_artifact_ids, [config.artifactID]);
    assert.deepEqual(result.provenance, [{ artifactID: config.artifactID, digest: config.version }]);
    assert.equal(result.data.section, 'processes');
    assert.equal(result.data.query_observed_at, observedAt);
    assert.equal(result.data.query_expires_at, expiresAt);
    assert.equal(result.data.summary.capture_mode, 'none');
    assert.equal(result.data.summary.coverage.traffic_complete, false);
    const rows = result.data.processes;
    const table = panel.getByRole('table', { name: 'Recorded processes', exact: true });
    await expect(table).toBeVisible();
    await expect(table.getByRole('row')).toHaveCount(rows.length + 1);
    for (const [index, recorded] of rows.entries()) {
      const row = table.getByRole('row').nth(index + 1);
      await expect(row).toContainText(String(recorded.display_pid));
      await expect(row).toContainText(recorded.process_ref);
      await expect(row).toContainText(recorded.executable_path ?? 'Executable path unavailable');
      await expect(row).toContainText(recorded.rss_bytes === undefined ? 'Unavailable' : `${recorded.rss_bytes.toLocaleString('en-US')} bytes`);
      await expect(row).toContainText(recorded.parent_ref ?? 'Unavailable');
      assert.equal(recorded.runtime, 'unknown');
    }
    assert.equal(await table.locator('a,img,script').count(), 0, 'recorded paths remain text');
    await expect(panel).toContainText('Runtime and build identities are unknown.');
    await expect(panel).toContainText(`${result.data.summary.coverage.covered_pods} of ${result.data.summary.coverage.requested_pods} selected Pods covered.`);
    if (rows.length === 0) await expect(panel.getByText('No processes were observed in this saved snapshot.', { exact: true })).toBeVisible();
    const bodyText = await page.locator('body').innerText();
    assert(!bodyText.includes('synthetic-process-argv-private') && !bodyText.includes('synthetic-process-env-private'), 'private source canaries absent from DOM');
    assert.equal(result.truncated, result.next_cursor !== null);
    terminal = true;
    // The Go caller starts independent final SQL proof only after this event:
    // the original React component has consumed and rendered the exact result.
    event({ kind: 'operation', ...response });
    process.stderr.write('installed processes real React source/clock/rows/paths/zero-RSS/unknown identities checked\n');
  }
} catch (error) {
  const category = error?.code === 'ERR_ASSERTION' ? 'assertion' : error?.matcherResult ? 'expectation' : error?.name === 'TimeoutError' ? 'timeout' : 'runtime';
  process.stderr.write(`installed processes failure stage=${stage} category=${category} pageErrors=${Math.min(8, errors.length)}\n` + timeline.slice(-30).join('\n') + '\n');
  process.exitCode = 1;
} finally {
  await context.close(); await browser.close(); lines.return?.();
  if (complete) event({ kind: 'closed' });
}
