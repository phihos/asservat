// Installed React, original HttpOnly session and actual operation transport.
// Go owns the single query, every paid poll and independent SQL/worker proof.
import { chromium, expect } from '@playwright/test';
import assert from 'node:assert/strict';
import { createInterface } from 'node:readline';
import { readInstalledHistoryResponse, parseInstalledHistoryText } from './installed-history-response.mjs';
import { validOutput_get_case } from '../src/generated/validate-evidence.js';
import { validInput_get_logs, validOutput_get_logs, validOutput_get_query_result } from '../src/generated/validate-projection.js';

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
assert.equal(config.mode, 'logs-query');
assert(config.query_request);
assert.match(config.grantID, /^[0-9a-f-]{36}$/);
assert.equal(new URL(config.origin).protocol, 'https:');
assert.equal(new URL(config.proxy).hostname, '127.0.0.1');
assert.match(config.caseID, /^[0-9a-f-]{36}$/);
assert.match(config.artifactID, /^[0-9a-f-]{36}$/);
assert.match(config.version, /^[0-9a-f]{64}$/);
const browser = await chromium.launch({ headless: true, proxy: { server: config.proxy, bypass: '<-loopback>' }, ...(process.env.ASSERVAT_CHROMIUM ? { executablePath: process.env.ASSERVAT_CHROMIUM } : {}) });
const context = await browser.newContext({ ignoreHTTPSErrors: true, acceptDownloads: false, locale: 'en-US', viewport: { width: 1440, height: 900 } });
let stage = 'session';
let complete = false;
let page;
let caseDiagnostic;
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
      if (/^\/api\/v1\/operations\/(get_case|get_logs|get_query_result|request_raw_access|get_grant)$/.test(path) && response.status === 200) {
        const key = path + '\n' + (typeof init?.body === 'string' ? init.body : '');
        response.clone().text().then(text => { if (text.length <= 32_768) replies.set(key, text); }, () => {});
      }
      return response;
    };
  });
  page = await context.newPage();
  const seen = [];
  let starts = 0, polls = 0, cases = 0;
  page.on('pageerror', () => errors.push('pageerror'));
  page.on('request', request => {
    const path = new URL(request.url()).pathname;
    if (path === '/api/v1/operations/get_logs') starts++;
    if (path === '/api/v1/operations/get_query_result') polls++;
    if (path === '/api/v1/operations/get_case') cases++;
    if (path.startsWith('/api/v1/operations/')) {
      if (!['/api/v1/operations/get_case', '/api/v1/operations/get_logs', '/api/v1/operations/get_query_result', '/api/v1/operations/request_raw_access', '/api/v1/operations/get_grant'].includes(path)) errors.push('unexpected-operation');
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
      let pageConsumed = false;
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
        pageConsumed = true;
      }
      if (name === 'get_case') {
        const data = read.reply?.data;
        const artifacts = Array.isArray(data?.artifacts) ? data.artifacts : [];
        const source = artifacts.find(a => a.artifact_id === config.artifactID);
        caseDiagnostic = { http: read.http, body: read.body, pageConsumed, schema: validOutput_get_case(read.reply), ok: read.status === 'ok', caseMatch: data?.case?.case_id === config.caseID, ordinary: data?.case?.access === 'ordinary', sourceMatch: source?.kind === 'logs' && source?.native_format === 'asservat-logs/v1' && source?.data_class === 'raw' && source?.digest === config.version && (!config.podUID || source?.target?.pod_uid === config.podUID) && Date.parse(source?.expires_at) > Date.now() };
        process.stderr.write('saved logs case ' + JSON.stringify(caseDiagnostic) + '\n');
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


  stage = 'case';
  await page.goto(config.origin + '/cases/' + config.caseID);
  const caseResponse = await observed('get_case', 0);
  assert(Object.values(caseResponse.transport).every(Boolean));
  assert(caseDiagnostic.schema && caseDiagnostic.ok && caseDiagnostic.caseMatch && caseDiagnostic.ordinary && caseDiagnostic.sourceMatch, 'exact ordinary raw source');
  const panel = page.getByRole('region', { name: 'Saved log query', exact: true });
  const approval = page.getByRole('region', { name: 'Request saved log query approval', exact: true });
  await expect(panel).toHaveCount(1);
  assert.equal(await page.evaluate(() => document.cookie), '');
  assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
  assert.equal(starts + polls, 0);
  await expect(panel.getByRole('button', { name: 'Inspect saved logs', exact: true })).toBeDisabled();
  stage = 'approval';
  await approval.getByLabel('Reason for raw access', { exact: true }).fill('Inspect the bytes already recorded in this saved log file.');
  let from = seen.length;
  await approval.getByRole('button', { name: 'Request query approval', exact: true }).click();
  let approved = await observed('request_raw_access', from);
  assert(Object.values(approved.transport).every(Boolean));
  assert.equal(approved.reply.status, 'ok');
  assert.equal(approved.reply.data.grant_id, config.grantID);
  assert.deepEqual(approved.input.operations, ['get_logs']);
  assert.deepEqual(approved.input.artifact_digests, [config.version]);
  assert.equal(approved.input.case_id, config.caseID);
  if (approved.reply.data.phase === 'Pending') {
    await expect(panel.getByRole('button', { name: 'Inspect saved logs', exact: true })).toBeDisabled();
    from = seen.length;
    await approval.getByRole('button', { name: 'Check approval', exact: true }).click();
    approved = await observed('get_grant', from);
    assert(Object.values(approved.transport).every(Boolean));
    assert.deepEqual(approved.input, { grant_id: config.grantID });
    assert.equal(approved.reply.status, 'ok');
    assert.equal(approved.reply.data.grant_id, config.grantID);
  }
  assert.equal(approved.reply.data.phase, 'Approved');
  const wanted = config.query_request;
  await panel.getByLabel('Fragments per page', { exact: true }).fill(String(wanted.limit ?? 100));
  await expect(panel.getByRole('button', { name: 'Inspect saved logs', exact: true })).toBeEnabled();
  assert.equal(starts + polls, 0, 'approval does not run a query');
  event({ kind: 'ready' });
  let handle, expiresAt, nextCursor, lastKey;
  let terminal = false, queries = 0, calls = 0;
  for (;;) {
    const next = await command();
    if (next.kind === 'close') {
      assert(terminal && queries >= 1 && queries <= 2 && starts === queries && polls <= 8 && cases === 1);
      await panel.getByRole('button', { name: 'Close log query', exact: true }).click();
      await expect(panel.getByRole('table', { name: 'Saved log fragments', exact: true })).toHaveCount(0);
      await expect(panel.getByRole('button', { name: 'Inspect saved logs', exact: true })).toBeEnabled();
      assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
      assert.deepEqual(errors, []);
      complete = true; break;
    }
    assert.equal(next.kind, 'call');
    assert(++calls <= 10);
    const begin = next.name === 'get_logs';
    let button;
    if (begin) {
      assert(++queries <= 2);
      if (queries === 1) button = 'Inspect saved logs';
      else { assert(terminal && nextCursor); assert.equal(next.input.cursor, nextCursor); button = 'Next log page'; }
      handle = undefined; expiresAt = undefined; terminal = false;
    } else { assert.equal(next.name, 'get_query_result'); assert(!terminal && handle); button = 'Check log query'; }
    stage = next.name;
    await expect(panel.getByRole('button', { name: button, exact: true })).toBeEnabled({ timeout: 30_000 });
    from = seen.length;
    await panel.getByRole('button', { name: button, exact: true }).click();
    const response = await observed(next.name, from);
    event({ kind: 'operation', ...response });
    assert(Object.values(response.transport).every(Boolean));
    if (begin) {
      assert(validInput_get_logs(response.input));
      assert.match(response.input.idempotency_key, /^[0-9a-f-]{36}$/);
      if (lastKey) assert.notEqual(response.input.idempotency_key, lastKey, 'explicit next-page fresh key');
      lastKey = response.input.idempotency_key;
      const actual = { ...response.input }, expected = { ...next.input };
      delete actual.idempotency_key; delete expected.idempotency_key;
      assert.deepEqual(actual, expected, 'exact source/grant/selection/cursor');
    } else assert.deepEqual(response.input, { query_handle: handle });
    const reply = response.reply;
    assert((begin ? validOutput_get_logs : validOutput_get_query_result)(reply));
    const currentObserved = reply.data.query_observed_at;
    if (expiresAt === undefined) expiresAt = reply.data.query_expires_at;
    assert.equal(reply.data.query_expires_at, expiresAt);
    assert(Number.isFinite(Date.parse(currentObserved)) && Date.parse(currentObserved) < Date.parse(expiresAt));
    if (reply.status === 'pending') {
      if (handle !== undefined) assert.equal(reply.data.query_handle, handle);
      handle = reply.data.query_handle;
      continue;
    }
    assert.equal(reply.status, 'ok');
    const result = begin ? reply : reply.data.result;
    if (!begin) { assert.equal(reply.data.query_handle, handle); assert.equal(reply.data.tool_name, 'get_logs'); assert.equal(reply.truncated, false); assert.equal(reply.next_cursor, null); }
    assert(validOutput_get_logs(result) && result.status === 'ok');
    assert.equal(result.request_id, reply.request_id);
    assert.equal(reply.data_class, 'raw'); assert.equal(result.data_class, 'raw');
    assert.equal(result.data.query_observed_at, currentObserved);
    assert.equal(result.data.query_expires_at, expiresAt);
    assert.deepEqual(result.provenance, [{ artifactID: config.artifactID, digest: config.version }]);
    assert.equal(result.data.kind, 'logs');
    assert.equal(result.data.pod_uid, config.podUID);
    const rows = result.data.entries;
    const table = panel.getByRole('table', { name: 'Saved log fragments', exact: true });
    if (rows.length) {
      await expect(table).toBeVisible();
      await expect(table.getByRole('row')).toHaveCount(rows.length + 1);
      for (const [index, entry] of rows.entries()) {
        const row = table.getByRole('row').nth(index + 1);
        await expect(row).toContainText(entry.origin.container_name);
        await expect(row).toContainText(entry.origin.source);
        await expect(row).toContainText('combined');
        await expect(row).toContainText(`Line ${entry.line}, byte ${entry.offset}`);
        if (entry.origin.restart_count === 0) await expect(row).toContainText('Restart: 0');
        if (entry.source_time === null) await expect(row).toContainText('Source time unknown');
        if (entry.text !== null) {
          assert.equal(await row.locator('pre').textContent(), entry.text, 'lossless original UTF-8 including empty lines');
          if (entry.text === '\n') await expect(row).toContainText('Empty line (LF)');
        } else {
          await expect(row).toContainText('Original non-UTF-8 bytes (base64)');
          await expect(row.locator('code')).toHaveText(entry.bytes_base64);
        }
      }
      assert.equal(await table.locator('a,img,script').count(), 0, 'log bytes remain inert text');
    } else await expect(panel.getByText(/No bytes were retained/)).toBeVisible();
    nextCursor = result.next_cursor;
    assert.equal(result.truncated, nextCursor !== null);
    await expect(panel.locator('dt:has-text("Completed fetches") + dd')).toHaveText(String(result.data.coverage.complete_origins));
    await expect(panel.getByText(/Fetch completion does not prove complete historical coverage/)).toBeVisible();
    process.stderr.write('saved logs real React empty/invalid UTF-8/combined/current+previous/coverage/source/clock checked\n');
    terminal = true;
  }
} catch (error) {
  const category = error?.code === 'ERR_ASSERTION' ? 'assertion' : error?.matcherResult ? 'expectation' : error?.name === 'TimeoutError' ? 'timeout' : 'operation';
  process.stderr.write(`saved logs failure stage=${stage} category=${category} pageErrors=${Math.min(8, errors.length)} case=${JSON.stringify(caseDiagnostic ?? null)}\n` + timeline.slice(-30).join('\n') + '\n');
  process.exitCode = 1;
} finally {
  await context.close(); await browser.close();
  if (complete) event({ kind: 'closed' });
  process.stdin.destroy();
}
