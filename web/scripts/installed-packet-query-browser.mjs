// Installed React, original HttpOnly session and actual operation transport.
// Go owns the single query, every paid poll and independent SQL/worker proof.
import { chromium, expect } from '@playwright/test';
import assert from 'node:assert/strict';
import { createInterface } from 'node:readline';
import { readInstalledHistoryResponse, parseInstalledHistoryText } from './installed-history-response.mjs';
import { validOutput_get_case } from '../src/generated/validate-evidence.js';
import { validInput_pcap_query, validOutput_pcap_query, validOutput_get_query_result } from '../src/generated/validate-projection.js';

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
assert.equal(config.mode, 'packet-query');
const captureMode = config.packet_capture_mode ?? 'networkHeaders';
assert(['networkHeaders', 'rawPackets'].includes(captureMode), 'closed expected source mode');
const raw = captureMode === 'rawPackets';
assert(config.query_request && Array.isArray(config.query_request.fields));
if(raw)assert.match(config.grantID,/^[0-9a-f-]{36}$/);
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
      if (/^\/api\/v1\/operations\/(get_case|pcap_query|get_query_result|request_raw_access|get_grant)$/.test(path) && response.status === 200) {
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
    if (path === '/api/v1/operations/pcap_query') starts++;
    if (path === '/api/v1/operations/get_query_result') polls++;
    if (path === '/api/v1/operations/get_case') cases++;
    if (path.startsWith('/api/v1/operations/')) {
      if (!['/api/v1/operations/get_case', '/api/v1/operations/pcap_query', '/api/v1/operations/get_query_result', ...(raw ? ['/api/v1/operations/request_raw_access', '/api/v1/operations/get_grant'] : [])].includes(path)) errors.push('unexpected-operation');
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
        caseDiagnostic = { http: read.http, body: read.body, pageConsumed, schema: validOutput_get_case(read.reply), ok: read.status === 'ok', caseMatch: data?.case?.case_id === config.caseID, ordinary: data?.case?.access === 'ordinary', sourceMatch: source?.kind === 'packetCapture' && source?.native_format === (raw ? 'pcapng-raw' : 'pcapng') && source?.data_class === (raw ? 'raw' : 'metadata') && source?.digest === config.version && (!config.podUID || source?.target?.pod_uid === config.podUID) && Date.parse(source?.expires_at) > Date.now() };
        process.stderr.write('installed packet case ' + JSON.stringify(caseDiagnostic) + '\n');
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
  assert(Object.values(caseResponse.transport).every(Boolean), 'original case transport');
  assert(caseDiagnostic.schema && caseDiagnostic.ok && caseDiagnostic.caseMatch && caseDiagnostic.ordinary && caseDiagnostic.sourceMatch, 'current exact packet source/Pod/version');
  const panel = page.getByRole('region', { name: 'Saved packet query', exact: true });
  await expect(panel).toHaveCount(1);
  assert.equal(await page.evaluate(() => document.cookie), '');
  assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
  assert.equal(starts + polls, 0, 'no query before explicit action');
  assert.equal(cases, 1);
  if (raw) {
    stage = 'covering-approval';
    await expect(panel.getByRole('button', { name: 'Run packet query', exact: true })).toBeDisabled();
    await panel.getByLabel('Reason for raw access', { exact: true }).fill('Inspect these saved packet fields under the existing reviewed result access.');
    const from = seen.length;
    await panel.getByRole('button', { name: 'Request query approval', exact: true }).click();
    const approved = await observed('request_raw_access', from);
    assert(Object.values(approved.transport).every(Boolean), 'original approval transport');
    assert.equal(approved.reply.status, 'ok');
    assert.equal(approved.reply.data.phase, 'Approved', 'existing reviewed grant must cover this query; no automatic review');
    assert.equal(approved.reply.data.grant_id, config.grantID, 'same original reviewed disclosure pool');
    assert.deepEqual(approved.input.operations, ['pcap_query']);
    assert.deepEqual(approved.input.artifact_digests, [config.version]);
    process.stderr.write('installed packet query covering approval: original grant reused through actual RawAccessPanel; no new approval or acquisition\n');
  }
  const wanted = config.query_request;
  stage = 'selection';
  for (const field of await panel.getByRole('checkbox').all()) {
    const label = await field.getAttribute('type');
    if (label === 'checkbox' && await field.isChecked() && await field.isEnabled()) await field.uncheck();
  }
  for (const field of wanted.fields) await panel.getByRole('checkbox', { name: field, exact: true }).check();
  await panel.getByLabel('tcpdump/libpcap packet filter', { exact: true }).fill(wanted.packet_filter ?? '');
  await panel.getByLabel('Maximum returned records', { exact: true }).fill(String(wanted.max_packets));
  await panel.getByLabel('Maximum saved bytes to scan', { exact: true }).fill(String(wanted.max_scan_bytes));
  await panel.getByLabel('Start packet time (UTC, optional)', { exact: true }).fill(wanted.start_time ?? '');
  await panel.getByLabel('End packet time (UTC, exclusive, optional)', { exact: true }).fill(wanted.end_time ?? '');
  if (wanted.tcp_flags) {
    await panel.getByRole('checkbox', { name: 'Filter TCP flags', exact: true }).check();
    await panel.getByLabel('TCP flag mask', { exact: true }).fill(String(wanted.tcp_flags.mask));
    await panel.getByLabel('TCP flag value', { exact: true }).fill(String(wanted.tcp_flags.value));
  }
  if (wanted.frame_prefix) {
    await panel.getByLabel('Saved-frame byte offset', { exact: true }).fill(String(wanted.frame_prefix.offset));
    await panel.getByLabel('Saved-frame byte length', { exact: true }).fill(String(wanted.frame_prefix.length));
  }
  await expect(panel.getByRole('button', { name: 'Run packet query', exact: true })).toBeEnabled();
  assert.equal(starts + polls, 0);
  event({ kind: 'ready' });
  let handle, expiresAt, uiKey;
  let terminal = false, calls = 0;
  for (;;) {
    const next = await command();
    if (next.kind === 'close') {
      assert(terminal && starts === 1 && polls <= 4 && cases === 1, 'one original query and source read');
      stage = 'close';
      const table = panel.getByRole('table', { name: 'Saved packet query rows', exact: true });
      await panel.getByRole('button', { name: 'Close packet query', exact: true }).click();
      await expect(table).toHaveCount(0);
      await expect(panel.getByRole('button', { name: 'Run packet query', exact: true })).toBeEnabled();
      assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
      assert.deepEqual(errors, []);
      complete = true;
      break;
    }
    assert.equal(next.kind, 'call');
    assert(!terminal && ++calls <= 5, 'bounded original query calls');
    const name = calls === 1 ? 'pcap_query' : 'get_query_result';
    assert.equal(next.name, name);
    stage = name;
    const button = panel.getByRole('button', { name: calls === 1 ? 'Run packet query' : 'Check packet query', exact: true });
    await expect(button).toBeEnabled({ timeout: 30_000 });
    await page.evaluate(prefix => { for (const key of window.__installedReplies.keys()) if (key.startsWith(prefix)) window.__installedReplies.delete(key); }, '/api/v1/operations/' + name + '\n');
    const from = seen.length;
    await button.click();
    const response = await observed(name, from);
    event({ kind: 'operation', ...response }); // Retain original locator before render assertions.
    assert(Object.values(response.transport).every(Boolean), 'original browser transport');
    if (calls === 1) {
      assert(validInput_pcap_query(response.input));
      assert.match(response.input.idempotency_key, /^[0-9a-f-]{36}$/);
      uiKey = response.input.idempotency_key;
      const actual = { ...response.input }, expected = { ...next.input };
      delete actual.idempotency_key; delete expected.idempotency_key;
      assert.deepEqual(actual, expected, 'actual authored selection and approved source');
      if (raw) assert.equal(response.input.grant_id, config.grantID);
    } else assert.deepEqual(response.input, { query_handle: handle });
    assert((calls === 1 ? validOutput_pcap_query : validOutput_get_query_result)(response.reply));
    const reply = response.reply;
    const observedAt = reply.data.query_observed_at;
    if (expiresAt === undefined) expiresAt = reply.data.query_expires_at;
    assert.equal(reply.data.query_expires_at, expiresAt);
    assert(Number.isFinite(Date.parse(observedAt)) && Date.parse(expiresAt) > Date.parse(observedAt), 'original finite query interval');
    if (reply.status === 'pending') {
      if (handle !== undefined) assert.equal(reply.data.query_handle, handle);
      handle = reply.data.query_handle;
    } else {
      assert.equal(reply.status, 'ok');
      if (calls > 1) { assert.equal(reply.data.query_handle, handle); assert.equal(reply.data.tool_name, 'pcap_query'); assert.equal(reply.truncated, false); }
      const result = calls === 1 ? reply : reply.data.result;
      assert(validOutput_pcap_query(result) && result.status === 'ok');
      assert.equal(result.request_id, reply.request_id);
      assert.equal(result.data.query_observed_at, observedAt);
      assert.equal(result.data.query_expires_at, expiresAt);
      assert.deepEqual(result.provenance, [{ artifactID: config.artifactID, digest: config.version }]);
      const data = result.data;
      assert.equal(data.capture_mode, captureMode);
      assert.equal(result.data_class, raw ? 'raw' : 'extract');
      assert.deepEqual(data.fields, wanted.fields);
      stage = 'rendered';
      const table = panel.getByRole('table', { name: 'Saved packet query rows', exact: true });
      if (data.rows.length) {
        await expect(table).toBeVisible();
        await expect(table.getByRole('row')).toHaveCount(data.rows.length + 1);
        await expect(table.getByRole('columnheader')).toHaveText(data.fields);
        for (const [index, row] of data.rows.entries()) {
          await expect(table.getByRole('row').nth(index + 1).getByRole('cell')).toHaveText(row.map(value => value === null ? 'Unavailable' : String(value)));
        }
      } else await expect(panel.getByText('No matching records were returned within this scan.', { exact: true })).toBeVisible();
      await expect(panel.locator('dt:has-text("Visited saved records") + dd')).toHaveText(data.scanned_packets.toLocaleString('en-US'));
      await expect(panel.locator('dt:has-text("Captured bytes scanned") + dd')).toHaveText(data.scanned_bytes.toLocaleString('en-US'));
      for (const [flag, text] of [['row_limit_reached', 'returned-record limit'], ['scan_limit_reached', 'captured-byte scan limit'], ['output_limit_reached', 'output-size limit']]) {
        if (data[flag]) await expect(panel.getByText(new RegExp(text))).toBeVisible();
      }
      assert.equal(result.truncated, data.row_limit_reached || data.scan_limit_reached || data.output_limit_reached);
      assert(!JSON.stringify(result).includes('synthetic-approved-recording'), 'query has typed numeric/hex output, no plaintext payload');
      process.stderr.write('installed packet query real React fields/rows/zero/null/prefix/scan/limit values checked before SQL terminal join\n');
      terminal = true;
    }
  }
} catch (error) {
  const category = error?.code === 'ERR_ASSERTION' ? 'assertion' : error?.matcherResult ? 'expectation' : error?.name === 'TimeoutError' ? 'timeout' : 'operation';
  process.stderr.write(`installed packet failure stage=${stage} category=${category} pageErrors=${Math.min(8, errors.length)} case=${JSON.stringify(caseDiagnostic ?? null)}\n` + timeline.slice(-30).join('\n') + '\n');
  process.exitCode = 1;
} finally {
  await context.close();
  await browser.close();
  if (complete) event({ kind: 'closed' });
  process.stdin.destroy();
}
