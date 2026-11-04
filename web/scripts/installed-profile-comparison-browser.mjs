// Installed image-owned React, original Keycloak-backed HttpOnly cookie.
// The Go owner schedules each existing paid poll; this driver only clicks UI.
import { chromium, expect } from '@playwright/test';
import assert from 'node:assert/strict';
import { createInterface } from 'node:readline';
import { readInstalledHistoryResponse, parseInstalledHistoryText } from './installed-history-response.mjs';

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
const origin = new URL(config.origin);
assert.equal(origin.protocol, 'https:');
assert.equal(new URL(config.proxy).hostname, '127.0.0.1');
assert.match(config.caseID, /^[0-9a-f-]{36}$/);
assert.match(config.artifactID, /^[0-9a-f-]{36}$/);
const browser = await chromium.launch({ headless: true, proxy: { server: config.proxy, bypass: '<-loopback>' }, ...(process.env.ASSERVAT_CHROMIUM ? { executablePath: process.env.ASSERVAT_CHROMIUM } : {}) });
const context = await browser.newContext({ ignoreHTTPSErrors: true, locale: 'en-US', viewport: { width: 1440, height: 900 } });
let stage = 'session';
let complete = false;
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
      if (/^\/api\/v1\/operations\/(compare_profiles|get_query_result)$/.test(path) && response.status === 200) {
        const key = path + '\n' + (typeof init?.body === 'string' ? init.body : '');
        response.clone().text().then(text => { if (text.length <= 24_576) replies.set(key, text); }, () => {});
      }
      return response;
    };
  });
  const page = await context.newPage();
  const errors = [];
  const seen = [];
  let compareRequests = 0;
  let pollRequests = 0;
  page.on('pageerror', () => errors.push('pageerror'));
  page.on('request', request => {
    const path = new URL(request.url()).pathname;
    if (path === '/api/v1/operations/compare_profiles') compareRequests++;
    if (path === '/api/v1/operations/get_query_result') pollRequests++;
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
  async function observed(name, from) {
    const path = '/api/v1/operations/' + name;
    for (let index = from, end = Date.now() + 30_000; Date.now() < end;) {
      if (index >= seen.length) { await page.waitForTimeout(100); continue; }
      const response = seen[index++];
      if (new URL(response.url()).pathname !== path) continue;
      let read = await readInstalledHistoryResponse(response);
      if (read.requestFailed && read.readFailure.includes('ERR_ABORTED') && response.status() === 200) {
        const key = path + '\n' + (response.request().postData() ?? '');
        let text = null;
        for (const until = Date.now() + 2000; Date.now() < until;) {
          text = await page.evaluate(k => { const value = window.__installedReplies.get(k) ?? null; window.__installedReplies.delete(k); return value; }, key);
          if (text !== null) break;
          await page.waitForTimeout(100);
        }
        if (text === null) continue; // Superseded before consumption, no replay.
        read = parseInstalledHistoryText(200, text);
      }
      assert.equal(read.http, 200, 'operation HTTP result');
      assert.equal(read.body, 'complete', 'operation body completion');
      const transport = {
        post: response.request().method() === 'POST',
        sameOrigin: await response.request().headerValue('origin') === config.origin,
        csrf: /^[A-Za-z0-9_-]{43}$/.test(await response.request().headerValue('x-csrf-token') ?? ''),
        noBearer: await response.request().headerValue('authorization') === null,
      };
      return { input: JSON.parse(response.request().postData()), reply: read.reply, transport };
    }
    throw new Error('operation response unavailable');
  }
  stage = 'case';
  await page.goto(config.origin + '/cases/' + config.caseID);
  await expect(page.getByRole('heading', { name: 'Evidence', exact: true })).toBeVisible();
  const panel = page.getByRole('region', { name: 'Saved profile comparison', exact: true });
  await expect(panel).toHaveCount(1, { timeout: 30_000 }); // Two captures are in separate real cases.
  await expect(panel).toBeVisible();
  assert.equal(await page.evaluate(() => document.cookie), '');
  assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
  await panel.getByLabel('Baseline profile', { exact: true }).selectOption(config.artifactID);
  await expect(panel.getByRole('button', { name: 'Compare profiles', exact: true })).toBeEnabled();
  assert.equal(compareRequests + pollRequests, 0, 'no automatic query on case load or selection');
  event({ kind: 'ready' });
  let handle;
  let terminal = false;
  let terminalComparison;
  let calls = 0;
  for (;;) {
    const next = await command();
    if (next.kind === 'close') {
      assert(terminal && compareRequests === 1 && pollRequests <= 4, 'exact original query count');
      await expect(panel.getByRole('table', { name: 'Profile acquisition details', exact: true })).toBeVisible();
      const table = panel.getByRole('table', { name: 'Profile comparison function costs', exact: true });
      await expect(table).toBeVisible();
      await expect(table.getByRole('row')).toHaveCount(terminalComparison.rows.length + 1);
      for (const [index, row] of terminalComparison.rows.entries()) {
        await expect(table.getByRole('row').nth(index + 1).getByRole('cell')).toHaveText([
          row.function ?? 'Unresolved', row.baseline.toLocaleString('en-US'), row.incident.toLocaleString('en-US'), row.delta.toLocaleString('en-US'),
        ]);
      }
      assert.deepEqual(errors, []);
      assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
      complete = true;
      break;
    }
    assert.equal(next.kind, 'call');
    assert(!terminal && ++calls <= 5, 'bounded original query calls');
    const name = calls === 1 ? 'compare_profiles' : 'get_query_result';
    assert.equal(next.name, name);
    const expected = name === 'compare_profiles'
      ? { case_id: config.caseID, artifact_id: config.artifactID, baseline_case_id: config.caseID, baseline_artifact_id: config.artifactID, sample_type: 'cpu', normalization: 'perSecond', top_n: 20 }
      : { query_handle: handle };
    assert.deepEqual(next.input, expected);
    stage = name;
    const button = panel.getByRole('button', { name: calls === 1 ? 'Compare profiles' : 'Check comparison result', exact: true });
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
    }
  }
} catch {
  process.stderr.write(`installed comparison failure stage=${stage}\n` + timeline.slice(-40).join('\n') + '\n');
  process.exitCode = 1;
} finally {
  await context.close();
  await browser.close();
  if (complete) event({ kind: 'closed' });
  process.stdin.destroy();
}
