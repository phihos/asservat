// Synthetic loopback HTTP and real Chromium; no installed backend or credentials.
import { createServer } from 'node:http';
import assert from 'node:assert/strict';
import { chromium } from '@playwright/test';
import { readInstalledHistoryResponse } from './installed-history-response.mjs';

let partial;
const server = createServer((req, res) => {
  if (req.url === '/') { res.end('<!doctype html><title>synthetic</title>'); return; }
  res.setHeader('Content-Type', 'application/json');
  if (req.url === '/partial' || req.url === '/abort') {
    res.setHeader('Content-Length', '200');
    res.flushHeaders(); res.write('{"status":'); partial = res; return;
  }
  const bodies = {
    '/ok': '{"status":"ok","data":{}}', '/error': '{"status":"error"}',
    '/pending': '{"status":"pending"}', '/empty': '', '/malformed': '{',
    '/navigate': '{"status":"ok","data":{}}', '/envelope': '{}', '/utf8': Buffer.from([0xc3, 0x28]),
  };
  res.end(bodies[req.url]);
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
let browser;
try {
  browser = await chromium.launch({ headless: true, ...(process.env.ASSERVAT_CHROMIUM ? { executablePath: process.env.ASSERVAT_CHROMIUM } : {}) });
  const page = await browser.newPage();
  const origin = `http://127.0.0.1:${server.address().port}`;
  await page.goto(origin);
  const cases = { ok: 'complete', error: 'complete', pending: 'complete', empty: 'empty', malformed: 'invalid-json', envelope: 'invalid-envelope', utf8: 'invalid-utf8', partial: 'read-failed', abort: 'read-failed', navigate: 'read-failed' };
  for (const [kind, expected] of Object.entries(cases)) {
    const pending = page.waitForResponse(response => response.url() === origin + '/' + kind);
    await page.evaluate(path => {
      window.syntheticRequest = new AbortController();
      window.syntheticCompletion = fetch(path, { signal: window.syntheticRequest.signal }).then(async response => ({ ok: true, bytes: (await response.text()).length })).catch(() => ({ ok: false, bytes: 0 }));
    }, '/' + kind);
    const response = await pending;
    // Control the fault only after the real response headers were observed.
    if (kind === 'partial') partial.destroy();
    if (kind === 'abort') {
      await page.evaluate(() => window.syntheticRequest.abort());
      partial.destroy();
    }
    if (kind === 'navigate') {
      const completed = await page.evaluate(() => window.syntheticCompletion);
      assert.equal(completed.ok, true);
      assert(completed.bytes > 0);
      await page.goto(origin);
    }
    const result = await readInstalledHistoryResponse(response);
    assert.equal(result.http, 200);
    assert.equal(result.body, expected);
    assert.equal(result.status, ['ok', 'error', 'pending'].includes(kind) ? kind : 'invalid');
    if (kind === 'partial' || kind === 'abort') {
      assert.equal(result.requestFailed, true);
      assert.equal(result.readFailure, 'network-failed');
    } else if (kind === 'navigate') {
      assert.equal(result.requestFailed, false);
      assert.equal(result.readFailure, 'inspector-no-resource');
    }
    console.log(`synthetic history case=${kind} http=${result.http} status=${result.status} body=${result.body} readFailure=${result.readFailure ?? 'none'} requestFailed=${result.requestFailed ?? false}`);
  }
  assert.deepEqual(await readInstalledHistoryResponse(null), { http: 0, status: 'unavailable', body: 'unavailable', reply: null });
} finally {
  partial?.destroy();
  await browser?.close();
  server.closeAllConnections();
  await new Promise(resolve => server.close(resolve));
}

// Closed classifier branches: no exception or request failure text is returned.
for (const [message, failed, expected] of [
  ['Protocol error (Network.getResponseBody): Request content was evicted from inspector cache', false, 'inspector-evicted'],
  ['Protocol error (Network.getResponseBody): No data found for resource with given identifier', false, 'inspector-no-data'],
  ['Protocol error (Network.getResponseBody): No resource with given identifier found', false, 'inspector-no-resource'],
  ['synthetic private exception content', false, 'other'],
  ['Protocol error (Network.getResponseBody): No data found for resource with given identifier', true, 'network-failed'],
]) {
  const response = { status: () => 200, body: async () => { throw new Error(message); }, request: () => ({ failure: () => failed ? { errorText: 'synthetic private failure content' } : null }) };
  assert.deepEqual(await readInstalledHistoryResponse(response), { http: 200, status: 'invalid', body: 'read-failed', reply: null, requestFailed: failed, readFailure: expected });
}
