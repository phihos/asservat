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
    '/envelope': '{}', '/utf8': Buffer.from([0xc3, 0x28]),
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
  const cases = { ok: 'complete', error: 'complete', pending: 'complete', empty: 'empty', malformed: 'invalid-json', envelope: 'invalid-envelope', utf8: 'invalid-utf8', partial: 'read-failed', abort: 'read-failed' };
  for (const [kind, expected] of Object.entries(cases)) {
    const pending = page.waitForResponse(response => response.url() === origin + '/' + kind);
    await page.evaluate(path => {
      window.syntheticRequest = new AbortController();
      void fetch(path, { signal: window.syntheticRequest.signal }).then(response => response.text()).catch(() => {});
    }, '/' + kind);
    const response = await pending;
    // Control the fault only after the real response headers were observed.
    if (kind === 'partial') partial.destroy();
    if (kind === 'abort') {
      await page.evaluate(() => window.syntheticRequest.abort());
      partial.destroy();
    }
    const result = await readInstalledHistoryResponse(response);
    assert.equal(result.http, 200);
    assert.equal(result.body, expected);
    assert.equal(result.status, ['ok', 'error', 'pending'].includes(kind) ? kind : 'invalid');
    console.log(`synthetic history case=${kind} http=${result.http} status=${result.status} body=${result.body}`);
  }
  assert.deepEqual(await readInstalledHistoryResponse(null), { http: 0, status: 'unavailable', body: 'unavailable', reply: null });
} finally {
  partial?.destroy();
  await browser?.close();
  server.closeAllConnections();
  await new Promise(resolve => server.close(resolve));
}
