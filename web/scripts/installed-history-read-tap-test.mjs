// Synthetic loopback fixture and real production postOperation/Chromium. No provider.
import { createServer } from 'node:http';
import { build } from 'vite';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
import { chromium, expect } from '@playwright/test';
import { installHistoryReadTap, readHistoryAppResponse } from './installed-history-read-tap.mjs';

const built = await build({ configFile: false, logLevel: 'silent', build: { write: false, minify: false, lib: { entry: fileURLToPath(new URL('../src/capture/http.ts', import.meta.url)), formats: ['es'] } } });
const bundle = (Array.isArray(built) ? built[0] : built).output[0].code;
const valid = JSON.stringify({ schema_version:'mcp-result/v1', request_id:'00000000-0000-4000-8000-000000000099', narrowing_hint:null, warnings:[], provenance:[], status: 'ok', data_class: 'metadata', truncated: false, next_cursor: null, data: { kind: 'captureHistoryPage', history: [], ordering: 'acceptedAtDescCaptureIDDesc' } });
let mode = 'normal', requests = 0;
const partials = new Set();
const server = createServer((req, res) => {
  if (req.url === '/') { res.end(`<script type="module">import {operations} from '/client.js';window.start=()=>{window.abort=new AbortController();window.result=operations.call('list_capture_history',{target_ref:{cluster_id:'00000000-0000-4000-8000-000000000001',namespace:'application',kind:'Deployment',name:'api'},origin:'all',limit:10},'synthetic',window.abort.signal).then(x=>{document.querySelector('#ready').hidden=false;return {ok:x.status==='ok'};}).catch(()=>({ok:false}));};</script><div id="ready" hidden>Ready</div>`); return; }
  if (req.url === '/client.js') { res.setHeader('Content-Type', 'text/javascript'); res.end(bundle); return; }
  if (req.url === '/auth/probe') { res.end('synthetic ignored route'); return; }
  assert.equal(req.url, '/api/v1/operations/list_capture_history');
  requests++;
  res.setHeader('Content-Type', mode === 'headers' ? 'text/plain' : 'application/json');
  if (['partial', 'abort', 'duplicate'].includes(mode)) {
    res.writeHead(200); res.write('{"status":'); partials.add(res); res.on('close', () => partials.delete(res)); return;
  }
  const body = mode === 'malformed' ? '{' : mode === 'schema' ? valid.replace('captureHistoryPage', 'wrong') : mode === 'over-limit' ? 'x'.repeat(32_769) : mode === 'empty' ? '' : mode === 'utf8' ? Buffer.from([0xc3, 0x28]) : valid;
  res.end(body);
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const browser = await chromium.launch({ headless: true });
try {
  const context = await browser.newContext();
  // Count actual APP reader calls and forbid alternate body acquisition. The tap
  // is installed afterward, so an extra read/clone/tee would trip this control.
  await context.addInitScript(() => {
    window.readerCounts = { gets: 0, reads: 0, cancels: 0, releases: 0 };
    const fetch = window.fetch;
    window.fetch = async function(...args) {
      const response = await fetch.apply(this, args);
      response.clone = () => { throw Error('clone forbidden'); };
      if (response.body) {
        response.body.tee = () => { throw Error('tee forbidden'); };
        const get = response.body.getReader;
        response.body.getReader = function(...args) {
          window.readerCounts.gets++;
          if (window.throwReader) throw Error('synthetic getReader failure');
          const reader = get.apply(this, args);
          for (const [method, key] of [['read', 'reads'], ['cancel', 'cancels'], ['releaseLock', 'releases']]) {
            const fn = reader[method];
            reader[method] = function(...args) { window.readerCounts[key]++; return fn.apply(this, args); };
          }
          return reader;
        };
      }
      return response;
    };
  });
  await context.addInitScript(installHistoryReadTap);
  const page = await context.newPage();
  const origin = `http://127.0.0.1:${server.address().port}`;
  await page.goto(origin);
  await page.waitForFunction(() => typeof window.start === 'function');
  const cases = { normal: 'complete', headers: 'headers', malformed: 'invalid-json', schema: 'invalid-envelope', 'over-limit': 'over-limit', empty: 'empty', utf8: 'invalid-json', partial: 'read-failed', abort: 'read-failed', 'reader-error': 'read-failed' };
  for (const [kind, expected] of Object.entries(cases)) {
    mode = kind;
    await page.evaluate(kind => { window.throwReader = kind === 'reader-error'; }, kind);
    const before = requests;
    const countsBefore = await page.evaluate(() => ({ ...window.readerCounts }));
    const pending = page.waitForResponse(r => new URL(r.url()).pathname === '/api/v1/operations/list_capture_history');
    await page.evaluate(() => { document.querySelector('#ready').hidden = true; window.start(); });
    const response = await pending;
    if (kind === 'abort') await page.evaluate(() => window.abort.abort());
    if (kind === 'partial') for (const res of partials) res.destroy();
    const observed = await readHistoryAppResponse(page, 'list_capture_history', response);
    const consumer = await page.evaluate(() => window.result);
    assert.equal(requests, before + 1);
    assert.equal(observed.body, expected);
    assert.equal(consumer.ok, kind === 'normal');
    assert.equal(await page.locator('#ready').isVisible(), kind === 'normal');
    const counts = await page.evaluate(() => window.readerCounts);
    assert.equal(counts.gets - countsBefore.gets, kind === 'headers' ? 0 : 1);
    // Existing postOperation may have cancel() reject after a stream error,
    // preventing its subsequent releaseLock. The tap must not add a release.
    if (kind === 'partial' || kind === 'abort') assert(counts.releases - countsBefore.releases <= 1);
    else assert.equal(counts.releases - countsBefore.releases, ['headers', 'reader-error'].includes(kind) ? 0 : 1);
    if (kind === 'normal') {
      assert.equal(counts.reads - countsBefore.reads, 2); // one chunk + EOF; tap adds none
      // Body evidence cannot substitute for the driver's independent UI witness.
      await page.locator('#ready').evaluate(el => { el.hidden = true; });
      await assert.rejects(expect(page.locator('#ready')).toBeVisible({ timeout: 100 }));
    }
    console.log(`app-reader control=${kind} observed=${observed.body} clientOK=${consumer.ok}`);
  }
  const ignored = await page.evaluate(async () => { await (await fetch('/auth/probe', { method: 'POST' })).text(); return window.__asservatHistoryReadTap.ready('auth/probe'); });
  assert.equal(ignored, false);
  mode = 'duplicate';
  await page.evaluate(() => { window.throwReader = false; });
  await page.evaluate(() => { window.start(); window.first = window.result; window.firstAbort = window.abort; window.start(); });
  await page.waitForFunction(() => window.__asservatHistoryReadTap.ready('list_capture_history'));
  const duplicate = await page.evaluate(() => window.__asservatHistoryReadTap.take('list_capture_history'));
  assert.equal(duplicate.state, 'duplicate'); assert.equal(duplicate.bytes, null);
  await page.evaluate(() => { window.firstAbort.abort(); window.abort.abort(); });
  assert.equal((await page.evaluate(() => window.first)).ok, false);
  assert.equal((await page.evaluate(() => window.result)).ok, false);
  await page.evaluate(() => window.__asservatHistoryReadTap.clear());
  console.log('app-reader duplicate refused; independent UI-negative refused');
  await context.close();
} finally {
  for (const res of partials) res.destroy();
  await browser.close();
  server.closeAllConnections();
  await new Promise(resolve => server.close(resolve));
}
