// Real Chromium and an owned CONNECT tunnel to a synthetic Go TLS server.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { connect } from 'node:net';
import { chromium } from '@playwright/test';
import { captureProcessingReportResponses } from '../tests/processing-report-journey.mjs';

const target = new URL(process.argv[2]), expectedDigest = process.argv[3], expectedBytes = Number(process.argv[4]);
assert.equal(target.hostname, '127.0.0.1', 'owned loopback upstream');
const origin = 'https://report.synthetic.invalid', path = '/api/v1/operations/get_processing_report';
const sockets = new Set();
let tunnels = 0, browser, observation;
const proxy = createServer((_request, reply) => reply.writeHead(502).end());
proxy.on('connection', socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
proxy.on('connect', (request, client, head) => {
  assert.equal(request.url, 'report.synthetic.invalid:443', 'closed CONNECT destination');
  tunnels++;
  const upstream = connect(Number(target.port), '127.0.0.1', () => {
    client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    if (head.length) upstream.write(head);
    client.pipe(upstream); upstream.pipe(client);
  });
  sockets.add(upstream);
  upstream.on('close', () => sockets.delete(upstream));
  upstream.on('error', () => client.destroy()); client.on('error', () => upstream.destroy());
});
await new Promise(resolve => proxy.listen(0, '127.0.0.1', resolve));
try {
  browser = await chromium.launch({ headless: true, proxy: { server: `http://127.0.0.1:${proxy.address().port}`, bypass: '<-loopback>' },
    ...(process.env.ASSERVAT_CHROMIUM ? { executablePath: process.env.ASSERVAT_CHROMIUM } : {}) });
  const context = await browser.newContext({ ignoreHTTPSErrors: true, acceptDownloads: true });
  await context.addCookies([{ name: 'synthetic', value: 'original', url: origin, secure: true }]);
  const page = await context.newPage();
  page.setDefaultTimeout(10000);
  observation = await captureProcessingReportResponses(page, origin);
  await page.goto(origin);
  // Change the jar after interception: route.fetch must retain the original
  // browser request Cookie rather than recomputing it from refreshed state.
  await page.route(origin + path, async route => {
    await context.addCookies([{ name: 'synthetic', value: 'changed', url: origin, secure: true }]);
    await route.fallback();
  }, { times: 1 });
  const downloading = page.waitForEvent('download');
  await page.evaluate(async path => {
    const response = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': 'A'.repeat(43) }, body: '{"section":"processors","limit":3}' });
    const body = await response.arrayBuffer(), link = document.createElement('a');
    link.href = URL.createObjectURL(new Blob([body], { type: 'application/json' }));
    link.download = 'synthetic-report.json'; link.click();
  }, path);
  const download = await downloading, chunks = [];
  for await (const chunk of await download.createReadStream()) chunks.push(chunk);
  const body = Buffer.concat(chunks);
  await page.goto(origin); // Deliberately invalidate Chromium's old body cache.
  assert.equal(observation.responses.length, 1, 'one original report response');
  const captured = observation.responses[0];
  assert.equal(body.length, expectedBytes, 'original browser download length');
  assert.equal(createHash('sha256').update(body).digest('hex'), expectedDigest, 'original browser download bytes');
  assert.equal(captured.responseBytes, expectedBytes, 'original capture length');
  assert.equal(createHash('sha256').update(captured.body).digest('hex'), expectedDigest, 'original upstream capture bytes');
  // The Go source truncates this second response. There must be one failure,
  // no automatic retry, and the original capture error must escape close().
  await context.addCookies([{ name: 'synthetic', value: 'original', url: origin, secure: true }]);
  const received = await page.evaluate(path => fetch(path, {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': 'A'.repeat(43) }, body: '{"section":"processors","limit":3}',
  }).then(response => response.text()).then(() => true, () => false), path);
  assert.equal(received, false, 'truncated response refuses delivery');
  const failure = await observation.failure;
  assert(failure instanceof Error, 'original capture failure is retained');
  const closing = observation.close(); observation = undefined;
  await assert.rejects(closing, error => error === failure, 'capture failure is rethrown after joined cleanup');
  assert(tunnels >= 1, 'browser and pass-through requests use the closed CONNECT proxy');
  console.log('report response capture: original proxied request/bytes survive Blob download and navigation; truncated response fails without replay');
} finally {
  try { await observation?.close(); } finally {
    await browser?.close();
    for (const socket of sockets) socket.destroy();
    await new Promise(resolve => proxy.close(resolve));
  }
}
