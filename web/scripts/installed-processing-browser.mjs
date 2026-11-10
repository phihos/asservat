// Private bounded stdin carries the existing HttpOnly session to the actual
// browser; stdout reports only content-minimized processing receipts/inputs.
import { chromium } from '@playwright/test';
import assert from 'node:assert/strict';
import { createInterface } from 'node:readline';
import { processingJourney } from '../tests/processing-journey.mjs';
const lines = createInterface({ input: process.stdin, crlfDelay: Infinity })[Symbol.asyncIterator]();
async function command() {
  const next = await lines.next();
  assert(!next.done && Buffer.byteLength(next.value) <= 16384, 'bounded private command');
  return JSON.parse(next.value);
}
const config = await command();
assert.equal(new URL(config.origin).protocol, 'https:');
if (config.proxy) assert.equal(new URL(config.proxy).hostname, '127.0.0.1');
assert.match(config.artifactID, /^[0-9a-f-]{36}$/);
const browser = await chromium.launch({ headless: true, ...(config.proxy ? { proxy: { server: config.proxy, bypass: '<-loopback>' } } : {}), ...(process.env.ASSERVAT_CHROMIUM ? { executablePath: process.env.ASSERVAT_CHROMIUM } : {}) });
let stage = 'session';
try {
  const context = await browser.newContext({ ignoreHTTPSErrors: true, acceptDownloads: false, locale: 'en-US', viewport: { width: 1440, height: 900 } });
  await context.addCookies(config.cookies); config.cookies = [];
  const page = await context.newPage(), errors = [];
  page.on('pageerror', () => errors.push('pageerror'));
  const observe = kind => async value => {
    stage = kind;
    const line = JSON.stringify({ kind, ...value }); assert(Buffer.byteLength(line) < 16384);
    process.stdout.write(line + '\n'); assert.deepEqual(await command(), { continue: true });
  };
  stage = 'processing';
  await processingJourney({ page, origin: config.origin, artifactID: config.artifactID, casePath: config.casePath, restricted: observe('restricted'), released: observe('released'), stage: value => { stage = value; } });
  assert.deepEqual(errors, []);
  process.stdout.write(JSON.stringify({ kind: 'complete' }) + '\n');
} catch (error) {
  process.stdout.write(JSON.stringify({ kind: 'failed', stage, reason: error?.name ?? 'Error', check: error?.message?.split('\n')[0]?.slice(0, 160) }) + '\n'); process.exitCode = 1;
} finally { await browser.close(); }
