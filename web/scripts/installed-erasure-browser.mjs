// Bounded private stdin supplies only the existing browser session and target.
// Stdout carries minimized evidence, receipt and status facts for SQL readback.
import assert from 'node:assert/strict';
import { createInterface } from 'node:readline';
import { chromium } from '@playwright/test';
import { erasureJourney, erasureUUID } from '../tests/erasure-journey.mjs';

const lines = createInterface({ input: process.stdin, crlfDelay: Infinity })[Symbol.asyncIterator]();
async function command() {
  const next = await lines.next();
  assert(!next.done && Buffer.byteLength(next.value) <= 16384, 'bounded private command');
  return JSON.parse(next.value);
}
function event(value) {
  const line = JSON.stringify(value);
  assert(Buffer.byteLength(line) < 16384, 'bounded summary');
  process.stdout.write(line + '\n');
}

let browser, stage = 'session';
try {
  const config = await command();
  const origin = new URL(config.origin);
  assert(origin.protocol === 'https:' && origin.origin === config.origin, 'exact HTTPS origin');
  if (config.proxy) assert.equal(new URL(config.proxy).hostname, '127.0.0.1', 'loopback fixture proxy');
  assert(erasureUUID.test(config.artifactID) && config.casePath?.startsWith('/cases/') &&
    erasureUUID.test(config.casePath.slice('/cases/'.length)), 'exact case and artifact identifiers');
  browser = await chromium.launch({ headless: true, ...(config.proxy ? { proxy: { server: config.proxy, bypass: '<-loopback>' } } : {}),
    ...(process.env.ASSERVAT_CHROMIUM ? { executablePath: process.env.ASSERVAT_CHROMIUM } : {}) });
  const context = await browser.newContext({ ignoreHTTPSErrors: true, acceptDownloads: false, locale: 'en-US', viewport: { width: 1440, height: 900 } });
  await context.addCookies(config.cookies);
  config.cookies = [];
  const page = await context.newPage(), errors = [];
  page.setDefaultTimeout(15000);
  page.on('pageerror', () => errors.push('pageerror'));
  const pause = kind => async value => {
    stage = kind;
    event({ kind, ...value });
    assert.deepEqual(await command(), { continue: true }, 'independent fixture check');
  };
  await erasureJourney({ page, origin: config.origin, artifactID: config.artifactID, casePath: config.casePath,
    accepted: pause('accepted'), pending: pause('pending'), verified: value => event({ kind: 'verified', ...value }),
    stage: value => { stage = value; } });
  assert.deepEqual(errors, []);
  event({ kind: 'complete' });
} catch (error) {
  event({ kind: 'failed', stage, reason: error?.name ?? 'Error', check: error?.message?.split('\n')[0]?.slice(0, 160) });
  process.exitCode = 1;
} finally {
  await browser?.close();
}
