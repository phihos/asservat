import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { join, isAbsolute } from 'node:path';
import { createInterface } from 'node:readline';
import { chromium } from '@playwright/test';
import { processingReportJourney } from '../tests/processing-report-journey.mjs';

const lines = createInterface({ input: process.stdin, crlfDelay: Infinity })[Symbol.asyncIterator]();
async function command() {
  const next = await lines.next();
  assert(!next.done && Buffer.byteLength(next.value) < 16384, 'bounded private browser command');
  return JSON.parse(next.value);
}
function event(value) {
  const line = JSON.stringify(value);
  assert(Buffer.byteLength(line) < 65536, 'bounded report export summary');
  process.stdout.write(line + '\n');
}
let browser, stage = 'session';
try {
  const config = await command(), origin = new URL(config.origin);
  assert(origin.protocol === 'https:' && origin.origin === config.origin, 'exact HTTPS origin');
  assert(isAbsolute(config.outputDirectory), 'owned absolute export directory');
  if (config.proxy) assert.equal(new URL(config.proxy).hostname, '127.0.0.1', 'loopback fixture proxy');
  browser = await chromium.launch({ headless: true, ...(config.proxy ? { proxy: { server: config.proxy, bypass: '<-loopback>' } } : {}),
    ...(process.env.ASSERVAT_CHROMIUM ? { executablePath: process.env.ASSERVAT_CHROMIUM } : {}) });
  const context = await browser.newContext({ ignoreHTTPSErrors: true, acceptDownloads: true, locale: 'en-US', viewport: { width: 1440, height: 900 } });
  await context.addCookies(config.cookies); config.cookies = [];
  const page = await context.newPage(), errors = [];
  page.setDefaultTimeout(15000);
  page.on('pageerror', () => errors.push('pageerror'));
  await processingReportJourney({
    page, origin: config.origin, stage: value => { stage = value; },
    exported: async (summary, _document, body) => {
      const file = 'processing-report-' + summary.part + '.json';
      await writeFile(join(config.outputDirectory, file), body, { flag: 'wx', mode: 0o600 });
      event({ kind: 'exported', file, ...summary });
      assert.deepEqual(await command(), { continue: true }, 'independent export readback');
    },
  });
  assert.deepEqual(errors, []);
  event({ kind: 'complete' });
} catch (error) {
  event({ kind: 'failed', stage, reason: error?.name ?? 'Error', check: error?.message?.split('\n')[0]?.slice(0, 160) });
  process.exitCode = 1;
} finally { await browser?.close(); }
