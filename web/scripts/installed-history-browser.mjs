// Actual installed backend and built React; no mocked HTTP responses, grants,
// identity settings or sessions. The Go driver supplies its real HttpOnly
// Keycloak-backed Asservat cookie through this private pipe.
import { chromium, expect } from '@playwright/test';
import assert from 'node:assert/strict';
import { createInterface } from 'node:readline';
import { parseInstalledHistoryText, readInstalledHistoryResponse } from './installed-history-response.mjs';

const lines = createInterface({ input: process.stdin, crlfDelay: Infinity })[Symbol.asyncIterator]();
const first = await lines.next();
assert(!first.done && Buffer.byteLength(first.value) <= 16 * 1024);
const config = JSON.parse(first.value);
const origin = new URL(config.origin);
assert.equal(origin.protocol, 'https:');
assert.equal(new URL(config.proxy).hostname, '127.0.0.1');
assert.match(config.sourceCaptureID, /^[0-9a-f-]{36}$/);
const browser = await chromium.launch({ headless: true, proxy: { server: config.proxy, bypass: '<-loopback>' }, ...(process.env.ASSERVAT_CHROMIUM ? { executablePath: process.env.ASSERVAT_CHROMIUM } : {}) });
const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 } });
await context.addCookies(config.cookies);
config.cookies = [];
// Chromium can report net::ERR_ABORTED for a 200 operation reply that the
// console had already read completely: the console continued with the data
// (native run 41535385808: list_diagnostics "failed" and the console then
// requested the history list). Keep the text the page itself received, keyed
// by path and request body, so such a reply is still observed. In-page only;
// never printed.
await context.addInitScript(() => {
  const original = window.fetch.bind(window);
  const replies = new Map();
  Object.defineProperty(window, '__installedReplies', { value: replies });
  window.fetch = async (input, init) => {
    const response = await original(input, init);
    const path = new URL(typeof input === 'string' ? input : input.url, location.href).pathname;
    if (path.startsWith('/api/v1/operations/') && response.status === 200) {
      const key = path + '\n' + (typeof init?.body === 'string' ? init.body : '');
      response.clone().text().then(text => replies.set(key, text), () => {});
    }
    return response;
  };
});
const page = await context.newPage();
const errors = [];
page.on('pageerror', error => errors.push(error.message));
const operation = name => response => new URL(response.url()).pathname === '/api/v1/operations/' + name;
// Observe each response under the existing Playwright network bound. Attach
// rejection handling when arming: early failure of the first operation still
// closes the browser in finally without an unhandled second waiter rejection.
// The console may abort an operation it supersedes (net::ERR_ABORTED) and
// request it again; observe the first response of an operation that was not
// aborted by the page, starting from the moment the wait is armed.
const seen = [];
page.on('response', response => seen.push(response));
// Failure timeline of the console's own API calls: path, status and Chromium's
// net error token with elapsed milliseconds only; never bodies or headers.
const started = Date.now();
const timeline = [];
const apiPath = request => { const path = new URL(request.url()).pathname; return path.startsWith('/api/') ? path : null; };
page.on('request', request => { const path = apiPath(request); if (path) timeline.push(`+${Date.now() - started}ms request ${request.method()} ${path}`); });
page.on('response', response => { const path = apiPath(response.request()); if (path) timeline.push(`+${Date.now() - started}ms response ${response.status()} ${path}`); });
page.on('requestfailed', request => { const path = apiPath(request); if (path) timeline.push(`+${Date.now() - started}ms failed ${/^net::ERR_[A-Z_]+$/.exec(request.failure()?.errorText ?? '')?.[0] ?? 'other'} ${path}`); });
async function settled(name, from) {
  const end = Date.now() + 30_000;
  for (let i = from; Date.now() < end;) {
    if (i >= seen.length) { await new Promise(resolve => setTimeout(resolve, 100)); continue; }
    const response = seen[i++];
    if (!operation(name)(response)) continue;
    const read = await readInstalledHistoryResponse(response);
    // A non-200 reply is final: the console cancels its body on purpose,
    // which Chromium also reports as ERR_ABORTED (native run 41529848773:
    // a 503 preview was skipped and the wait ended with no response).
    if (read.requestFailed && read.readFailure.includes('ERR_ABORTED') && response.status() === 200) {
      const consumed = await pageReply(response);
      if (consumed === null) continue; // superseded by the page before it was read
      return { pageConsumed: parseInstalledHistoryText(200, consumed), status: () => 200 };
    }
    return response;
  }
  return null;
}
// Arming clears this operation's cached page replies, and a read consumes its
// entry: a retried identical request never reads an earlier attempt's text.
const waitOperation = name => {
  const from = seen.length;
  const cleared = page.evaluate(prefix => { for (const k of [...window.__installedReplies.keys()]) if (k.startsWith(prefix)) window.__installedReplies.delete(k); }, '/api/v1/operations/' + name + '\n');
  return cleared.then(() => settled(name, from));
};
async function pageReply(response) {
  const key = new URL(response.url()).pathname + '\n' + (response.request().postData() ?? '');
  for (const end = Date.now() + 2_000; Date.now() < end;) {
    const text = await page.evaluate(k => { const v = window.__installedReplies.get(k) ?? null; window.__installedReplies.delete(k); return v; }, key);
    if (text !== null) return text;
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  return null;
}
const readSettled = response => response?.pageConsumed ? Promise.resolve({ ...response.pageConsumed, readFailure: 'page-consumed' }) : readInstalledHistoryResponse(response);
const closedCodes = new Set(['NotAvailable', 'ParametersUnavailable', 'ProfileChanged', 'RequiresSelection', 'RecorderUnavailable', 'InvalidComposition', 'ProfileUnavailable', 'FilterRejected', 'ApprovalRequired', 'FilterCompilerUnavailable', 'UnsupportedRequest', 'SharingNotPermitted', 'TargetReplaced', 'ProcessingCoverageUnavailable', 'CapacityUnavailable']);
async function readOperation(name, pending) {
  const response = await pending;
  const { http, reply, status, body, readFailure = 'none', requestFailed = false } = await readSettled(response);
  // Never stringify settings, bodies, identities, credentials or provider text.
  const code = status === 'ok' ? 'none' : status === 'error' && closedCodes.has(reply?.data?.code) ? reply.data.code : 'other';
  const diagnostic = `installed history ${name} http=${http} status=${status} code=${code} body=${body} readFailure=${readFailure} requestFailed=${requestFailed}`;
  process.stderr.write(diagnostic + '\n');
  assert.equal(http, 200, diagnostic);
  assert.equal(status, 'ok', diagnostic);
  return reply;
}
try {
  await page.goto(config.origin + '/captures/new');
  await expect(page.getByRole('heading', { name: 'Collect evidence', exact: true })).toBeVisible();
  assert.equal(await page.evaluate(() => document.cookie), '');
  assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
  await page.getByLabel('Cluster ID', { exact: true }).fill(config.target.cluster_id);
  await page.getByLabel('Namespace', { exact: true }).fill(config.target.namespace);
  await page.getByLabel('Workload or pod name', { exact: true }).fill(config.target.name);
  // discover awaits diagnostics and then history; a row's five-second DOM
  // assertion must not also time those two serial public operations.
  const diagnosticsResponse = waitOperation('list_diagnostics');
  const historyResponse = waitOperation('list_capture_history');
  await page.getByRole('button', { name: 'Find diagnostics', exact: true }).click();
  await readOperation('list_diagnostics', diagnosticsResponse);
  await readOperation('list_capture_history', historyResponse);
  const row = page.getByRole('listitem').filter({ has: page.locator('a[href="/captures/' + config.sourceCaptureID + '"]') });
  await expect(row).toHaveCount(1);
  // A transient 503 on the repeat preview (a standby reopening right after
  // the source capture) is retried like a user would: the failed review
  // clears the loaded settings, so reopen them, re-enter the edits and
  // review again. The MCP paths retry this as well. At most three attempts.
  let settings;
  let preview;
  for (let attempt = 1; ; attempt++) {
    const [settingsResponse] = await Promise.all([waitOperation('get_capture_settings'), row.getByRole('button', { name: 'View settings', exact: true }).click()]);
    settings = await readOperation('get_capture_settings', settingsResponse);
    assert.equal(settings.data.capture_id, config.sourceCaptureID);
    await expect(page.getByRole('heading', { name: 'Saved settings', exact: true })).toBeVisible();
    await page.getByLabel('network / sample / packetFilter', { exact: true }).fill('tcp dst port 8080');
    await page.getByLabel('network / sample / packetAfter', { exact: true }).fill('3s');
    const [previewResponse] = await Promise.all([waitOperation('preview_capture'), page.getByRole('button', { name: 'Review these settings', exact: true }).click()]);
    if (attempt < 3 && previewResponse && previewResponse.status() === 503) {
      process.stderr.write(`installed history preview_capture http=503 attempt=${attempt}; retrying\n`);
      await page.waitForTimeout(2000);
      continue;
    }
    // ParametersUnavailable is the product's retryable answer when the saved
    // settings could not be read this time (a regional exchange failed).
    if (attempt < 3 && previewResponse && (await readSettled(previewResponse)).reply?.data?.code === 'ParametersUnavailable') {
      process.stderr.write(`installed history preview_capture ParametersUnavailable attempt=${attempt}; retrying\n`);
      await page.waitForTimeout(2000);
      continue;
    }
    preview = await readOperation('preview_capture', previewResponse);
    break;
  }
  assert.equal(preview.data.repeated_from_capture_id, config.sourceCaptureID);
  assert.equal(preview.data.approval_required, true);
  assert.deepEqual(preview.data.profile_composition.authored.components.map(component => component.profileRef), settings.data.settings.profile_composition.authored.components.map(component => component.profileRef));
  const edits = preview.data.profile_composition.authored.components[0].overrides;
  assert(edits.some(edit => edit.field === 'packetFilter' && edit.value === 'tcp dst port 8080'));
  assert(edits.some(edit => edit.field === 'packetAfter' && edit.value === '3s'));
  await page.getByRole('button', { name: 'Request approval', exact: true }).click();
  const approval = page.getByRole('link', { name: 'View approval', exact: true });
  await expect(approval).toBeVisible();
  const grantID = new URL(await approval.getAttribute('href'), config.origin).pathname.split('/').at(-1);
  process.stdout.write(JSON.stringify({ Kind: 'review', GrantID: grantID, PreviewID: preview.data.preview_id, Digest: preview.data.execution_digest }) + '\n');
  const command = await lines.next();
  assert(!command.done && command.value === 'approved');
  await page.getByRole('button', { name: 'Continue after approval', exact: true }).click();
  await page.waitForURL(/\/captures\/[0-9a-f-]{36}$/, { timeout: 45_000 });
  const captureID = new URL(page.url()).pathname.split('/').at(-1);
  assert.notEqual(captureID, config.sourceCaptureID);
  const end = Date.now() + 180_000;
  while (Date.now() < end && !await page.getByText('Collection complete', { exact: true }).isVisible()) {
    const continuation = page.getByRole('button', { name: 'Continue collection', exact: true });
    if (await continuation.isVisible()) await continuation.click();
    const refresh = page.getByRole('button', { name: 'Check status', exact: true });
    if (await refresh.isVisible()) await refresh.click();
    await page.waitForTimeout(2000);
  }
  await expect(page.getByText('Collection complete', { exact: true })).toBeVisible();
  assert.deepEqual(errors, []);
  assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
  process.stdout.write(JSON.stringify({ Kind: 'captured', GrantID: grantID, PreviewID: preview.data.preview_id, Digest: preview.data.execution_digest, CaptureID: captureID, SettingsDigest: settings.data.settings_digest, SourceExpiresAt: settings.data.expires_at }) + '\n');
} catch (error) {
  process.stderr.write('installed history API timeline:\n' + timeline.slice(-60).join('\n') + '\n');
  throw error;
} finally {
  await context.close();
  await browser.close();
  process.stdin.destroy();
}
