// Actual installed backend and built React; no mocked HTTP responses, grants,
// identity settings or sessions. The Go driver supplies its real HttpOnly
// Keycloak-backed Asservat cookie through this private pipe.
import { chromium, expect } from '@playwright/test';
import assert from 'node:assert/strict';
import { createInterface } from 'node:readline';
import { readInstalledHistoryResponse } from './installed-history-response.mjs';

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
const page = await context.newPage();
const errors = [];
page.on('pageerror', error => errors.push(error.message));
const operation = name => response => new URL(response.url()).pathname === '/api/v1/operations/' + name;
// Observe each response under the existing Playwright network bound. Attach
// rejection handling when arming: early failure of the first operation still
// closes the browser in finally without an unhandled second waiter rejection.
const waitOperation = name => page.waitForResponse(operation(name)).catch(() => null);
const closedCodes = new Set(['NotAvailable', 'ParametersUnavailable', 'ProfileChanged', 'RequiresSelection', 'RecorderUnavailable', 'InvalidComposition', 'ProfileUnavailable', 'FilterRejected', 'ApprovalRequired', 'FilterCompilerUnavailable', 'UnsupportedRequest', 'SharingNotPermitted', 'TargetReplaced', 'ProcessingCoverageUnavailable', 'CapacityUnavailable']);
async function readOperation(name, pending) {
  const response = await pending;
  const { http, reply, status, body, readFailure = 'none', requestFailed = false, networkFailure = 'none' } = await readInstalledHistoryResponse(response);
  // Never stringify settings, bodies, identities, credentials or provider text.
  const code = status === 'ok' ? 'none' : status === 'error' && closedCodes.has(reply?.data?.code) ? reply.data.code : 'other';
  const diagnostic = `installed history ${name} http=${http} status=${status} code=${code} body=${body} readFailure=${readFailure} requestFailed=${requestFailed} networkFailure=${networkFailure}`;
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
  const [settingsResponse] = await Promise.all([waitOperation('get_capture_settings'), row.getByRole('button', { name: 'View settings', exact: true }).click()]);
  const settings = await readOperation('get_capture_settings', settingsResponse);
  assert.equal(settings.data.capture_id, config.sourceCaptureID);
  await expect(page.getByRole('heading', { name: 'Saved settings', exact: true })).toBeVisible();
  await page.getByLabel('network / sample / packetFilter', { exact: true }).fill('tcp dst port 8080');
  await page.getByLabel('network / sample / packetAfter', { exact: true }).fill('3s');
  const [previewResponse] = await Promise.all([waitOperation('preview_capture'), page.getByRole('button', { name: 'Review these settings', exact: true }).click()]);
  const preview = await readOperation('preview_capture', previewResponse);
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
} finally {
  await context.close();
  await browser.close();
  process.stdin.destroy();
}
