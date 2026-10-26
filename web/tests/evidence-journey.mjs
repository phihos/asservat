// Run only against the owned Go fixture. Case authority/publication is synthetic;
// UI, static delivery, sessions, CSRF, C16 projection and HTTP routes are real.
import { expect } from '@playwright/test';
import assert from 'node:assert/strict';

export async function evidenceJourney({ page, origin, output, scan, checks, captureControl, control, evidenceLoads }) {
  const caseID = '00000000-0000-4000-8000-000000000080';
  const casePath = '/cases/' + caseID;
  const evidenceControl = async (state, extra = {}) => {
    const response = await page.request.post(origin + '/test/evidence', { headers: { Origin: origin }, data: { state, ...extra } });
    assert.equal(response.status(), 204);
  };
  const nativeRequests = [], browserDownloads = [];
  const requestListener = request => { if (/\/api\/v1\/downloads\/.+\/content$/.test(new URL(request.url()).pathname)) nativeRequests.push(request.url()); };
  const downloadListener = download => browserDownloads.push(download.suggestedFilename());
  page.on('request', requestListener);
  page.on('download', downloadListener);
  try {
    assert.deepEqual(evidenceLoads, [], 'evidence bundle should stay unloaded during capture review/progress');
    await expect(page.getByRole('link', { name: 'View evidence', exact: true })).toHaveCount(0);
    await captureControl('evidence-ready');
    await page.getByRole('button', { name: 'Check status' }).click();
    await expect(page.getByRole('heading', { name: 'Collection complete', exact: true })).toBeVisible();
    await expect(page.getByRole('link', { name: 'View evidence', exact: true })).toHaveAttribute('href', casePath);
    // Navigation and its first real response must succeed. Read the complete
    // wire on an explicit refresh after navigation: Chromium can discard the
    // navigation response's CDP body even when response.json() is called at once.
    const initialReply = page.waitForResponse(response => response.url() === origin + '/api/v1/operations/get_case' && response.request().method() === 'POST')
      .then(response => response.status());
    const [, initialStatus] = await Promise.all([
      page.getByRole('link', { name: 'View evidence', exact: true }).click(),
      initialReply,
    ]);
    await expect(page.getByRole('heading', { name: 'Evidence', exact: true })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Pod status', exact: true })).toBeVisible();
    assert.equal(new URL(page.url()).pathname, casePath);
    assert(evidenceLoads.length >= 1, 'case navigation must load the separate actual evidence bundle');
    assert.equal(initialStatus, 200);
    const caseReply = page.waitForResponse(response => response.url() === origin + '/api/v1/operations/get_case' && response.request().method() === 'POST')
      .then(async response => ({ status: response.status(), wire: await response.json() }));
    const [, response] = await Promise.all([
      page.getByRole('button', { name: 'Refresh evidence details', exact: true }).click(),
      caseReply,
    ]);
    assert.equal(response.status, 200);
    const { wire } = response;
    assert.equal(wire.status, 'ok');
    assert.equal(wire.data.case.access, 'ordinary');
    assert.equal(wire.data.artifacts[0].digest, '09' + '00'.repeat(31));
    assert.equal(wire.data.artifacts[0].handling_notice.expiresAt, wire.data.artifacts[0].expires_at);
    assert.equal(wire.data.artifacts[0].handling_notice.externalCopiesRecallable, false);
    await expect(page.getByText('Approved metadata · complete', { exact: true })).toBeVisible();
    await expect(page.getByText(/May contain user data: personal identifiers, network addresses, paths/)).toBeVisible();
    await expect(page.getByText('Access until', { exact: true })).toBeVisible();
    await expect(page.getByText('Managed deletion', { exact: true })).toBeVisible();
    await expect(page.getByText(/Downloaded copies are outside Asservat's automatic deletion/)).toBeVisible();
    await expect(page.getByText('SHA-256', { exact: true })).toHaveCount(0);
    await expect(page.getByText(wire.data.artifacts[0].digest, { exact: true })).toHaveCount(0);
    await expect(page.getByRole('link', { name: 'Download native file', exact: true })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Download', exact: true })).toBeEnabled();
    await scan('case-evidence-desktop');
    await page.screenshot({ path: output + '/case-evidence.png', fullPage: true });
    await page.setViewportSize({ width: 320, height: 740 });
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
    await scan('case-evidence-mobile');
    await page.screenshot({ path: output + '/case-evidence-mobile.png', fullPage: true });
    checks.push('authorized capture case link; separate lazy bundle; actual C16 wire and user-data/deletion notices; verified artifact version never labeled as native SHA');

    // ADR-232 console sharing through the actual browser route, CSRF,
    // identical Idempotency-Key header and canonical contracts (synthetic service).
    const summary = page.getByText('Share this artifact', { exact: true });
    await summary.click();
    const panel = page.locator('details', { has: summary });
    const preview = panel.getByRole('region', { name: 'What recipients will see' });
    await expect(preview).toBeVisible();
    await expect(preview.getByText('Approved metadata · complete', { exact: true })).toBeVisible();
    await expect(preview.getByText(/Native download, other evidence in this case/)).toBeVisible();
    await panel.getByLabel('Recipient ID').fill('synthetic-recipient');
    await panel.getByRole('button', { name: 'Add recipient', exact: true }).click();
    await panel.getByLabel('Reason').fill('incident review');
    const createReply = page.waitForResponse(r => r.url() === origin + '/api/v1/operations/create_share');
    await panel.getByRole('button', { name: 'Share', exact: true }).click();
    const created = await createReply;
    assert.equal(created.status(), 200);
    const createBody = JSON.parse(created.request().postData());
    assert.equal(created.request().headers()['idempotency-key'], createBody.idempotency_key);
    assert.equal(created.request().headers()['x-csrf-token'].length, 43);
    assert.deepEqual(createBody.artifacts, [{ artifactID: wire.data.artifacts[0].artifact_id, digest: wire.data.artifacts[0].digest }]);
    await expect(panel.getByText(/Shared with 1 recipient until/)).toBeVisible();
    await expect(panel.getByLabel('Case link')).toHaveValue(origin + casePath);
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
    await scan('case-share-panel');
    await summary.click();
    await page.goto(origin + '/shares');
    await expect(page.getByRole('heading', { name: 'Shared evidence', exact: true })).toBeVisible();
    const owned = page.getByRole('region', { name: 'Shared by me' });
    await expect(owned.getByText(/Active · until/)).toBeVisible();
    await expect(page.getByText('Nothing is shared with you right now.', { exact: true })).toBeVisible();
    await scan('shares-page');
    const revokeReply = page.waitForResponse(r => r.url() === origin + '/api/v1/operations/revoke_share');
    await owned.getByRole('button', { name: 'Revoke', exact: true }).click();
    assert.equal((await revokeReply).status(), 200);
    await expect(owned.getByText(/Revoked · until/)).toBeVisible();
    await expect(owned.getByRole('button', { name: 'Revoke', exact: true })).toHaveCount(0);
    await page.goto(origin + casePath);
    await expect(page.getByRole('heading', { name: 'Pod status', exact: true })).toBeVisible();
    checks.push('share panel previews the recipient view and creates one share with CSRF and identical Idempotency-Key; Shares page lists and revokes it');

    await evidenceControl('ready', { expires_in_ms: 2000 });
    const shortExpiryReply = page.waitForResponse(r => r.url() === origin + '/api/v1/operations/get_case');
    await page.getByRole('button', { name: 'Refresh evidence details', exact: true }).click();
    assert.equal((await shortExpiryReply).status(), 200);
    await expect(page.getByRole('button', { name: 'Download', exact: true })).toBeEnabled();
    const idleBefore = await (await page.request.get(origin + '/test/evidence-stats')).json();
    await expect(page.getByText('Evidence access has expired.', { exact: true })).toBeVisible({ timeout: 5000 });
    await expect(page.getByRole('button', { name: 'Download', exact: true })).toHaveCount(0);
    const idleAfter = await (await page.request.get(origin + '/test/evidence-stats')).json();
    assert.equal(idleAfter.case_reads, idleBefore.case_reads, 'expiry must not refresh authority or poll');
    await scan('case-idle-expiry');
    await evidenceControl('ready');
    await page.getByRole('button', { name: 'Refresh evidence details', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Download', exact: true })).toBeEnabled();
    checks.push('idle artifact expiry removes Download and explains expiry without metadata polling or renewing retention');

    // Native worker/session/relay composition is intentionally absent. The
    // real dispatch returns 404, not fabricated Preparing or transfer success.
    const prepareReply = page.waitForResponse(r => r.url() === origin + '/api/v1/operations/prepare_artifact_download');
    await page.getByRole('button', { name: 'Download', exact: true }).click();
    const missing = await prepareReply;
    assert.equal(missing.status(), 404);
    assert.notEqual(missing.headers()['content-type'], 'text/html; charset=utf-8');
    await expect(page.getByRole('alert')).toContainText('unavailable');
    await expect(page.getByRole('button', { name: 'Retry same download request', exact: true })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Preparing the native file', exact: true })).toHaveCount(0);
    await expect(page.getByRole('link', { name: 'Download native file', exact: true })).toHaveCount(0);
    await expect(page.getByText('SHA-256', { exact: true })).toHaveCount(0);
    await scan('native-download-unavailable');
    checks.push('missing native-download runtime produces real unavailable response; original request retained; no invented file checksum, content path or successful transfer');

    const beforeDenied = await (await page.request.get(origin + '/test/evidence-stats')).json();
    await evidenceControl('expired');
    await page.getByRole('button', { name: 'Refresh evidence details', exact: true }).click();
    await expect(page.getByRole('alert')).toContainText('Evidence is not available');
    await expect(page.getByRole('heading', { name: 'Pod status', exact: true })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Download', exact: true })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Check evidence access', exact: true })).toBeVisible();
    const afterDenied = await (await page.request.get(origin + '/test/evidence-stats')).json();
    assert(afterDenied.case_reads > beforeDenied.case_reads);
    await scan('case-expired');
    await evidenceControl('ready');
    await page.getByRole('button', { name: 'Check evidence access', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Pod status', exact: true })).toBeVisible();
    await evidenceControl('revoked');
    await page.getByRole('button', { name: 'Refresh evidence details', exact: true }).click();
    await expect(page.getByRole('alert')).toContainText('Evidence is not available');
    await expect(page.getByRole('heading', { name: 'Pod status', exact: true })).toHaveCount(0);
    await expect(page.getByRole('heading', { name: 'Evidence', exact: true })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Sign in to Asservat', exact: true })).toHaveCount(0);
    await evidenceControl('ready');
    await page.reload();
    await expect(page.getByRole('heading', { name: 'Pod status', exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Download', exact: true })).toBeEnabled();
    assert.equal(new URL(page.url()).pathname, casePath);
    checks.push('expired or revoked case rights clear metadata on actual recheck without claiming session logout; exact case URL reload works through real static allowlist');

    await control('revoked');
    await page.reload();
    await expect(page.getByRole('heading', { name: 'Sign in to Asservat', exact: true })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Pod status', exact: true })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Download', exact: true })).toHaveCount(0);
    await control('ready');
    await page.getByRole('link', { name: 'Sign in', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Pod status', exact: true })).toBeVisible();
    assert.equal(new URL(page.url()).pathname, casePath);
    assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
    assert.deepEqual(nativeRequests, []);
    assert.deepEqual(browserDownloads, []);
    await page.setViewportSize({ width: 1440, height: 1080 });
    checks.push('revoked session removes the evidence workspace; sign-in returns to exact case; no browser persistence or synthetic native transfer');
  } finally {
    page.off('request', requestListener);
    page.off('download', downloadListener);
  }
}
