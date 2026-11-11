import { expect } from '@playwright/test';
import assert from 'node:assert/strict';

export async function fleetJourney({ page, origin, scan = async () => {} }) {
  const originalViewport = page.viewportSize(), requests = [];
  const observe = request => { if (new URL(request.url()).pathname === '/api/v1/fleet/cluster-bootstraps') requests.push(request); };
  page.on('request', observe);
  try {
    await page.getByRole('link', { name: 'Enroll a cluster', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Enroll a cluster', exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Issue bootstrap slot', exact: true })).toBeDisabled();
    assert.equal(requests.length, 0, 'navigation must not issue a slot');
    await page.setViewportSize({ width: 1440, height: 900 });
    await scan('fleet-empty');
    await page.getByLabel('Cluster display name', { exact: true }).fill('Workload cluster');
    await page.getByLabel('Region', { exact: true }).fill('eu-test');
    await page.getByLabel('Delivery profile', { exact: true }).fill('regional-installer');
    assert.equal(requests.length, 0, 'editing must not issue a slot');
    const response = async (button, status) => {
      const reply = page.waitForResponse(r => new URL(r.url()).pathname === '/api/v1/fleet/cluster-bootstraps' && r.request().method() === 'POST');
      await page.getByRole('button', { name: button, exact: true }).click();
      const actual = await reply;
      assert.equal(actual.status(), status, 'actual Fleet HTTP status');
      const request = actual.request(), headers = await request.allHeaders();
      assert.equal(headers.origin, origin); assert.equal(headers['x-csrf-token'], 'C'.repeat(43));
      assert.equal(headers.authorization, undefined); assert.match(headers['idempotency-key'], /^[0-9a-f-]{36}$/);
      assert.deepEqual(request.postDataJSON(), { displayName: 'Workload cluster', region: 'eu-test', deliveryProfile: 'regional-installer' });
      return { actual, key: headers['idempotency-key'] };
    };
    const first = await response('Issue bootstrap slot', 503);
    await expect(page.getByRole('button', { name: 'Retry same issuance', exact: true })).toBeVisible();
    await expect(page.getByLabel('Region', { exact: true })).toBeDisabled();
    await scan('fleet-uncertain');
    const retried = await response('Retry same issuance', 201);
    assert.equal(retried.key, first.key, 'explicit retry retains original idempotency key');
    const receipt = await retried.actual.json();
    assert.deepEqual(Object.keys(receipt).sort(), ['bootstrapID', 'clusterID', 'peerID', 'issuerEpoch', 'deliveryProfile', 'credentialVersion', 'notBefore', 'notAfter'].sort());
    assert.equal(receipt.credentialVersion, 1); assert.equal(receipt.deliveryProfile, 'regional-installer');
    assert.equal(Date.parse(receipt.notAfter) - Date.parse(receipt.notBefore), 300_000);
    await expect(page.getByRole('heading', { name: 'Bootstrap slot issued', exact: true })).toBeVisible();
    for (const key of ['bootstrapID', 'clusterID', 'peerID', 'issuerEpoch']) await expect(page.getByText(receipt[key], { exact: true })).toBeVisible();
    await expect(page.getByText(new Date(receipt.notBefore).toISOString(), { exact: true })).toBeVisible();
    await expect(page.getByText(new Date(receipt.notAfter).toISOString(), { exact: true })).toBeVisible();
    await page.setViewportSize({ width: 320, height: 740 });
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'Fleet receipt reflows at 320px');
    await scan('fleet-issued-mobile');
    assert.equal(requests.length, 2, 'issuance and explicit retry only');
    await page.getByRole('button', { name: 'Create another slot', exact: true }).click();
    const refused = await response('Issue bootstrap slot', 403);
    assert.notEqual(refused.key, first.key, 'another explicit request uses a new key');
    await expect(page.getByRole('alert')).toHaveText('Current fleet operator access is required.');
    await expect(page.getByRole('heading', { name: 'Bootstrap slot issued', exact: true })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Retry same issuance', exact: true })).toHaveCount(0);
    assert.equal(requests.length, 3, 'denial must not be replayed');
  } finally {
    page.off('request', observe);
    if (originalViewport) await page.setViewportSize(originalViewport);
  }
  await page.getByRole('link', { name: 'Asservat', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Collect evidence', exact: true })).toBeVisible();
}
