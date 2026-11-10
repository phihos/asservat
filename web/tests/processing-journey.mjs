// The same actual React/HTTP journey is used by controlled and installed tests.
import { expect } from '@playwright/test';
import assert from 'node:assert/strict';
import { validProcessingInventory, validProcessingReceipt } from '../src/generated/validate-processing.js';

export async function processingJourney({ page, origin, artifactID, casePath, restricted = async () => {}, released = async () => {}, stage = () => {} }) {
  const selected = '/processing/artifacts/' + artifactID;
  stage('case-navigation');
  if (casePath) {
    await page.goto(origin + casePath);
    const link = page.getByRole('link', { name: 'Manage processing restriction', exact: true });
    stage('artifact-link');
    await expect(link).toHaveAttribute('href', selected);
    await link.click();
  } else await page.goto(origin + selected);
  stage('selected-page');
  await expect(page.getByRole('heading', { name: 'Processing restrictions', exact: true })).toBeVisible();
  await expect(page.getByLabel('Artifact ID', { exact: true })).toHaveValue(artifactID);
  const refresh = async () => {
    const response = page.waitForResponse(r => new URL(r.url()).pathname === '/api/v1/processing/rules' && r.request().method() === 'GET');
    await page.getByRole('button', { name: 'Refresh processing rules', exact: true }).click();
    const actual = await response;
    assert.equal(actual.status(), 200, "processing HTTP status " + actual.status());
    const inventory = await actual.json();
    assert(validProcessingInventory(inventory), 'closed inventory contract');
    return inventory;
  };
  const mutate = async name => {
    const response = page.waitForResponse(r => new URL(r.url()).pathname === '/api/v1/processing/changes' && r.request().method() === 'POST');
    await page.getByRole('button', { name, exact: true }).click();
    const actual = await response;
    assert.equal(actual.status(), 200, "processing HTTP status " + actual.status());
    const receipt = await actual.json();
    assert(validProcessingReceipt(receipt), 'closed receipt contract');
    const input = actual.request().postDataJSON(), headers = await actual.request().allHeaders(), key = headers['idempotency-key'];
    assert.match(key, /^[0-9a-f-]{36}$/);
    assert.equal(receipt.requestID, key, 'receipt request key');
    assert.equal(headers['x-csrf-token'].length, 43, 'request CSRF length');
    assert.equal(headers.origin, origin, 'request exact origin');
    return { receipt, input, key };
  };
  stage('initial-inventory');
  const initial = await refresh();
  assert(initial.initialized, 'processing initialized before the bounded restriction/release journey');
  stage('restrict');
  const restriction = await mutate('Restrict processing');
  assert.deepEqual(restriction.input, { action: 'restrict_processing', artifactID, ruleID: restriction.receipt.ruleID, expectedRevision: 0 });
  assert.equal(restriction.receipt.state, 'restricted', 'restriction receipt state'); assert.equal(restriction.receipt.revision, 1, 'restriction receipt revision');
  await expect(page.getByRole('status')).toContainText('Processing restricted.');
  await restricted(restriction);
  // Reload a route with no artifact/case state: durable inventory is the only
  // source of the release scope and revision, even while evidence is restricted.
  stage('restricted-reload');
  await page.goto(origin + '/processing');
  const inventory = await refresh();
  const row = inventory.rules.find(rule => rule.id === restriction.receipt.ruleID);
  assert(row && row.state === 'restricted' && row.revision === 1, 'persisted exact restriction after reload');
  const panel = page.getByRole('region', { name: 'Processing rule ' + row.id, exact: true });
  stage('release');
  const response = page.waitForResponse(r => new URL(r.url()).pathname === '/api/v1/processing/changes');
  await panel.getByRole('button', { name: 'Release restriction', exact: true }).click();
  const actual = await response;
  assert.equal(actual.status(), 200, "processing HTTP status " + actual.status());
  const release = { receipt: await actual.json(), input: actual.request().postDataJSON(), key: actual.request().headers()['idempotency-key'] };
  assert(validProcessingReceipt(release.receipt)); assert.equal(release.receipt.state, 'released'); assert.equal(release.receipt.revision, 2);
  assert.equal(release.receipt.requestID, release.key); assert.notEqual(release.key, restriction.key);
  assert.deepEqual(release.input, { action: 'release_processing', ruleID: row.id, expectedRevision: row.revision, scope: row.scope });
  await expect(page.getByRole('status')).toContainText('Restriction released.');
  await released(release);
  stage('released-inventory');
  await refresh();
  await expect(page.getByText('State: released. Revision 2.', { exact: true })).toBeVisible();
  assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
  stage('mobile-reflow');
  await page.setViewportSize({ width: 320, height: 740 });
  assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'processing page reflows at 320px');
  return { restriction, release };
}
