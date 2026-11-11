// The same actual React/HTTP journey is used by controlled and installed tests.
import { expect } from '@playwright/test';
import assert from 'node:assert/strict';
import { validProcessingChange, validProcessingInventory, validProcessingReceipt } from '../src/generated/validate-processing.js';
import { validInput_search_processing_evidence, validOutput_search_processing_evidence } from '../src/generated/validate-processing-discovery.js';

export async function processingJourney({ page, origin, artifactID, casePath, parents = [], workloadRestriction = false, restricted = async () => {}, discovered = async () => {}, released = async () => {}, stage = () => {} }) {
  const selected = '/processing/artifacts/' + artifactID;
  stage('case-navigation');
  await page.goto(origin + casePath);
  const link = page.getByRole('link', { name: 'Manage processing restriction', exact: true });
  stage('artifact-link');
  await expect(link).toHaveAttribute('href', selected);
  await link.click();
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
  const caseID = casePath.split('/').at(-1);
  const search = page.getByRole('region', { name: 'Find evidence', exact: true });
  const discoverCase = async () => {
    await search.getByLabel('Case ID', { exact: true }).fill(caseID);
    const discoveryResponse = page.waitForResponse(r => new URL(r.url()).pathname === '/api/v1/operations/search_processing_evidence' && r.request().method() === 'POST');
    await search.getByRole('button', { name: 'Search evidence', exact: true }).click();
    const discovery = await discoveryResponse;
    assert.equal(discovery.status(), 200, 'processing discovery HTTP status ' + discovery.status());
    const query = discovery.request().postDataJSON(), headers = await discovery.request().allHeaders();
    assert(validInput_search_processing_evidence(query), 'closed discovery query contract');
    assert.deepEqual(Object.keys(query).sort(), ['case_id', 'limit']);
    assert.equal(query.case_id, caseID, 'search uses the exact case');
    assert.equal(headers.origin, origin, 'discovery exact origin');
    assert.equal(headers['x-csrf-token'].length, 43, 'discovery CSRF length');
    const body = await discovery.body(), reply = JSON.parse(body.toString('utf8'));
    assert(validOutput_search_processing_evidence(reply), 'closed discovery response contract');
    assert.equal(reply.status, 'ok');
    assert.equal(reply.data_class, 'metadata');
    assert.equal(reply.data.candidates.length, 1, 'exact case has one published candidate');
    const candidate = reply.data.candidates[0];
    assert.equal(candidate.artifact_id, artifactID);
    assert.equal(candidate.case_id, caseID);
    assert.equal(candidate.origin, parents.length ? 'derived' : 'capture');
    assert.deepEqual(candidate.parents, parents, 'recorded direct lineage');
    return { requestID: reply.request_id, candidate, responseBytes: body.length };
  };
  stage('initial-inventory');
  const initial = await refresh();
  assert(initial.initialized, 'processing initialized before the bounded restriction/release journey');
  let scope, initialDiscovery, workloadDiscovery;
  if (workloadRestriction) {
    stage('workload-source-discovery');
    initialDiscovery = await discoverCase();
    const candidate = initialDiscovery.candidate;
    const second = Math.floor(Date.parse(candidate.anchor_at) / 1000) * 1000;
    assert(Number.isFinite(second), 'original acquisition anchor');
    const from = new Date(second - 1000), until = new Date(second + 1000);
    scope = {
      kind: 'workloadInterval', clusterID: candidate.cluster_id, namespaceUID: candidate.namespace_uid,
      workloadUID: candidate.workload_uid, acquiredFrom: from.toISOString(), acquiredUntil: until.toISOString(),
    };
    stage('workload-discovery');
    await search.getByLabel('Search by', { exact: true }).selectOption('workload');
    await search.getByLabel('Cluster ID', { exact: true }).fill(scope.clusterID);
    await search.getByLabel('Namespace UID', { exact: true }).fill(scope.namespaceUID);
    await search.getByLabel('Workload UID', { exact: true }).fill(scope.workloadUID);
    await search.getByLabel('Acquired from (UTC)', { exact: true }).fill(from.toISOString().slice(0, 19));
    await search.getByLabel('Acquired until (UTC)', { exact: true }).fill(until.toISOString().slice(0, 19));
    await search.getByLabel('Purpose reference (optional)', { exact: true }).fill(candidate.purpose_ref);
    const response = page.waitForResponse(r => new URL(r.url()).pathname === '/api/v1/operations/search_processing_evidence' && r.request().method() === 'POST');
    await search.getByRole('button', { name: 'Search evidence', exact: true }).click();
    const actual = await response;
    assert.equal(actual.status(), 200, 'workload discovery HTTP status ' + actual.status());
    const query = actual.request().postDataJSON();
    assert(validInput_search_processing_evidence(query), 'closed workload discovery query');
    assert.deepEqual(query, {
      cluster_id: scope.clusterID, namespace_uid: scope.namespaceUID, workload_uid: scope.workloadUID,
      acquired_from: scope.acquiredFrom, acquired_until: scope.acquiredUntil, purpose_ref: candidate.purpose_ref, limit: 12,
    });
    const body = await actual.body(), reply = JSON.parse(body.toString('utf8'));
    assert(validOutput_search_processing_evidence(reply), 'closed workload discovery response');
    assert.equal(reply.status, 'ok');
    const matching = reply.data.candidates.find(row => row.artifact_id === artifactID);
    assert(matching, 'selected artifact occurs in original workload interval');
    workloadDiscovery = { requestID: reply.request_id, candidate: matching, responseBytes: body.length };
    stage('workload-review');
    await search.getByRole('button', { name: 'Review workload restriction', exact: true }).click();
    const review = page.getByRole('region', { name: 'Confirm workload restriction', exact: true });
    await expect(review.getByRole('heading', { name: 'Confirm workload restriction', exact: true })).toBeVisible();
    await expect(review).toContainText(scope.clusterID);
    await expect(review).toContainText(scope.namespaceUID);
    await expect(review).toContainText(scope.workloadUID);
    await expect(review).toContainText(scope.acquiredFrom);
    await expect(review).toContainText(scope.acquiredUntil);
    await expect(review).toContainText(/all purposes/i);
    await expect(review).toContainText(/every page/i);
    await expect(review).toContainText(/published later/i);
  }
  stage('restrict');
  const restriction = await mutate(workloadRestriction ? 'Confirm workload restriction' : 'Restrict processing');
  assert(validProcessingChange(restriction.input), 'closed processing change contract');
  assert.deepEqual(restriction.input, workloadRestriction
    ? { action: 'restrict_processing', scope, ruleID: restriction.receipt.ruleID, expectedRevision: 0 }
    : { action: 'restrict_processing', artifactID, ruleID: restriction.receipt.ruleID, expectedRevision: 0 });
  if (workloadRestriction) {
    restriction.discovery = initialDiscovery;
    restriction.workloadDiscovery = workloadDiscovery;
  }
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
  if (workloadRestriction) {
    assert.deepEqual({
      ...row.scope, acquiredFrom: new Date(row.scope.acquiredFrom).toISOString(),
      acquiredUntil: new Date(row.scope.acquiredUntil).toISOString(),
    }, scope, 'reload preserves the original workload scope and interval instants');
  }
  const panel = page.getByRole('region', { name: 'Processing rule ' + row.id, exact: true });
  stage('restricted-discovery');
  if (workloadRestriction) {
    await search.getByLabel('Search by', { exact: true }).selectOption('case');
    await search.getByLabel('Purpose reference (optional)', { exact: true }).fill('');
  }
  const discovery = await discoverCase();
  const result = search.getByRole('article', { name: 'Evidence candidate ' + artifactID, exact: true });
  await expect(result.getByRole('heading', { name: 'Artifact ' + artifactID, exact: true })).toBeVisible();
  if (parents.length) {
    await expect(result.getByText('Recorded direct parents', { exact: true })).toBeVisible();
    await expect(result.getByRole('listitem')).toHaveText(parents);
  } else await expect(result.getByText('Original capture', { exact: true })).toBeVisible();
  const artifact = page.getByLabel('Artifact ID', { exact: true });
  await expect(artifact).toHaveValue('');
  await result.getByRole('button', { name: 'Select artifact for restriction', exact: true }).click();
  await expect(artifact).toHaveValue(artifactID);
  await expect(artifact).toBeFocused();
  await expect(panel.getByText('State: restricted. Revision 1.', { exact: true })).toBeVisible();
  await discovered({ discovery });
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
