import assert from 'node:assert/strict';
import { expect } from '@playwright/test';
import { validProcessingChange, validProcessingReceipt } from '../src/generated/validate-processing.js';
import { validInput_search_processing_evidence, validOutput_search_processing_evidence } from '../src/generated/validate-processing-discovery.js';
import { validInput_get_processing_erasure, validOutput_get_processing_erasure } from '../src/generated/validate-processing-erasure.js';

export const erasureUUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const discoveryPath = '/api/v1/operations/search_processing_evidence';
const changePath = '/api/v1/processing/changes';
const statusPath = '/api/v1/operations/get_processing_erasure';

export async function erasureJourney({ page, origin, casePath, artifactID, accepted, pending, verified, stage = () => {} }) {
  const counts = new Map([[discoveryPath, 0], [changePath, 0], [statusPath, 0]]);
  page.on('request', request => {
    const url = new URL(request.url());
    if (url.origin === origin && counts.has(url.pathname)) counts.set(url.pathname, counts.get(url.pathname) + 1);
  });
  const checkedPost = async (path, button, inputValid, outputValid) => {
    const response = page.waitForResponse(r => r.url() === origin + path && r.request().method() === 'POST');
    await button.click();
    const actual = await response;
    assert.equal(actual.status(), 200, path + ' HTTP status');
    assert.equal(actual.headers()['content-type']?.split(';')[0], 'application/json', path + ' response content type');
    const request = actual.request(), input = request.postDataJSON(), headers = await request.allHeaders();
    assert(inputValid(input), path + ' closed input');
    assert.equal(headers.origin, origin, path + ' exact origin');
    assert.equal(headers['x-csrf-token']?.length, 43, path + ' request CSRF length');
    assert(!headers.authorization, path + ' uses the browser session');
    const body = await actual.body(), output = JSON.parse(body.toString('utf8'));
    assert(outputValid(output), path + ' closed output');
    return { input, output, key: headers['idempotency-key'], responseBytes: body.length };
  };

  const open = async () => {
    await page.goto(origin + '/processing');
    await expect(page.getByRole('heading', { name: 'Processing restrictions', exact: true })).toBeVisible();
  };
  stage('erasure-discovery');
  await open();
  const caseID = casePath.split('/').at(-1);
  const search = page.getByRole('region', { name: 'Find evidence', exact: true });
  await search.getByLabel('Case ID', { exact: true }).fill(caseID);
  const { input: query, output: found, responseBytes } = await checkedPost(discoveryPath, search.getByRole('button', { name: 'Search evidence', exact: true }),
    validInput_search_processing_evidence, validOutput_search_processing_evidence);
  assert.deepEqual(query, { case_id: caseID, limit: 12 }, 'exact case discovery');
  assert.equal(found.status, 'ok', 'discovery accepted');
  assert.equal(found.data_class, 'metadata');
  assert.equal(found.data.candidates.length, 1, 'one exact published candidate');
  const candidate = found.data.candidates[0];
  assert.equal(candidate.artifact_id, artifactID);
  assert.equal(candidate.case_id, caseID);
  const row = search.getByRole('article', { name: 'Evidence candidate ' + artifactID, exact: true });

  stage('erasure-confirmation');
  await row.getByRole('button', { name: 'Request early erasure', exact: true }).click();
  const confirmation = page.getByRole('region', { name: 'Confirm early erasure', exact: true });
  await expect(confirmation.getByRole('heading')).toBeFocused();
  await expect(confirmation.getByText(artifactID, { exact: true })).toBeVisible();
  await expect(confirmation.getByText(/existing hard deletion deadline still applies/)).toBeVisible();
  assert.equal(counts.get(changePath), 0, 'review does not submit an erasure');
  assert.equal(counts.get(statusPath), 0, 'review does not read status');

  stage('erasure-mutation');
  const { input, output: receipt, key } = await checkedPost(changePath, confirmation.getByRole('button', { name: 'Confirm early erasure', exact: true }),
    validProcessingChange, validProcessingReceipt);
  assert.deepEqual(input, { action: 'request_early_erasure', artifactID }, 'exact erasure request');
  assert.match(key, erasureUUID);
  assert.equal(receipt.requestID, key, 'exact erasure receipt key');
  assert.equal(receipt.state, 'erasureRequested');
  assert.notEqual(found.request_id, key);
  await expect(page.getByRole('status').filter({ hasText: 'Early erasure request accepted' })).toContainText(key);
  const panel = page.getByRole('region', { name: 'Early erasure status', exact: true });
  const requestID = panel.getByLabel('Erasure request ID', { exact: true });
  await expect(requestID).toHaveValue(key);
  assert.equal(counts.get(statusPath), 0, 'acceptance does not read status');
  await accepted({ receipt, input, key, discovery: { requestID: found.request_id, candidate, responseBytes } });

  const read = async () => {
    const { input, output, key: statusKey } = await checkedPost(statusPath, panel.getByRole('button', { name: 'Check erasure status', exact: true }),
      validInput_get_processing_erasure, validOutput_get_processing_erasure);
    assert.deepEqual(input, { request_id: key });
    assert.equal(statusKey, undefined, 'status does not replay the mutation');
    assert.equal(output.status, 'ok', 'status accepted');
    assert.equal(output.data_class, 'metadata');
    assert.equal(output.data.request_id, key, 'exact status request');
    assert.equal(output.data.artifact_id, artifactID, 'exact status artifact');
    assert.match(output.request_id, erasureUUID);
    assert.notEqual(output.request_id, key, 'status has a separate audit operation');
    assert.notEqual(output.request_id, found.request_id, 'status and discovery use separate audit operations');
    return { status: output.data, operationID: output.request_id };
  };

  stage('erasure-pending-status');
  const waiting = await read();
  assert.equal(waiting.status.deletion_state, 'pending');
  assert.equal(waiting.status.deleted_at, undefined);
  await expect(panel.getByRole('status')).toHaveText('Deletion pending.');
  await pending(waiting);

  stage('erasure-reloaded-status');
  await open();
  await expect(requestID).toHaveValue('');
  await expect(panel.getByRole('button', { name: 'Check erasure status', exact: true })).toBeDisabled();
  assert.equal(counts.get(statusPath), 1, 'reload does not read status');
  await requestID.fill(key);
  const finished = await read();
  assert.equal(finished.status.audit_state, 'acknowledged');
  assert.equal(finished.status.deletion_state, 'deleted');
  assert(finished.status.deleted_at, 'verified deletion time');
  assert.notEqual(finished.operationID, waiting.operationID, 'fresh status audit operation');
  assert.equal(finished.status.accepted_at, waiting.status.accepted_at, 'original acceptance');
  assert.equal(finished.status.access_until, waiting.status.access_until, 'original access cutoff');
  assert.equal(finished.status.delete_by, waiting.status.delete_by, 'original hard deadline');
  await expect(panel.getByRole('status')).toHaveText('Managed deletion verified.');
  await expect(panel.getByText('Verified deletion time', { exact: true })).toBeVisible();
  assert.deepEqual([...counts.values()], [1, 1, 2], 'one discovery, one confirmed mutation, two explicit status reads');
  assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0, 'no erasure request persisted in browser storage');
  await verified(finished);
}
