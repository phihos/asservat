import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { expect } from '@playwright/test';
import { validInput_get_processing_report, validOutput_get_processing_report, validProcessingReportExport } from '../src/generated/validate-processing-report.js';

const sections = ['artifacts', 'shares', 'downloads', 'operations', 'rules', 'paths', 'processors'];
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const path = '/api/v1/operations/get_processing_report';
const maximumBytes = 4 * 1024 * 1024;

// Compare each actual downloaded JSON part with the exact validated HTTP
// responses that supplied it. The callback stores the file in the owned lab.
export async function processingReportJourney({ page, origin, exported, stage = () => {} }) {
  const responses = [];
  page.on('response', response => {
    if (response.url() !== origin + path || response.request().method() !== 'POST') return;
    responses.push((async () => {
      assert.equal(response.status(), 200, 'report HTTP status');
      const request = response.request(), query = request.postDataJSON(), headers = await request.allHeaders();
      assert(validInput_get_processing_report(query), 'closed report input');
      assert.equal(headers.origin, origin, 'report exact origin');
      assert.equal(headers['x-csrf-token']?.length, 43, 'report request CSRF');
      assert(!headers.authorization, 'report uses browser session');
      const body = await response.body(), envelope = JSON.parse(body.toString('utf8'));
      assert(validOutput_get_processing_report(envelope), 'closed report envelope');
      assert.equal(envelope.status, 'ok', 'report page accepted');
      assert.equal(envelope.data_class, 'metadata', 'report data class');
      assert(uuid.test(envelope.request_id), 'report audit request ID');
      return { query, envelope, responseBytes: body.length };
    })());
  });
  stage('report-navigation');
  await page.goto(origin + '/processing');
  const panel = page.getByRole('region', { name: 'Processing inventory report', exact: true });
  await expect(panel).toBeVisible();
  await expect(panel).toContainText(/Client receipt remains unknown/i);
  const seen = new Set(), observedSections = [];
  let processed = 0, expectedNext, root, installation, selection, revision;
  for (let part = 1; part <= 8; part++) {
    stage('report-export-part-' + part);
    const downloading = page.waitForEvent('download');
    await panel.getByRole('button', { name: part === 1 ? 'Export inventory report' : 'Export next report part', exact: true }).click();
    const download = await downloading, stream = await download.createReadStream();
    assert(stream, 'downloaded report stream');
    const chunks = [];
    let size = 0;
    for await (const chunk of stream) {
      size += chunk.length;
      assert(size <= maximumBytes, 'bounded JSON report part');
      chunks.push(chunk);
    }
    assert.equal(await download.failure(), null, 'completed JSON report download');
    const body = Buffer.concat(chunks), document = JSON.parse(body.toString('utf8'));
    assert(validProcessingReportExport(document), 'closed exported report document');
    assert.equal(document.format, 'asservat-processing-inventory/v1');
    assert.equal(document.part, part, 'sequential report part');
    assert(Array.isArray(document.pages) && document.pages.length > 0 && document.pages.length <= 32, 'bounded nonempty report part');
    const captured = await Promise.all(responses.slice(processed));
    assert.equal(captured.length, document.pages.length, 'export contains every response from this part');
    for (let i = 0; i < captured.length; i++) {
      const { query, envelope } = captured[i], data = envelope.data;
      assert.deepEqual(document.pages[i], envelope, 'downloaded page matches actual response');
      if (expectedNext !== undefined) assert.deepEqual(query, expectedNext, 'report follows exact server continuation');
      assert.equal(data.section, query.section ?? 'artifacts', 'section matches request');
      assert(!seen.has(envelope.request_id), 'fresh page audit operation');
      seen.add(envelope.request_id);
      if (root === undefined) {
        root = data.root_id; installation = data.installation_id;
        selection = data.selection_created_before; revision = data.policy_revision;
      }
      assert.equal(data.root_id, root, 'same report root');
      assert.equal(data.installation_id, installation, 'same installation');
      assert.equal(data.selection_created_before, selection, 'same selection ceiling');
      assert.deepEqual(data.policy_revision, revision, 'same accepted policy');
      if (observedSections.at(-1) !== data.section) {
        assert.equal(data.section, sections[observedSections.length], 'all report sections in order');
        observedSections.push(data.section);
      }
      for (const record of data.records) {
        assert(Date.parse(data.valid_until) <= Date.parse(record.visible_until), 'original metadata visibility bounds page');
        const variants = ['artifact', 'share', 'download', 'operation', 'rule', 'path', 'processor'].filter(key => record[key] !== undefined);
        assert.equal(variants.length, 1, 'exactly one typed report record');
      }
      expectedNext = data.next;
    }
    processed += captured.length;
    assert.equal(document.complete, expectedNext === undefined, 'export completion matches terminal cursor');
    assert.deepEqual(document.next, expectedNext, 'export preserves continuation');
    if (document.selection_created_before !== undefined) assert.equal(document.selection_created_before, selection);
    if (document.policy_revision !== undefined) assert.deepEqual(document.policy_revision, revision);
    await exported({
      part, complete: document.complete, bytes: body.length, sha256: createHash('sha256').update(body).digest('hex'),
      pages: captured.map(({ query, envelope, responseBytes }) => ({ query, requestID: envelope.request_id, responseBytes })),
    }, document, body);
    if (document.complete) {
      assert.deepEqual(observedSections, sections, 'all seven report sections completed');
      await expect(panel.getByRole('status')).toHaveText('Inventory export complete.');
      assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0, 'report is not persisted in browser storage');
      return;
    }
    assert.equal(document.pages.length, 32, 'part stops only at the page cap');
  }
  assert.fail('report did not finish within bounded parts');
}
