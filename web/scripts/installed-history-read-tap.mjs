// Test-driver only. Observe only bytes the application actually reads; CDP body
// retention/ERR_ABORTED is not authoritative for an already consumed response.
import * as validators from '../src/generated/validate-capture.js';

// Passed to Playwright addInitScript before application startup; self-contained.
export function installHistoryReadTap() {
  const caps = { list_diagnostics: 32_768, list_capture_history: 32_768, get_capture_settings: 160 * 1024, preview_capture: 32_768 };
  const records = new Map();
  const discard = record => { record.bytes?.fill(0); record.bytes = null; };
  const fail = (record, reason) => { discard(record); record.state = reason; };
  const fetch = window.fetch;
  window.fetch = async function(input, init) {
    const url = new URL(input instanceof Request ? input.url : input, location.href);
    const method = init?.method ?? (input instanceof Request ? input.method : 'GET');
    const name = url.origin === location.origin && !url.search && method === 'POST' && url.pathname.startsWith('/api/v1/operations/') ? url.pathname.slice('/api/v1/operations/'.length) : '';
    if (!Object.hasOwn(caps, name)) return fetch.apply(this, arguments);
    if (records.has(name)) {
      fail(records.get(name), 'duplicate');
      return fetch.apply(this, arguments);
    }
    const record = { state: 'pending', bytes: null, size: 0, http: 0, reader: false };
    records.set(name, record);
    let response;
    try { response = await fetch.apply(this, arguments); }
    catch (error) { fail(record, 'read-failed'); throw error; }
    record.http = response.status;
    if (record.state !== 'pending') return response;
    if (response.status !== 200 || response.headers.get('Content-Type')?.split(';')[0].trim() !== 'application/json' || !response.body) {
      fail(record, 'headers'); return response;
    }
    record.bytes = new Uint8Array(caps[name]);
    const getReader = response.body.getReader;
    response.body.getReader = function(...args) {
      let reader;
      try { reader = getReader.apply(this, args); }
      catch (error) { fail(record, 'read-failed'); throw error; }
      if (record.reader) { fail(record, 'duplicate'); return reader; }
      record.reader = true;
      const read = reader.read;
      reader.read = async function(...args) {
        try {
          const result = await read.apply(this, args);
          if (record.state === 'pending') {
            if (result.done) record.state = 'complete';
            else if (!(result.value instanceof Uint8Array) || result.value.length > caps[name] - record.size) fail(record, 'over-limit');
            else { record.bytes.set(result.value, record.size); record.size += result.value.length; }
          }
          return result;
        } catch (error) { fail(record, 'read-failed'); throw error; }
      };
      return reader;
    };
    return response;
  };
  window.__asservatHistoryReadTap = {
    ready: name => records.has(name) && records.get(name).state !== 'pending',
    take(name) {
      const record = records.get(name);
      if (!record) return { http: 0, state: 'missing', bytes: null };
      const out = { http: record.http, state: record.state, bytes: record.state === 'complete' ? Array.from(record.bytes.subarray(0, record.size)) : null };
      discard(record); records.delete(name); return out;
    },
    clear() { for (const record of records.values()) discard(record); records.clear(); },
  };
}

export async function readHistoryAppResponse(page, name, response) {
  if (!response) return { http: 0, status: 'unavailable', body: 'unavailable', reply: null };
  await page.waitForFunction(name => window.__asservatHistoryReadTap.ready(name), name);
  const observed = await page.evaluate(name => window.__asservatHistoryReadTap.take(name), name);
  const invalid = body => ({ http: observed.http, status: 'invalid', body, reply: null });
  if (observed.state !== 'complete' || observed.http !== response.status()) return invalid(observed.state);
  if (!observed.bytes?.length) return invalid('empty');
  let reply;
  const bytes = Uint8Array.from(observed.bytes);
  try { reply = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
  catch { return invalid('invalid-json'); }
  finally { bytes.fill(0); observed.bytes.fill(0); }
  if (!validators[`validOutput_${name}`]?.(reply)) return invalid('invalid-envelope');
  const allowedClass = reply.data_class === 'metadata' || reply.data_class === 'extract' && (name === 'get_capture_settings' || name === 'preview_capture');
  if (!allowedClass || reply.truncated || reply.next_cursor !== null && name !== 'list_capture_history') return invalid('invalid-envelope');
  return { http: observed.http, status: reply.status, body: 'complete', reply };
}
