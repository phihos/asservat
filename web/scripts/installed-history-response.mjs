// Installed-driver evidence only. Never include response bytes or exception text
// in the diagnostic; HTTP headers do not establish successful body completion.
export async function readInstalledHistoryResponse(response) {
  if (!response) return { http: 0, status: 'unavailable', body: 'unavailable', reply: null };
  const http = response.status();
  let bytes;
  try { bytes = await response.body(); }
  catch (error) {
    const requestFailed = response.request().failure() !== null;
    const text = typeof error?.message === 'string' ? error.message : '';
    const protocol = text.includes('Protocol error (Network.getResponseBody)');
    const readFailure = requestFailed ? 'network-failed'
      : protocol && text.includes('Request content was evicted from inspector cache') ? 'inspector-evicted'
      : protocol && text.includes('No resource with given identifier found') ? 'inspector-no-resource'
      : protocol && text.includes('No data found for resource with given identifier') ? 'inspector-no-data'
      : 'other';
    return { http, status: 'invalid', body: 'read-failed', reply: null, requestFailed, readFailure };
  }
  if (bytes.length === 0) return { http, status: 'invalid', body: 'empty', reply: null };
  let text;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); }
  catch { return { http, status: 'invalid', body: 'invalid-utf8', reply: null }; }
  let reply;
  try { reply = JSON.parse(text); }
  catch { return { http, status: 'invalid', body: 'invalid-json', reply: null }; }
  const status = ['ok', 'error', 'pending'].includes(reply?.status) ? reply.status : 'invalid';
  return { http, status, body: status === 'invalid' ? 'invalid-envelope' : 'complete', reply };
}
