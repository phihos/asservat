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
    // Chromium's net error token only (for example net::ERR_ABORTED), never text.
    const net = /^net::ERR_[A-Z_]+$/.exec(response.request().failure()?.errorText ?? '')?.[0] ?? 'none';
    return { http, status: 'invalid', body: 'read-failed', reply: null, requestFailed, readFailure: requestFailed ? `${readFailure}(${net})` : readFailure };
  }
  if (bytes.length === 0) return { http, status: 'invalid', body: 'empty', reply: null };
  let text;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); }
  catch { return { http, status: 'invalid', body: 'invalid-utf8', reply: null }; }
  return parseInstalledHistoryText(http, text);
}

// parseInstalledHistoryText classifies a complete reply text the page itself
// consumed (see the installed history browser's fetch observer).
export function parseInstalledHistoryText(http, text) {
  if (text.length === 0) return { http, status: 'invalid', body: 'empty', reply: null };
  let reply;
  try { reply = JSON.parse(text); }
  catch { return { http, status: 'invalid', body: 'invalid-json', reply: null }; }
  const status = ['ok', 'error', 'pending'].includes(reply?.status) ? reply.status : 'invalid';
  return { http, status, body: status === 'invalid' ? 'invalid-envelope' : 'complete', reply };
}
