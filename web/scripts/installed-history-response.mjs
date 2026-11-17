// Installed-driver evidence only. Never include response bytes or exception text
// in the diagnostic; HTTP headers do not establish successful body completion.
export async function readInstalledHistoryResponse(response, readBody) {
  if (!response) return { http: 0, status: 'unavailable', body: 'unavailable', reply: null };
  const http = response.status();
  let bytes;
  try { bytes = await readBody(response); }
  catch {
    const requestFailed = response.request().failure() !== null;
    const readFailure = requestFailed ? 'network-failed' : 'fetch-body-failed';
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

// parseInstalledHistoryText classifies complete reply text captured from the
// console fetch; observing a clone does not prove the console consumed it.
export function parseInstalledHistoryText(http, text) {
  if (text.length === 0) return { http, status: 'invalid', body: 'empty', reply: null };
  let reply;
  try { reply = JSON.parse(text); }
  catch { return { http, status: 'invalid', body: 'invalid-json', reply: null }; }
  const status = ['ok', 'error', 'pending'].includes(reply?.status) ? reply.status : 'invalid';
  return { http, status, body: status === 'invalid' ? 'invalid-envelope' : 'complete', reply };
}
