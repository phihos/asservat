// Installed-driver evidence only. Never include response bytes or exception text
// in the diagnostic; HTTP headers do not establish successful body completion.
export async function readInstalledHistoryResponse(response) {
  if (!response) return { http: 0, status: 'unavailable', body: 'unavailable', reply: null };
  const http = response.status();
  let bytes;
  try { bytes = await response.body(); }
  catch { return { http, status: 'invalid', body: 'read-failed', reply: null }; }
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
