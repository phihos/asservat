// Opaque preview IDs identify one already-reviewed intent. This key is not
// authority; the server checks its original actor/client, scope and admission.
// The server scopes request identity to the current actor/client and binds
// its submission digest to this preview. A closed preview cannot become a
// fresh attempt under this or another key; a new intent needs a new preview.
// Deriving it keeps approval submission/recovery stable across page remounts.
export const approvalSubmissionKey = (previewID: string) => 'approved-preview-' + previewID;

export function approvalPath(value: unknown): string | undefined {
  if (typeof value !== 'string') return;
  try {
    const url = new URL(value, window.location.origin);
    if (url.search || url.hash || !/^\/approvals\/[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i.test(url.pathname)) return;
    return url.pathname;
  } catch { return; }
}
