export function approvalPath(value: unknown): string | undefined {
  if (typeof value !== 'string') return;
  try {
    const url = new URL(value, window.location.origin);
    if (url.search || url.hash || !/^\/approvals\/[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i.test(url.pathname)) return;
    return url.pathname;
  } catch { return; }
}
