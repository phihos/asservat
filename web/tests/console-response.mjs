// Keep the console's own fetch body before same-document navigation makes
// Chromium's inspector response body unavailable. Never replace the response.
const captures = new WeakMap();
export async function captureConsoleResponses(page) {
  if (captures.has(page)) return captures.get(page);
  const install = () => {
    const replies = new Map(), original = window.fetch.bind(window);
    Object.defineProperty(window, '__consoleReplies', { value: replies });
    window.fetch = async (input, init) => {
      const response = await original(input, init);
      const url = new URL(typeof input === 'string' ? input : input.url, location.href);
      if (url.origin === location.origin && (url.pathname.startsWith('/api/v1/') || url.pathname === '/auth/refresh') &&
          /^application\/(?:problem\+)?json(?:\s*;|$)/i.test(response.headers.get('Content-Type') ?? '')) {
        const key = (init?.method ?? 'GET') + '\n' + url.pathname + url.search + '\n' + (init?.body ?? '');
        const body = response.clone().text();
        if (!replies.has(key)) replies.set(key, []);
        replies.get(key).push(body);
        void body.catch(() => {}); // The reader below propagates body failures.
      }
      return response;
    };
  };
  await page.addInitScript(install);
  await page.evaluate(install);
  const captured = new WeakMap(), claims = new Map();
  page.on('response', response => {
    const request = response.request(), url = new URL(response.url());
    if (request.resourceType() !== 'fetch' ||
        !/^application\/(?:problem\+)?json(?:\s*;|$)/i.test(response.headers()['content-type'] ?? '') ||
        (!url.pathname.startsWith('/api/v1/') && url.pathname !== '/auth/refresh')) return;
    const key = request.method() + '\n' + url.pathname + url.search + '\n' + (request.postData() ?? '');
    // Fetch settles in response order, including out-of-order completion of
    // identical requests. Claim every response immediately, not when a journey
    // eventually reads it; cancellation must not shift the remaining claims.
    const body = (claims.get(key) ?? Promise.resolve()).then(async () => {
      await page.waitForFunction(key => window.__consoleReplies?.get(key)?.length, key);
      const text = await page.evaluate(async key => {
        const queue = window.__consoleReplies.get(key), body = queue.shift();
        if (!queue.length) window.__consoleReplies.delete(key);
        return await body;
      }, key);
      return Buffer.from(text, 'utf8');
    });
    captured.set(response, body);
    claims.set(key, body.then(() => {}, () => {}));
  });
  const read = response => captured.get(response);
  captures.set(page, read);
  return read;
}
