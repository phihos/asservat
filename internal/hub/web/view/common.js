// What every viewer shares: the file it shows, how to fetch it, and a list
// that only draws the rows in sight.
export const $ = id => document.getElementById(id);
export const esc = s => String(s).replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
const query = new URLSearchParams(location.search);
export const capture = query.get('capture'), file = query.get('file') || '';
export const filePath = file.split('/').map(encodeURIComponent).join('/');
export const address = `/api/captures/${capture}/artifacts/${filePath}`;
// A token typed into the console lives in this tab; a single sign-on session is a cookie.
const token = sessionStorage.getItem('token');
export const headers = token ? {Authorization: 'Bearer ' + token} : {};

// notice replaces the viewer with a message, show brings the viewer back.
export function notice(text, retry) {
  $('root').hidden = true; $('notice').hidden = false;
  $('notice').innerHTML = esc(text) + (retry ? '<br><button id="retry">Open again</button>' : '');
  if (retry) $('retry').onclick = () => location.reload();
}
export function show() { $('notice').hidden = true; $('root').hidden = false; }

// The browser holds a text file and an index of its lines in memory, so a
// text viewer reads at most this much and says so when a file is longer.
const textLimit = 64 << 20;
export async function loadText() {
  const res = await fetch(address, {headers});
  if (!res.ok) throw new Error('The file could not be read.');
  const reader = res.body.getReader(), parts = [];
  let size = 0, truncated = false;
  for (;;) {
    const {done, value} = await reader.read();
    if (done) break;
    parts.push(value); size += value.length;
    if (size >= textLimit) { truncated = true; reader.cancel(); break; }
  }
  return {text: await new Blob(parts).text(), truncated};
}
export const truncatedNote = 'This file is longer than the viewer reads (64 MiB). Download it to see all of it.';

// virtual draws the rows of a long list that are in sight. The element
// scrolls; row(i) returns the HTML of row i, which must be rowHeight high
// and positioned by the caller's style at top i * rowHeight.
export function virtual(scroller, rows, rowHeight, row) {
  let count = 0;
  const draw = () => {
    const from = Math.max(0, Math.floor(scroller.scrollTop / rowHeight) - 10), to = Math.min(count, from + Math.ceil(scroller.clientHeight / rowHeight) + 20);
    let html = '';
    for (let i = from; i < to; i++) html += row(i);
    rows.innerHTML = html;
  };
  scroller.addEventListener('scroll', draw);
  new ResizeObserver(draw).observe(scroller);
  return {
    draw,
    count(n) { count = n; rows.style.height = n * rowHeight + 'px'; draw(); },
    // reveal scrolls as little as needed to bring row i into sight, below a sticky head of the given height.
    reveal(i, head = 0) {
      const top = i * rowHeight, room = scroller.clientHeight - head;
      if (top < scroller.scrollTop) scroller.scrollTop = top;
      else if (top + rowHeight > scroller.scrollTop + room) scroller.scrollTop = top + rowHeight - room;
    },
  };
}
