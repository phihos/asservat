// The packet viewer follows Wireshark's main window. Wireshark's sharkd reads
// the capture in the hub; this page asks it for what is in sight.
import {$, esc, headers, notice, openView, show, virtual} from './common.js';

const markup = `
  <div class="toolbar">
    <button id="first" title="Go to the first packet">⏮</button>
    <button id="prev" title="Go to the previous packet (↑)">▲</button>
    <button id="next" title="Go to the next packet (↓)">▼</button>
    <button id="last" title="Go to the last packet">⏭</button>
    <span class="sep"></span>
    <label>Go to packet <input id="goto" type="number" min="1"></label>
    <span class="sep"></span>
    <button id="follow" disabled title="Show the payload of this packet's stream">Follow stream</button>
    <button id="asFilter" disabled title="Filter by the field selected in the packet details">Apply as filter</button>
  </div>
  <form class="filter" id="filterForm">
    <input id="filter" list="fields" autocomplete="off" spellcheck="false" placeholder="Apply a display filter … for example  tcp.port == 8080 and http">
    <datalist id="fields"></datalist>
    <button type="button" id="clear" title="Clear the display filter" disabled>✕</button>
    <button id="apply" title="Apply the display filter (Enter)">→</button>
  </form>
  <div id="panes">
    <div class="pane" id="list" tabindex="0">
      <div id="head"></div>
      <div id="rows"></div>
    </div>
    <div class="splitter" data-above="list" data-below="details"></div>
    <div class="pane" id="details" tabindex="0"></div>
    <div class="splitter" data-above="details" data-below="bytes"></div>
    <div class="pane" id="bytes">
      <div id="sources" hidden></div>
      <pre id="hex"></pre>
    </div>
  </div>
  <footer><span id="field"></span><span id="counts"></span></footer>
<dialog id="stream">
  <h2 id="streamTitle"></h2>
  <pre id="streamText"></pre>
  <div class="bar"><span id="streamSides"></span><span class="grow"></span><button id="streamFilter">Filter on this stream</button><button id="streamClose">Close</button></div>
</dialog>
`;

// The view: the hub keeps the file open as long as this stream stays open.
let view = null;
async function ask(method, params = {}) {
  const res = await fetch(`/api/views/${view}/${method}`, {method: 'POST', headers: {...headers, 'Content-Type': 'application/json'}, body: JSON.stringify(params)});
  const data = await res.json().catch(() => null);
  if (res.status === 404 || res.status === 410) { notice('This view has ended.', true); throw new Error('view ended'); }
  if (!res.ok) throw new Error(data?.error || res.statusText);
  return data;
}

const rowHeight = 20, pageSize = 200;
let total = 0, shown = 0, applied = '', pages = new Map(), selected = -1, frame = null, sources = [], source = 0, node = null;
const expanded = new Set(); // subtree kinds that stay open from packet to packet, as in Wireshark

function open() {
  openView(async id => {
    view = id;
    const status = await ask('status');
    total = status.frames;
    $('head').innerHTML = status.columns.map(c => `<span>${esc(c)}</span>`).join('');
    $('goto').max = total;
    show();
    await applyFilter($('filter').value.trim());
  });
}

// Packet list: only the rows in sight exist; their pages are fetched as needed.
async function applyFilter(filter) {
  // The number of displayed packets also tells whether the filter is valid.
  const counted = await ask('intervals', filter ? {filter} : {});
  applied = filter; shown = counted.frames; pages = new Map(); selected = -1;
  $('filter').value = filter; $('filter').className = filter ? 'valid' : '';
  $('clear').disabled = !filter;
  $('list').scrollTop = 0;
  list.count(shown);
  $('counts').textContent = `Packets: ${total} · Displayed: ${shown} (${total ? (shown * 100 / total).toFixed(1) : '0.0'}%)`;
  showFrame(null);
  draw();
  if (shown) await select(0);
}
function page(n) {
  if (!pages.has(n)) {
    const wanted = pages, entry = {rows: null};
    pages.set(n, entry);
    // sharkd takes no "skip": 0.
    entry.loaded = ask('frames', {...(applied ? {filter: applied} : {}), ...(n ? {skip: n * pageSize} : {}), limit: pageSize})
      .then(rows => { entry.rows = rows; if (wanted === pages) draw(); }, () => { wanted.delete(n); });
  }
  return pages.get(n);
}
const rowAt = i => page(Math.floor(i / pageSize)).rows?.[i % pageSize];
let list; // the packet list, of which only the rows in sight exist
const draw = () => list.draw();
function rowHtml(i) {
  const r = rowAt(i), top = `top:${i * rowHeight}px;`;
  return r ? `<div class="row${i === selected ? ' selected' : ''}" data-i="${i}" style="${top}${r.bg ? `background:#${r.bg};` : ''}${r.fg ? `color:#${r.fg};` : ''}">${r.c.map(c => `<span>${esc(c)}</span>`).join('')}</div>`
    : `<div class="row loading" style="${top}"><span>…</span></div>`;
}
async function rowWhenLoaded(i) {
  const p = page(Math.floor(i / pageSize));
  await p.loaded;
  return p.rows?.[i % pageSize];
}
async function select(i) {
  if (i < 0 || i >= shown) return;
  selected = i;
  list.reveal(i, $('head').offsetHeight);
  draw();
  const r = await rowWhenLoaded(i);
  if (!r || selected !== i) return;
  draw();
  const f = await ask('frame', {frame: r.num, proto: true, bytes: true});
  if (selected === i) showFrame(f);
}

// Packet details and bytes.
function showFrame(f) {
  frame = f; node = null; source = 0;
  sources = f ? [{name: 'Frame', bytes: decode(f.bytes)}, ...(f.ds || []).map(d => ({name: d.name, bytes: decode(d.bytes)}))] : [];
  $('follow').disabled = !f?.fol?.length;
  $('follow').textContent = f?.fol?.length ? `Follow ${f.fol[0][0]} stream` : 'Follow stream';
  drawTree(); drawBytes(); showField();
}
const decode = b64 => Uint8Array.from(atob(b64 || ''), c => c.charCodeAt(0));
const kindOf = n => n.e ?? n.l.split(':')[0];
function drawTree() {
  const walk = (list, depth, path) => list.map((n, i) => {
    const here = [...path, i], open = n.n && expanded.has(kindOf(n));
    return `<div class="node${n === node ? ' selected' : ''}${n.s ? ' ' + esc(n.s) : ''}" data-path="${here.join('.')}" style="padding-left:${4 + depth * 16}px"><span class="twist">${n.n ? (open ? '▼' : '▶') : ''}</span>${esc(n.g ? `[${n.l}]` : n.l)}</div>`
      + (open ? walk(n.n, depth + 1, here) : '');
  }).join('');
  $('details').innerHTML = frame ? walk(frame.tree, 0, []) : '';
}
const nodeAt = path => path.split('.').reduce((n, i) => (n.n || n)[i], frame.tree);
function showField() {
  $('field').textContent = node ? (node.fn ? node.fn + (node.h ? `, ${node.h[1]} byte${node.h[1] === 1 ? '' : 's'}` : '') : node.l) : '';
  $('asFilter').disabled = !node?.f;
}
function drawBytes() {
  const data = sources[source]?.bytes || new Uint8Array(), hl = node?.h && (node.ds || 0) === source ? node.h : null;
  const marked = i => hl && i >= hl[0] && i < hl[0] + hl[1];
  const hex = i => `<b data-o="${i}"${marked(i) ? ' class="hl"' : ''}>${data[i].toString(16).padStart(2, '0')}</b>`;
  const chr = i => `<b data-o="${i}"${marked(i) ? ' class="hl"' : ''}>${data[i] >= 32 && data[i] < 127 ? esc(String.fromCharCode(data[i])) : '·'}</b>`;
  let html = '';
  for (let at = 0; at < data.length; at += 16) {
    const n = Math.min(16, data.length - at), idx = [...Array(n).keys()].map(i => at + i);
    html += `<span class="off">${at.toString(16).padStart(4, '0')}</span>  ` + idx.map((i, k) => hex(i) + (k === 7 ? '  ' : ' ')).join('') + '   '.repeat(16 - n) + (n < 8 ? ' ' : '') + '  ' + idx.map(chr).join('') + '\n';
  }
  $('hex').innerHTML = html;
  $('sources').hidden = sources.length < 2;
  $('sources').innerHTML = sources.map((s, i) => `<button data-source="${i}"${i === source ? ' class="on"' : ''}>${esc(s.name)}</button>`).join('');
  $('hex').querySelector('.hl')?.scrollIntoView({block: 'nearest'});
}
// The field that a byte belongs to is the deepest one that covers it.
function fieldAt(offset) {
  let found = null;
  const walk = (list, path) => list.forEach((n, i) => {
    if ((n.ds || 0) !== source || !n.h || offset < n.h[0] || offset >= n.h[0] + n.h[1]) return;
    found = {n, path: [...path, n]};
    if (n.n) walk(n.n, found.path);
  });
  walk(frame.tree, []);
  return found;
}

// Follow stream.
async function follow() {
  const [protocol, filter] = frame.fol[0];
  const s = await ask('follow', {follow: protocol, filter});
  $('streamTitle').textContent = `Follow ${protocol} stream (${filter})`;
  const text = bytes => new TextDecoder('latin1').decode(decode(bytes)).replace(/[^\x20-\x7e\n\r\t]/g, '.');
  $('streamText').innerHTML = (s.payloads || []).map(p => `<span class="${p.s ? 'server' : 'client'}">${esc(text(p.d))}</span>`).join('') || 'This stream carries no payload.';
  $('streamSides').innerHTML = `<span class="client">${esc(s.chost)}:${esc(s.cport)} → (${s.cbytes} bytes)</span> <span class="server">${esc(s.shost)}:${esc(s.sport)} → (${s.sbytes} bytes)</span>`;
  $('streamFilter').onclick = () => { $('stream').close(); run(() => applyFilter(filter)); };
  $('stream').showModal();
}

// Problems show in the status bar, where Wireshark shows them.
const run = async f => { try { await f(); } catch (err) { if (err.message !== 'view ended') $('field').textContent = err.message; } };
function wire() {
$('filterForm').onsubmit = e => { e.preventDefault(); run(async () => {
  try { await applyFilter($('filter').value.trim()); } catch (err) { $('filter').className = 'invalid'; throw err; }
}); };
$('clear').onclick = () => run(() => applyFilter(''));
// The colour of the input tells whether the filter is valid before it is applied.
let checking = 0;
$('filter').oninput = async () => {
  const text = $('filter').value.trim(), mine = ++checking;
  if (!text) { $('filter').className = ''; return; }
  const word = text.split(/[\s()!=<>&|]+/).pop();
  const [valid, fields] = await Promise.all([
    ask('check', {filter: text}).then(() => true, () => false),
    word.length > 1 ? ask('complete', {field: word}).then(r => r.field || [], () => []) : [],
  ]);
  if (mine !== checking) return;
  $('filter').className = valid ? 'valid' : 'invalid';
  const before = text.slice(0, text.length - word.length);
  // 50 suggestions fill the browser's list; typing on narrows them.
  $('fields').innerHTML = fields.slice(0, 50).map(f => `<option value="${esc(before + f.f)}">${esc(f.n)}</option>`).join('');
};
list = virtual($('list'), $('rows'), rowHeight, rowHtml);
$('rows').onclick = e => { const row = e.target.closest('.row'); if (row?.dataset.i) run(() => select(Number(row.dataset.i))); };
$('list').onkeydown = e => {
  const visible = Math.max(1, Math.floor($('list').clientHeight / rowHeight) - 1);
  const to = {ArrowDown: selected + 1, ArrowUp: selected - 1, PageDown: selected + visible, PageUp: selected - visible, Home: 0, End: shown - 1}[e.key];
  if (to === undefined) return;
  e.preventDefault();
  run(() => select(Math.max(0, Math.min(shown - 1, to))));
};
$('first').onclick = () => run(() => select(0));
$('last').onclick = () => run(() => select(shown - 1));
$('prev').onclick = () => run(() => select(selected - 1));
$('next').onclick = () => run(() => select(selected + 1));
$('goto').onchange = () => run(async () => {
  const number = Number($('goto').value);
  if (!number) return;
  // Without a filter a packet's number is its place in the list; with one, the list is searched.
  if (!applied) return select(number - 1);
  // Numbers rise along the list: halve the range until the first packet from that number on is found.
  let low = 0, high = shown - 1;
  while (low < high) {
    const middle = (low + high) >> 1, r = await rowWhenLoaded(middle);
    if (!r) return;
    if (r.num >= number) high = middle; else low = middle + 1;
  }
  await select(low);
});
$('details').onclick = e => {
  const el = e.target.closest('.node');
  if (!el) return;
  const n = nodeAt(el.dataset.path);
  if (n.n && (e.target.classList.contains('twist') || e.detail > 1)) expanded.has(kindOf(n)) ? expanded.delete(kindOf(n)) : expanded.add(kindOf(n));
  node = n;
  if (n.h) source = n.ds || 0;
  drawTree(); drawBytes(); showField();
};
$('hex').onclick = e => {
  if (e.target.dataset.o === undefined) return;
  const found = fieldAt(Number(e.target.dataset.o));
  if (!found) return;
  for (const n of found.path.slice(0, -1)) expanded.add(kindOf(n));
  node = found.n;
  drawTree(); drawBytes(); showField();
  $('details').querySelector('.selected')?.scrollIntoView({block: 'nearest'});
};
$('sources').onclick = e => { if (e.target.dataset.source !== undefined) { source = Number(e.target.dataset.source); drawBytes(); } };
$('follow').onclick = () => run(follow);
$('asFilter').onclick = () => run(() => applyFilter(node.f));
$('streamClose').onclick = () => $('stream').close();
// The borders between the panes can be dragged.
for (const s of document.querySelectorAll('.splitter')) s.onpointerdown = down => {
  const above = $(s.dataset.above), below = $(s.dataset.below), a = above.offsetHeight, b = below.offsetHeight;
  s.setPointerCapture(down.pointerId);
  s.onpointermove = move => {
    const d = Math.max(40 - a, Math.min(b - 40, move.clientY - down.clientY));
    above.style.flex = `0 0 ${a + d}px`; below.style.flex = `0 0 ${b - d}px`;
    draw();
  };
  s.onpointerup = () => { s.onpointermove = null; };
};
}

export default function (root) {
  root.innerHTML = markup;
  wire();
  open();
}
