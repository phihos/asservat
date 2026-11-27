// The trace viewer shows strace's output as a table of calls that can be
// narrowed, and the summary that "strace -c" prints: time, calls and errors
// per system call.
import {$, capture, esc, filePath, headers, loadText, moment, spot, truncatedNote, show, virtual} from './common.js';

const markup = `
  <div class="tabs"><button data-tab="calls" class="on">Calls</button><button data-tab="summary">Summary</button><span id="shown" class="tally"></span></div>
  <div id="calls" class="tab">
    <div class="narrow">
      <input id="text" type="search" placeholder="Search arguments and results" autocomplete="off" spellcheck="false">
      <label>System call <select id="syscall"></select></label>
      <label>Process <select id="pid"></select></label>
      <label><input type="checkbox" id="failed"> Failed only</label>
      <label>Slower than <input id="slower" type="number" min="0" step="any" placeholder="0"> ms</label>
    </div>
    <div id="table" tabindex="0"><div id="thead" class="cols"><span>Time</span><span>Process</span><span>System call</span><span>Arguments</span><span>Result</span><span>Duration</span></div><div id="trows"></div></div>
    <pre id="call" class="drawer" hidden></pre>
  </div>
  <div id="summary" class="tab" hidden></div>
  <div id="note" hidden></div>
`;
const rowHeight = 20;

// parse turns strace's lines (-f -tt -T) into calls. A call that another
// process interrupts is printed in two lines, which become one call again.
export function parse(text) {
  const calls = [], open = new Map();
  for (const line of text.split('\n')) {
    const m = /^(?:\[pid\s+)?(\d+)?\]?\s*(\d\d:\d\d:\d\d(?:\.\d+)?) (.*)$/.exec(line);
    if (!m) continue;
    const [, pid = '', time, rest] = m;
    let c;
    const resumed = /^<\.\.\. (\S+) resumed>(.*)$/.exec(rest);
    if (resumed && open.has(pid)) {
      c = open.get(pid); open.delete(pid);
      finish(c, c.args + resumed[2]);
      continue;
    }
    if (rest.startsWith('---')) c = {kind: 'signal', name: rest.split(' ')[1] || 'signal', args: rest.replace(/^--- | ---$/g, ''), result: ''};
    else if (rest.startsWith('+++')) c = {kind: 'exit', name: 'exit', args: rest.replace(/^\+\+\+ | \+\+\+$/g, ''), result: ''};
    else {
      const paren = rest.indexOf('(');
      if (paren < 0) continue;
      c = {kind: 'call', name: rest.slice(0, paren), result: ''};
      const unfinished = rest.endsWith(' <unfinished ...>');
      if (unfinished) { c.args = rest.slice(paren + 1, -' <unfinished ...>'.length); c.result = '…'; open.set(pid, c); }
      else finish(c, rest.slice(paren + 1));
    }
    c.pid = pid; c.time = time;
    calls.push(c);
  }
  return calls;
}
// finish splits "args) = result <duration>".
function finish(c, tail) {
  const d = / <(\d+\.\d+)>$/.exec(tail);
  if (d) { c.seconds = Number(d[1]); tail = tail.slice(0, d.index); }
  // strace pads short calls with spaces before the "=".
  const eq = [...tail.matchAll(/\)\s+= /g)].pop();
  if (!eq) { c.args = tail; return; }
  c.args = tail.slice(0, eq.index); c.result = tail.slice(eq.index + eq[0].length).trim();
  c.failed = /^-1\b/.test(c.result);
  c.error = c.failed ? c.result.split(' ')[1] : '';
}
const duration = s => s === undefined ? '' : s >= 1 ? s.toFixed(3) + ' s' : s >= 0.001 ? (s * 1000).toFixed(3) + ' ms' : Math.round(s * 1e6) + ' µs';

export default async function (root, {capture}) {
  const {text, truncated} = await loadText();
  const calls = parse(text);
  // strace prints the time of day, in UTC as the agent runs; the capture gives the day.
  const requested = Date.parse(capture.createdAt) / 1000, midnight = Date.parse(capture.createdAt.slice(0, 10) + 'T00:00:00Z') / 1000;
  const momentOf = c => {
    const [h, m, s] = c.time.split(':').map(Number), at = midnight + h * 3600 + m * 60 + s;
    return at < requested - 43200 ? at + 86400 : at; // past midnight
  };
  root.innerHTML = markup;
  let visible = calls, selected = null;

  const counts = by => { const n = new Map(); for (const c of calls) n.set(by(c), (n.get(by(c)) || 0) + 1); return [...n].sort((a, b) => b[1] - a[1]); };
  $('syscall').innerHTML = '<option value="">All</option>' + counts(c => c.name).map(([name, n]) => `<option value="${esc(name)}">${esc(name)} (${n})</option>`).join('');
  $('pid').innerHTML = '<option value="">All</option>' + counts(c => c.pid).map(([pid, n]) => `<option value="${esc(pid)}">${esc(pid)} (${n})</option>`).join('');

  const list = virtual($('table'), $('trows'), rowHeight, i => {
    const c = visible[i];
    return `<div class="c ${c.kind}${c.failed ? ' failed' : ''}${c === selected ? ' selected' : ''}" data-i="${i}" style="top:${i * rowHeight}px"><span>${esc(c.time)}</span><span>${esc(c.pid)}</span><span class="name">${esc(c.name)}</span><span>${esc(c.args)}</span><span class="result">${esc(c.result)}</span><span class="dur">${duration(c.seconds)}</span></div>`;
  });
  const narrow = () => {
    const words = $('text').value.toLowerCase(), name = $('syscall').value, pid = $('pid').value, failed = $('failed').checked, slower = Number($('slower').value) / 1000;
    visible = calls.filter(c => (!name || c.name === name) && (!pid || c.pid === pid) && (!failed || c.failed) && (!slower || c.seconds >= slower)
      && (!words || c.args.toLowerCase().includes(words) || c.result.toLowerCase().includes(words) || c.name.includes(words)));
    $('shown').textContent = `${calls.length.toLocaleString('en')} entries · ${visible.length.toLocaleString('en')} shown`;
    $('table').scrollTop = 0;
    list.count(visible.length);
  };
  const select = i => {
    selected = visible[i];
    $('call').hidden = false;
    $('call').textContent = `${selected.time}  process ${selected.pid}\n${selected.kind === 'call' ? `${selected.name}(${selected.args}) = ${selected.result}` : selected.args}${selected.seconds === undefined ? '' : `\ntook ${duration(selected.seconds)}`}`;
    spot.write({e: calls.indexOf(selected) + 1});
    moment(momentOf(selected));
    list.reveal(i, $('thead').offsetHeight);
    list.draw();
  };
  const tab = name => {
    for (const b of root.querySelectorAll('[data-tab]')) b.classList.toggle('on', b.dataset.tab === name);
    $('calls').hidden = name !== 'calls'; $('summary').hidden = name !== 'summary';
    if (name === 'calls') list.draw();
  };

  // The summary: what "strace -c" prints, with the call's name first, so that it is in sight on a narrow screen too.
  const per = new Map();
  for (const c of calls) if (c.kind === 'call') {
    const s = per.get(c.name) || {name: c.name, calls: 0, errors: 0, seconds: 0};
    s.calls++; s.errors += c.failed ? 1 : 0; s.seconds += c.seconds || 0;
    per.set(c.name, s);
  }
  const sum = (rows, all, said = '') => {
    const line = (s, name) => `<td class="name">${name}</td><td>${all.seconds ? (s.seconds * 100 / all.seconds).toFixed(2) : '0.00'}</td><td>${s.seconds.toFixed(6)}</td><td>${s.calls ? Math.round(s.seconds * 1e6 / s.calls) : 0}</td><td>${s.calls}</td><td>${s.errors || ''}</td>`;
    $('summary').innerHTML = (said && `<p class="said">${esc(said)}</p>`) + `<table><thead><tr><th>syscall</th><th>% time</th><th>seconds</th><th>usecs/call</th><th>calls</th><th>errors</th></tr></thead>
      <tbody>${rows.map(s => `<tr data-name="${esc(s.name)}" title="Show these calls">${line(s, esc(s.name))}</tr>`).join('')}</tbody>
      <tfoot><tr>${line(all, 'total')}</tr></tfoot></table>`;
  };
  const rows = [...per.values()].sort((a, b) => b.seconds - a.seconds);
  sum(rows, rows.reduce((t, s) => ({calls: t.calls + s.calls, errors: t.errors + s.errors, seconds: t.seconds + s.seconds}), {calls: 0, errors: 0, seconds: 0}),
    truncated ? 'Of the beginning of the trace that is shown.' : '');
  // Of a trace larger than is loaded, the hub sums up the whole.
  if (truncated) fetch(`/api/captures/${capture}/summaries/${filePath}`, {headers}).then(r => r.ok ? r.json() : null).then(whole => {
    if (whole) sum(whole.calls, whole.total, 'Of the whole trace. The list of calls holds its beginning only.');
  }).catch(() => {});

  for (const id of ['text', 'syscall', 'pid', 'failed', 'slower']) $(id).oninput = narrow;
  $('trows').onclick = e => { const r = e.target.closest('.c'); if (r && !getSelection().toString()) select(Number(r.dataset.i)); };
  $('table').onkeydown = e => {
    const step = {ArrowDown: 1, ArrowUp: -1}[e.key], at = visible.indexOf(selected);
    if (!step || at < 0 || at + step < 0 || at + step >= visible.length) return;
    e.preventDefault();
    select(at + step);
  };
  root.querySelector('.tabs').onclick = e => { if (e.target.dataset.tab) tab(e.target.dataset.tab); };
  $('summary').onclick = e => { const r = e.target.closest('tr[data-name]'); if (!r) return;
    // The calls of that name, all of them: the other narrowing is dropped.
    $('text').value = ''; $('pid').value = ''; $('failed').checked = false; $('slower').value = '';
    $('syscall').value = r.dataset.name; tab('calls'); narrow();
  };
  if (truncated) { $('note').hidden = false; $('note').textContent = truncatedNote; }
  if (!calls.length) { $('note').hidden = false; $('note').textContent = 'This trace holds no calls.'; }
  show();
  narrow();
  // The address names an entry, or a moment: then the first entry from that moment on.
  const named = spot.read();
  let to = named.e ? Number(named.e) - 1 : -1;
  if (to < 0 && named.at) to = calls.findIndex(c => momentOf(c) >= Number(named.at));
  if (to < 0 && named.at && calls.length) to = calls.length - 1;
  if (to >= 0 && to < calls.length) select(to);
}
