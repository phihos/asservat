// The log viewer follows the log panels of Lens and the Kubernetes
// dashboard: a dark terminal with timestamps, search and a wrapped view of
// the selected line.
import {$, esc, loadText, truncatedNote, show, virtual} from './common.js';

const markup = `
  <div class="logbar">
    <input id="search" type="search" placeholder="Search … text, or /regular expression/" autocomplete="off" spellcheck="false">
    <button id="up" title="Previous match (Shift+Enter)">▲</button>
    <button id="down" title="Next match (Enter)">▼</button>
    <span id="found"></span>
    <label><input type="checkbox" id="only"> Only matching lines</label>
    <label><input type="checkbox" id="stamps" checked> Timestamps</label>
    <span class="grow"></span>
    <span id="span"></span>
  </div>
  <div id="log" tabindex="0"><div id="lines"></div></div>
  <pre id="line" hidden></pre>
  <div id="note" hidden></div>
`;
// The kubelet puts an RFC 3339 timestamp in front of every line.
const stamp = /^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)) /;
const levels = [[/\b(error|fatal|panic|critical|exception)\b/i, 'error'], [/\bwarn(ing)?\b/i, 'warn'], [/\b(debug|trace)\b/i, 'debug']];
const rowHeight = 18;

export default async function (root) {
  const {text, truncated} = await loadText();
  const lines = text.split('\n');
  if (lines.at(-1) === '') lines.pop();
  root.innerHTML = markup;
  let pattern = null, matches = [], at = -1, visible = null, selected = -1;

  const parts = i => { const m = stamp.exec(lines[i]); return m ? [m[1], lines[i].slice(m[0].length)] : ['', lines[i]]; };
  const marked = s => {
    if (!pattern) return esc(s);
    let out = '', last = 0;
    for (const m of s.matchAll(pattern)) {
      if (!m[0]) continue;
      out += esc(s.slice(last, m.index)) + '<mark>' + esc(m[0]) + '</mark>'; last = m.index + m[0].length;
    }
    return out + esc(s.slice(last));
  };
  const index = i => visible ? visible[i] : i;
  const list = virtual($('log'), $('lines'), rowHeight, i => {
    const n = index(i), [time, message] = parts(n), level = levels.find(([re]) => re.test(message))?.[1] || '';
    return `<div class="l ${level}${n === selected ? ' selected' : ''}${n === matches[at] ? ' current' : ''}" data-n="${n}" style="top:${i * rowHeight}px"><span class="no">${n + 1}</span>${time && $('stamps').checked ? `<span class="ts">${esc(time)}</span> ` : ''}${marked(message)}</div>`;
  });
  const count = () => list.count(visible ? visible.length : lines.length);
  const go = to => {
    if (!matches.length) return;
    at = (to + matches.length) % matches.length;
    $('found').textContent = `${at + 1} of ${matches.length}`;
    list.reveal(visible ? at : matches[at]);
    list.draw();
  };
  const search = () => {
    const typed = $('search').value;
    $('search').classList.remove('bad');
    pattern = null;
    if (typed) {
      const re = /^\/(.+)\/$/.exec(typed);
      try { pattern = new RegExp(re ? re[1] : typed.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi'); } catch { $('search').classList.add('bad'); }
    }
    matches = [];
    if (pattern) lines.forEach((l, i) => { pattern.lastIndex = 0; if (pattern.test(l)) matches.push(i); });
    visible = pattern && $('only').checked ? matches : null;
    at = -1;
    $('found').textContent = pattern ? (matches.length ? `${matches.length} matching lines` : 'No match') : '';
    $('log').scrollTop = 0;
    count();
    if (matches.length) go(0);
  };
  const select = n => {
    selected = n;
    const [time, message] = parts(n);
    let shownText = message;
    // A line of JSON reads better spread out.
    if (/^\s*[{[]/.test(message)) try { shownText = JSON.stringify(JSON.parse(message), null, 2); } catch {}
    $('line').hidden = false;
    $('line').textContent = (time ? time + '\n' : '') + shownText;
    list.draw();
  };

  $('search').oninput = search;
  $('only').onchange = search;
  $('stamps').onchange = list.draw;
  $('search').onkeydown = e => { if (e.key === 'Enter') { e.preventDefault(); go(at + (e.shiftKey ? -1 : 1)); } };
  $('down').onclick = () => go(at + 1);
  $('up').onclick = () => go(at - 1);
  $('lines').onclick = e => { const l = e.target.closest('.l'); if (l && !getSelection().toString()) select(Number(l.dataset.n)); };
  $('log').onkeydown = e => {
    const step = {ArrowDown: 1, ArrowUp: -1}[e.key];
    if (!step || selected < 0) return;
    e.preventDefault();
    const order = visible || null, pos = order ? order.indexOf(selected) : selected, to = pos + step;
    if (to < 0 || to >= (order ? order.length : lines.length)) return;
    select(order ? order[to] : to);
    list.reveal(to);
  };
  const first = parts(0)[0], last = lines.length ? parts(lines.length - 1)[0] : '';
  $('span').textContent = `${lines.length} line${lines.length === 1 ? '' : 's'}` + (first && last ? ` · ${first.slice(0, 19).replace('T', ' ')} to ${last.slice(0, 19).replace('T', ' ')} UTC` : '');
  if (truncated) { $('note').hidden = false; $('note').textContent = truncatedNote; }
  if (!lines.length) { $('note').hidden = false; $('note').textContent = 'This log is empty.'; }
  show();
  count();
}
