// The viewer for goroutine and thread dumps follows the tools that analyse
// them (panicparse for Go, the thread dump analysers of Java IDEs): stacks
// that are the same are shown once with their number, by state.
import {$, esc, loadText, spot, truncatedNote, show} from './common.js';

const markup = `
  <div class="narrow">
    <input id="text" type="search" placeholder="Search names and stacks" autocomplete="off" spellcheck="false">
    <label>State <select id="state"></select></label>
    <label><input type="checkbox" id="group" checked> Group identical stacks</label>
    <span id="shown" class="tally"></span>
  </div>
  <div id="split"><div id="groups" tabindex="0"></div><pre id="stack"></pre></div>
  <div id="note" hidden></div>
`;

// parse splits a dump into its goroutines or threads: blocks that a blank
// line separates and whose first line names one.
export function parse(text) {
  const all = [];
  for (const block of text.split(/\n\s*\n/)) {
    const lines = block.replace(/^\n+|\s+$/g, '').split('\n');
    const go = /^goroutine (\d+)(?: gp=\S+ m=\S+(?: mp=\S+)?)? \[([^\],]+)(?:, ([^\]]+))?\]:/.exec(lines[0]);
    const java = /^"([^"]*)"/.exec(lines[0]);
    if (!go && !java) continue;
    const stack = lines.slice(1);
    const state = go ? go[2] : (/java\.lang\.Thread\.State: (\S+)/.exec(block)?.[1] || /\b(runnable|waiting on condition|in Object\.wait\(\))/.exec(lines[0])?.[1] || 'unknown');
    // What makes two stacks the same: their frames with file and line, without addresses, Go's argument values and Java's object identities.
    const same = stack.map(l => (go ? l.replace(/^(\S.*)\(.*\)$/, '$1') : l).replace(/0x[0-9a-f]+/g, '').replace(/ \+$/, '').replace(/<[^>]*>/g, '<>').trim())
      .filter(l => !l.startsWith('java.lang.Thread.State')).join('\n');
    const frames = stack.map(l => l.trim()).filter(l => go ? !l.startsWith('/') && !l.startsWith('created by') : l.startsWith('at '));
    all.push({name: go ? `goroutine ${go[1]}` : java[1], state, waited: go?.[3] || '', top: (frames[0] || '').replace(/^at /, '').replace(/\([^()]*\)$/, ''), text: block.trim(), same});
  }
  return all;
}

export default async function (root) {
  const {text, truncated} = await loadText();
  const all = parse(text);
  root.innerHTML = markup;
  let groups = [], selected = 0;
  const states = new Map();
  for (const s of all) states.set(s.state, (states.get(s.state) || 0) + 1);
  $('state').innerHTML = '<option value="">All</option>' + [...states].sort((a, b) => b[1] - a[1]).map(([s, n]) => `<option value="${esc(s)}">${esc(s)} (${n})</option>`).join('');

  const draw = () => {
    $('groups').innerHTML = groups.map((g, i) => `<div class="g${i === selected ? ' selected' : ''}" data-i="${i}"><span class="n">${g.length > 1 ? g.length + ' ×' : ''}</span><span class="state">${esc(g[0].state)}</span><span class="top">${esc(g[0].top || g[0].name)}</span><span class="who">${esc(g.length > 1 ? '' : g[0].name)}</span></div>`).join('')
      || '<p class="muted">Nothing matches.</p>';
    const g = groups[selected];
    $('stack').textContent = !g ? '' : (g.length > 1 ? `${g.length} with this stack: ${g.map(s => s.name + (s.waited ? ` (${s.waited})` : '')).join(', ')}\n\n` : '') + g[0].text;
  };
  const narrow = () => {
    const words = $('text').value.toLowerCase(), state = $('state').value;
    const kept = all.filter(s => (!state || s.state === state) && (!words || s.text.toLowerCase().includes(words)));
    const by = new Map();
    for (const s of kept) { const k = $('group').checked ? s.state + '\n' + s.same : by.size; by.set(k, [...(by.get(k) || []), s]); }
    groups = [...by.values()];
    // The stacks that most share come first, as the likeliest place of a pile-up.
    if ($('group').checked) groups.sort((a, b) => b.length - a.length);
    selected = 0;
    $('shown').textContent = `${all.length.toLocaleString('en')} in the dump · ${kept.length.toLocaleString('en')} shown` + ($('group').checked ? ` in ${groups.length} stacks` : '');
    draw();
  };
  for (const id of ['text', 'state', 'group']) $(id).oninput = narrow;
  const choose = i => { selected = i; spot.write({g: groups[i]?.[0].name}); draw(); };
  $('groups').onclick = e => { const g = e.target.closest('.g'); if (g) choose(Number(g.dataset.i)); };
  $('groups').onkeydown = e => {
    const step = {ArrowDown: 1, ArrowUp: -1}[e.key];
    if (!step || selected + step < 0 || selected + step >= groups.length) return;
    e.preventDefault();
    choose(selected + step);
    $('groups').querySelector('.selected')?.scrollIntoView({block: 'nearest'});
  };
  if (truncated) { $('note').hidden = false; $('note').textContent = truncatedNote; }
  if (!all.length) { $('note').hidden = false; $('note').textContent = 'No goroutines or threads were recognized in this file. Its text follows.'; $('stack').textContent = text; }
  show();
  if (all.length) narrow();
  // The address names a goroutine or thread: its stack is selected.
  const named = spot.read().g, at = named ? groups.findIndex(g => g.some(s => s.name === named)) : -1;
  if (at >= 0) { choose(at); $('groups').querySelector('.selected')?.scrollIntoView({block: 'nearest'}); }
}
