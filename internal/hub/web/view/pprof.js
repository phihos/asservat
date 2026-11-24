// A profile is shown by pprof itself: the hub holds the pages of pprof's web
// interface for the open file, and this page frames them. Against a base,
// another profile of the same kind, pprof shows what changed.
import {$, esc, capture, file, headers, openView, show, spot} from './common.js';

const markup = `
  <div id="compare" class="narrow">
    <label>Compare with <select id="base"><option value="">nothing: this profile alone</option></select></label>
    <span id="comparing"></span>
    <span class="tally" title="pprof draws a box as wide as its share, so a small one cannot hold its name">Point at a box for its full name and share · click it to see what calls it and what it calls, at full width</span>
  </div>
  <iframe id="pprof" title="pprof"></iframe>
`;

export default async function (root, {capture: mine}) {
  root.innerHTML = markup;
  const base = spot.read().base || '';
  // The bases on offer: profiles of the same kind in the user's captures, the same workload's first, the newest first.
  const name = file.split('/').pop(), list = await (await fetch('/api/captures', {headers})).json();
  const others = list.flatMap(c => c.artifacts.filter(a => a.viewer === 'pprof' && a.name.split('/').pop() === name && !(c.id === capture && a.name === file)).map(a => ({c, a})))
    .sort((x, y) => ((y.c.workload === mine.workload) - (x.c.workload === mine.workload)) || y.c.createdAt.localeCompare(x.c.createdAt));
  $('base').innerHTML += others.map(({c, a}) => `<option value="${esc(c.id + '/' + a.name)}">${esc(c.createdAt.slice(0, 19).replace('T', ' '))} UTC · ${esc(c.workload)} · pod ${esc(a.name.split('/')[0])}</option>`).join('');
  $('base').value = base;
  if (base && $('base').value !== base) $('base').innerHTML += `<option value="${esc(base)}" selected>${esc(base)}</option>`;
  $('comparing').textContent = base ? 'Shown is this profile minus the chosen one: what the workload does more of now is positive.' : others.length ? '' : `No other ${name} in your captures yet.`;
  // The base is part of the address, so a link leads to the same comparison.
  $('base').onchange = () => { spot.write({base: $('base').value}); location.reload(); };
  openView(id => { $('pprof').src = `/api/views/${id}/pages/`; show(); }, base ? '?base=' + encodeURIComponent(base) : '');
}
