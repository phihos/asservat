// The viewer for a heap dump, of Java (HPROF) or of .NET (gcdump), follows
// how heap analysers begin (VisualVM, Eclipse MAT, PerfView): a summary, the
// histogram of classes with the number and size of their objects, the
// biggest single objects, and for Java the threads' stacks. The hub reads
// the dump and hands over this summary; the objects themselves stay in the
// dump, for an analyser on your machine.
import {$, esc, headers, openView, show, spot, virtual} from './common.js';

const markup = `
  <div class="tabs">
    <button data-tab="overview" class="on">Overview</button><button data-tab="classes">Classes</button>
    <button data-tab="biggest">Biggest objects</button><button data-tab="threads">Threads</button>
  </div>
  <div class="tab" id="overview"></div>
  <div class="tab" id="classes" hidden>
    <div class="narrow">
      <input id="find" type="search" placeholder="Name, or /regular expression/" autocomplete="off" spellcheck="false">
      <span id="shown" class="tally"></span>
    </div>
    <div class="histogram head cols"><button data-sort="name">Class</button><button data-sort="instances">Objects</button><button data-sort="bytes" class="sorted">Size</button><span>Share of the heap</span></div>
    <div id="scroll" tabindex="0"><div id="rows"></div></div>
  </div>
  <div class="tab" id="biggest" hidden></div>
  <div class="tab" id="threads" hidden></div>
`;

const number = n => n.toLocaleString('en-US');
const size = n => n < 1024 ? `${n} B` : n < 1 << 20 ? `${(n / 1024).toFixed(1)} KiB` : n < 2 ** 30 ? `${(n / 2 ** 20).toFixed(1)} MiB` : `${(n / 2 ** 30).toFixed(2)} GiB`;

export default function (root) {
  root.innerHTML = markup;
  openView(async id => {
    const heap = await (await fetch(`/api/views/${id}/pages/summary`, {headers})).json();
    draw(root, heap);
    show();
  });
}

function draw(root, heap) {
  // A .NET dump holds neither threads nor the kinds of roots, and calls a class a type.
  const java = !!heap.threads, classes = java ? 'classes' : 'types';
  heap.threads ||= []; heap.roots ||= {};
  root.querySelector('[data-tab=threads]').hidden = !java;
  root.querySelector('[data-tab=classes]').textContent = java ? 'Classes' : 'Types';
  root.querySelector('[data-sort=name]').textContent = java ? 'Class' : 'Type';
  const share = bytes => heap.bytes ? 100 * bytes / heap.bytes : 0;
  const top = heap.classes.slice(0, 8);
  $('overview').innerHTML = `<div class="page">
    <div class="figures">
      <div><b>${size(heap.bytes)}</b><span>in objects</span></div><div><b>${number(heap.objects)}</b><span>objects</span></div>
      <div><b>${number(heap.classes.length)}</b><span>${classes} with objects${java ? `, of ${number(heap.loaded)} loaded` : ''}</span></div>${java ? `<div><b>${number(heap.threads.length)}</b><span>threads</span></div>` : ''}
    </div>
    <h2>Largest ${classes}</h2>
    ${top.map(c => `<div class="bar" title="${esc(c.name)}"><span class="name">${esc(c.name)}</span><span class="track"><i style="width:${share(c.bytes).toFixed(1)}%"></i></span><span class="value">${size(c.bytes)} · ${share(c.bytes).toFixed(1)} %</span></div>`).join('')}
    ${java ? `<h2>GC roots</h2>
    <table class="plain">${Object.entries(heap.roots).sort((a, b) => b[1] - a[1]).map(([kind, n]) => `<tr><td>${esc(kind)}</td><td class="n">${number(n)}</td></tr>`).join('') || '<tr><td class="muted">None recorded.</td></tr>'}</table>` : ''}
    <h2>The dump</h2>
    <table class="plain">
      ${java ? `<tr><td>Written</td><td>${heap.time ? esc(new Date(heap.time).toISOString().replace('T', ' ').replace(/\.\d+Z/, ' UTC')) : 'unknown'}</td></tr>` : ''}
      <tr><td>Format</td><td>${esc(heap.format)}${java ? `, references of ${heap.idSize} bytes` : ': the objects of the heap with their types and sizes, without their contents'}</td></tr>
      <tr><td>Sizes</td><td>${!java ? 'As the .NET runtime reports them.' : heap.compressed ? 'As the JVM lays objects out with compressed references, its default below 32 GiB of heap: the figures of its own class histogram.' : 'As the JVM lays objects out with full references.'} They are the objects' own sizes ("shallow"). What an object keeps alive ("retained") needs the whole dump in an analyser such as ${java ? 'Eclipse MAT' : 'PerfView or Visual Studio'}: download it for that.</td></tr>
    </table></div>`;

  // The histogram: every class with objects, narrowed by name and sorted by a column.
  const rowHeight = 22; // as the rows of every list
  let rows = heap.classes, sort = 'bytes';
  const list = virtual($('scroll'), $('rows'), rowHeight, i => {
    const c = rows[i];
    return `<div class="histogram" style="top:${i * rowHeight}px"><span class="name" title="${esc(c.name)}">${esc(c.name)}</span><span class="n">${number(c.instances)}</span><span class="n">${size(c.bytes)}</span><span class="track labelled"><i style="width:calc((100% - 58px) * ${(share(c.bytes) / 100).toFixed(4)})"></i><em>${share(c.bytes).toFixed(1)} %</em></span></div>`;
  });
  const narrow = () => {
    const typed = $('find').value.trim(), re = /^\/(.*)\/$/.exec(typed);
    let matches = () => true;
    $('find').classList.remove('bad');
    if (re) { try { const pattern = new RegExp(re[1], 'i'); matches = c => pattern.test(c.name); } catch { $('find').classList.add('bad'); } }
    else if (typed) { const words = typed.toLowerCase(); matches = c => c.name.toLowerCase().includes(words); }
    rows = heap.classes.filter(matches).sort((a, b) => sort === 'name' ? a.name.localeCompare(b.name) : b[sort] - a[sort] || a.name.localeCompare(b.name));
    const bytes = rows.reduce((sum, c) => sum + c.bytes, 0);
    $('shown').textContent = `${number(rows.length)} of ${number(heap.classes.length)} ${classes} · ${size(bytes)} · ${share(bytes).toFixed(1)} % of the heap`;
    list.count(rows.length);
    spot.write({tab: 'classes', find: typed, sort: sort === 'bytes' ? '' : sort});
  };
  $('find').oninput = narrow;
  for (const b of root.querySelectorAll('[data-sort]')) b.onclick = () => {
    sort = b.dataset.sort;
    for (const other of root.querySelectorAll('[data-sort]')) other.classList.toggle('sorted', other === b);
    narrow();
  };

  $('biggest').innerHTML = `<div class="page"><p class="muted">The ${heap.biggest.length} single objects with the largest size of their own. A large array is often the storage of a collection, a buffer or a cache.</p>
    <table class="grid"><thead><tr><th>${java ? 'Class' : 'Type'}</th><th class="n">Size</th>${java ? '<th class="n">Length</th>' : ''}</tr></thead><tbody>
    ${heap.biggest.map(o => `<tr><td class="name">${esc(o.class)}</td><td class="n">${size(o.bytes)}</td>${java ? `<td class="n">${o.array ? number(o.length || 0) : ''}</td>` : ''}</tr>`).join('')}</tbody></table></div>`;

  $('threads').innerHTML = `<div class="page"><p class="muted">The stacks of the threads when the dump was written. The dump numbers the threads; their names are among its objects.</p>
    ${heap.threads.map(t => `<div class="thread"><h4>Thread ${t.serial}</h4><pre>${t.frames.length ? t.frames.map(f => 'at ' + esc(f)).join('\n') : '<span class="muted">no Java frames</span>'}</pre></div>`).join('') || '<p class="muted">The dump holds no thread stacks.</p>'}</div>`;

  const open = name => {
    for (const b of root.querySelectorAll('[data-tab]')) b.classList.toggle('on', b.dataset.tab === name);
    for (const tab of root.querySelectorAll('.tab')) tab.hidden = tab.id !== name;
    if (name === 'classes') list.draw();
  };
  root.querySelector('.tabs').onclick = e => {
    if (!e.target.dataset.tab) return;
    open(e.target.dataset.tab);
    spot.write({tab: e.target.dataset.tab === 'overview' ? '' : e.target.dataset.tab});
  };
  // The address names the tab, and for the classes what narrows and sorts them.
  const at = spot.read();
  if (at.sort && root.querySelector(`[data-sort="${CSS.escape(at.sort)}"]`)) { sort = at.sort; for (const b of root.querySelectorAll('[data-sort]')) b.classList.toggle('sorted', b.dataset.sort === sort); }
  $('find').value = at.find || '';
  if ($(at.tab)?.classList.contains('tab')) open(at.tab);
  if (at.tab === 'classes') narrow(); else { rows = heap.classes; list.count(rows.length); $('shown').textContent = `${number(rows.length)} ${classes}`; }
}
